from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Any

from cve_scanner.config import get_settings
from cve_scanner.db import get_cached_cve, set_cached_cve
from cve_scanner.enrichment.epss_client import get_epss
from cve_scanner.enrichment.kev_client import is_in_kev
from cve_scanner.models import CVEFinding, Severity

logger = logging.getLogger(__name__)


def _map_severity(value: str) -> Severity:
    normalized = value.strip().upper()
    if normalized == "CRITICAL":
        return Severity.CRITICAL
    if normalized == "HIGH":
        return Severity.HIGH
    if normalized == "MEDIUM":
        return Severity.MODERATE
    if normalized == "LOW":
        return Severity.LOW
    return Severity.LOW


def _extract_cvss_score(vuln: dict[str, Any]) -> float:
    cvss_data = vuln.get("CVSS") or {}
    scores: list[float] = []
    for vendor in cvss_data.values():
        if not isinstance(vendor, dict):
            continue
        v3_score = vendor.get("V3Score")
        v2_score = vendor.get("V2Score")
        if isinstance(v3_score, (int, float)):
            scores.append(float(v3_score))
        if isinstance(v2_score, (int, float)):
            scores.append(float(v2_score))
    return max(scores) if scores else 0.0


def _extract_grype_cvss(match: dict[str, Any]) -> float:
    vuln = match.get("vulnerability", {})
    cvss_entries = vuln.get("cvss") or []
    scores: list[float] = []
    for entry in cvss_entries:
        metrics = entry.get("metrics", {})
        base_score = metrics.get("baseScore")
        if isinstance(base_score, (int, float)):
            scores.append(float(base_score))
    return max(scores) if scores else 0.0


def _ensure_tool(tool_path: str, tool_name: str, install_url: str) -> None:
    if shutil.which(tool_path) is None and not Path(tool_path).exists():
        raise RuntimeError(f"{tool_name} not found. Install: {install_url}")


async def run_trivy(repo_path: str) -> list[CVEFinding]:
    settings = get_settings()
    _ensure_tool(settings.TRIVY_PATH, "Trivy", "https://aquasecurity.github.io/trivy/")

    cmd = [
        settings.TRIVY_PATH,
        "fs",
        "--format",
        "json",
        "--severity",
        "LOW,MEDIUM,HIGH,CRITICAL",
        repo_path,
    ]
    logger.debug("Running Trivy command: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise RuntimeError("Trivy scan timed out after 120s")
    if proc.returncode != 0:
        raise RuntimeError(f"Trivy scan failed: {stderr.decode(errors='ignore')}")

    payload = json.loads(stdout.decode())
    findings: list[CVEFinding] = []
    results = payload.get("Results") or []

    staged: list[dict[str, Any]] = []

    for result in results:
        target = result.get("Target") or "unknown"
        vulnerabilities = result.get("Vulnerabilities") or []
        for vuln in vulnerabilities:
            cve_id = vuln.get("VulnerabilityID") or ""
            if not cve_id:
                continue
            cached = await get_cached_cve(settings.DB_PATH, cve_id, settings.CVE_CACHE_TTL_HOURS)
            description = vuln.get("Description") or ""
            severity = _map_severity(vuln.get("Severity") or "LOW")
            cvss_score = _extract_cvss_score(vuln)
            if cached:
                description = cached.get("description", description)
                severity = _map_severity(cached.get("severity", severity.value))
                cvss_score = float(cached.get("cvss_score", cvss_score))

            staged.append(
                {
                    "cve_id": cve_id,
                    "package_name": vuln.get("PkgName") or "",
                    "installed_version": vuln.get("InstalledVersion") or "",
                    "fixed_version": vuln.get("FixedVersion") or "",
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "defined_in": target,
                    "description": description,
                }
            )

    epss_tasks = [get_epss(entry["cve_id"]) for entry in staged]
    kev_tasks = [is_in_kev(entry["cve_id"]) for entry in staged]
    epss_scores = await asyncio.gather(*epss_tasks) if epss_tasks else []
    kev_flags = await asyncio.gather(*kev_tasks) if kev_tasks else []

    for entry, epss_score, kev_listed in zip(staged, epss_scores, kev_flags):
        finding = CVEFinding(
            cve_id=entry["cve_id"],
            package_name=entry["package_name"],
            installed_version=entry["installed_version"],
            fixed_version=entry["fixed_version"],
            severity=entry["severity"],
            cvss_score=entry["cvss_score"],
            epss_score=epss_score,
            kev_listed=kev_listed,
            defined_in=entry["defined_in"],
            description=entry["description"],
        )
        await set_cached_cve(
            settings.DB_PATH,
            entry["cve_id"],
            {
                "description": entry["description"],
                "severity": entry["severity"].value,
                "cvss_score": entry["cvss_score"],
                "epss_score": epss_score,
                "kev_listed": kev_listed,
            },
        )
        findings.append(finding)

    return findings


async def run_grype(repo_path: str) -> list[CVEFinding]:
    grype_path = "grype"
    _ensure_tool(grype_path, "Grype", "https://github.com/anchore/grype")

    cmd = [grype_path, f"dir:{repo_path}", "-o", "json"]
    logger.debug("Running Grype command: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise RuntimeError("Grype scan timed out after 120s")
    if proc.returncode != 0:
        raise RuntimeError(f"Grype scan failed: {stderr.decode(errors='ignore')}")

    payload = json.loads(stdout.decode())
    findings: list[CVEFinding] = []
    matches = payload.get("matches") or []

    for match in matches:
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        cve_id = vulnerability.get("id") or ""
        if not cve_id:
            continue
        cached = await get_cached_cve(settings.DB_PATH, cve_id, settings.CVE_CACHE_TTL_HOURS)
        description = vulnerability.get("description") or ""
        severity = _map_severity(vulnerability.get("severity") or "LOW")
        cvss_score = _extract_grype_cvss(match)
        if cached:
            description = cached.get("description", description)
            severity = _map_severity(cached.get("severity", severity.value))
            cvss_score = float(cached.get("cvss_score", cvss_score))

        epss_score = await get_epss(cve_id)
        kev_listed = await is_in_kev(cve_id)

        finding = CVEFinding(
            cve_id=cve_id,
            package_name=artifact.get("name") or "",
            installed_version=artifact.get("version") or "",
            fixed_version=vulnerability.get("fix", {}).get("versions", [""])[0],
            severity=severity,
            cvss_score=cvss_score,
            epss_score=epss_score,
            kev_listed=kev_listed,
            defined_in=artifact.get("locations", [{}])[0].get("path", "unknown"),
            description=description,
        )
        await set_cached_cve(
            settings.DB_PATH,
            cve_id,
            {
                "description": description,
                "severity": finding.severity.value,
                "cvss_score": finding.cvss_score,
                "epss_score": finding.epss_score,
                "kev_listed": finding.kev_listed,
            },
        )
        findings.append(finding)

    return findings
