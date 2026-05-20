from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path

from cve_scanner.config import get_settings
from cve_scanner.models import CVEFinding, ReachabilityResult

logger = logging.getLogger(__name__)


def _semgrep_available() -> bool:
    settings = get_settings()
    return shutil.which(settings.SEMGREP_PATH) is not None or Path(settings.SEMGREP_PATH).exists()


def _build_rule_yaml(findings: list[CVEFinding]) -> str:
    rules = ["rules:"]
    for finding in findings:
        package = finding.package_name
        rule_id = f"reach-{finding.cve_id}"
        rules.extend(
            [
                f"  - id: {rule_id}",
                "    patterns:",
                "      - pattern-either:",
                f"          - pattern: import {package}",
                f"          - pattern: from {package} import ...",
                f"          - pattern: import '{package}'",
                f"          - pattern: import \"{package}\"",
                f"          - pattern: import $X from '{package}'",
                f"          - pattern: import $X from \"{package}\"",
                f"          - pattern: import {{...}} from '{package}'",
                f"          - pattern: import {{...}} from \"{package}\"",
                f"          - pattern: export * from '{package}'",
                f"          - pattern: export * from \"{package}\"",
                f"          - pattern: export {{...}} from '{package}'",
                f"          - pattern: export {{...}} from \"{package}\"",
                f"          - pattern: export {{ default as $X }} from '{package}'",
                f"          - pattern: export {{ default as $X }} from \"{package}\"",
                f"          - pattern: require('{package}')",
                f"          - pattern: require(\"{package}\")",
                f"          - pattern: $X = require('{package}')",
                f"          - pattern: $X = require(\"{package}\")",
                (
                    "    message: "
                    f"\"Package {package} is used - CVE {finding.cve_id} may be reachable\""
                ),
                "    languages: [python, javascript, typescript]",
                "    severity: ERROR",
            ]
        )
    return "\n".join(rules) + "\n"


async def _run_semgrep(config_path: str, repo_path: str) -> dict:
    settings = get_settings()
    cmd = [settings.SEMGREP_PATH, "--config", config_path, "--json", repo_path]
    logger.debug("Running Semgrep command: %s", " ".join(cmd))
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
        raise RuntimeError("Semgrep scan timed out after 120s")
    if proc.returncode != 0:
        logger.warning("Semgrep returned non-zero status: %s", stderr.decode(errors="ignore"))
    if not stdout:
        return {"results": []}
    return json.loads(stdout.decode())


async def run_semgrep_ci(repo_path: str) -> None:
    if not _semgrep_available():
        logger.warning("Semgrep not found; skipping p/ci ruleset.")
        return
    try:
        await _run_semgrep("p/ci", repo_path)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Semgrep p/ci failed: %s", exc)


async def check_reachability(
    repo_path: str,
    findings: list[CVEFinding],
    run_ci: bool = True,
) -> list[ReachabilityResult]:
    if not _semgrep_available():
        logger.warning("Semgrep not found; marking all findings as not reachable.")
        return [
            ReachabilityResult(
                cve_id=finding.cve_id,
                reachable=False,
                call_chain=[],
                sink_label=f"{finding.package_name} import",
                semgrep_rule_id=f"reach-{finding.cve_id}",
            )
            for finding in findings
        ]

    if not findings:
        return []

    rule_yaml = _build_rule_yaml(findings)
    with tempfile.TemporaryDirectory() as temp_dir:
        rule_path = Path(temp_dir) / "reachability.yml"
        rule_path.write_text(rule_yaml, encoding="utf-8")

        payload = await _run_semgrep(str(rule_path), repo_path)
        results = payload.get("results") or []
        matches_by_rule: dict[str, list[str]] = {}
        for result in results:
            rule_id = result.get("check_id") or ""
            path = result.get("path") or ""
            line = result.get("start", {}).get("line")
            if not rule_id or not path or not line:
                continue
            entry = f"{path}:{line}"
            matches_by_rule.setdefault(rule_id, []).append(entry)

        if run_ci:
            await _run_semgrep("p/ci", repo_path)

    reachability_results: list[ReachabilityResult] = []
    for finding in findings:
        rule_id = f"reach-{finding.cve_id}"
        call_chain = matches_by_rule.get(rule_id, [])
        reachability_results.append(
            ReachabilityResult(
                cve_id=finding.cve_id,
                reachable=bool(call_chain),
                call_chain=call_chain,
                sink_label=f"{finding.package_name} import",
                semgrep_rule_id=rule_id,
            )
        )

    return reachability_results


async def run_custom_rules(repo_path: str, rules: list[dict]) -> list[dict]:
    if not rules:
        return []
    if not _semgrep_available():
        logger.warning("Semgrep not found; skipping custom rules.")
        return []

    with tempfile.TemporaryDirectory() as temp_dir:
        rule_path = Path(temp_dir) / "custom_rules.json"
        rule_path.write_text(json.dumps({"rules": rules}), encoding="utf-8")
        payload = await _run_semgrep(str(rule_path), repo_path)

    results = payload.get("results") or []
    hits: list[dict] = []
    for result in results:
        message = result.get("extra", {}).get("message") or ""
        path = result.get("path") or ""
        line = result.get("start", {}).get("line")
        location = f"{path}:{line}" if path and line else path
        hits.append({"message": message, "location": location})

    return hits
