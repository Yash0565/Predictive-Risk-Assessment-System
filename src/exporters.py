"""Standards-compliant exporters: SARIF 2.1.0, OpenVEX, CycloneDX (with VEX).

The differentiator here is that the VEX status for every CVE is derived from the
engine's reachability analysis: an unreachable vulnerability is emitted as
``not_affected`` with the justification ``vulnerable_code_not_in_execute_path``
-- exactly the machine-readable triage signal downstream consumers (and
auditors) want, instead of a flat "found N CVEs" dump.

All functions take the ``risk_assessment`` dict produced by ``scorer.score_cves``
and return plain dicts (JSON-serializable).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from typing import Any, Optional

TOOL_NAME = "Predictive-Risk-Assessment-System"
TOOL_VERSION = "2.0.0"
TOOL_URI = "https://github.com/your-org/predictive-risk-assessment-system"

# recommendation -> SARIF level
_SARIF_LEVEL = {"BLOCK": "error", "REVIEW": "warning", "PROCEED": "note"}


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _purl(package: str, version: str = "") -> str:
    pkg = (package or "unknown").strip().lower()
    return f"pkg:pypi/{pkg}@{version}" if version else f"pkg:pypi/{pkg}"


# -- SARIF 2.1.0 -----------------------------------------------------------

def to_sarif(assessment: dict[str, Any]) -> dict[str, Any]:
    cves = assessment.get("cves", [])
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()

    for cve in cves:
        cve_id = cve.get("cve_id", "")
        if not cve_id:
            continue
        if cve_id not in seen_rules:
            seen_rules.add(cve_id)
            rules.append({
                "id": cve_id,
                "name": cve_id.replace("-", ""),
                "shortDescription": {"text": f"{cve_id} in {cve.get('package', '')}"},
                "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "properties": {
                    "security-severity": str(cve.get("cvss_score", 0.0)),
                    "cwe": cve.get("cwe", []),
                },
            })

        prob = cve.get("probabilistic", {})
        evidence = cve.get("evidence", {})
        level = _SARIF_LEVEL.get(cve.get("recommendation", "PROCEED"), "note")
        locations = _sarif_locations(evidence)
        msg = (
            f"{cve_id} ({cve.get('package', '')}): risk {cve.get('scores', {}).get('raw_risk', 0)}/100 "
            f"[{cve.get('recommendation', 'PROCEED')}]. "
            f"reachability={prob.get('reachability_kind', 'none')}, "
            f"confidence={cve.get('confidence', 0)}."
        )
        results.append({
            "ruleId": cve_id,
            "level": level,
            "message": {"text": msg},
            "locations": locations or [_sarif_no_location(cve.get("package", ""))],
            "properties": {
                "risk_score": cve.get("scores", {}).get("raw_risk", 0),
                "recommendation": cve.get("recommendation", "PROCEED"),
                "exploitability": prob.get("exploitability"),
                "reachability_eff": prob.get("reachability_eff"),
                "confidence": cve.get("confidence"),
                "in_kev": evidence.get("in_kev"),
                "epss": evidence.get("epss"),
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": TOOL_URI,
                "rules": rules,
            }},
            "results": results,
        }],
    }


def _sarif_locations(evidence: dict[str, Any]) -> list[dict]:
    locs: list[dict] = []
    for p in evidence.get("reachable_paths", []) or []:
        file = p.get("file")
        if not file:
            continue
        locs.append({
            "physicalLocation": {
                "artifactLocation": {"uri": file},
                "region": {"startLine": max(1, int(p.get("line", 1) or 1))},
            },
            "logicalLocations": [{"fullyQualifiedName": p.get("vuln_fn", "")}],
        })
    return locs


def _sarif_no_location(package: str) -> dict:
    return {
        "physicalLocation": {"artifactLocation": {"uri": "requirements.txt"}},
        "message": {"text": f"Dependency {package} (no reachable code path identified)"},
    }


# -- OpenVEX ---------------------------------------------------------------

# reachability_kind -> (vex status, justification)
def _vex_status(cve: dict[str, Any]) -> tuple[str, Optional[str]]:
    kind = cve.get("probabilistic", {}).get("reachability_kind", "none")
    if kind == "direct":
        return "affected", None
    if kind == "none":
        return "not_affected", "vulnerable_code_not_in_execute_path"
    return "under_investigation", None


def to_openvex(assessment: dict[str, Any], author: str = TOOL_NAME) -> dict[str, Any]:
    statements: list[dict] = []
    for cve in assessment.get("cves", []):
        cve_id = cve.get("cve_id", "")
        if not cve_id:
            continue
        status, justification = _vex_status(cve)
        stmt: dict[str, Any] = {
            "vulnerability": {"name": cve_id},
            "products": [{"@id": _purl(cve.get("package", ""))}],
            "status": status,
        }
        if status == "not_affected" and justification:
            stmt["justification"] = justification
            stmt["impact_statement"] = (
                "Reachability analysis found no call path from an application "
                "entry point to the vulnerable symbol."
            )
        elif status == "affected":
            stmt["action_statement"] = (
                f"Upgrade {cve.get('package', '')}; vulnerable code is reachable "
                f"from an entry point (risk {cve.get('scores', {}).get('raw_risk', 0)}/100)."
            )
        statements.append(stmt)

    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "",
        "author": author,
        "timestamp": _now_iso(),
        "version": 1,
        "statements": statements,
    }
    digest = hashlib.sha256(
        json.dumps(doc["statements"], sort_keys=True).encode("utf-8")
    ).hexdigest()
    doc["@id"] = f"https://openvex.dev/docs/{digest[:16]}"
    return doc


# -- CycloneDX 1.5 (SBOM + vulnerabilities + VEX analysis) -----------------

def to_cyclonedx(
    assessment: dict[str, Any],
    components: Optional[list[dict[str, str]]] = None,
) -> dict[str, Any]:
    """CycloneDX BOM with embedded vulnerabilities and VEX analysis state.

    ``components`` is an optional list of ``{"name","version"}``; if omitted it is
    derived from the CVE list (versions left blank when unknown).
    """
    cves = assessment.get("cves", [])
    if components is None:
        names = {c.get("package", "") for c in cves if c.get("package")}
        components = [{"name": n, "version": ""} for n in sorted(names)]

    bom_components = [{
        "type": "library",
        "name": c["name"],
        "version": c.get("version", ""),
        "purl": _purl(c["name"], c.get("version", "")),
        "bom-ref": _purl(c["name"], c.get("version", "")),
    } for c in components]

    vex_state = {"affected": "exploitable", "not_affected": "not_affected",
                 "under_investigation": "in_triage"}
    vulnerabilities = []
    for cve in cves:
        cve_id = cve.get("cve_id", "")
        if not cve_id:
            continue
        status, justification = _vex_status(cve)
        vuln = {
            "id": cve_id,
            "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
            "ratings": [{
                "score": cve.get("cvss_score", 0.0),
                "severity": (cve.get("severity") or "unknown").lower(),
                "method": "CVSSv3",
            }],
            "affects": [{"ref": _purl(cve.get("package", ""))}],
            "analysis": {"state": vex_state.get(status, "in_triage")},
            "properties": [
                {"name": "pras:risk_score", "value": str(cve.get("scores", {}).get("raw_risk", 0))},
                {"name": "pras:recommendation", "value": cve.get("recommendation", "PROCEED")},
                {"name": "pras:reachability", "value": cve.get("probabilistic", {}).get("reachability_kind", "none")},
            ],
        }
        if justification:
            vuln["analysis"]["justification"] = "code_not_reachable"
            vuln["analysis"]["detail"] = (
                "No call path from an application entry point to the vulnerable symbol."
            )
        vulnerabilities.append(vuln)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": [{"name": TOOL_NAME, "version": TOOL_VERSION}],
        },
        "components": bom_components,
        "vulnerabilities": vulnerabilities,
    }


def write_all(assessment: dict[str, Any], output_dir: str,
              components: Optional[list[dict[str, str]]] = None) -> dict[str, str]:
    """Write sarif/vex/sbom files and return their paths."""
    os.makedirs(output_dir, exist_ok=True)
    artifacts = {
        "sarif": ("report.sarif.json", to_sarif(assessment)),
        "vex": ("report.openvex.json", to_openvex(assessment)),
        "sbom": ("report.cyclonedx.json", to_cyclonedx(assessment, components)),
    }
    paths: dict[str, str] = {}
    for key, (fname, doc) in artifacts.items():
        path = os.path.join(output_dir, fname)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        paths[key] = path
    return paths
