"""Tests for SARIF / OpenVEX / CycloneDX exporters."""

from __future__ import annotations

import json

from src.exporters import to_cyclonedx, to_openvex, to_sarif, write_all

ASSESSMENT = {
    "scorer_version": "2.0.0",
    "summary": {"overall_recommendation": "BLOCK", "overall_raw_risk": 100},
    "cves": [
        {
            "cve_id": "CVE-2020-1747", "package": "pyyaml", "severity": "CRITICAL",
            "cvss_score": 9.8, "cwe": ["CWE-20"], "recommendation": "BLOCK",
            "confidence": 0.88,
            "scores": {"raw_risk": 100},
            "probabilistic": {"reachability_kind": "direct", "exploitability": 0.85,
                              "reachability_eff": 0.89},
            "evidence": {"epss": 0.02, "in_kev": False,
                         "reachable_paths": [{"file": "config_loader.py", "line": 10,
                                              "vuln_fn": "load_config"}]},
        },
        {
            "cve_id": "CVE-2019-11324", "package": "urllib3", "severity": "HIGH",
            "cvss_score": 7.5, "cwe": [], "recommendation": "PROCEED",
            "confidence": 0.56,
            "scores": {"raw_risk": 1},
            "probabilistic": {"reachability_kind": "none", "exploitability": 0.88,
                              "reachability_eff": 0.05},
            "evidence": {"epss": 0.005, "in_kev": False, "reachable_paths": []},
        },
    ],
}


def test_sarif_structure_and_levels() -> None:
    sarif = to_sarif(ASSESSMENT)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"CVE-2020-1747", "CVE-2019-11324"} <= rule_ids
    by_rule = {r["ruleId"]: r for r in run["results"]}
    assert by_rule["CVE-2020-1747"]["level"] == "error"
    assert by_rule["CVE-2019-11324"]["level"] == "note"
    # Reachable CVE carries a real code location.
    loc = by_rule["CVE-2020-1747"]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "config_loader.py"
    assert loc["region"]["startLine"] == 10


def test_openvex_reachability_drives_status() -> None:
    vex = to_openvex(ASSESSMENT)
    assert vex["@context"].startswith("https://openvex.dev/")
    by_cve = {s["vulnerability"]["name"]: s for s in vex["statements"]}
    assert by_cve["CVE-2020-1747"]["status"] == "affected"
    # Unreachable -> not_affected with the reachability justification.
    nv = by_cve["CVE-2019-11324"]
    assert nv["status"] == "not_affected"
    assert nv["justification"] == "vulnerable_code_not_in_execute_path"
    assert vex["@id"]


def test_cyclonedx_has_components_and_vex_analysis() -> None:
    bom = to_cyclonedx(ASSESSMENT)
    assert bom["bomFormat"] == "CycloneDX"
    names = {c["name"] for c in bom["components"]}
    assert {"pyyaml", "urllib3"} <= names
    by_id = {v["id"]: v for v in bom["vulnerabilities"]}
    assert by_id["CVE-2020-1747"]["analysis"]["state"] == "exploitable"
    assert by_id["CVE-2019-11324"]["analysis"]["state"] == "not_affected"


def test_write_all_creates_files(tmp_path) -> None:
    paths = write_all(ASSESSMENT, str(tmp_path))
    for key in ("sarif", "vex", "sbom"):
        with open(paths[key], encoding="utf-8") as fh:
            json.load(fh)  # valid JSON
