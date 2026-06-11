"""Tests for the automated remediation fix-plan generator."""

from __future__ import annotations

from src.fix_plan import apply_upgrades, generate_fix_plan

REQS = "flask==0.12\nrequests==2.20.0\npyyaml==5.1\n# pinned\n"

STEPS = [
    {"package": "requests", "from": "2.20.0", "to": "2.31.0"},
    {"package": "flask", "from": "0.12", "to": "2.3.0"},
]

ASSESSMENT = {
    "cves": [
        {"cve_id": "CVE-2023-32681", "package": "requests", "recommendation": "BLOCK"},
        {"cve_id": "CVE-2018-1000656", "package": "flask", "recommendation": "REVIEW"},
        {"cve_id": "CVE-2020-1747", "package": "pyyaml", "recommendation": "PROCEED"},
    ]
}


def test_apply_upgrades_rewrites_only_targets() -> None:
    out = apply_upgrades(REQS, STEPS)
    assert "requests==2.31.0" in out
    assert "flask==2.3.0" in out
    assert "pyyaml==5.1" in out          # untouched
    assert "# pinned" in out             # comment preserved


def test_fix_plan_diff_and_cves() -> None:
    plan = generate_fix_plan(REQS, STEPS, ASSESSMENT, feasible=True)
    assert plan["validated"] is True
    assert plan["changed"] is True
    assert "requests==2.31.0" in plan["new_requirements"]
    assert "--- a/requirements.txt" in plan["diff"]
    # Only BLOCK/REVIEW CVEs for upgraded packages are cited; PROCEED excluded.
    assert "CVE-2023-32681" in plan["fixed_cves"]
    assert "CVE-2018-1000656" in plan["fixed_cves"]
    assert "CVE-2020-1747" not in plan["fixed_cves"]
    assert "remediate 2" in plan["pr_title"]


def test_fix_plan_no_steps_is_noop() -> None:
    plan = generate_fix_plan(REQS, [], ASSESSMENT, feasible=True)
    assert plan["changed"] is False
    assert plan["fixed_cves"] == []
