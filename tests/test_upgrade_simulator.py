"""Tests for src.upgrade_simulator."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet

from src.upgrade_simulator import (
    _tree_diff,
    detect_cascade,
    detect_conflicts,
    detect_runtime_conflicts,
    fetch_depsdev,
    parse_requirements,
    simulate_upgrade,
)

TASKFLOW_REQ = Path(__file__).resolve().parent.parent / "vulnerable-task-tracker" / "requirements.txt"
FIXTURE_REQ = Path(__file__).resolve().parent / "fixtures" / "upgrade_simulator" / "sample_requirements.txt"


@pytest.fixture
def taskflow_req() -> dict[str, str]:
    return parse_requirements(str(TASKFLOW_REQ))


def test_parse_requirements_pins_and_skips() -> None:
    FIXTURE_REQ.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_REQ.write_text(
        "# comment\nrequests[security]==2.20.0\n-e git+https://example.com/foo\nflask==0.12\n",
        encoding="utf-8",
    )
    parsed = parse_requirements(str(FIXTURE_REQ))
    assert parsed["requests"] == "2.20.0"
    assert parsed["flask"] == "0.12"
    assert "git" not in parsed


def test_specifier_intersection() -> None:
    a = SpecifierSet("<1.26,>=1.20.0")
    b = SpecifierSet(">=1.21.1,<3.0")
    inter = a & b
    assert inter.contains("1.24.1", prereleases=True)
    assert not inter.contains("2.0.7", prereleases=True)


def test_tree_diff_bumped() -> None:
    current = {"urllib3": {"version": "1.24.1", "requires": {}}}
    target = {"urllib3": {"version": "2.0.7", "requires": {}}}
    diff = _tree_diff(current, target)
    assert diff["bumped"] == [{"package": "urllib3", "from": "1.24.1", "to": "2.0.7"}]


def test_runtime_conflict_detection() -> None:
    tree = {
        "okpkg": {"version": "1.0.0", "requires": {}, "python_requires": ">=3.8"},
        "badpkg": {"version": "2.0.0", "requires": {}, "python_requires": ">=3.12"},
    }
    results = detect_runtime_conflicts(tree, "3.9.5", scope_packages={"okpkg", "badpkg"})
    by_name = {r["package"]: r for r in results}
    assert by_name["okpkg"]["compatible"] is True
    assert by_name["badpkg"]["compatible"] is False


def test_fetch_depsdev_cache_hit() -> None:
    data = fetch_depsdev("urllib3", "1.24.1", force_refresh=False)
    assert data is not None
    assert "nodes" in data


@pytest.mark.skipif(not TASKFLOW_REQ.is_file(), reason="TaskFlow requirements missing")
def test_taskflow_scenario1_requests_upgrade(taskflow_req: dict[str, str]) -> None:
    """urllib3 / boto3 conflict when upgrading requests."""
    result = simulate_upgrade(
        taskflow_req,
        [{"package": "requests", "target_version": "2.31.0"}],
        python_version="3.9.5",
    )
    assert result["status"] in ("ok", "degraded")
    assert result["summary"]["verdict"] == "PROCEED_AFTER_RESOLUTION"
    assert result["resolution_plan"]["feasible"] is True

    assert len(result["conflicts"]) >= 1
    conflict = result["conflicts"][0]
    assert conflict["class"] == "DIRECT_CONFLICT"
    assert conflict["shared_dependency"] == "urllib3"
    assert conflict["would_break_build"] is True

    steps = result["resolution_plan"]["steps"]
    assert len(steps) >= 2
    # Structural contract (no memorized demo versions): the primary upgrade is
    # the final step, and at least one constraint-derived blocker precedes it.
    assert steps[-1]["package"] == "requests"
    assert steps[-1]["to"] == "2.31.0"
    blockers = [s["package"] for s in steps[:-1]]
    assert blockers, "expected at least one blocker step before the primary upgrade"
    # The blocker must be a package that actually constrains the shared dep.
    assert any(b in {"boto3", "botocore"} for b in blockers)
    for s in steps[:-1]:
        assert s["to"], "every blocker step must carry a concrete target version"

    chain_pkgs = [c["package"] for c in result["cascade"]["chain"]]
    assert "urllib3" in chain_pkgs
    # Every cascade link is attributed to a concrete dependent (constraint-derived).
    assert all(c["forced_by"] for c in result["cascade"]["chain"])


@pytest.mark.skipif(not TASKFLOW_REQ.is_file(), reason="TaskFlow requirements missing")
def test_taskflow_scenario2_flask_upgrade(taskflow_req: dict[str, str]) -> None:
    result = simulate_upgrade(
        taskflow_req,
        [{"package": "flask", "target_version": "2.3.0"}],
        python_version="3.9.5",
    )
    assert result["summary"]["verdict"] == "PROCEED_AFTER_RESOLUTION"
    bumped = {b["package"] for b in result["tree_diff"]["bumped"]}
    assert "flask" in bumped
    assert "jinja2" in bumped


@pytest.mark.skipif(not TASKFLOW_REQ.is_file(), reason="TaskFlow requirements missing")
def test_taskflow_scenario3_pyyaml_safe(taskflow_req: dict[str, str]) -> None:
    result = simulate_upgrade(
        taskflow_req,
        [{"package": "pyyaml", "target_version": "5.4.0"}],
        python_version="3.9.5",
    )
    assert result["summary"]["verdict"] == "SAFE"
    assert result["conflicts"] == []


@pytest.mark.skipif(not TASKFLOW_REQ.is_file(), reason="TaskFlow requirements missing")
def test_cache_second_run_identical_except_timestamp(taskflow_req: dict[str, str]) -> None:
    upgrades = [{"package": "requests", "target_version": "2.31.0"}]
    r1 = simulate_upgrade(taskflow_req, upgrades, python_version="3.9.5")
    t0 = time.perf_counter()
    r2 = simulate_upgrade(taskflow_req, upgrades, python_version="3.9.5")
    elapsed = time.perf_counter() - t0

    assert elapsed < 5.0
    d1 = {k: v for k, v in r1.items() if k != "simulated_at"}
    d2 = {k: v for k, v in r2.items() if k != "simulated_at"}
    assert d1 == d2


def test_simulate_never_raises_on_empty() -> None:
    result = simulate_upgrade({}, [], python_version="3.9.5")
    assert result["status"] in ("ok", "degraded", "error")
    assert "summary" in result
