"""Tests for the privacy-safe aggregate data flywheel."""

from __future__ import annotations

from src.ml.data_flywheel import get_aggregate_stats, record_scan_outcome


def test_record_scan_outcome_increments_counts(tmp_path) -> None:
    store = str(tmp_path / "flywheel.json")
    assessment = {
        "cves": [
            {"cve_id": "CVE-1", "package": "requests", "recommendation": "BLOCK"},
            {"cve_id": "CVE-2", "package": "flask", "recommendation": "PROCEED"},
        ],
    }
    symbol = {
        "summary": {"reachable_cves": ["CVE-1"], "unreachable_cves": ["CVE-2"]},
    }
    upgrade = {"summary": {"verdict": "SAFE"}}
    agg = record_scan_outcome(assessment, symbol, upgrade, store_path=store)
    assert agg["total_scans"] == 1
    assert agg["reachability"]["reachable"] == 1
    assert agg["recommendations"]["BLOCK"] == 1
    assert agg["upgrade_outcomes"]["safe"] == 1

    agg2 = record_scan_outcome(assessment, symbol, upgrade, store_path=store)
    assert agg2["total_scans"] == 2
    assert get_aggregate_stats(store)["total_scans"] == 2
