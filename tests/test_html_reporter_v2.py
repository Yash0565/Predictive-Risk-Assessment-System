"""Tests for presentation-grade html_reporter_v2."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.html_reporter_v2 import build_report_data, generate_report

_REPO = Path(__file__).resolve().parent.parent
_VENDOR = _REPO / "static" / "vendor"


@pytest.fixture
def minimal_assessment() -> dict:
    return {
        "generated_at": "2026-05-19T12:00:00Z",
        "scorer_version": "1.0.0",
        "summary": {
            "overall_recommendation": "REVIEW",
            "overall_raw_risk": 55,
            "total_cves_scored": 1,
        },
        "cves": [
            {
                "cve_id": "CVE-2023-32681",
                "package": "requests",
                "installed_version": "2.28.0",
                "fixed_version": "2.31.0",
                "cvss_score": 6.1,
                "recommendation": "REVIEW",
                "evidence": {"epss": 0.02, "in_kev": False},
                "scores": {
                    "severity_score": 20,
                    "exploit_score": 8,
                    "reachability_score": 15,
                    "blast_radius_score": 7,
                    "raw_risk": 50,
                },
            }
        ],
    }


def test_build_report_data_v2_schema(minimal_assessment: dict) -> None:
    data = build_report_data(minimal_assessment, explanations={"executive_summary": "Test headline"})
    assert "fix_plan" in data
    assert "conflicts" in data
    assert "audit" in data
    assert data["overall"]["headline"] == "Test headline"
    assert data["metadata"]["data_sources"]["patches_cached"] >= 0


def test_generate_v2_has_six_tabs(minimal_assessment: dict, tmp_path: Path) -> None:
    data = build_report_data(minimal_assessment, target_repo="test-repo")
    out = tmp_path / "report_v2.html"
    path = generate_report(data, output_path=str(out), offline=False)
    html = Path(path).read_text(encoding="utf-8")
    assert html.count('role="tabpanel"') == 6
    assert "panel-overview" in html
    assert "panel-audit" in html
    assert "hero-num" in html
    assert "CVE-2023-32681" in html


def test_generate_v2_offline_under_2mb(minimal_assessment: dict, tmp_path: Path) -> None:
    if not (_VENDOR / "vis-network.min.js").is_file():
        pytest.skip("vendor assets not present")
    data = build_report_data(minimal_assessment)
    out = tmp_path / "offline_v2.html"
    generate_report(data, output_path=str(out), offline=True)
    html = out.read_text(encoding="utf-8")
    assert "cdn.jsdelivr.net" not in html
    assert out.stat().st_size < 2_000_000


def test_assemble_sample_v2(tmp_path: Path) -> None:
    from src.html_reporter_v2 import assemble_sample_report

    out = tmp_path / "sample_report_v2.html"
    path = assemble_sample_report(str(out), offline=True)
    html = Path(path).read_text(encoding="utf-8")
    assert "hero-num" in html
    assert "Fix Plan" in html
    assert "Audit" in html
