"""Tests for src.html_reporter — tabbed offline HTML risk report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.html_reporter import (
    _escape_script_for_html,
    build_graph_from_cves,
    build_report_data,
    generate_report,
    inline_vendor_assets,
)

_REPO = Path(__file__).resolve().parent.parent
_DEMO = _REPO / "demo_out"
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


def test_build_report_data_missing_symbol_scan(minimal_assessment: dict) -> None:
    data = build_report_data(minimal_assessment, explanations={"per_cve": [], "executive_summary": "Test"})
    assert data["metadata"]["target_repo"] == "project"
    assert len(data["cves"]) == 1
    assert "nodes" in data["graph"] and "edges" in data["graph"]


def test_build_graph_node_ids_are_consistent() -> None:
    graph = build_graph_from_cves(
        [
            {
                "cve_id": "CVE-TEST",
                "recommendation": "BLOCK",
                "vulnerable_symbol": "foo",
                "references": [
                    {
                        "file": "app.py",
                        "enclosing_function": "handler",
                        "entry_point_info": {"route": "/api", "method": "GET"},
                    }
                ],
            }
        ]
    )
    ids = {n["id"] for n in graph["nodes"]}
    for e in graph["edges"]:
        assert e["source"] in ids
        assert e["target"] in ids


def test_generate_report_has_five_tabs(minimal_assessment: dict, tmp_path: Path) -> None:
    data = build_report_data(minimal_assessment, target_repo="test-repo")
    out = tmp_path / "report.html"
    path = generate_report(data, output_path=str(out), offline=False)
    html = Path(path).read_text(encoding="utf-8")
    assert html.count('role="tabpanel"') == 5
    assert "tab-executive" in html
    assert "tab-graph" in html
    assert "CVE-2023-32681" in html


def test_generate_report_offline_inlines_vendor(minimal_assessment: dict, tmp_path: Path) -> None:
    if not (_VENDOR / "chart.umd.min.js").is_file():
        pytest.skip("vendor assets not present")
    data = build_report_data(minimal_assessment)
    out = tmp_path / "offline.html"
    generate_report(data, output_path=str(out), offline=True)
    html = out.read_text(encoding="utf-8")
    assert "cdn.jsdelivr.net" not in html
    assert "Chart" in html or "chart" in html.lower()
    assert out.stat().st_size < 2_000_000


def test_assemble_demo_from_repo(tmp_path: Path) -> None:
    if not (_DEMO / "risk_assessment.json").is_file():
        pytest.skip("demo_out not present")
    from src.html_reporter import assemble_and_generate_demo

    out = tmp_path / "sample_report.html"
    path = assemble_and_generate_demo(str(out), offline=True)
    html = Path(path).read_text(encoding="utf-8")
    assert "TaskFlow" in html or "vulnerable" in html.lower()
    assert html.count('data-tab=') >= 5


def test_escape_script_for_html_breaks_premature_close() -> None:
    escaped = _escape_script_for_html('end:/</script>/')
    assert "</script>" not in escaped
    assert r"<\/script>" in escaped


def test_offline_report_has_no_raw_script_closer_in_highlight(tmp_path: Path) -> None:
    """Regenerated offline HTML must not embed literal </script> inside vendor JS."""
    from src.html_reporter import assemble_and_generate_demo

    out = tmp_path / "report.html"
    assemble_and_generate_demo(str(out), offline=True)
    html = out.read_text(encoding="utf-8")
    # highlight grammar references script tags; must be escaped when inlined
    assert "end:/<\\/script>/" in html or "end:/<\\/script>" in html
    assert 'end:/</script>/' not in html


def test_inline_vendor_assets_noop_when_online() -> None:
    html = "<script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js' defer></script>"
    assert inline_vendor_assets(html, offline=False) == html
