"""Tests for the final v2 tabbed HTML report (pipeline integration)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.html_reporter_final_v2 import (
    assemble_sample_report,
    build_report_data,
    generate_report,
    render_html,
)

_REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def minimal_assessment() -> dict:
    return {
        "generated_at": "2026-05-19T12:00:00Z",
        "scorer_version": "1.0.0",
        "summary": {
            "overall_recommendation": "BLOCK",
            "overall_raw_risk": 81,
            "total_cves_scored": 2,
            "block_count": 1,
            "review_count": 1,
        },
        "thresholds": {"BLOCK": 70, "REVIEW": 40},
        "cves": [
            {
                "cve_id": "CVE-2023-32681",
                "package": "requests",
                "installed_version": "2.28.0",
                "fixed_version": "2.31.0",
                "cvss_score": 6.1,
                "severity": "HIGH",
                "recommendation": "BLOCK",
                "evidence": {
                    "epss": 0.18,
                    "in_kev": True,
                    "service_names": ["task-tracker"],
                    "impacted_services": 1,
                },
                "scores": {
                    "severity_score": 24,
                    "exploit_score": 18,
                    "reachability_score": 25,
                    "blast_radius_score": 14,
                    "raw_risk": 81,
                },
            },
            {
                "cve_id": "CVE-2020-1747",
                "package": "pyyaml",
                "installed_version": "5.1",
                "fixed_version": "5.3.1",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "recommendation": "REVIEW",
                "evidence": {
                    "epss": 0.04,
                    "in_kev": False,
                    "service_names": ["task-tracker"],
                    "impacted_services": 1,
                },
                "scores": {
                    "severity_score": 39,
                    "exploit_score": 4,
                    "reachability_score": 25,
                    "blast_radius_score": 6,
                    "raw_risk": 74,
                },
            },
        ],
    }


@pytest.fixture
def upgrade_simulation() -> dict:
    return {
        "summary": {
            "verdict": "PROCEED_AFTER_RESOLUTION",
            "headline": "Upgrade pulls transitive bumps; review before proceeding.",
        },
        "resolution_plan": {
            "feasible": True,
            "steps": [
                {"order": 1, "package": "requests", "from": "2.28.0", "to": "2.31.0",
                 "reason": "Patch reachable BLOCK CVE."},
                {"order": 2, "package": "pyyaml", "from": "5.1", "to": "5.3.1",
                 "reason": "Patch reachable REVIEW CVE."},
            ],
        },
        "conflicts": [
            {
                "id": "C1",
                "class": "DIRECT_CONFLICT",
                "shared_dependency": "urllib3",
                "would_break_build": True,
                "conflicting_packages": [
                    {"package": "requests", "constraint": ">=1.21.1,<2"},
                    {"package": "boto3", "constraint": ">=1.25.0,<3"},
                ],
                "human_explanation": "Packages impose incompatible ranges on urllib3.",
            }
        ],
        "cascade": {
            "trigger": "requests 2.28.0 -> 2.31.0",
            "chain": [
                {"package": "urllib3", "from": "1.26.5", "to": "2.0.7", "forced_by": "requests"},
                {"package": "botocore", "from": "1.27.5", "to": "1.31.0", "forced_by": "urllib3"},
            ],
            "total_packages_affected": 3,
        },
    }


@pytest.fixture
def symbol_scan() -> dict:
    return {
        "findings_by_cve": {
            "CVE-2023-32681": {
                "package": "requests",
                "vulnerable_symbol": "requests.api.request",
                "change_classification": "SIGNATURE_CHANGED",
                "is_reachable": True,
                "confidence": "HIGH",
                "reference_count": 1,
                "references": [
                    {
                        "file": "src/api/client.py",
                        "line": 72,
                        "source": "resp = requests.request('POST', url, data=payload)",
                        "enclosing_function": "send_request",
                        "in_entry_point": True,
                        "entry_point_info": {"framework": "flask", "method": "POST", "route": "/api/data"},
                        "kind": "call",
                    }
                ],
            }
        },
        "summary": {"reachable_cves": ["CVE-2023-32681"], "noise_reduction_percent": 50.0},
    }


@pytest.fixture
def graph_snapshot() -> dict:
    return {
        "nodes": {
            "packages": [
                {"id": "pkg:requests@2.28.0", "name": "requests", "installed_version": "2.28.0"},
                {"id": "pkg:urllib3@1.26.5", "name": "urllib3", "installed_version": "1.26.5"},
                {"id": "pkg:pyyaml@5.1", "name": "pyyaml", "installed_version": "5.1"},
            ],
            "cves": [
                {"id": "cve:CVE-2023-32681", "cve_id": "CVE-2023-32681",
                 "cvss_score": 6.1, "severity": "HIGH"},
            ],
            "functions": [
                {"id": "fn:app.api.handle", "qualified_name": "app.api.handle",
                 "file": "app/api.py", "line_start": 10},
            ],
            "services": [{"id": "svc:/api/data:POST", "name": "task-tracker",
                          "route": "/api/data", "method": "POST"}],
        },
        "edges": {
            "depends_on": [
                {"from": "pkg:requests@2.28.0", "to": "pkg:urllib3@1.26.5"},
            ],
            "affected_by": [
                {"from": "pkg:requests@2.28.0", "to": "cve:CVE-2023-32681"},
            ],
            # service -> function -> CVE so the reachability chain is complete
            # (orphan nodes are pruned from the graph, so every kept node connects).
            "vulnerable_in": [
                {"from": "cve:CVE-2023-32681", "to": "fn:app.api.handle"},
            ],
            "exposes": [
                {"from": "svc:/api/data:POST", "to": "fn:app.api.handle"},
            ],
            "calls": [],
        },
        "meta": {"mode": "snapshot"},
    }


def test_vis_graph_adapter_uses_snapshot(
    minimal_assessment: dict,
    upgrade_simulation: dict,
    symbol_scan: dict,
    graph_snapshot: dict,
) -> None:
    """The snapshot must drive a real vis-network payload with typed nodes/edges."""
    graph_snapshot = dict(graph_snapshot)
    graph_snapshot["meta"] = {"mode": "neo4j", "neo4j_uri": "bolt://localhost:7687"}

    data = build_report_data(
        minimal_assessment,
        symbol_scan=symbol_scan,
        upgrade_simulation=upgrade_simulation,
        graph_snapshot=graph_snapshot,
        target_repo="vulnerable-task-tracker",
    )
    vis = data["vis_graph"]
    stats = data["graph_stats"]

    groups = {n["group"] for n in vis["nodes"]}
    assert {"package", "cve", "service"} <= groups, groups
    assert any(n["id"] == "cve:CVE-2023-32681" for n in vis["nodes"])
    assert any(e["kind"] == "DEPENDS_ON" for e in vis["edges"])
    assert any(e["kind"] == "AFFECTED_BY" for e in vis["edges"])

    assert stats["mode"] == "neo4j"
    assert stats["connected"] is True
    assert stats["counts"]["packages"] == 3
    assert stats["counts"]["cves"] == 1
    assert stats["visible_nodes"] == len(vis["nodes"])


def test_vis_graph_falls_back_without_snapshot(minimal_assessment: dict) -> None:
    data = build_report_data(minimal_assessment, target_repo="empty")
    vis = data["vis_graph"]
    stats = data["graph_stats"]
    assert vis["meta"]["source"] == "assessment_fallback"
    assert any(n["group"] == "cve" for n in vis["nodes"])
    assert stats["mode"] in {"fallback", "snapshot"}
    assert stats["connected"] is False


def test_build_report_data_extends_v2(
    minimal_assessment: dict,
    upgrade_simulation: dict,
    symbol_scan: dict,
    graph_snapshot: dict,
) -> None:
    data = build_report_data(
        minimal_assessment,
        explanations={"executive_summary": "Composite headline."},
        symbol_scan=symbol_scan,
        upgrade_simulation=upgrade_simulation,
        graph_snapshot=graph_snapshot,
        target_repo="vulnerable-task-tracker",
    )
    # v2 base fields
    assert "fix_plan" in data
    assert "audit" in data
    # Final v2 additions
    assert data["risk_intelligence"]["top_cve"]["id"] == "CVE-2023-32681"
    assert data["risk_intelligence"]["blast"]["reachable_cves"] == 1
    assert data["risk_intelligence"]["blast"]["kev_listed"] == 1
    assert data["version_jump"]["package"] == "requests"
    assert data["version_jump"]["from_version"] == "2.28.0"
    assert data["version_jump"]["to_version"] == "2.31.0"
    assert "requests" in data["dep_tree_html"]
    assert "urllib3" in data["dep_tree_html"]
    assert "CVE-2023-32681" in data["cypher_html"]
    assert "<svg" in data["blast_svg_html"]
    assert data["sbom"]["total_packages"] == 3
    assert data["sbom"]["source"] == "graph_snapshot"
    assert any("requests" in chain["chain"] for chain in data["reachability_chains"])
    assert any("Trivy" in label for label in data["tools_metadata"])
    assert len(data["recommended_actions"]) >= 1
    assert data["pipeline_coverage"]
    assert data["score_breakdown"]["rows"]
    assert data["score_breakdown"]["verdict"] == "BLOCK"


def test_generate_report_renders_all_tabs(
    minimal_assessment: dict,
    upgrade_simulation: dict,
    symbol_scan: dict,
    graph_snapshot: dict,
    tmp_path: Path,
) -> None:
    data = build_report_data(
        minimal_assessment,
        explanations={"executive_summary": "Composite headline."},
        symbol_scan=symbol_scan,
        upgrade_simulation=upgrade_simulation,
        graph_snapshot=graph_snapshot,
        target_repo="vulnerable-task-tracker",
    )
    out = tmp_path / "risk_report.html"
    path = generate_report(data, output_path=str(out), offline=False)
    html = Path(path).read_text(encoding="utf-8")

    # Six tab panels
    panels = ["panel-overview", "panel-risks", "panel-fixplan",
              "panel-patches", "panel-graph", "panel-audit"]
    for panel in panels:
        assert f'id="{panel}"' in html, f"Missing panel {panel}"

    # Interactive Neo4j graph card is wired in.
    assert 'id="neo4j-graph"' in html
    assert "vis-network" in html  # script tag or vendor inline
    assert "Live Knowledge Graph" in html
    assert '"group": "package"' in html or '"group":"package"' in html
    assert '"group": "cve"' in html or '"group":"cve"' in html

    # Real data leaked into the template instead of hardcoded samples
    assert "CVE-2023-32681" in html
    assert "requests" in html
    assert "task-tracker" in html
    assert "Upgrade pulls transitive bumps" in html
    assert "BLOCK" in html  # verdict pill
    assert "src/api/client.py" in html
    assert "urllib3" in html  # cascade chain
    assert "CVE-2020-1747" in html

    # No AI-related branding
    lower = html.lower()
    assert "claude" not in lower
    assert "ai generated" not in lower


def test_render_html_writes_risk_report_filename(
    minimal_assessment: dict,
    upgrade_simulation: dict,
    symbol_scan: dict,
    tmp_path: Path,
) -> None:
    symbol_path = tmp_path / "symbol_scan.json"
    upgrade_path = tmp_path / "upgrade_simulation.json"
    symbol_path.write_text(__import__("json").dumps(symbol_scan), encoding="utf-8")
    upgrade_path.write_text(__import__("json").dumps(upgrade_simulation), encoding="utf-8")

    out = render_html(
        minimal_assessment,
        {"executive_summary": "Headline."},
        {"snapshot_path": None},
        str(tmp_path),
        symbol_scan_path=str(symbol_path),
        upgrade_sim_path=str(upgrade_path),
        target_repo="vulnerable-task-tracker",
        offline=False,
    )
    out_path = Path(out)
    assert out_path.name == "risk_report.html"
    assert out_path.exists()
    assert out_path.stat().st_size > 5000


def test_empty_assessment_renders_safely(tmp_path: Path) -> None:
    empty = {"summary": {"overall_recommendation": "PROCEED", "overall_raw_risk": 0,
                          "total_cves_scored": 0}, "cves": []}
    data = build_report_data(empty, target_repo="empty")
    out = tmp_path / "empty.html"
    path = generate_report(data, output_path=str(out), offline=False)
    html = Path(path).read_text(encoding="utf-8")
    assert "No CVEs" in html or "PROCEED" in html
    assert data["risk_intelligence"]["top_cve"] is None
    assert data["sbom"]["total_packages"] == 0


def test_assemble_sample_report_offline(tmp_path: Path) -> None:
    out = tmp_path / "sample.html"
    path = assemble_sample_report(str(out), offline=False)
    html = Path(path).read_text(encoding="utf-8")
    assert "panel-overview" in html
    assert "CVE-2018-1000656" in html
    assert "vulnerable-task-tracker" in html
