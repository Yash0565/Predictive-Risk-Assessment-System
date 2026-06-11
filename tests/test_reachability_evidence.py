"""Tests for unified reachability evidence and call-graph enrichment."""

from __future__ import annotations

from pathlib import Path

from src.reachability_evidence import (
    build_graph_evidence,
    enrich_with_call_graph,
    merge_into_graph_evidence,
    symbol_findings_to_rows,
)

FIXT = Path(__file__).resolve().parent / "fixtures" / "call_graph"


def test_symbol_findings_to_rows_includes_hops_and_taint() -> None:
    findings = {
        "findings_by_cve": {
            "CVE-TEST": {
                "is_reachable": True,
                "vulnerable_symbol": "yaml.load",
                "references": [{
                    "file": "app.py",
                    "line": 10,
                    "in_entry_point": True,
                    "confidence": "HIGH",
                    "tainted": True,
                    "entry_point_info": {"route": "/api", "method": "POST"},
                }],
            },
        },
    }
    rows = symbol_findings_to_rows(findings)
    assert len(rows) == 1
    assert rows[0]["hops"] == 1
    assert rows[0]["tainted"] is True
    assert rows[0]["service"] == "/api"


def test_merge_deduplicates_by_cve() -> None:
    graph = {"reachability": [{"cve_id": "CVE-A", "hops": 1}], "blast_radius": {}, "dependency_chains": []}
    findings = {
        "findings_by_cve": {
            "CVE-A": {"is_reachable": True, "references": [{"file": "x.py", "line": 1}]},
            "CVE-B": {"is_reachable": True, "references": [{"file": "y.py", "line": 2}]},
        },
    }
    merge_into_graph_evidence(graph, findings)
    cves = {r["cve_id"] for r in graph["reachability"]}
    assert "CVE-A" in cves and "CVE-B" in cves
    assert len([r for r in graph["reachability"] if r["cve_id"] == "CVE-A"]) == 1


def test_call_graph_enrichment_finds_yaml_load_path() -> None:
    findings = {
        "findings_by_cve": {
            "CVE-2020-1747": {
                "is_reachable": True,
                "vulnerable_symbol": "yaml.load",
                "references": [{"file": "app.py", "line": 5, "confidence": "HIGH"}],
            },
        },
    }
    graph = build_graph_evidence(findings)
    enrich_with_call_graph(str(FIXT), findings, graph)
    assert graph.get("call_graph_enriched") is True
    rows = graph["reachability"]
    assert any(r.get("source") == "call_graph" for r in rows)
    cg_rows = [r for r in rows if r.get("source") == "call_graph"]
    assert cg_rows[0]["hops"] >= 1
