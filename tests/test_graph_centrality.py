"""Tests for PageRank centrality and its effect on the blast factor."""

from __future__ import annotations

from src.graph_centrality import (
    augment_blast_with_centrality,
    compute_pagerank,
    cve_centrality,
)
from src.scorer import score_single


def test_pagerank_sums_to_one_and_ranks_hub() -> None:
    nodes = ["a", "b", "c", "hub"]
    # everyone points at hub -> hub most central
    edges = [("a", "hub"), ("b", "hub"), ("c", "hub"), ("a", "b")]
    pr = compute_pagerank(nodes, edges)
    assert abs(sum(pr.values()) - 1.0) < 1e-6
    assert pr["hub"] == max(pr.values())


def test_pagerank_empty() -> None:
    assert compute_pagerank([], []) == {}


def _snapshot() -> dict:
    return {
        "nodes": {
            "packages": [{"id": "pkg:central"}, {"id": "pkg:leaf"}],
            "cves": [
                {"id": "cve:1", "cve_id": "CVE-CENTRAL"},
                {"id": "cve:2", "cve_id": "CVE-LEAF"},
            ],
            "functions": [{"id": "fn:1"}, {"id": "fn:2"}, {"id": "fn:3"}],
            "services": [{"id": "svc:1"}],
        },
        "edges": {
            "affected_by": [
                {"from": "pkg:central", "to": "cve:1"},
                {"from": "pkg:leaf", "to": "cve:2"},
            ],
            "depends_on": [
                {"from": "fn:1", "to": "pkg:central"},
                {"from": "fn:2", "to": "pkg:central"},
                {"from": "fn:3", "to": "pkg:central"},
                {"from": "svc:1", "to": "pkg:central"},
            ],
        },
    }


def test_cve_centrality_ranks_central_higher() -> None:
    cent = cve_centrality(_snapshot())
    assert cent["CVE-CENTRAL"] >= cent["CVE-LEAF"]
    assert max(cent.values()) == 1.0  # normalized


def test_centrality_raises_blast_factor_in_scorer() -> None:
    vuln = {"cve": "X", "package": "p", "cvss_score": 9.8}
    low = score_single(vuln, epss_val=0.1, blast={"impacted_services": 0, "centrality": 0.0})
    high = score_single(vuln, epss_val=0.1, blast={"impacted_services": 0, "centrality": 1.0})
    assert high["factors"]["blast_factor"] > low["factors"]["blast_factor"]
    assert high["raw_risk"] >= low["raw_risk"]


def test_augment_blast_adds_centrality() -> None:
    blast: dict = {}
    augment_blast_with_centrality(blast, _snapshot())
    assert "centrality" in blast["CVE-CENTRAL"]
