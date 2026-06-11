"""Knowledge-graph centrality feeding the scorer's blast-radius factor.

A vulnerability in a highly-central dependency (one that many components or
services transitively rely on) has a larger blast radius than one in a leaf
package. We quantify "central" with PageRank over the security graph snapshot
and feed a normalized centrality into the probabilistic scorer's blast factor,
so graph structure -- not just a raw service count -- shapes the score.

``compute_pagerank`` is a dependency-free, tested implementation of the standard
power-iteration PageRank with a damping factor and dangling-node handling.
"""

from __future__ import annotations

from typing import Any, Iterable


def compute_pagerank(
    node_ids: Iterable[str],
    edges: Iterable[tuple[str, str]],
    damping: float = 0.85,
    iterations: int = 100,
    tol: float = 1.0e-9,
) -> dict[str, float]:
    """PageRank via power iteration. Returns node_id -> score (sums to ~1)."""
    nodes = list(dict.fromkeys(node_ids))
    n = len(nodes)
    if n == 0:
        return {}
    idx = {nid: i for i, nid in enumerate(nodes)}
    out_links: list[list[int]] = [[] for _ in range(n)]
    for src, dst in edges:
        if src in idx and dst in idx:
            out_links[idx[src]].append(idx[dst])

    rank = [1.0 / n] * n
    base = (1.0 - damping) / n
    for _ in range(iterations):
        new = [base] * n
        dangling = 0.0
        for i in range(n):
            if out_links[i]:
                share = damping * rank[i] / len(out_links[i])
                for j in out_links[i]:
                    new[j] += share
            else:
                dangling += damping * rank[i] / n
        if dangling:
            new = [v + dangling for v in new]
        delta = sum(abs(new[i] - rank[i]) for i in range(n))
        rank = new
        if delta < tol:
            break
    return {nodes[i]: rank[i] for i in range(n)}


def _snapshot_edges(snapshot: dict[str, Any]) -> list[tuple[str, str]]:
    edges = snapshot.get("edges", {})
    out: list[tuple[str, str]] = []
    for group in edges.values():
        for e in group:
            src, dst = e.get("from"), e.get("to")
            if src and dst:
                out.append((src, dst))
    return out


def _all_node_ids(snapshot: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for group in snapshot.get("nodes", {}).values():
        for node in group:
            if node.get("id"):
                ids.append(node["id"])
    return ids


def cve_centrality(snapshot: dict[str, Any]) -> dict[str, float]:
    """Map cve_id -> normalized centrality in [0,1] for the CVE's graph node.

    Normalized by the maximum CVE centrality so the most blast-prone CVE in the
    repo anchors at 1.0 and the rest are relative to it.
    """
    node_ids = _all_node_ids(snapshot)
    if not node_ids:
        return {}
    pr = compute_pagerank(node_ids, _snapshot_edges(snapshot))

    cve_nodes = snapshot.get("nodes", {}).get("cves", [])
    raw: dict[str, float] = {}
    for node in cve_nodes:
        cid = node.get("cve_id") or node.get("name") or node.get("id")
        if cid:
            raw[cid] = pr.get(node["id"], 0.0)
    if not raw:
        return {}
    peak = max(raw.values()) or 1.0
    return {cid: round(score / peak, 4) for cid, score in raw.items()}


def augment_blast_with_centrality(
    blast_radius: dict[str, Any],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Add a ``centrality`` field to each CVE's blast-radius entry (in place)."""
    centrality = cve_centrality(snapshot)
    for cid, c in centrality.items():
        entry = blast_radius.setdefault(cid, {})
        entry["centrality"] = c
    return blast_radius
