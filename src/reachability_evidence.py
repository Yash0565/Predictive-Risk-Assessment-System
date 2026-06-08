"""Single source of truth for converting symbol-scan findings into the
reachability evidence shape consumed by the scorer.

Both Pipeline A (``pipeline_a.py``) and the ReAct agent (``tool_registry.py``)
previously built this structure with separate, slowly-diverging code, which
meant the two entry points could score the same repo differently. They now both
call into this module, so reachability evidence is constructed identically
regardless of orchestration path.

Phase 3 upgrade: ``enrich_with_call_graph`` merges inter-procedural call-graph
paths (with hop counts and taint flags) so reachability is based on confirmed
entry-point-to-sink paths, not symbol presence alone.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _findings_by_cve(symbol_findings: dict[str, Any]) -> dict[str, Any]:
    """Tolerate both the flat scan result and the agent's nested wrapper."""
    findings = symbol_findings.get("findings_by_cve")
    if findings is None and isinstance(symbol_findings.get("symbol_findings"), dict):
        findings = symbol_findings["symbol_findings"].get("findings_by_cve")
    return findings or {}


def symbol_findings_to_rows(symbol_findings: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten reachable symbol findings into scorer reachability rows."""
    rows: list[dict[str, Any]] = []
    for cve_id, finding in _findings_by_cve(symbol_findings).items():
        if not finding.get("is_reachable"):
            continue
        for ref in finding.get("references") or []:
            ep = ref.get("entry_point_info") or {}
            rows.append({
                "cve_id": cve_id,
                "service": ep.get("route") or ref.get("file", ""),
                "vuln_fn": ref.get("enclosing_function") or finding.get("vulnerable_symbol", ""),
                "file": ref.get("file", ""),
                "line_start": ref.get("line", 0),
                "hops": ref.get("hops", 1 if ref.get("in_entry_point") else 2),
                "confidence": ref.get("confidence", "HIGH"),
                "tainted": ref.get("tainted", False),
                "source": ref.get("source", "symbol_scanner"),
            })
    return rows


def build_graph_evidence(symbol_findings: dict[str, Any]) -> dict[str, Any]:
    """Build a standalone graph_evidence dict from symbol findings alone."""
    return {
        "reachability": symbol_findings_to_rows(symbol_findings),
        "blast_radius": {},
        "dependency_chains": [],
    }


def merge_into_graph_evidence(
    graph_evidence: dict[str, Any],
    symbol_findings: dict[str, Any],
) -> dict[str, Any]:
    """Append symbol-derived rows for CVEs not already present in graph evidence."""
    existing = {
        row.get("cve_id") or row.get("cve")
        for row in graph_evidence.get("reachability", [])
    }
    for row in symbol_findings_to_rows(symbol_findings):
        if row["cve_id"] in existing:
            continue
        graph_evidence.setdefault("reachability", []).append(row)
        existing.add(row["cve_id"])
    return graph_evidence


def enrich_with_call_graph(
    project_dir: str,
    symbol_findings: dict[str, Any],
    graph_evidence: dict[str, Any],
    *,
    patches: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Augment reachability evidence with inter-procedural call-graph paths.

    For each CVE marked reachable by the symbol scanner, attempt to find a
    confirmed path from an application entry point to the vulnerable external
    symbol. When found, replace heuristic hop counts with graph-derived hops and
    set the taint flag when attacker-controlled data may reach the sink.
    """
    try:
        from src.call_graph import build_call_graph, reachable_to_symbol
    except Exception as exc:
        logger.debug("Call-graph enrichment unavailable: %s", exc)
        return graph_evidence

    findings = _findings_by_cve(symbol_findings)
    if not findings:
        return graph_evidence

    try:
        cg = build_call_graph(project_dir)
    except Exception as exc:
        logger.warning("Call-graph build failed: %s", exc)
        return graph_evidence

    existing_by_cve: dict[str, list[dict[str, Any]]] = {}
    for row in graph_evidence.get("reachability", []):
        cid = row.get("cve_id") or row.get("cve", "")
        if cid:
            existing_by_cve.setdefault(cid, []).append(row)

    enriched: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()

    for cve_id, finding in findings.items():
        if not finding.get("is_reachable"):
            continue
        target = finding.get("vulnerable_symbol", "")
        if not target:
            continue

        cg_paths = reachable_to_symbol(cg, target)
        if cg_paths:
            for p in cg_paths:
                key = (cve_id, p.get("route", ""), p.get("entry_point", ""))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                enriched.append({
                    "cve_id": cve_id,
                    "service": p.get("route") or p.get("entry_point", ""),
                    "vuln_fn": target,
                    "file": "",
                    "line_start": 0,
                    "hops": p.get("hops", 1),
                    "confidence": "HIGH" if p.get("hops", 99) <= 3 else "MEDIUM",
                    "tainted": bool(p.get("tainted")),
                    "source": "call_graph",
                    "path": p.get("path", []),
                })
        else:
            for row in existing_by_cve.get(cve_id, symbol_findings_to_rows(
                {"findings_by_cve": {cve_id: finding}}
            )):
                key = (cve_id, row.get("service", ""), row.get("file", ""))
                if key not in seen_keys:
                    seen_keys.add(key)
                    enriched.append(row)

    if enriched:
        graph_evidence["reachability"] = enriched
        graph_evidence["call_graph_enriched"] = True
        graph_evidence["call_graph_nodes"] = len(cg.nodes)
        graph_evidence["call_graph_edges"] = sum(len(v) for v in cg.edges.values())

    return graph_evidence
