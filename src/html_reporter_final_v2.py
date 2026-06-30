"""Presentation-grade HTML risk report (final v2) — combined tabbed design.

Wraps the v2 data builder and adds the extra fields the new tabbed
template (``templates/report_final_v2.html.j2``) consumes:

* Risk intelligence rollups (top CVE, readiness, blast summary)
* Pre-rendered dependency tree, Cypher block, and blast-radius SVG
  derived from the upgrade simulation and graph snapshot
* SBOM aggregation from the graph snapshot
* Reachability call-chain bullets from symbol scanner findings
* Tools metadata, recommended actions, mitigations, score breakdown

The public ``render_html`` signature matches v1/v2 so the pipeline and
agent can switch reporter implementations via a single CLI flag.
"""

from __future__ import annotations

import html as html_lib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Iterable, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.html_reporter import (
    CDN_ASSETS,
    _load_json,
    inline_vendor_assets,
)
from src.html_reporter_v2 import (
    _fmt_num,
    _fmt_pct,
    _rec_class,
    build_report_data as v2_build_report_data,
)

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES = _REPO_ROOT / "templates"
_TEMPLATE_NAME = "report_final_v2.html.j2"

_SEMVER_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _jinja_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["fmt_num"] = _fmt_num
    env.filters["fmt_pct"] = _fmt_pct
    env.filters["rec_class"] = _rec_class
    return env


# ─────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────


def build_report_data(
    assessment: dict[str, Any],
    explanations: Optional[dict[str, Any]] = None,
    symbol_scan: Optional[dict[str, Any]] = None,
    upgrade_simulation: Optional[dict[str, Any]] = None,
    graph: Optional[dict[str, Any]] = None,
    graph_snapshot: Optional[dict[str, Any]] = None,
    *,
    target_repo: str = "project",
    project_dir: Optional[str] = None,
    patches_dir: Optional[str] = None,
) -> dict[str, Any]:
    """Build the dict consumed by ``report_final_v2.html.j2``.

    Inputs are the same artifacts produced by Pipeline A
    (``risk_assessment.json``, ``symbol_scan.json``,
    ``upgrade_simulation.json``, ``graph_snapshot.json``,
    ``explanations.json``) plus optional patch cache under
    ``data/patches/``.
    """
    base = v2_build_report_data(
        assessment,
        explanations=explanations,
        symbol_scan=symbol_scan,
        upgrade_simulation=upgrade_simulation,
        graph=graph,
        target_repo=target_repo,
        project_dir=project_dir,
        patches_dir=patches_dir,
    )
    upgrade = upgrade_simulation or {}
    snapshot = graph_snapshot or {}
    scan = symbol_scan or {}

    upgrade_summary = (upgrade.get("summary") or {}) if isinstance(upgrade, dict) else {}
    base["upgrade_headline"] = upgrade_summary.get("headline", "") or upgrade_summary.get("one_line", "")
    base["upgrade_verdict"] = upgrade_summary.get("verdict", "")
    base["risk_intelligence"] = _build_risk_intelligence(base, upgrade, scan)
    base["version_jump"] = _build_version_jump(upgrade, base)
    base["changed_symbols"] = _build_changed_symbols(base)
    base["semgrep_hits"] = _build_semgrep_hits(base, scan)
    base["dep_tree_html"] = _build_dep_tree_html(upgrade, snapshot, base)
    base["cypher_html"] = _build_cypher_html(base, target_repo)
    base["blast_svg_html"] = _build_blast_svg_html(base)
    base["vis_graph"] = _build_vis_graph(snapshot, base)
    base["graph_stats"] = _build_graph_stats(snapshot, base["vis_graph"])
    base["sbom"] = _build_sbom(snapshot, base)
    base["reachability_chains"] = _build_reachability_chains(scan, base)
    base["tools_metadata"] = _build_tools_metadata(snapshot, scan, upgrade, base)
    base["scan_configuration"] = _build_scan_configuration(base, target_repo)
    base["recommended_actions"] = _build_recommended_actions(base, upgrade)
    base["mitigations"] = _build_mitigations(base, upgrade)
    base["score_breakdown"] = _build_score_breakdown(base)
    base["pipeline_coverage"] = _build_pipeline_coverage(
        base, upgrade, snapshot, scan
    )
    base["narrative"] = _build_narrative(base, upgrade)
    return base


def generate_report(
    report_data: dict[str, Any],
    output_path: str = "report.html",
    offline: bool = False,
) -> str:
    """Render the final v2 template to a single, self-contained HTML file."""
    env = _jinja_env()
    html = env.get_template(_TEMPLATE_NAME).render(
        **report_data,
        offline=offline,
        cdn_assets=CDN_ASSETS,
        cves_json=json.dumps(report_data.get("cves") or []),
        vis_graph_json=json.dumps(
            report_data.get("vis_graph") or {"nodes": [], "edges": [], "meta": {}}
        ),
    )
    html = inline_vendor_assets(html, offline=offline)
    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    logger.info("Wrote final v2 report to %s (%d bytes)", out, len(html.encode("utf-8")))
    return str(out)


def render_html(
    assessment: dict[str, Any],
    explanations: dict[str, Any],
    graph_meta: dict[str, Any],
    output_dir: str,
    *,
    symbol_scan_path: Optional[str] = None,
    upgrade_sim_path: Optional[str] = None,
    project_dir: Optional[str] = None,
    target_repo: str = "project",
    offline: bool = False,
) -> str:
    """Pipeline entry — same contract as ``html_reporter.render_html``."""
    scan = _load_json(Path(symbol_scan_path)) if symbol_scan_path and Path(symbol_scan_path).is_file() else None
    upgrade = _load_json(Path(upgrade_sim_path)) if upgrade_sim_path and Path(upgrade_sim_path).is_file() else None

    snapshot = None
    if graph_meta:
        snap_path = graph_meta.get("snapshot_path")
        if snap_path and Path(snap_path).is_file():
            snapshot = _load_json(Path(snap_path))

    data = build_report_data(
        assessment,
        explanations,
        symbol_scan=scan,
        upgrade_simulation=upgrade,
        graph=None,
        graph_snapshot=snapshot,
        target_repo=target_repo,
        project_dir=project_dir,
    )
    out_path = os.path.join(output_dir, "risk_report.html")
    return generate_report(data, output_path=out_path, offline=offline)


def assemble_sample_report(output_path: str, *, offline: bool = True) -> str:
    """Render a sample report from repo fixtures (no pipeline run needed)."""
    fixtures = _REPO_ROOT / "tests" / "fixtures"
    scan = _load_json(fixtures / "symbol_scan_output.json")
    assessment = {
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
                "cve_id": "CVE-2018-1000656",
                "package": "flask",
                "installed_version": "0.12",
                "fixed_version": "0.12.3",
                "cvss_score": 7.5,
                "severity": "HIGH",
                "recommendation": "BLOCK",
                "evidence": {
                    "epss": 0.18,
                    "in_kev": True,
                    "service_names": ["task-tracker"],
                    "impacted_services": 1,
                },
                "scores": {
                    "severity_score": 30,
                    "exploit_score": 18,
                    "reachability_score": 25,
                    "blast_radius_score": 8,
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
    explanations = {
        "per_cve": [],
        "executive_summary": "Sample report assembled from tests/fixtures for offline preview.",
    }
    upgrade = {
        "summary": {
            "verdict": "PROCEED_AFTER_RESOLUTION",
            "headline": "Upgrade pulls transitive bumps; review before proceeding.",
        },
        "resolution_plan": {
            "feasible": True,
            "steps": [
                {"order": 1, "package": "flask", "from": "0.12", "to": "0.12.3",
                 "reason": "Patch reachable BLOCK CVE."},
                {"order": 2, "package": "pyyaml", "from": "5.1", "to": "5.3.1",
                 "reason": "Patch reachable REVIEW CVE."},
            ],
        },
        "conflicts": [],
        "cascade": {"trigger": "flask 0.12 -> 0.12.3", "chain": []},
    }

    data = build_report_data(
        assessment,
        explanations,
        symbol_scan=scan,
        upgrade_simulation=upgrade,
        target_repo="vulnerable-task-tracker",
        project_dir=str(_REPO_ROOT / "vulnerable-task-tracker"),
    )
    return generate_report(data, output_path=output_path, offline=offline)


# ─────────────────────────────────────────────────────────────────────
# Risk intelligence rollup
# ─────────────────────────────────────────────────────────────────────


def _build_risk_intelligence(
    base: dict[str, Any],
    upgrade: dict[str, Any],
    scan: dict[str, Any],
) -> dict[str, Any]:
    cves = base.get("cves") or []
    if not cves:
        return {
            "top_cve": None,
            "readiness_score": 100,
            "blast": _empty_blast(),
            "critical_services": [],
            "headline": "No CVEs found in this scan.",
        }

    top = max(cves, key=lambda c: c.get("raw_risk", 0))
    overall_raw = base.get("overall", {}).get("raw_risk", top.get("raw_risk", 0)) or 0
    readiness = max(0, 100 - int(overall_raw))

    services: set[str] = set()
    packages: set[str] = set()
    reachable = 0
    kev_listed = 0
    for c in cves:
        if c.get("package"):
            packages.add(str(c["package"]))
        ev = (c.get("evidence") or {})
        for svc in ev.get("service_names") or []:
            if svc:
                services.add(str(svc))
        if c.get("is_reachable"):
            reachable += 1
        if c.get("in_kev"):
            kev_listed += 1

    if not services:
        for ref in _iter_all_references(cves):
            ep = (ref.get("entry_point_info") or {})
            route = ep.get("route")
            if route:
                services.add(str(route))

    critical_services = sorted(services)[:3] or ["—"]

    top_label = top.get("severity") or _severity_label(top.get("cvss", 0))
    headline = base.get("overall", {}).get("headline") or _default_headline(
        base.get("summary_stats") or {}, upgrade,
    )

    return {
        "top_cve": {
            "id": top.get("cve_id", ""),
            "package": top.get("package", ""),
            "cvss": top.get("cvss", 0),
            "epss": top.get("epss", 0),
            "in_kev": top.get("in_kev", False),
            "severity": top_label,
            "raw_risk": top.get("raw_risk", 0),
            "fixed_version": top.get("fixed_version", ""),
            "vulnerable_symbol": top.get("vulnerable_symbol", ""),
        },
        "readiness_score": readiness,
        "blast": {
            "affected_packages": len(packages),
            "affected_services": len(services),
            "reachable_cves": reachable,
            "total_cves": len(cves),
            "kev_listed": kev_listed,
            "would_break_build": bool(
                base.get("overall", {}).get("would_break_build")
                or (base.get("summary_stats") or {}).get("would_break_build")
            ),
        },
        "critical_services": critical_services,
        "headline": headline,
    }


def _empty_blast() -> dict[str, Any]:
    return {
        "affected_packages": 0,
        "affected_services": 0,
        "reachable_cves": 0,
        "total_cves": 0,
        "kev_listed": 0,
        "would_break_build": False,
    }


def _default_headline(stats: dict[str, Any], upgrade: dict[str, Any]) -> str:
    reachable = stats.get("reachable_cves", 0) or 0
    total = stats.get("total_cves", 0) or 0
    upgrade_headline = ((upgrade or {}).get("summary") or {}).get("headline") or ""
    if upgrade_headline:
        return upgrade_headline
    if total and reachable:
        return f"{reachable} of {total} CVEs are reachable in your application code."
    if total:
        return f"Scanned {total} dependency CVEs; none are directly referenced in application code."
    return "No CVEs detected for this dependency upgrade."


def _severity_label(cvss: Any) -> str:
    try:
        n = float(cvss)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if n >= 9.0:
        return "CRITICAL"
    if n >= 7.0:
        return "HIGH"
    if n >= 4.0:
        return "MODERATE"
    if n > 0:
        return "LOW"
    return "UNKNOWN"


# ─────────────────────────────────────────────────────────────────────
# Version jump card
# ─────────────────────────────────────────────────────────────────────


def _build_version_jump(
    upgrade: dict[str, Any], base: dict[str, Any],
) -> Optional[dict[str, Any]]:
    plan = (upgrade or {}).get("resolution_plan") or {}
    steps = plan.get("steps") or []
    primary = steps[0] if steps else None
    if primary:
        from_v = primary.get("from") or primary.get("from_version", "")
        to_v = primary.get("to") or primary.get("to_version", "")
        package = primary.get("package", "")
    else:
        cves = base.get("cves") or []
        top = max(cves, key=lambda c: c.get("raw_risk", 0), default=None)
        if not top:
            return None
        package = top.get("package", "")
        from_v = top.get("installed_version", "")
        to_v = top.get("fixed_version", "")

    if not package or not (from_v or to_v):
        return None

    is_major = _is_major_jump(from_v, to_v)
    description = (
        "Major version increment indicates breaking API changes."
        if is_major
        else "Minor/patch version upgrade; expected to be backwards compatible."
    )
    return {
        "package": package,
        "from_version": from_v or "?",
        "to_version": to_v or "?",
        "is_major": is_major,
        "description": description,
    }


def _is_major_jump(from_v: str, to_v: str) -> bool:
    m1 = _SEMVER_RE.match(from_v or "")
    m2 = _SEMVER_RE.match(to_v or "")
    if not m1 or not m2:
        return False
    return int(m1.group(1)) != int(m2.group(1))


# ─────────────────────────────────────────────────────────────────────
# Changed symbols
# ─────────────────────────────────────────────────────────────────────


def _build_changed_symbols(base: dict[str, Any]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for c in base.get("cves") or []:
        patch = c.get("patch") or {}
        for sym in patch.get("symbols") or []:
            name = (sym.get("short_name") or sym.get("fully_qualified_name") or "").strip()
            if not name:
                continue
            classification = (
                sym.get("change_classification")
                or c.get("change_classification")
                or "UNKNOWN"
            )
            key = (name, classification)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "name": name,
                "classification": classification,
                "summary": sym.get("summary", "") or "",
            })
        # Fallback: surface vulnerable_symbol if no detailed patch metadata.
        if not patch.get("symbols") and c.get("vulnerable_symbol"):
            name = str(c["vulnerable_symbol"]).split(".")[-1] or c["vulnerable_symbol"]
            cls = c.get("change_classification") or "UNKNOWN"
            key = (name, cls)
            if key not in seen:
                seen.add(key)
                out.append({"name": name, "classification": cls, "summary": ""})
    return out[:20]


# ─────────────────────────────────────────────────────────────────────
# Semgrep / symbol-scan hits
# ─────────────────────────────────────────────────────────────────────


def _build_semgrep_hits(
    base: dict[str, Any], scan: dict[str, Any],
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for c in base.get("cves") or []:
        if not c.get("is_reachable"):
            continue
        for ref in c.get("references") or []:
            snippet = ref.get("source") or ref.get("code_snippet") or ""
            if not snippet and not ref.get("file"):
                continue
            ep = ref.get("entry_point_info") or {}
            hits.append({
                "cve_id": c.get("cve_id", ""),
                "package": c.get("package", ""),
                "file": ref.get("file", ""),
                "line": ref.get("line", ""),
                "enclosing_function": ref.get("enclosing_function") or "",
                "route": ep.get("route") or "",
                "method": ep.get("method") or "",
                "kind": ref.get("kind") or "",
                "snippet": snippet.strip().splitlines()[0] if snippet else "",
                "symbol": c.get("vulnerable_symbol", ""),
            })
    return hits[:25]


def _iter_all_references(cves: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    for c in cves or []:
        for ref in c.get("references") or []:
            yield ref


# ─────────────────────────────────────────────────────────────────────
# Dependency tree (graph snapshot + upgrade simulation)
# ─────────────────────────────────────────────────────────────────────


def _esc(text: Any) -> str:
    return html_lib.escape(str(text or ""))


def _build_dep_tree_html(
    upgrade: dict[str, Any],
    snapshot: dict[str, Any],
    base: dict[str, Any],
) -> str:
    plan = (upgrade or {}).get("resolution_plan") or {}
    cascade = (upgrade or {}).get("cascade") or {}
    conflicts = (upgrade or {}).get("conflicts") or []
    steps = plan.get("steps") or []

    primary = steps[0] if steps else None
    if not primary:
        # Fall back to top CVE
        cves = base.get("cves") or []
        if cves:
            top = max(cves, key=lambda c: c.get("raw_risk", 0))
            primary = {
                "package": top.get("package", ""),
                "from": top.get("installed_version", ""),
                "to": top.get("fixed_version", ""),
            }

    lines: list[str] = []
    if primary and primary.get("package"):
        pkg = _esc(primary.get("package"))
        from_v = _esc(primary.get("from") or primary.get("from_version", ""))
        to_v = _esc(primary.get("to") or primary.get("to_version", ""))
        lines.append(
            f'<span class="dt-node">{pkg}</span> '
            f'<span class="dt-conn">({from_v} → {to_v})</span> '
            f'<span class="dt-warn">◀ UPGRADE TARGET</span>'
        )
        # Find conflicts that involve this package via shared dependency.
        for conflict in conflicts:
            shared = _esc(conflict.get("shared_dependency", ""))
            if not shared:
                continue
            pkgs = conflict.get("conflicting_packages") or []
            pkg_names = ", ".join(
                _esc(p.get("package", "")) for p in pkgs if p.get("package")
            )
            constraints = " · ".join(
                f'{_esc(p.get("package",""))} {_esc(p.get("constraint",""))}'
                for p in pkgs if p.get("package")
            )
            lines.append(
                '<span class="dt-conn">  ├──[DEPENDS_ON]──▶</span> '
                f'<span class="dt-node">{shared}</span> '
                f'<span class="dt-conn">({constraints})</span> '
                '<span class="dt-warn">◀ CONFLICT POINT</span>'
            )
            if pkg_names:
                lines.append(
                    '<span class="dt-conn">  │                    └─ involves </span>'
                    f'<span class="dt-conn">{pkg_names}</span>'
                )

        if cascade.get("chain"):
            lines.append("")
            lines.append(
                '<span class="dt-conn">── CASCADE CHAIN ─────────────────────</span>'
            )
            for link in cascade["chain"][:10]:
                lines.append(
                    f'<span class="dt-conn">  ↳ </span>'
                    f'<span class="dt-node">{_esc(link.get("package",""))}</span> '
                    f'<span class="dt-conn">{_esc(link.get("from",""))} → {_esc(link.get("to",""))}</span>'
                    f' <span class="dt-conn">(forced by {_esc(link.get("forced_by",""))})</span>'
                )

    # Fallback: walk the graph snapshot
    if not lines:
        pkgs = (snapshot.get("nodes") or {}).get("packages") or []
        if pkgs:
            lines.append(
                '<span class="dt-node">Dependency graph</span> '
                f'<span class="dt-conn">({len(pkgs)} packages)</span>'
            )
            for pkg in pkgs[:8]:
                lines.append(
                    f'<span class="dt-conn">  ├──▶</span> '
                    f'<span class="dt-node">{_esc(pkg.get("name",""))}</span> '
                    f'<span class="dt-conn">{_esc(pkg.get("installed_version",""))}</span>'
                )
            if len(pkgs) > 8:
                lines.append(
                    f'<span class="dt-conn">  └─ … and {len(pkgs) - 8} more</span>'
                )
        else:
            lines.append(
                '<span class="dt-conn">No dependency graph data available for this scan.</span>'
            )

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────
# Cypher block (knowledge graph view)
# ─────────────────────────────────────────────────────────────────────


def _build_cypher_html(base: dict[str, Any], target_repo: str) -> str:
    cves = base.get("cves") or []
    if not cves:
        return (
            '<span class="cypher-comment">// No CVEs to render in the knowledge graph.</span>'
        )

    top = max(cves, key=lambda c: c.get("raw_risk", 0))
    pkg = _esc(top.get("package", "package"))
    version = _esc(top.get("installed_version", "?"))
    cve_id = _esc(top.get("cve_id", "CVE-UNKNOWN"))
    cvss = top.get("cvss", 0) or 0
    epss = top.get("epss", 0) or 0
    kev = "true" if top.get("in_kev") else "false"

    parts: list[str] = []
    parts.append(
        '<span class="cypher-comment">// Security knowledge graph relationships</span>'
    )
    parts.append("")
    parts.append(
        f'<span class="cypher-node">({pkg}:Package &#123;name:"{pkg}", '
        f'version:"{version}"&#125;)</span>'
    )
    parts.append(
        '<span class="cypher-arrow">  -[:HAS_CVE]-&gt;</span> '
        f'<span class="cypher-node">(cve:CVE &#123;id:"{cve_id}", '
        f'cvss:{cvss}, epss:{epss}, kev:{kev}&#125;)</span>'
    )

    sym = top.get("vulnerable_symbol")
    if sym:
        short = _esc(str(sym).split(".")[-1] or sym)
        parts.append("")
        parts.append(
            '<span class="cypher-node">(cve)</span>'
        )
        parts.append(
            '<span class="cypher-arrow">  -[:MODIFIES_SYMBOL]-&gt;</span> '
            f'<span class="cypher-node">(sym:Symbol &#123;name:"{short}", '
            'type:"function"&#125;)</span>'
        )

    refs = (top.get("references") or [])[:3]
    if refs:
        parts.append("")
        parts.append('<span class="cypher-node">(sym)</span>')
        for ref in refs:
            file_path = _esc(ref.get("file", ""))
            line = ref.get("line", "")
            parts.append(
                '<span class="cypher-arrow">  -[:USED_BY]-&gt;</span> '
                f'<span class="cypher-node">(file:File &#123;path:"{file_path}",'
                f' line:{line or 0}&#125;)</span>'
            )

    services = (top.get("evidence") or {}).get("service_names") or []
    if services:
        parts.append("")
        parts.append('<span class="cypher-node">(file)</span>')
        for svc in services[:3]:
            parts.append(
                '<span class="cypher-arrow">  -[:CONTAINED_BY]-&gt;</span> '
                f'<span class="cypher-node">(svc:Service &#123;name:"{_esc(svc)}"&#125;)</span>'
            )

    parts.append("")
    parts.append(
        '<span class="cypher-comment">// Blast radius path:  CVE → Symbol → File → Service</span>'
    )
    return "<br/>".join(parts)


# ─────────────────────────────────────────────────────────────────────
# Blast radius SVG (positioned diagram of CVE → symbols → files → services)
# ─────────────────────────────────────────────────────────────────────


def _build_blast_svg_html(base: dict[str, Any]) -> str:
    cves = base.get("cves") or []
    if not cves:
        return ('<p style="font-size:12px;color:var(--text-3);">'
                "No CVE data available to render a blast diagram.</p>")

    top = max(cves, key=lambda c: c.get("raw_risk", 0))
    refs = (top.get("references") or [])[:5]
    services = (top.get("evidence") or {}).get("service_names") or []

    # Build symbol -> file rows.
    symbols: list[str] = []
    if top.get("vulnerable_symbol"):
        short = str(top["vulnerable_symbol"]).split(".")[-1] or str(top["vulnerable_symbol"])
        symbols.append(short)
    for ref in refs:
        fn = ref.get("enclosing_function")
        if fn and fn not in symbols and len(symbols) < 3:
            symbols.append(fn)

    if not symbols:
        symbols = ["(symbol)"]

    files = [f"{ref.get('file','?')}:{ref.get('line','?')}" for ref in refs]
    if not files:
        files = ["(file)"]

    svcs = services[:3] or ["(service)"]

    cve_id = _esc(top.get("cve_id", "CVE"))
    cvss = top.get("cvss", 0) or 0
    kev_text = "CVSS {} · KEV".format(cvss) if top.get("in_kev") else "CVSS {}".format(cvss)

    # Layout
    svg_w, svg_h = 780, 220
    cve_x, cve_y = 20, max(0, svg_h // 2 - 22)
    sym_x = 250
    file_x = 500
    svc_x = 720

    def _y_positions(count: int, top_pad: int = 30, bottom_pad: int = 30) -> list[int]:
        usable = svg_h - top_pad - bottom_pad
        if count <= 1:
            return [svg_h // 2]
        gap = usable // (count - 1)
        return [top_pad + i * gap for i in range(count)]

    sym_ys = _y_positions(len(symbols))
    file_ys = _y_positions(len(files))
    svc_ys = _y_positions(len(svcs))

    parts: list[str] = []
    parts.append(
        f'<svg class="blast-svg" viewBox="0 0 {svg_w} {svg_h}" '
        'xmlns="http://www.w3.org/2000/svg">'
    )

    # Connecting lines (CVE -> symbols)
    cve_cx = cve_x + 60
    cve_cy = cve_y + 22
    for y in sym_ys:
        parts.append(
            f'<line x1="{cve_cx + 60}" y1="{cve_cy}" x2="{sym_x}" y2="{y}" '
            'stroke="currentColor" stroke-opacity="0.18" stroke-width="1.5"/>'
        )
    # Symbols -> files
    for sy in sym_ys:
        for fy in file_ys:
            parts.append(
                f'<line x1="{sym_x + 130}" y1="{sy}" x2="{file_x}" y2="{fy}" '
                'stroke="currentColor" stroke-opacity="0.12" stroke-width="1"/>'
            )
    # Files -> services
    for fy in file_ys:
        for sy in svc_ys:
            parts.append(
                f'<line x1="{file_x + 120}" y1="{fy}" x2="{svc_x}" y2="{sy}" '
                'stroke="currentColor" stroke-opacity="0.12" stroke-width="1"/>'
            )

    # CVE box
    parts.append(
        f'<rect x="{cve_x}" y="{cve_y}" width="120" height="44" rx="6" '
        'fill="rgba(197,48,74,0.12)" stroke="rgba(197,48,74,0.5)" stroke-width="1.5"/>'
    )
    parts.append(
        f'<text x="{cve_cx}" y="{cve_cy - 3}" text-anchor="middle" '
        'font-family="JetBrains Mono,monospace" font-size="11" fill="#c5304a" '
        f'font-weight="700">{cve_id}</text>'
    )
    parts.append(
        f'<text x="{cve_cx}" y="{cve_cy + 10}" text-anchor="middle" '
        'font-family="JetBrains Mono,monospace" font-size="10" '
        f'fill="rgba(197,48,74,0.7)">{_esc(kev_text)}</text>'
    )

    # Symbol boxes
    for sym, y in zip(symbols, sym_ys):
        parts.append(
            f'<rect x="{sym_x}" y="{y - 17}" width="130" height="34" rx="5" '
            'fill="rgba(176,110,0,0.10)" stroke="rgba(176,110,0,0.4)" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{sym_x + 65}" y="{y + 4}" text-anchor="middle" '
            f'font-family="JetBrains Mono,monospace" font-size="11" fill="#b06e00">{_esc(sym)}</text>'
        )

    # File boxes
    for f, y in zip(files, file_ys):
        parts.append(
            f'<rect x="{file_x}" y="{y - 15}" width="120" height="30" rx="5" '
            'fill="rgba(31,123,204,0.08)" stroke="rgba(31,123,204,0.35)" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{file_x + 60}" y="{y + 4}" text-anchor="middle" '
            f'font-family="JetBrains Mono,monospace" font-size="10" fill="#1f7bcc">{_esc(f)}</text>'
        )

    # Service boxes
    for s, y in zip(svcs, svc_ys):
        parts.append(
            f'<rect x="{svc_x}" y="{y - 14}" width="54" height="28" rx="4" '
            'fill="rgba(197,48,74,0.12)" stroke="rgba(197,48,74,0.5)" stroke-width="1.5"/>'
        )
        parts.append(
            f'<text x="{svc_x + 27}" y="{y + 4}" text-anchor="middle" '
            f'font-family="JetBrains Mono,monospace" font-size="10" fill="#c5304a" '
            f'font-weight="700">{_esc(s)[:8]}</text>'
        )

    # Labels
    parts.append(
        '<text x="195" y="14" text-anchor="middle" font-family="JetBrains Mono,monospace" '
        'font-size="10" fill="#6a7e9c">MODIFIES</text>'
    )
    parts.append(
        '<text x="445" y="14" text-anchor="middle" font-family="JetBrains Mono,monospace" '
        'font-size="10" fill="#6a7e9c">USED_BY</text>'
    )
    parts.append(
        '<text x="676" y="14" text-anchor="middle" font-family="JetBrains Mono,monospace" '
        'font-size="10" fill="#6a7e9c">OWNED_BY</text>'
    )
    parts.append("</svg>")
    return "".join(parts)


# ─────────────────────────────────────────────────────────────────────
# Live knowledge graph (vis-network) — snapshot → interactive nodes/edges
# ─────────────────────────────────────────────────────────────────────


_GRAPH_NODE_LIMITS = {
    "packages": 80,
    "cves": 100,
    "services": 50,
    "functions": 60,
}
_GRAPH_EDGE_LIMIT = 800

_GRAPH_NODE_STYLES = {
    "package":  {"color": "#7C3AED", "border": "#5B21B6", "shape": "box",     "size": 22},
    "cve":      {"color": "#EF4444", "border": "#991B1B", "shape": "diamond", "size": 28},
    "service":  {"color": "#3B82F6", "border": "#1D4ED8", "shape": "hexagon", "size": 26},
    "function": {"color": "#334155", "border": "#1E293B", "shape": "dot",     "size": 11},
}
_GRAPH_EDGE_STYLES = {
    "DEPENDS_ON":    {"color": "#8B5CF6", "label": "DEPENDS_ON",    "width": 1.5, "dashes": False},
    "AFFECTED_BY":   {"color": "#F59E0B", "label": "AFFECTED_BY",   "width": 2.0, "dashes": False},
    "VULNERABLE_IN": {"color": "#EF4444", "label": "VULNERABLE_IN", "width": 2.0, "dashes": True},
    "EXPOSES":       {"color": "#3B82F6", "label": "EXPOSES",       "width": 2.0, "dashes": False},
    "CALLS":         {"color": "#475569", "label": "CALLS",         "width": 1.0, "dashes": False},
}


def _build_vis_graph(
    snapshot: dict[str, Any], base: dict[str, Any],
) -> dict[str, Any]:
    """Convert ``graph_snapshot.json`` into a vis-network payload.

    Falls back to a CVE-derived graph when the snapshot is missing.
    """
    snap_nodes = (snapshot.get("nodes") or {}) if isinstance(snapshot, dict) else {}
    snap_edges = (snapshot.get("edges") or {}) if isinstance(snapshot, dict) else {}
    meta = (snapshot.get("meta") or {}) if isinstance(snapshot, dict) else {}

    if not any(snap_nodes.get(k) for k in ("packages", "cves", "services", "functions")):
        return _fallback_vis_graph(base, meta)

    # Index CVE risk metadata from the assessment so we can colour by recommendation.
    cve_meta = {
        (c.get("cve_id") or "").upper(): c
        for c in (base.get("cves") or [])
        if c.get("cve_id")
    }

    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(node_id: str, label: str, group: str, **extra: Any) -> None:
        if not node_id or node_id in seen:
            return
        seen.add(node_id)
        style = dict(_GRAPH_NODE_STYLES.get(group, _GRAPH_NODE_STYLES["function"]))
        node = {
            "id": node_id,
            "label": label,
            "group": group,
            "shape": style["shape"],
            "size": style["size"],
            "color": {
                "background": style["color"],
                "border": style.get("border", style["color"]),
                "highlight": {"background": style["color"], "border": style.get("border", style["color"])},
            },
            **extra,
        }
        nodes.append(node)

    # CVEs first so they remain even when we cap packages/functions.
    for cve in (snap_nodes.get("cves") or [])[: _GRAPH_NODE_LIMITS["cves"]]:
        cid = cve.get("id") or f"cve:{cve.get('cve_id','')}"
        cve_id = cve.get("cve_id") or ""
        cvss = cve.get("cvss_score") or 0
        sev = (cve.get("severity") or "").upper()
        risk = cve_meta.get(cve_id.upper(), {})
        rec = (risk.get("recommendation") or "").upper()
        _CVE_REC_COLORS = {
            "BLOCK":   {"bg": "#EF4444", "border": "#991B1B"},
            "REVIEW":  {"bg": "#F59E0B", "border": "#92400E"},
            "PROCEED": {"bg": "#10B981", "border": "#065F46"},
        }
        col = _CVE_REC_COLORS.get(rec, {"bg": "#EF4444", "border": "#991B1B"})
        label = f"{cve_id}\nCVSS {cvss}"
        _add(
            cid, label, "cve",
            color={"background": col["bg"], "border": col["border"], "highlight": col},
            title=f"{cve_id} · {sev or '—'} · CVSS {cvss}"
                  + (f" · KEV" if risk.get("in_kev") else ""),
            recommendation=rec or None,
            cve_id=cve_id,
        )

    for pkg in (snap_nodes.get("packages") or [])[: _GRAPH_NODE_LIMITS["packages"]]:
        pid = pkg.get("id") or ""
        name = pkg.get("name") or "pkg"
        ver = pkg.get("installed_version") or ""
        label = f"{name}\n{ver}" if ver and ver != "unknown" else name
        _add(pid, label, "package",
             title=f"Package: {name}@{ver}",
             package=name, version=ver)

    for svc in (snap_nodes.get("services") or [])[: _GRAPH_NODE_LIMITS["services"]]:
        sid = svc.get("id") or ""
        name = svc.get("name") or svc.get("handler") or "service"
        route = svc.get("route") or ""
        method = svc.get("method") or ""
        label = f"{name}" + (f"\n{method} {route}" if route else "")
        _add(sid, label, "service",
             title=f"Service: {method} {route}".strip(),
             service=name, route=route, method=method)

    for fn in (snap_nodes.get("functions") or [])[: _GRAPH_NODE_LIMITS["functions"]]:
        fid = fn.get("id") or ""
        qname = fn.get("qualified_name") or "function"
        short = qname.split(".")[-1] or qname
        file_path = fn.get("file") or ""
        line = fn.get("line_start")
        _add(fid, short, "function",
             title=f"{qname}\n{file_path}:{line}" if line else f"{qname}\n{file_path}",
             qualified_name=qname, file=file_path, line=line)

    # Build edges only between nodes that survived the caps.
    edges: list[dict[str, Any]] = []
    edge_counts: dict[str, int] = {k: 0 for k in _GRAPH_EDGE_STYLES}
    for kind, snap_key in (
        ("DEPENDS_ON",    "depends_on"),
        ("AFFECTED_BY",   "affected_by"),
        ("VULNERABLE_IN", "vulnerable_in"),
        ("EXPOSES",       "exposes"),
        ("CALLS",         "calls"),
    ):
        style = _GRAPH_EDGE_STYLES[kind]
        for edge in snap_edges.get(snap_key) or []:
            src = edge.get("from")
            dst = edge.get("to")
            if not src or not dst or src not in seen or dst not in seen:
                continue
            edges.append({
                "id": f"e{len(edges)}",
                "from": src,
                "to": dst,
                "label": style["label"],
                "kind": kind,
                "color": {"color": style["color"], "highlight": style["color"]},
                "width": style["width"],
                "dashes": style["dashes"],
                "arrows": "to",
                "smooth": {"type": "continuous"},
            })
            edge_counts[kind] += 1
            if len(edges) >= _GRAPH_EDGE_LIMIT:
                break
        if len(edges) >= _GRAPH_EDGE_LIMIT:
            break

    truncation = {
        "packages_truncated": max(0, len(snap_nodes.get("packages") or []) - _GRAPH_NODE_LIMITS["packages"]),
        "cves_truncated":     max(0, len(snap_nodes.get("cves") or [])     - _GRAPH_NODE_LIMITS["cves"]),
        "services_truncated": max(0, len(snap_nodes.get("services") or []) - _GRAPH_NODE_LIMITS["services"]),
        "functions_truncated":max(0, len(snap_nodes.get("functions") or []) - _GRAPH_NODE_LIMITS["functions"]),
        "edges_truncated":    max(0, sum(len(snap_edges.get(k) or []) for k in ("depends_on","affected_by","vulnerable_in","exposes","calls")) - len(edges)),
    }

    return {
        "nodes": nodes,
        "edges": edges,
        "edge_counts": edge_counts,
        "meta": {
            "mode": meta.get("mode") or "snapshot",
            "neo4j_uri": meta.get("neo4j_uri") or "bolt://localhost:7687",
            "source": "graph_snapshot",
            "truncation": truncation,
        },
    }


def _fallback_vis_graph(base: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    """Best-effort graph when no snapshot is available."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(node_id: str, label: str, group: str, **extra: Any) -> None:
        if node_id in seen:
            return
        seen.add(node_id)
        style = _GRAPH_NODE_STYLES.get(group, _GRAPH_NODE_STYLES["function"])
        nodes.append({
            "id": node_id, "label": label, "group": group,
            "shape": style["shape"], "size": style["size"],
            "color": {
                "background": style["color"],
                "border": style.get("border", style["color"]),
            },
            **extra,
        })

    for c in base.get("cves") or []:
        cve_id = c.get("cve_id") or ""
        pkg = c.get("package") or "package"
        pkg_id = f"pkg:{pkg}"
        cve_node_id = f"cve:{cve_id}"
        _add(pkg_id, pkg, "package", title=f"Package: {pkg}")
        rec = (c.get("recommendation") or "").upper()
        colour = {
            "BLOCK":   "#c5304a",
            "REVIEW":  "#b06e00",
            "PROCEED": "#157a52",
        }.get(rec, "#c5304a")
        _add(cve_node_id,
             f"{cve_id}\nCVSS {c.get('cvss', 0)}",
             "cve",
             color={"background": colour, "border": colour},
             title=f"{cve_id} · {c.get('severity','')} · CVSS {c.get('cvss',0)}",
             recommendation=rec, cve_id=cve_id)
        style = _GRAPH_EDGE_STYLES["AFFECTED_BY"]
        edges.append({
            "id": f"e{len(edges)}", "from": pkg_id, "to": cve_node_id,
            "label": style["label"], "kind": "AFFECTED_BY",
            "color": {"color": style["color"], "highlight": style["color"]},
            "width": style["width"], "dashes": style["dashes"],
            "arrows": "to", "smooth": {"type": "continuous"},
        })

        for ref in (c.get("references") or [])[:3]:
            ep = ref.get("entry_point_info") or {}
            if ep.get("route"):
                svc_id = f"svc:{ep.get('method','GET')}:{ep['route']}"
                _add(svc_id,
                     f"{ep.get('method','GET')} {ep['route']}", "service",
                     title=f"Reachable via {ep.get('framework','')}")
                exp_style = _GRAPH_EDGE_STYLES["EXPOSES"]
                edges.append({
                    "id": f"e{len(edges)}", "from": svc_id, "to": cve_node_id,
                    "label": "REACHES", "kind": "EXPOSES",
                    "color": {"color": exp_style["color"]},
                    "width": exp_style["width"], "dashes": False,
                    "arrows": "to", "smooth": {"type": "continuous"},
                })

    return {
        "nodes": nodes,
        "edges": edges,
        "edge_counts": {"AFFECTED_BY": len(edges)},
        "meta": {
            "mode": meta.get("mode") or "fallback",
            "neo4j_uri": meta.get("neo4j_uri") or "",
            "source": "assessment_fallback",
            "truncation": {},
        },
    }


def _build_graph_stats(
    snapshot: dict[str, Any], vis_graph: dict[str, Any],
) -> dict[str, Any]:
    """Counts + Neo4j connection metadata for the Graph tab badge."""
    snap_nodes = (snapshot.get("nodes") or {}) if isinstance(snapshot, dict) else {}
    snap_edges = (snapshot.get("edges") or {}) if isinstance(snapshot, dict) else {}
    meta = (snapshot.get("meta") or {}) if isinstance(snapshot, dict) else {}
    counts = {
        "packages":  len(snap_nodes.get("packages") or []),
        "cves":      len(snap_nodes.get("cves") or []),
        "services":  len(snap_nodes.get("services") or []),
        "functions": len(snap_nodes.get("functions") or []),
    }
    total_nodes = sum(counts.values())
    total_edges = sum(len(v or []) for v in snap_edges.values()) if snap_edges else 0
    mode = meta.get("mode") or vis_graph.get("meta", {}).get("mode") or "fallback"
    return {
        "mode": mode,
        "label": "Live Neo4j" if mode == "neo4j" else (
            "Snapshot" if mode == "snapshot" else "Derived"
        ),
        "connected": mode == "neo4j",
        "uri": meta.get("neo4j_uri") or vis_graph.get("meta", {}).get("neo4j_uri") or "",
        "counts": counts,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "visible_nodes": len(vis_graph.get("nodes") or []),
        "visible_edges": len(vis_graph.get("edges") or []),
        "edge_counts": vis_graph.get("edge_counts") or {},
    }


# ─────────────────────────────────────────────────────────────────────
# SBOM rollups
# ─────────────────────────────────────────────────────────────────────


def _build_sbom(snapshot: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    nodes = (snapshot.get("nodes") or {}) if isinstance(snapshot, dict) else {}
    edges = (snapshot.get("edges") or {}) if isinstance(snapshot, dict) else {}
    pkgs = nodes.get("packages") or []
    cves_nodes = nodes.get("cves") or []
    depends = edges.get("depends_on") or []

    total = len(pkgs)
    children: set[str] = {edge.get("to", "") for edge in depends if edge.get("to")}
    direct = max(0, total - len(children)) if total else 0
    transitive = total - direct if total else 0

    python_pkgs = [
        p for p in pkgs
        if not re.search(r"\b(node|npm|yarn)\b", str(p.get("name") or ""), re.I)
    ]
    npm_pkgs = total - len(python_pkgs)

    vulnerable_pkgs = {
        edge.get("from", "")
        for edge in (edges.get("affected_by") or [])
        if edge.get("from")
    }

    kev_count = 0
    for c in base.get("cves") or []:
        if c.get("in_kev"):
            kev_count += 1

    if total == 0:
        # Pipeline ran without a graph phase; fall back to CVE-driven minimums.
        cves = base.get("cves") or []
        pkg_names = {c.get("package") for c in cves if c.get("package")}
        total = len(pkg_names)
        direct = len(pkg_names)
        transitive = 0
        vulnerable_pkgs = pkg_names
        python_pkgs = list(pkg_names)
        npm_pkgs = 0

    return {
        "total_packages": total,
        "direct_dependencies": direct,
        "transitive_dependencies": transitive,
        "python_packages": len(python_pkgs) if total else len(python_pkgs),
        "npm_packages": npm_pkgs,
        "vulnerable_packages": len(vulnerable_pkgs),
        "kev_listed": kev_count,
        "total_cves_in_graph": len(cves_nodes),
        "source": "graph_snapshot" if pkgs else "assessment_fallback",
    }


# ─────────────────────────────────────────────────────────────────────
# Reachability call chains
# ─────────────────────────────────────────────────────────────────────


def _build_reachability_chains(
    scan: dict[str, Any], base: dict[str, Any],
) -> list[dict[str, str]]:
    chains: list[dict[str, str]] = []
    findings = (scan.get("findings_by_cve") or {}) if isinstance(scan, dict) else {}
    for cve_id, finding in findings.items():
        if not finding.get("is_reachable"):
            continue
        refs = finding.get("references") or []
        if not refs:
            continue
        ref = refs[0]
        symbol = finding.get("vulnerable_symbol") or ""
        sym_short = symbol.split(".")[-1] or symbol
        package = finding.get("package", "")
        chains.append({
            "cve_id": cve_id,
            "package": package,
            "label": f"{package} · {cve_id}",
            "chain": f"{ref.get('file','?')}:{ref.get('line','?')} → {symbol or sym_short or '?'}",
        })
    if chains:
        return chains[:10]

    # Fallback: derive from base["cves"].references
    for c in base.get("cves") or []:
        if not c.get("is_reachable"):
            continue
        refs = c.get("references") or []
        if not refs:
            continue
        ref = refs[0]
        symbol = c.get("vulnerable_symbol") or ""
        chains.append({
            "cve_id": c.get("cve_id", ""),
            "package": c.get("package", ""),
            "label": f"{c.get('package','')} · {c.get('cve_id','')}",
            "chain": f"{ref.get('file','?')}:{ref.get('line','?')} → {symbol or '?'}",
        })
    return chains[:10]


# ─────────────────────────────────────────────────────────────────────
# Tools metadata + scan configuration
# ─────────────────────────────────────────────────────────────────────


def _build_tools_metadata(
    snapshot: dict[str, Any],
    scan: dict[str, Any],
    upgrade: dict[str, Any],
    base: dict[str, Any],
) -> dict[str, str]:
    meta = base.get("metadata") or {}
    neo4j_mode = ((snapshot or {}).get("meta") or {}).get("mode", "")
    return {
        "SBOM / Trivy": "Trivy enriched scan",
        "CVE Scanner": "Trivy (fallback: Grype)",
        "Threat Intel": "OSV · EPSS · CISA KEV",
        "Conflict Engine": "deps.dev resolver",
        "AST Analysis": "Tree-sitter",
        "Reachability": "Semgrep + symbol scanner",
        "Graph DB": "Neo4j 5.x" if neo4j_mode == "neo4j" else "Snapshot-only (no Neo4j)",
        "Risk Scorer": f"Deterministic v{meta.get('scorer_version', '1.0.0')}",
        "Narrative Summary": "Template-based (deterministic)",
    }


def _build_scan_configuration(
    base: dict[str, Any], target_repo: str,
) -> dict[str, str]:
    meta = base.get("metadata") or {}
    overall = base.get("overall") or {}
    return {
        "Scan Timestamp": meta.get("generated_at", "—"),
        "Target Repo": target_repo,
        "Pipeline": meta.get("pipeline_version", "12-phase"),
        "Reproducibility Hash": meta.get("reproducibility_hash", "—"),
        "Verdict": overall.get("recommendation", "—"),
        "Risk Score": f"{overall.get('raw_risk', 0)} / 100",
    }


# ─────────────────────────────────────────────────────────────────────
# Recommended actions + mitigations
# ─────────────────────────────────────────────────────────────────────


def _build_recommended_actions(
    base: dict[str, Any], upgrade: dict[str, Any],
) -> list[str]:
    actions: list[str] = []
    fix_plan = base.get("fix_plan") or {}
    for step in (fix_plan.get("steps") or [])[:4]:
        pkg = step.get("package", "")
        to_v = step.get("to_version") or step.get("to") or ""
        if pkg and to_v:
            actions.append(f"Upgrade <code>{html_lib.escape(pkg)}</code> to "
                           f"<code>{html_lib.escape(to_v)}</code>.")
        elif pkg:
            actions.append(f"Update <code>{html_lib.escape(pkg)}</code> per the fix plan.")

    for conflict in (upgrade or {}).get("conflicts", [])[:2]:
        shared = conflict.get("shared_dependency")
        if shared:
            actions.append(
                f"Resolve <code>{html_lib.escape(str(shared))}</code> constraint clash "
                "before merging."
            )

    cves = base.get("cves") or []
    block_cves = [c for c in cves if c.get("recommendation") == "BLOCK"]
    if block_cves and not actions:
        first = block_cves[0]
        actions.append(
            f"Patch <code>{html_lib.escape(first.get('package',''))}</code> for "
            f"<code>{html_lib.escape(first.get('cve_id',''))}</code> immediately."
        )
    if any(c.get("is_reachable") for c in cves):
        actions.append("Run integration tests against reachable entry points after patching.")
    if not actions:
        actions.append("No remediation required — proceed with the upgrade.")
    return actions[:6]


def _build_mitigations(
    base: dict[str, Any], upgrade: dict[str, Any],
) -> list[dict[str, str]]:
    items: list[dict[str, str]] = [
        {
            "icon": "🛡",
            "title": "Add a compatibility shim",
            "body": "Wrap deprecated calls in a thin adapter module so the migration "
                    "can happen incrementally instead of a big-bang refactor.",
        },
        {
            "icon": "🧪",
            "title": "Run integration tests on reachable flows",
            "body": "Replay end-to-end tests covering routes and functions surfaced "
                    "in the Risks tab before promoting the upgrade.",
        },
        {
            "icon": "🚀",
            "title": "Stage the deployment",
            "body": "Deploy dev → staging → canary (1% prod) → full prod with "
                    "automated smoke tests at each gate.",
        },
        {
            "icon": "🔔",
            "title": "Add SBOM diff to CI",
            "body": "Trigger a re-scan on every PR that touches dependency files and "
                    "block merges that introduce new BLOCK-level findings.",
        },
    ]

    cascade = (upgrade or {}).get("cascade") or {}
    if cascade.get("chain"):
        items.insert(0, {
            "icon": "📦",
            "title": "Pin transitive deps before upgrading",
            "body": ("Cascade requires bumping "
                     f"{cascade.get('total_packages_affected', len(cascade['chain']))} packages. "
                     "Pin them explicitly to avoid resolver surprises."),
        })
    return items[:6]


# ─────────────────────────────────────────────────────────────────────
# Score breakdown rollup
# ─────────────────────────────────────────────────────────────────────


def _factor_band(value: float) -> tuple[str, str]:
    """Map a normalized [0,1] factor to an (impact label, color) pair."""
    if value >= 0.66:
        return "HIGH", "danger"
    if value >= 0.33:
        return "MODERATE", "warning"
    return "LOW", "success"


def _probabilistic_rows(f: dict[str, Any]) -> list[dict[str, Any]]:
    """Score-breakdown rows from the scorer's real multiplicative factors."""
    e = float(f.get("exploitability", 0) or 0)
    i = float(f.get("impact", 0) or 0)
    r = float(f.get("reachability_eff", 0) or 0)
    b_norm = float(f.get("blast_normalized", 0) or 0)
    b_fac = float(f.get("blast_factor", 1) or 1)
    phi = float(f.get("confidence", 0) or 0)

    def _row(dim: str, value: float, raw: str, weight: str, *, neutral: bool = False) -> dict[str, Any]:
        impact, color = _factor_band(value)
        return {
            "dimension": dim,
            "raw_value": raw,
            "weight": weight,
            "contribution_pts": round(value * 100),
            "contribution_max": 100,
            "impact": impact,
            "color": "info" if neutral else color,
        }

    return [
        _row("Exploitability (E)", e, _fmt_num(e, 2), "× factor"),
        _row("Impact (I)", i, _fmt_num(i, 2), "× factor"),
        _row("Reachability (R_eff)", r, _fmt_num(r, 2), "× factor"),
        _row("Blast (B)", b_norm, f"×{_fmt_num(b_fac, 2)}", "amplifier"),
        _row("Confidence (Φ)", phi, _fmt_num(phi, 2), "evidence", neutral=True),
    ]


def _legacy_score_rows(top: dict[str, Any]) -> list[dict[str, Any]]:
    """Fallback rows for assessments without a probabilistic factor trace."""
    scores = top.get("scores") or {}
    cvss = top.get("cvss", 0) or 0
    epss = top.get("epss", 0) or 0
    in_kev = top.get("in_kev", False)
    ev = top.get("evidence") or {}
    impacted = ev.get("impacted_services", 0) or 0
    reach_refs = len(top.get("references") or [])
    return [
        {
            "dimension": "CVSS Severity",
            "raw_value": _fmt_num(cvss, 1),
            "weight": "severity",
            "contribution_pts": scores.get("severity_score", 0),
            "contribution_max": 40,
            "impact": "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MODERATE",
            "color": "danger",
        },
        {
            "dimension": "EPSS Exploitability",
            "raw_value": _fmt_pct(epss),
            "weight": "exploit",
            "contribution_pts": scores.get("exploit_score", 0),
            "contribution_max": 20,
            "impact": "HIGH" if (epss >= 0.3 or in_kev) else "MODERATE" if epss > 0 else "LOW",
            "color": "warning",
        },
        {
            "dimension": "Reachability",
            "raw_value": f"{reach_refs} hits" if reach_refs else "Not reachable",
            "weight": "reach",
            "contribution_pts": scores.get("reachability_score", 0),
            "contribution_max": 25,
            "impact": "HIGH" if reach_refs else "LOW",
            "color": "warning",
        },
        {
            "dimension": "Blast Radius",
            "raw_value": f"{impacted} service{'s' if impacted != 1 else ''}",
            "weight": "blast",
            "contribution_pts": scores.get("blast_radius_score", 0),
            "contribution_max": 15,
            "impact": "HIGH" if impacted >= 3 else "MODERATE" if impacted else "LOW",
            "color": "warning",
        },
    ]


def _build_score_breakdown(base: dict[str, Any]) -> dict[str, Any]:
    cves = base.get("cves") or []
    if not cves:
        return {
            "rows": [],
            "total": 0,
            "verdict": base.get("overall", {}).get("recommendation", "PROCEED"),
        }
    top = max(cves, key=lambda c: c.get("raw_risk", 0))
    factors = top.get("probabilistic") or {}
    rows = _probabilistic_rows(factors) if factors else _legacy_score_rows(top)
    total = top.get("raw_risk", 0) or sum(r["contribution_pts"] for r in rows)
    verdict = top.get("recommendation") or base.get("overall", {}).get("recommendation", "PROCEED")
    return {"rows": rows, "total": total, "verdict": verdict}


# ─────────────────────────────────────────────────────────────────────
# Pipeline coverage panel
# ─────────────────────────────────────────────────────────────────────


def _build_pipeline_coverage(
    base: dict[str, Any],
    upgrade: dict[str, Any],
    snapshot: dict[str, Any],
    scan: dict[str, Any],
) -> list[dict[str, str]]:
    has_cves = bool(base.get("cves"))
    has_upgrade = bool(upgrade and (upgrade.get("resolution_plan") or upgrade.get("conflicts")))
    has_symbols = bool((scan or {}).get("findings_by_cve"))
    has_snapshot = bool(snapshot)
    neo4j = ((snapshot or {}).get("meta") or {}).get("mode") == "neo4j"
    has_patches = any(
        bool((c.get("patch") or {}).get("before_code") or (c.get("patch") or {}).get("symbols"))
        for c in base.get("cves") or []
    )

    def _badge(present: bool) -> str:
        return "Included" if present else "Skipped"

    def _color(present: bool) -> str:
        return "success" if present else "warning"

    items = [
        ("CVE Scoring",      has_cves),
        ("Dependency Conflicts", has_upgrade),
        ("Semgrep Reachability", has_symbols),
        ("Knowledge Graph Snapshot", has_snapshot),
        ("Neo4j Live Connection", neo4j),
        ("Patch Diff View", has_patches),
        ("Risk Score Audit", True),
        ("Reachability Call Chains", has_symbols),
    ]
    return [
        {"name": name, "status": _badge(present), "color": _color(present)}
        for name, present in items
    ]


# ─────────────────────────────────────────────────────────────────────
# Narrative (Overview body text)
# ─────────────────────────────────────────────────────────────────────


def _build_narrative(base: dict[str, Any], upgrade: dict[str, Any]) -> str:
    ri = base.get("risk_intelligence") or {}
    headline = ri.get("headline") or base.get("overall", {}).get("headline") or ""
    if headline:
        return headline
    return _default_headline(base.get("summary_stats") or {}, upgrade)
