"""Tabbed HTML risk report generator (self-contained, offline-capable)."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES = _REPO_ROOT / "templates"
_VENDOR = _REPO_ROOT / "static" / "vendor"
_PATCHES = _REPO_ROOT / "data" / "patches"

PIPELINE_VERSION = "1.0.0"

CDN_ASSETS = [
    {
        "kind": "css",
        "href": "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap",
        "vendor": "inter.css",
    },
    {
        "kind": "js",
        "src": "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js",
        "vendor": "chart.umd.min.js",
    },
    {
        "kind": "js",
        "src": "https://cdn.jsdelivr.net/npm/vis-network@9.1.9/standalone/umd/vis-network.min.js",
        "vendor": "vis-network.min.js",
    },
    {
        "kind": "js",
        "src": "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js",
        "vendor": "highlight.min.js",
    },
    {
        "kind": "js",
        "src": "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/python.min.js",
        "vendor": "python.min.js",
    },
]


def _jinja_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["fmt_num"] = _fmt_num
    env.filters["fmt_pct"] = _fmt_pct
    env.filters["rec_class"] = _rec_class
    return env


def _fmt_num(value: Any, decimals: int = 1) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return str(value)
    if decimals == 0 or n == int(n):
        return str(int(n))
    return f"{n:.{decimals}f}"


def _fmt_pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "—"


def _rec_class(recommendation: str) -> str:
    rec = (recommendation or "PROCEED").upper()
    if rec == "BLOCK":
        return "BLOCK"
    if rec == "REVIEW":
        return "REVIEW"
    return "PROCEED"


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _read_snippet(project_dir: Optional[str], file_path: str, line: int, context: int = 3) -> str:
    if not project_dir or not file_path:
        return ""
    full = Path(project_dir) / file_path
    if not full.is_file():
        return ""
    try:
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    out: list[str] = []
    for i in range(start, end):
        prefix = ">>>" if i == line - 1 else "   "
        out.append(f"{prefix} {i + 1:4d} | {lines[i]}")
    return "\n".join(out)


def _patch_code_from_symbol(patch: dict[str, Any], symbol: dict[str, Any]) -> tuple[str, str]:
    before = symbol.get("before_signature") or "# See upstream commit for full diff"
    after = symbol.get("after_signature") or before
    summary = symbol.get("summary", "")
    if summary:
        before = f"# {summary}\n{before}"
        after = f"# Patched\n{after}"
    return before, after


def build_graph_from_cves(cves: list[dict[str, Any]]) -> dict[str, Any]:
    """Build vis-network nodes/edges from CVE reference chains."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    key_to_id: dict[str, str] = {}
    nid = 0

    def add_node(label: str, ntype: str, **extra: Any) -> str:
        nonlocal nid
        key = f"{ntype}:{label}:{extra.get('cve', '')}"
        if key in key_to_id:
            return key_to_id[key]
        node_id = f"n{nid}"
        nid += 1
        key_to_id[key] = node_id
        nodes.append({"id": node_id, "label": label, "type": ntype, **extra})
        return node_id

    for cve in cves:
        cve_id = cve.get("cve_id", "")
        rec = cve.get("recommendation", "REVIEW")
        sym = cve.get("vulnerable_symbol", "symbol")
        for ref in cve.get("references") or []:
            ep = ref.get("entry_point_info") or {}
            route = ep.get("route") or ref.get("file", "entry")
            prev = add_node(
                route,
                "entry_point",
                framework=ep.get("framework", ""),
                method=ep.get("method", "GET"),
            )
            fn = ref.get("enclosing_function")
            if fn:
                mid = add_node(fn, "function", file=ref.get("file", ""))
                edges.append({"source": prev, "target": mid, "kind": "calls"})
                prev = mid
            vuln = add_node(sym, "vulnerable", cve=cve_id, recommendation=rec)
            edges.append({"source": prev, "target": vuln, "kind": "calls"})

    return {"nodes": nodes, "edges": edges}


def build_report_data(
    assessment: dict[str, Any],
    explanations: Optional[dict[str, Any]] = None,
    symbol_scan: Optional[dict[str, Any]] = None,
    upgrade_simulation: Optional[dict[str, Any]] = None,
    graph: Optional[dict[str, Any]] = None,
    *,
    target_repo: str = "project",
    project_dir: Optional[str] = None,
    patches_dir: Optional[str] = None,
) -> dict[str, Any]:
    """Assemble unified report payload for templates."""
    explanations = explanations or {}
    expl_by_cve = {e.get("cve_id"): e for e in explanations.get("per_cve", []) if e.get("cve_id")}

    scan = symbol_scan or {}
    findings = scan.get("findings_by_cve") or {}
    summary_stats = scan.get("summary") or {}

    patch_dir = Path(patches_dir or _PATCHES)
    cves_out: list[dict[str, Any]] = []

    for row in assessment.get("cves", []):
        cve_id = row.get("cve_id", "")
        finding = findings.get(cve_id, {})
        refs = list(finding.get("references") or [])
        for ref in refs:
            line = ref.get("line") or 0
            ref["code_snippet"] = _read_snippet(project_dir, ref.get("file", ""), int(line))

        patch_raw = _load_json(patch_dir / f"{cve_id}.json") if cve_id else None
        symbols = (patch_raw or {}).get("vulnerable_symbols") or []
        primary_sym = symbols[0] if symbols else {}
        if finding.get("vulnerable_symbol"):
            for s in symbols:
                if s.get("short_name") in str(finding.get("vulnerable_symbol", "")):
                    primary_sym = s
                    break
        before_code, after_code = _patch_code_from_symbol(patch_raw or {}, primary_sym)

        ev = row.get("evidence") or {}
        cves_out.append({
            "cve_id": cve_id,
            "package": row.get("package", finding.get("package", "")),
            "installed_version": row.get("installed_version", ""),
            "fixed_version": row.get("fixed_version", ""),
            "cvss": row.get("cvss_score", 0),
            "epss": ev.get("epss", 0),
            "in_kev": ev.get("in_kev", False),
            "recommendation": row.get("recommendation", "REVIEW"),
            "scores": row.get("scores", {}),
            "vulnerable_symbol": finding.get("vulnerable_symbol") or primary_sym.get("short_name", ""),
            "change_classification": finding.get("change_classification")
            or primary_sym.get("change_classification", ""),
            "patch": {
                "url": (patch_raw or {}).get("patch_url", ""),
                "before_code": before_code,
                "after_code": after_code,
                "summary": primary_sym.get("summary", ""),
                "symbols": symbols,
            },
            "is_reachable": finding.get("is_reachable", bool(refs)),
            "references": refs,
            "explanation": (expl_by_cve.get(cve_id) or {}).get("paragraph", ""),
            "confidence": finding.get("confidence", "LOW"),
        })

    total = summary_stats.get("reachable_cves", [])
    unreachable = summary_stats.get("unreachable_cves", [])
    total_cves = len(cves_out) or assessment.get("summary", {}).get("total_cves_scored", 0)

    stats = {
        "total_cves": total_cves,
        "reachable_cves": len(total) if isinstance(total, list) else summary_stats.get("reachable_cves", 0),
        "noise_filtered": len(unreachable) if isinstance(unreachable, list) else summary_stats.get("noise_filtered", 0),
        "noise_reduction_percent": summary_stats.get("noise_reduction_percent", 0),
        "would_break_build": bool(
            upgrade_simulation
            and upgrade_simulation.get("summary", {}).get("verdict", "").startswith("BLOCK")
        ),
    }
    if isinstance(stats["reachable_cves"], list):
        stats["reachable_cves"] = len(stats["reachable_cves"])

    graph_data = graph if graph and graph.get("nodes") else build_graph_from_cves(cves_out)

    upgrade = upgrade_simulation or {}
    up_summary = upgrade.get("summary") or {}

    return {
        "metadata": {
            "generated_at": assessment.get("generated_at", ""),
            "target_repo": target_repo,
            "scorer_version": assessment.get("scorer_version", "1.0.0"),
            "pipeline_version": PIPELINE_VERSION,
        },
        "overall": {
            "recommendation": assessment.get("summary", {}).get("overall_recommendation", "PROCEED"),
            "raw_risk": assessment.get("summary", {}).get("overall_raw_risk", 0),
            "confidence": 0.92,
            "headline": explanations.get("executive_summary", ""),
        },
        "summary_stats": stats,
        "cves": cves_out,
        "upgrade_simulation": upgrade,
        "graph": graph_data,
        "top_concerns": _top_concerns(cves_out),
        "next_action": _next_action(upgrade, cves_out),
        "chart_scores": _chart_scores(cves_out),
        "project_dir": project_dir or "",
    }


def _top_concerns(cves: list[dict[str, Any]], limit: int = 3) -> list[dict[str, str]]:
    ranked = sorted(
        cves,
        key=lambda c: (-(c.get("scores") or {}).get("raw_risk", 0), c.get("cve_id", "")),
    )
    out: list[dict[str, str]] = []
    for c in ranked[:limit]:
        ref = (c.get("references") or [{}])[0]
        ep = ref.get("entry_point_info") or {}
        where = ep.get("route") or ref.get("file", "codebase")
        out.append({
            "title": f"{c.get('package', '')} — {c.get('cve_id', '')}",
            "detail": (
                f"{c.get('recommendation')} ({(c.get('scores') or {}).get('raw_risk', 0)}/100). "
                f"Symbol {c.get('vulnerable_symbol', '—')}; "
                f"{'reachable at ' + str(where) if c.get('is_reachable') else 'not directly referenced'}."
            ),
        })
    return out


def _next_action(upgrade: dict[str, Any], cves: list[dict[str, Any]]) -> str:
    if upgrade.get("resolution_plan", {}).get("steps"):
        steps = upgrade["resolution_plan"]["steps"]
        parts = [f"{s['package']} → {s['to']}" for s in steps]
        return "Upgrade " + ", then ".join(parts) + ". Test affected endpoints."
    block = [c for c in cves if c.get("recommendation") == "BLOCK"]
    if block:
        return f"Address {len(block)} BLOCK-rated CVE(s) before production deploy."
    return "Proceed with staged upgrades and regression tests."


def _chart_scores(cves: list[dict[str, Any]]) -> dict[str, float]:
    if not cves:
        return {"severity": 0, "exploit": 0, "reachability": 0, "blast": 0}
    top = max(cves, key=lambda c: (c.get("scores") or {}).get("raw_risk", 0))
    s = top.get("scores") or {}
    return {
        "severity": s.get("severity_score", 0),
        "exploit": s.get("exploit_score", 0),
        "reachability": s.get("reachability_score", 0),
        "blast": s.get("blast_radius_score", 0),
    }


def render_executive_tab(data: dict[str, Any]) -> str:
    """Render the executive tab HTML."""
    return _jinja_env().get_template("tabs/_executive.html.j2").render(**data)


def render_technical_tab(data: dict[str, Any]) -> str:
    """Render the technical tab HTML."""
    return _jinja_env().get_template("tabs/_technical.html.j2").render(**data)


def render_patches_tab(data: dict[str, Any]) -> str:
    """Render the patches tab HTML."""
    return _jinja_env().get_template("tabs/_patches.html.j2").render(**data)


def render_upgrade_tab(data: dict[str, Any]) -> str:
    """Render the upgrade tab HTML."""
    return _jinja_env().get_template("tabs/_upgrade.html.j2").render(**data)


def render_graph_tab(data: dict[str, Any]) -> str:
    """Render the reachability graph tab HTML."""
    return _jinja_env().get_template("tabs/_graph.html.j2").render(**data)


def _escape_script_for_html(js: str) -> str:
    """Prevent inlined JS from closing the HTML script element early (e.g. highlight.js)."""
    return re.sub(r"</script>", r"<\/script>", js, flags=re.IGNORECASE)


def _vendor_inline_blocks() -> str:
    """Build inline style/script blocks from static/vendor/."""
    parts: list[str] = []
    for asset in CDN_ASSETS:
        vendor_path = _VENDOR / asset["vendor"]
        if not vendor_path.is_file():
            logger.warning("Missing vendor file: %s", vendor_path)
            continue
        content = vendor_path.read_text(encoding="utf-8", errors="replace")
        if asset["kind"] == "css":
            parts.append(f"<style>\n{content}\n</style>")
        else:
            parts.append(f"<script>\n{_escape_script_for_html(content)}\n</script>")
    return "\n".join(parts)


def inline_vendor_assets(html: str, offline: bool = True) -> str:
    """Replace CDN tags with inline content, or inject vendor blocks when offline."""
    if not offline:
        return html
    blocks = _vendor_inline_blocks()
    if not blocks:
        return html
    for asset in CDN_ASSETS:
        if asset["kind"] == "css":
            patterns = [f'<link rel="stylesheet" href="{asset["href"]}">']
        else:
            patterns = [
                f'<script src="{asset["src"]}" defer></script>',
                f'<script src="{asset["src"]}"></script>',
            ]
        vendor_path = _VENDOR / asset["vendor"]
        if not vendor_path.is_file():
            continue
        content = vendor_path.read_text(encoding="utf-8", errors="replace")
        if asset["kind"] == "css":
            inline = f"<style>\n{content}\n</style>"
        else:
            inline = f"<script>\n{_escape_script_for_html(content)}\n</script>"
        for tag in patterns:
            if tag in html:
                html = html.replace(tag, inline, 1)
                break
    if blocks not in html:
        html = html.replace("</head>", f"{blocks}\n</head>", 1)
    return html


def generate_report(
    report_data: dict[str, Any],
    output_path: str = "report.html",
    offline: bool = False,
    theme: str = "light",
) -> str:
    """Generate self-contained HTML report. Returns absolute path."""
    _ = theme
    env = _jinja_env()
    html = env.get_template("report.html.j2").render(
        **report_data,
        offline=offline,
        cdn_assets=CDN_ASSETS,
        graph_json=json.dumps(report_data.get("graph") or {"nodes": [], "edges": []}),
        chart_json=json.dumps(report_data.get("chart_scores") or {}),
        cves_json=json.dumps(report_data.get("cves") or []),
    )
    html = inline_vendor_assets(html, offline=offline)
    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    logger.info("Wrote report to %s (%d bytes)", out, len(html.encode("utf-8")))
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
    """Backward-compatible entry used by pipeline_a.py."""
    scan = None
    if symbol_scan_path and Path(symbol_scan_path).is_file():
        scan = _load_json(Path(symbol_scan_path))
    upgrade = None
    if upgrade_sim_path and Path(upgrade_sim_path).is_file():
        upgrade = _load_json(Path(upgrade_sim_path))

    snapshot = None
    snap_path = graph_meta.get("snapshot_path")
    if snap_path and Path(snap_path).is_file():
        snapshot = _load_json(Path(snap_path))

    data = build_report_data(
        assessment,
        explanations,
        symbol_scan=scan,
        upgrade_simulation=upgrade,
        graph=None,
        target_repo=target_repo,
        project_dir=project_dir,
    )
    out_path = os.path.join(output_dir, "risk_report.html")
    return generate_report(data, output_path=out_path, offline=offline)


def assemble_sample_report(
    output_path: str,
    *,
    offline: bool = True,
) -> str:
    """Build sample HTML report from repo test fixtures (no pipeline run required)."""
    fixtures = _REPO_ROOT / "tests" / "fixtures"
    scan = _load_json(fixtures / "symbol_scan_output.json")
    assessment = {
        "generated_at": "2026-05-19T12:00:00Z",
        "scorer_version": "1.0.0",
        "summary": {
            "overall_recommendation": "REVIEW",
            "overall_raw_risk": 69,
            "total_cves_scored": 81,
            "block_count": 0,
            "review_count": 47,
        },
        "cves": [
            {
                "cve_id": "CVE-2018-1000656",
                "package": "flask",
                "installed_version": "0.12",
                "fixed_version": "0.12.3",
                "cvss_score": 7.5,
                "recommendation": "REVIEW",
                "evidence": {"epss": 0.02, "in_kev": False},
                "scores": {"raw_risk": 63, "severity_score": 20, "exploit_score": 8,
                           "reachability_score": 25, "blast_radius_score": 10},
            },
            {
                "cve_id": "CVE-2020-1747",
                "package": "pyyaml",
                "installed_version": "5.1",
                "fixed_version": "5.3.1",
                "cvss_score": 9.8,
                "recommendation": "REVIEW",
                "evidence": {"epss": 0.01, "in_kev": False},
                "scores": {"raw_risk": 64, "severity_score": 25, "exploit_score": 5,
                           "reachability_score": 25, "blast_radius_score": 9},
            },
        ],
    }
    explanations = {
        "per_cve": [],
        "executive_summary": "Sample report built from tests/fixtures for offline preview.",
    }

    upgrade = None
    try:
        from src.upgrade_simulator import parse_requirements, simulate_upgrade

        req_path = _REPO_ROOT / "vulnerable-task-tracker" / "requirements.txt"
        if req_path.is_file():
            reqs = parse_requirements(str(req_path))
            upgrade = simulate_upgrade(
                reqs,
                [{"package": "requests", "target_version": "2.31.0"}],
                python_version="3.9.5",
            )
    except Exception as exc:
        logger.warning("Upgrade simulation skipped: %s", exc)

    data = build_report_data(
        assessment,
        explanations,
        symbol_scan=scan,
        upgrade_simulation=upgrade,
        target_repo="vulnerable-task-tracker",
        project_dir=str(_REPO_ROOT / "vulnerable-task-tracker"),
    )
    return generate_report(data, output_path=output_path, offline=offline)


# Backward-compatible alias
assemble_and_generate_demo = assemble_sample_report
