"""Presentation-grade HTML risk report (v2) — story-first, six-tab layout."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.html_reporter import (
    CDN_ASSETS,
    PIPELINE_VERSION,
    _escape_script_for_html,
    _load_json,
    _read_snippet,
    build_graph_from_cves,
    inline_vendor_assets,
)

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES = _REPO_ROOT / "templates"
_PATCHES = _REPO_ROOT / "data" / "patches"
_DEPSDEV = _REPO_ROOT / "data" / "depsdev"

SCORER_FORMULA = """Probabilistic expected-loss model (data/scoring_model.json):

  risk_unit   = clamp(E * I * R_eff * A * B, 0, 1)
  score(0-100) = round(100 * risk_unit)

  E  Exploitability  = 1 - (1-EPSS)(1-KEV)(1-cvss_prior)(1-ml)   (noisy-OR)
  I  Impact          = CVSS CIA magnitude (else cvss/10)
  R  Reachability    = c_res * exp(-lambda*(hops-1)) * (1+taint)
  R_eff              = Phi*R + (1-Phi)*no_path_prior              (confidence-blended)
  A  Asset           = criticality multiplier (default 1.0)
  B  Blast           = 1 + beta*saturation(impacted_services, centrality)
  Phi Confidence     = geometric mean of evidence confidences

  BLOCK if score >= threshold.BLOCK; REVIEW if >= threshold.REVIEW; else PROCEED.
The LLM never sets the verdict; thresholds live in the versioned model file."""


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


def _patch_code_from_symbol(patch: dict[str, Any], symbol: dict[str, Any]) -> tuple[str, str]:
    before = symbol.get("before_signature") or "# See upstream commit for full diff"
    after = symbol.get("after_signature") or before
    summary = symbol.get("summary", "")
    if summary:
        before = f"# {summary}\n{before}"
        after = f"# Patched\n{after}"
    return before, after


def _commit_sha(url: str) -> str:
    if not url:
        return ""
    m = re.search(r"/commit/([0-9a-f]{7,40})", url, re.I)
    return m.group(1)[:12] if m else ""


def _count_cached(dir_path: Path, pattern: str = "*.json") -> int:
    if not dir_path.is_dir():
        return 0
    return sum(1 for _ in dir_path.rglob(pattern))


def _build_fix_plan(upgrade: dict[str, Any]) -> dict[str, Any]:
    plan = upgrade.get("resolution_plan") or {}
    steps_in = plan.get("steps") or []
    steps_out: list[dict[str, Any]] = []
    for i, step in enumerate(steps_in, start=1):
        pkg = step.get("package", "")
        to_v = step.get("to") or step.get("to_version", "")
        from_v = step.get("from") or step.get("from_version", "")
        steps_out.append({
            "order": step.get("order", i),
            "package": pkg,
            "from_version": from_v,
            "to_version": to_v,
            "command": f"pip install {pkg}=={to_v}" if pkg and to_v else "",
            "reason": step.get("reason", ""),
            "estimated_minutes": 30 if i < len(steps_in) else 15,
            "tests_to_run": _tests_for_package(pkg, upgrade),
        })
    total_min = sum(s.get("estimated_minutes", 0) for s in steps_out) or 0
    return {
        "feasible": plan.get("feasible", bool(steps_out)),
        "total_estimated_minutes": total_min,
        "steps": steps_out,
    }


def _tests_for_package(package: str, upgrade: dict[str, Any]) -> list[str]:
    pkg = (package or "").lower()
    hints = {
        "boto3": ["S3 backup endpoint", "integrations backup_to_s3"],
        "requests": ["/auth/login route", "webhook POST handler"],
        "flask": ["Flask app smoke test", "/health endpoint"],
        "pyyaml": ["/admin/config YAML loader"],
        "pillow": ["/tasks upload image endpoint"],
        "urllib3": ["HTTP client integration tests"],
    }
    return hints.get(pkg, ["Run integration tests for affected routes"])


def _build_conflicts(upgrade: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in upgrade.get("conflicts") or []:
        out.append({
            "shared_dependency": c.get("shared_dependency", ""),
            "conflicting_packages": [
                {
                    "package": p.get("package", ""),
                    "constraint": p.get("constraint", ""),
                }
                for p in c.get("conflicting_packages") or []
            ],
            "would_break_build": c.get("would_break_build", False),
            "human_explanation": c.get("human_explanation", c.get("explanation", "")),
        })
    return out


def _build_cascade(upgrade: dict[str, Any]) -> dict[str, Any]:
    cascade = upgrade.get("cascade") or {}
    return {
        "trigger": cascade.get("trigger", ""),
        "chain": cascade.get("chain") or [],
    }


def _headline(explanations: dict[str, Any], upgrade: dict[str, Any], stats: dict[str, Any]) -> str:
    if explanations.get("executive_summary"):
        return explanations["executive_summary"]
    up = (upgrade.get("summary") or {}).get("headline", "")
    if up:
        return up
    reachable = stats.get("reachable_cves", 0)
    total = stats.get("total_cves", 0)
    if stats.get("would_break_build"):
        return (
            f"{reachable} of {total} CVEs are reachable in your code; "
            "a naive upgrade would break dependency resolution."
        )
    if reachable:
        return f"{reachable} of {total} CVEs are reachable in your application code."
    return f"Scanned {total} dependency CVEs; none are directly referenced in application code."


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
    """Assemble v2 report payload (story-first schema)."""
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
            matched = ref.get("source") or ref.get("code_snippet") or ""
            # Keep the matched call line in ``source`` and a surrounding block
            # (the vulnerable code block) in ``code_snippet`` for the diff view.
            block = _read_snippet(project_dir, ref.get("file", ""), int(line))
            ref["source"] = matched or block
            ref["code_snippet"] = block or matched

        patch_raw = _load_json(patch_dir / f"{cve_id}.json") if cve_id else None
        symbols = (patch_raw or {}).get("vulnerable_symbols") or []
        primary_sym = symbols[0] if symbols else {}
        if finding.get("vulnerable_symbol"):
            for s in symbols:
                if s.get("short_name") in str(finding.get("vulnerable_symbol", "")):
                    primary_sym = s
                    break
        before_code, after_code = _patch_code_from_symbol(patch_raw or {}, primary_sym)
        patch_url = (patch_raw or {}).get("patch_url", "")

        scores = row.get("scores") or {}
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
            "raw_risk": scores.get("raw_risk", 0),
            "scores": {
                "severity_score": scores.get("severity_score", 0),
                "exploit_score": scores.get("exploit_score", 0),
                "reachability_score": scores.get("reachability_score", 0),
                "blast_radius_score": scores.get("blast_radius_score", 0),
            },
            # Full probabilistic factor trace from the scorer, so the report
            # shows the real multiplicative factors instead of stale heuristics.
            "probabilistic": row.get("probabilistic") or {},
            "score_confidence": row.get("confidence", 0),
            "is_reachable": finding.get("is_reachable", bool(refs)),
            "confidence": finding.get("confidence", "LOW"),
            "vulnerable_symbol": finding.get("vulnerable_symbol") or primary_sym.get("short_name", ""),
            "change_classification": (
                finding.get("change_classification") or primary_sym.get("change_classification", "")
            ),
            "references": refs,
            "patch": {
                "url": patch_url,
                "commit_sha": _commit_sha(patch_url),
                "before_code": before_code,
                "after_code": after_code,
                "summary": primary_sym.get("summary", ""),
                "symbols": symbols,
            },
            "explanation": (expl_by_cve.get(cve_id) or {}).get("paragraph", ""),
            "evidence_sources": _evidence_sources(finding, patch_raw),
        })

    reachable_list = summary_stats.get("reachable_cves", [])
    unreachable_list = summary_stats.get("unreachable_cves", [])
    total_cves = len(cves_out) or assessment.get("summary", {}).get("total_cves_scored", 0)
    reachable_count = (
        len(reachable_list) if isinstance(reachable_list, list)
        else int(reachable_list or 0)
    )
    noise_filtered = (
        len(unreachable_list) if isinstance(unreachable_list, list)
        else int(unreachable_list or 0)
    )

    upgrade = upgrade_simulation or {}
    conflicts = _build_conflicts(upgrade)
    build_blockers = sum(1 for c in conflicts if c.get("would_break_build"))

    stats = {
        "total_cves": total_cves,
        "reachable_cves": reachable_count,
        "noise_filtered": noise_filtered,
        "build_blockers": build_blockers,
        "noise_reduction_percent": summary_stats.get("noise_reduction_percent", 0),
        "would_break_build": bool(build_blockers or (
            (upgrade.get("summary") or {}).get("verdict", "").startswith("BLOCK")
        )),
    }

    graph_data = graph if graph and graph.get("nodes") else build_graph_from_cves(cves_out)
    fix_plan = _build_fix_plan(upgrade)

    generated = assessment.get("generated_at") or datetime.now(timezone.utc).isoformat()
    payload_core = json.dumps({
        "cves": [c.get("cve_id") for c in cves_out],
        "generated_at": generated,
        "target_repo": target_repo,
    }, sort_keys=True)
    repro_hash = hashlib.sha256(payload_core.encode()).hexdigest()[:16]

    return {
        "metadata": {
            "generated_at": generated,
            "target_repo": target_repo,
            "scorer_version": assessment.get("scorer_version", "1.0.0"),
            "pipeline_version": f"12-phase v{PIPELINE_VERSION}",
            "reproducibility_hash": repro_hash,
            "data_sources": {
                "trivy_db_date": _snapshot_date(_REPO_ROOT / "data"),
                "epss_snapshot": _file_date(_REPO_ROOT / "data" / "epss_snapshot.json"),
                "kev_snapshot": _file_date(_REPO_ROOT / "data" / "kev_snapshot.json"),
                "patches_cached": _count_cached(_PATCHES),
                "depsdev_cached": _count_cached(_DEPSDEV),
            },
            "phase_timestamps": {
                "assessment": generated,
                "symbol_scan": scan.get("scanned_at", ""),
                "upgrade_simulation": upgrade.get("simulated_at", ""),
            },
        },
        "overall": {
            "recommendation": assessment.get("summary", {}).get("overall_recommendation", "PROCEED"),
            "raw_risk": assessment.get("summary", {}).get("overall_raw_risk", 0),
            "headline": _headline(explanations, upgrade, stats),
            "would_break_build": stats["would_break_build"],
        },
        "summary_stats": stats,
        "cves": cves_out,
        "fix_plan": fix_plan,
        "conflicts": conflicts,
        "cascade": _build_cascade(upgrade),
        "graph": graph_data,
        "audit": {
            "formula": SCORER_FORMULA,
            "thresholds": assessment.get("thresholds", {"BLOCK": 70, "REVIEW": 40}),
            "degraded_sources": [],
        },
        "project_dir": project_dir or "",
    }


def _evidence_sources(finding: dict[str, Any], patch_raw: Optional[dict[str, Any]]) -> list[str]:
    sources = ["Trivy", "Risk Scorer v1.0.0"]
    if finding.get("references"):
        sources.append("Symbol Scanner (AST)")
    if patch_raw and patch_raw.get("vulnerable_symbols"):
        sources.append("Patch Fetcher (GitHub)")
    sources.extend(["EPSS snapshot", "KEV snapshot"])
    return sources


def _file_date(path: Path) -> str:
    if not path.is_file():
        return "—"
    ts = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return ts.strftime("%Y-%m-%d")


def _snapshot_date(data_dir: Path) -> str:
    for name in ("kev_snapshot.json", "epss_snapshot.json"):
        p = data_dir / name
        if p.is_file():
            return _file_date(p)
    return "—"


def generate_report(
    report_data: dict[str, Any],
    output_path: str = "report.html",
    offline: bool = False,
) -> str:
    """Generate self-contained v2 HTML report."""
    env = _jinja_env()
    html = env.get_template("report_v2.html.j2").render(
        **report_data,
        offline=offline,
        cdn_assets=CDN_ASSETS,
        cves_json=json.dumps(report_data.get("cves") or []),
        graph_json=json.dumps(report_data.get("graph") or {"nodes": [], "edges": []}),
        fix_plan_json=json.dumps(report_data.get("fix_plan") or {}),
        conflicts_json=json.dumps(report_data.get("conflicts") or []),
        cascade_json=json.dumps(report_data.get("cascade") or {}),
        audit_json=json.dumps(report_data.get("audit") or {}),
        metadata_json=json.dumps(report_data.get("metadata") or {}),
    )
    html = inline_vendor_assets(html, offline=offline)
    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    logger.info("Wrote v2 report to %s (%d bytes)", out, len(html.encode("utf-8")))
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
    """Pipeline entry point — same contract as html_reporter.render_html."""
    scan = _load_json(Path(symbol_scan_path)) if symbol_scan_path and Path(symbol_scan_path).is_file() else None
    upgrade = _load_json(Path(upgrade_sim_path)) if upgrade_sim_path and Path(upgrade_sim_path).is_file() else None

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
    """Build sample v2 HTML report from repo test fixtures."""
    fixtures = _REPO_ROOT / "tests" / "fixtures"
    scan = _load_json(fixtures / "symbol_scan_output.json")
    assessment = {
        "generated_at": "2026-05-19T12:00:00Z",
        "scorer_version": "1.0.0",
        "summary": {
            "overall_recommendation": "REVIEW",
            "overall_raw_risk": 69,
            "total_cves_scored": 81,
        },
        "cves": [
            {
                "cve_id": "CVE-2018-1000656",
                "package": "flask",
                "recommendation": "REVIEW",
                "scores": {"raw_risk": 63},
            },
        ],
    }
    explanations = {"per_cve": [], "executive_summary": "Sample v2 report from fixtures."}
    data = build_report_data(
        assessment,
        explanations,
        symbol_scan=scan,
        target_repo="vulnerable-task-tracker",
        project_dir=str(_REPO_ROOT / "vulnerable-task-tracker"),
    )
    return generate_report(data, output_path=output_path, offline=offline)
