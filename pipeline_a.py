#!/usr/bin/env python3
"""Pipeline A — Pre-Upgrade Risk Detection (fully integrated).

Patch fetcher, symbol scanner, and upgrade simulator are wired before
graph scoring and the HTML report.

PIPELINE PHASES
───────────────
  Phase 1   Ingestion & Normalization        src/normalizer.py
  Phase 2   Patch Intelligence (preload)     src/patch_fetcher.py
  Phase 3   Triple-Check Rule Resolution     src/rule_resolver.py
            + patch-aware sink rules         src/symbol_rule_builder.py
  Phase 4   Parallel Semgrep Execution       src/executor.py
  Phase 5   Reporting (Semgrep side)         src/reporter.py
  Phase 6   Symbol Reachability              src/symbol_scanner.py
  Phase 7   Upgrade Simulation               src/upgrade_simulator.py
  Phase 8   Graph Ingestion                  src/graph_builder.py
  Phase 9   Graph Queries (Neo4j-aware)      src/graph_queries.py
  Phase 10  Risk Scoring                     src/scorer.py
  Phase 11  Template Explanations            src/explainer.py
  Phase 12  Tabbed HTML Report               src/html_reporter.py

USAGE
─────
  python pipeline_a.py \\
      --project-dir ./vulnerable-task-tracker \\
      --services services.yaml \\
      --output-dir ./output \\
      --skip-llm --present --offline
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Neo4j optionally imports numpy (OpenBLAS). Limit threads to avoid OOM on Windows
# after long pipeline runs (Ollama + patch fetch already consume RAM).
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

from dotenv import load_dotenv

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
else:
    sys.stdout.reconfigure(line_buffering=True)

load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from src.executor import run_scans
from src.explainer import explain_risk, save_explanations
from src.graph_builder import build_graph
from src.graph_queries import get_neo4j_driver, run_all_queries
from src.html_reporter import render_html as _render_html_v1
from src.html_reporter_v2 import render_html as _render_html_v2
from src.html_reporter_final_v2 import render_html as _render_html_final_v2

_REPORT_RENDERERS = {
    "v1": _render_html_v1,
    "v2": _render_html_v2,
    "final": _render_html_final_v2,
}


def _resolve_renderer(version: str):
    return _REPORT_RENDERERS.get(version, _render_html_final_v2)
from src.normalizer import normalize
from src.patch_fetcher import fetch_patches_batch
from src.pipeline_console import (
    configure as configure_console,
    print_banner,
    print_families_table,
    print_final_story,
    print_graph_stats,
    print_hero_fraction,
    print_outputs_table,
    print_phase,
    print_reachable_cves,
    print_risk_summary,
    print_stat_row,
    print_stats_table,
    print_upgrade_table,
)
from src.registry_matcher import load_registry_index
from src.reporter import build_report, print_summary, save_report
from src.rule_resolver import resolve_rules
from src.scorer import save_assessment, score_cves
from src.symbol_rule_builder import enrich_rules_with_patch_sinks
from src.symbol_scanner import save_findings, scan_symbols
from src.upgrade_simulator import simulate_upgrade
from src.utils import detect_language

log = logging.getLogger("pipeline_a")


def _utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _section(title: str) -> None:
    """Legacy wrapper — parse 'Phase N   Title' into print_phase."""
    parts = title.split("  ", 1)
    phase = parts[0].strip() if parts else title
    subtitle = parts[1].strip() if len(parts) > 1 else ""
    print_phase(phase, subtitle)


def _configure_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(level=level, format="%(message)s", force=True)
    if quiet:
        logging.getLogger("src.patch_fetcher").setLevel(logging.WARNING)


def _resolve_input(raw: str, project_dir: str) -> str:
    if os.path.isabs(raw):
        return raw
    if os.path.exists(raw):
        return os.path.abspath(raw)
    return os.path.join(project_dir, raw)


def _ensure_trivy_input(
    input_path: str,
    project_dir: str,
    output_dir: str,
) -> str:
    """Return path to enriched Trivy JSON; run live scan when missing."""
    if os.path.isfile(input_path):
        return input_path
    from src.tool_registry import run_trivy_on_repo

    print(f"   No Trivy JSON at {input_path}; running live scan on {project_dir}…")
    cves, mode = run_trivy_on_repo(project_dir)
    if not cves and mode.startswith("trivy_unavailable"):
        raise SystemExit(
            "Trivy scan failed and no CVE input file was found. "
            "Install Trivy (https://github.com/aquasecurity/trivy) or pass "
            "--input path/to/enriched_trivy_output.json"
        )
    out = os.path.join(output_dir, "enriched_trivy_output.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(cves, fh, indent=2)
    print(f"   Wrote {len(cves)} CVEs to {out} (scan mode: {mode})")
    return out


def _cve_id_to_package(trivy_vulns: list[dict[str, Any]]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for v in trivy_vulns:
        cve = v.get("cve") or v.get("VulnerabilityID")
        pkg = v.get("package") or v.get("PkgName")
        if cve and pkg:
            mapping[str(cve).upper()] = pkg
    return mapping


def _pick_upgrade_targets(
    trivy_vulns: list[dict[str, Any]],
    reachable_cves: set[str],
) -> list[dict[str, str]]:
    proposed: dict[str, str] = {}
    for v in trivy_vulns:
        cve = v.get("cve") or v.get("VulnerabilityID")
        if not cve or str(cve).upper() not in reachable_cves:
            continue
        pkg = v.get("package") or v.get("PkgName")
        fixed = v.get("fixed_version") or v.get("FixedVersion")
        if not pkg or not fixed:
            continue
        proposed.setdefault(pkg, str(fixed).split(",")[0].strip())
    return [{"package": p, "target_version": ver} for p, ver in proposed.items()]


def _merge_symbol_reachability(
    graph_evidence: dict[str, Any],
    symbol_findings: dict[str, Any],
    reachable_cves: set[str],
) -> None:
    """Append symbol-scanner paths to graph evidence (scorer indexes by cve_id)."""
    existing = {
        row.get("cve_id") or row.get("cve")
        for row in graph_evidence.get("reachability", [])
    }
    for cve in reachable_cves:
        if cve in existing:
            continue
        finding = symbol_findings.get("findings_by_cve", {}).get(cve, {})
        for ref in finding.get("references") or []:
            ep = ref.get("entry_point_info") or {}
            graph_evidence.setdefault("reachability", []).append({
                "cve_id": cve,
                "service": ep.get("route") or ref.get("file", ""),
                "vuln_fn": ref.get("enclosing_function")
                or finding.get("vulnerable_symbol", ""),
                "file": ref.get("file", ""),
                "line_start": ref.get("line", 0),
                "hops": 1 if ref.get("in_entry_point") else 2,
                "source": "symbol_scanner",
            })


async def run_pipeline(args: argparse.Namespace) -> None:
    plain = getattr(args, "plain", False)
    quiet = getattr(args, "quiet", False)
    configure_console(plain=plain)
    _configure_logging(args.verbose, quiet)

    project_dir = os.path.abspath(args.project_dir)
    output_dir = os.path.abspath(args.output_dir) if args.output_dir else os.getcwd()
    os.makedirs(output_dir, exist_ok=True)

    skip_llm = args.skip_llm
    use_graph = not args.no_graph
    use_neo4j = args.neo4j and use_graph

    input_path = _resolve_input(args.input, project_dir)

    input_path = _ensure_trivy_input(input_path, project_dir, output_dir)

    api_key = args.api_key or os.environ.get("GOOGLE_API_KEY")
    rules_dir = os.path.join(output_dir, "semgrep_rules")
    services_path = args.services or "services.yaml"

    started_at = _utc_iso()
    t0 = time.perf_counter()
    print_banner(
        project_dir=project_dir,
        output_dir=output_dir,
        started_at=started_at,
        use_graph=use_graph,
        use_neo4j=use_neo4j,
        llm_backend=args.llm,
        skip_llm=skip_llm,
        input_path=input_path,
    )

    _section("Phase 1   Ingestion & Normalization")
    families = normalize(input_path, include_low=args.include_low, quiet=True)
    if not families:
        log.warning("No vulnerability families to process. Exiting.")
        return
    with open(input_path, "r", encoding="utf-8") as fh:
        trivy_vulns = json.load(fh)
    total_vulns = len(trivy_vulns)
    print_stats_table([
        ("Total CVEs (Trivy)", total_vulns, "white"),
        ("CWE families", len(families), "green"),
    ])
    print_families_table(families)

    cve_to_pkg = _cve_id_to_package(trivy_vulns)
    cve_ids = sorted(cve_to_pkg.keys())

    _section("Phase 2   Patch Intelligence (preload for sink rules)")
    if not quiet:
        print_stat_row("Loading patches", f"{len(cve_ids)} CVEs (cached)…", style="cyan")
    patches = fetch_patches_batch(
        [{"cve_id": c, "package": cve_to_pkg.get(c)} for c in cve_ids],
        max_workers=4,
    )
    patches_path = os.path.join(output_dir, "patches.json")
    with open(patches_path, "w", encoding="utf-8") as fh:
        json.dump(patches, fh, indent=2)
    n_with_symbols = sum(1 for p in patches.values() if p.get("vulnerable_symbols"))
    print_stats_table([
        ("Patches loaded", len(patches), "green"),
        ("With vulnerable symbols", n_with_symbols, "yellow"),
    ])

    _section("Phase 3   Triple-Check Rule Resolution")
    language = detect_language(project_dir)
    registry_index = load_registry_index()
    print_stat_row("Language", language, style="white")
    print_stat_row("Registry CWEs indexed", len(registry_index), style="dim")
    resolved_rules = await resolve_rules(
        families, language, registry_index, api_key,
        rules_dir, max_concurrent=4,
        llm_backend=args.llm, ollama_model=args.ollama_model,
        skip_llm=skip_llm, quiet=quiet,
    )
    print_stat_row("Rules resolved", len(resolved_rules), style="green")

    resolved_rules = enrich_rules_with_patch_sinks(
        families, resolved_rules, patches, cve_to_pkg, rules_dir, language,
        quiet=quiet,
    )

    _section("Phase 4   Parallel Semgrep Execution")
    scan_results = run_scans(
        resolved_rules, project_dir, max_workers=4,
        quiet=quiet, use_rich=not plain,
    )
    semgrep_total = sum(len(m) for m in scan_results.values())

    _section("Phase 5   Reporting (Semgrep side)")
    report = build_report(families, resolved_rules, scan_results)
    save_report(report, output_dir)
    print_summary(report, use_rich=not plain, hits_only=quiet)

    vulnerable_symbols_by_cve = {
        cve: {
            "package": cve_to_pkg.get(cve),
            "vulnerable_symbols": p.get("vulnerable_symbols", []),
        }
        for cve, p in patches.items()
        if p.get("vulnerable_symbols")
    }

    _section("Phase 6   Symbol Reachability Scan")
    symbol_path = os.path.join(output_dir, "symbol_scan.json")
    if not vulnerable_symbols_by_cve:
        print_stat_row("Symbol scan", "skipped (no symbols)", style="dim")
        symbol_findings = {
            "scanned_at": _utc_iso(),
            "target_dir": project_dir,
            "stats": {"files_scanned": 0, "total_findings": 0},
            "findings_by_cve": {},
            "summary": {
                "reachable_cves": [],
                "unreachable_cves": [],
                "noise_reduction_percent": 0.0,
            },
        }
    else:
        symbol_findings = scan_symbols(project_dir, vulnerable_symbols_by_cve)
        save_findings(symbol_findings, symbol_path)
        stats = symbol_findings.get("stats", {})
        summary = symbol_findings.get("summary", {})
        reachable_n = len(summary.get("reachable_cves", []))
        unreachable_n = len(summary.get("unreachable_cves", []))
        noise_pct = summary.get("noise_reduction_percent", 0.0)
        print_hero_fraction(reachable_n, total_vulns, noise_pct=noise_pct)
        print_stats_table([
            ("Files scanned", stats.get("files_scanned", 0), "white"),
            ("Code references found", stats.get("total_findings", 0), "yellow"),
            ("Reachable CVEs", reachable_n, "green"),
            ("Filtered (noise)", unreachable_n, "dim"),
            ("Noise reduction", f"{noise_pct:.1f}%", "green"),
        ])

    reachable_cves = set(symbol_findings.get("summary", {}).get("reachable_cves", []))

    _section("Phase 7   Upgrade Simulation")
    upgrade_sim: Optional[dict[str, Any]] = None
    upgrade_sim_path: Optional[str] = None
    if not reachable_cves:
        print_stat_row("Upgrade sim", "skipped (no reachable CVEs)", style="dim")
    else:
        try:
            from src.project_deps import DependencyDiscoveryError, discover_dependency_pins

            try:
                current_reqs, dep_label = discover_dependency_pins(project_dir)
            except DependencyDiscoveryError as exc:
                print(f"   ({exc}; skipping)")
                current_reqs = None
            if current_reqs:
                print_stat_row("Pinned packages", f"{len(current_reqs)} from {dep_label}", style="white")
                targets = _pick_upgrade_targets(trivy_vulns, reachable_cves)
                if not targets:
                    print_stat_row("Upgrade sim", "no fixed versions for reachable CVEs", style="yellow")
                else:
                    upgrade_sim = simulate_upgrade(
                        current_requirements=current_reqs,
                        target_upgrades=targets,
                        cve_data_source={"vulnerabilities": trivy_vulns},
                    )
                    upgrade_sim_path = os.path.join(output_dir, "upgrade_simulation.json")
                    with open(upgrade_sim_path, "w", encoding="utf-8") as fh:
                        json.dump(upgrade_sim, fh, indent=2)
                    print_upgrade_table(upgrade_sim)
        except Exception as exc:
            log.exception("Upgrade simulation failed: %s", exc)
            print(f"   (failed: {exc})")

    snapshot_path = os.path.join(output_dir, "graph_snapshot.json")
    graph_meta: dict[str, Any] = {
        "neo4j_connected": False,
        "snapshot_path": snapshot_path,
        "use_neo4j_requested": use_neo4j,
    }
    snapshot: Optional[dict[str, Any]] = None
    driver = None
    graph_evidence: dict[str, Any] = {
        "reachability": [],
        "blast_radius": {},
        "dependency_chains": [],
    }

    if use_graph:
        _section("Phase 8   Graph Ingestion")
        graph_summary, snapshot = build_graph(
            input_path, report, services_path, project_dir,
            families=families,
            snapshot_path=snapshot_path,
        )
        graph_meta["neo4j_connected"] = graph_summary.get("neo4j_connected", False)
        print_graph_stats(graph_summary, neo4j=graph_meta["neo4j_connected"])

        _section("Phase 9   Graph Queries (reachability, blast radius)")
        if use_neo4j:
            driver = get_neo4j_driver()
        elif graph_meta["neo4j_connected"]:
            driver = get_neo4j_driver()
        svc_names = [s["name"] for s in snapshot.get("nodes", {}).get("services", [])]
        graph_evidence = run_all_queries(driver, snapshot, cve_ids, svc_names)
        print_stats_table([
            ("Reachability paths", len(graph_evidence["reachability"]), "green"),
            ("Dependency chains", len(graph_evidence["dependency_chains"]), "white"),
            ("Blast-radius keys", len(graph_evidence["blast_radius"]), "yellow"),
        ])
    else:
        print_stat_row("Graph", "phases 8–9 skipped (--no-graph)", style="dim")

    _merge_symbol_reachability(graph_evidence, symbol_findings, reachable_cves)

    _section("Phase 10  Risk Scoring (deterministic v1.0.0)")
    assessment = score_cves(trivy_vulns, graph_evidence)
    save_assessment(assessment, output_dir)
    print_risk_summary(assessment)

    _section("Phase 11  Template Explanations")
    explanations = explain_risk(assessment)
    save_explanations(explanations, output_dir)
    print_stat_row("CVE summaries", len(explanations.get("per_cve", [])), style="green")

    # Show reachable CVE table now that we have verdicts
    print_reachable_cves(symbol_findings, assessment)

    _section("Phase 12  Tabbed HTML Report")
    symbol_scan_path = args.symbol_scan or (
        symbol_path if os.path.exists(symbol_path) else None
    )
    upgrade_path = args.upgrade_sim or upgrade_sim_path
    renderer = _resolve_renderer(getattr(args, "report_version", "final"))
    report_path = renderer(
        assessment,
        explanations,
        graph_meta,
        output_dir,
        symbol_scan_path=symbol_scan_path,
        upgrade_sim_path=upgrade_path,
        project_dir=project_dir,
        target_repo=os.path.basename(project_dir) or "project",
        offline=args.offline,
    )

    if driver:
        driver.close()

    summary = assessment["summary"]
    sym_summary = symbol_findings.get("summary") or {}
    reachable_n = len(sym_summary.get("reachable_cves") or [])
    elapsed = time.perf_counter() - t0
    print_final_story(
        total_cves=total_vulns,
        reachable=reachable_n,
        noise_pct=float(sym_summary.get("noise_reduction_percent") or 0),
        recommendation=summary.get("overall_recommendation", "PROCEED"),
        risk_score=int(summary.get("overall_raw_risk") or 0),
        semgrep_hits=semgrep_total,
        elapsed_sec=elapsed,
    )

    _section("Pipeline Complete")
    print_outputs_table(output_dir, report_path)


def main() -> None:
    p = argparse.ArgumentParser(
        description="Pipeline A — Pre-Upgrade Risk Detection (fully integrated)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--input", default="enriched_trivy_output.json",
                   help="Trivy enriched JSON (live Trivy scan if missing)")
    p.add_argument("--project-dir", default=".", help="Target project to analyze")
    p.add_argument("--output-dir", default=None, help="Artifact output directory (default: cwd)")
    p.add_argument("--services", default="services.yaml", help="Service entry-points YAML")
    p.add_argument("--api-key", default=None, help="Gemini API key (overrides GOOGLE_API_KEY)")
    p.add_argument("--llm", default="ollama", choices=["gemini", "ollama"])
    p.add_argument("--ollama-model", default="qwen2.5:3b")
    p.add_argument("--include-low", action="store_true", help="Include LOW severity CVEs")
    p.add_argument("--skip-llm", action="store_true", help="Skip LLM rule generation (Phase 3)")
    p.add_argument("--no-graph", action="store_true", help="Skip graph phases 8–9")
    p.add_argument("--neo4j", action="store_true",
                   help="Connect to Neo4j at bolt://localhost:7687")
    p.add_argument("--offline", action="store_true",
                   help="Inline JS/CSS vendor assets in HTML report")
    p.add_argument("--report-version", default="final",
                   choices=["v1", "v2", "final"],
                   help="HTML report layout: final (default, tabbed) / v2 / v1")
    p.add_argument("--symbol-scan", default=None, help="Override symbol_scan.json for HTML report")
    p.add_argument("--upgrade-sim", default=None, help="Override upgrade_simulation.json for HTML")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--quiet", action="store_true",
                   help="Compact tables; suppress patch-fetcher logs and per-family chatter")
    p.add_argument("--present", action="store_true",
                   help="Presentation mode: same as --quiet --no-graph (colored tables, no graph phases)")
    p.add_argument("--plain", action="store_true",
                   help="Disable colors (plain terminal output)")
    args = p.parse_args()

    if args.present:
        args.quiet = True
        args.no_graph = True

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    main()
