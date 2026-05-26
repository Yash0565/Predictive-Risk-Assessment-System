#!/usr/bin/env python3
"""Pipeline A — Pre-Upgrade Risk Detection (fully integrated).

Every phase produces real data from the target project (except ``--demo``,
which uses frozen Trivy + Semgrep overlay). Patch fetcher, symbol scanner,
and upgrade simulator are wired before graph scoring and the HTML report.

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
      --output-dir ./demo_out \\
      --offline

  python pipeline_a.py --demo \\
      --project-dir ./vulnerable-task-tracker \\
      --output-dir ./demo_out \\
      --offline
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
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
from src.html_reporter import render_html
from src.normalizer import normalize
from src.patch_fetcher import fetch_patches_batch
from src.registry_matcher import load_registry_index
from src.reporter import build_report, print_summary, save_report
from src.rule_resolver import resolve_rules
from src.scorer import save_assessment, score_cves
from src.symbol_rule_builder import enrich_rules_with_patch_sinks
from src.symbol_scanner import save_findings, scan_symbols
from src.upgrade_simulator import simulate_upgrade
from src.utils import detect_language

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("pipeline_a")


def _utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _section(title: str) -> None:
    bar = "═" * 70
    print(f"\n{bar}\n   {title}\n{bar}")


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
    *,
    demo_mode: bool,
) -> str:
    """Return path to enriched Trivy JSON; run live scan when not in demo and missing."""
    if demo_mode:
        return input_path
    if os.path.isfile(input_path):
        return input_path
    from src.tool_registry import run_trivy_on_repo

    print(f"   No Trivy JSON at {input_path}; running live scan on {project_dir}…")
    cves, mode = run_trivy_on_repo(project_dir)
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
    project_dir = os.path.abspath(args.project_dir)
    output_dir = os.path.abspath(args.output_dir) if args.output_dir else os.getcwd()
    os.makedirs(output_dir, exist_ok=True)

    demo_mode = args.demo
    skip_llm = args.skip_llm or demo_mode
    use_graph = not args.no_graph
    use_neo4j = args.neo4j and use_graph

    if demo_mode:
        input_path = os.path.join("data", "demo", "enriched_trivy_output.json")
    else:
        input_path = _resolve_input(args.input, project_dir)

    input_path = _ensure_trivy_input(
        input_path, project_dir, output_dir, demo_mode=demo_mode,
    )

    api_key = args.api_key or os.environ.get("GOOGLE_API_KEY")
    rules_dir = os.path.join(output_dir, "semgrep_rules")
    services_path = args.services or "services.yaml"

    print("\n  Pre-Upgrade Risk Detection — Pipeline A")
    print(f"  Started at:    {_utc_iso()}")
    print(f"  Project dir:   {project_dir}")
    print(f"  Trivy input:   {input_path}")
    print(f"  Output dir:    {output_dir}")
    print(f"  Demo mode:     {demo_mode}")
    print(f"  Graph phases:  {'enabled' if use_graph else 'skipped'}")
    print(f"  Neo4j:         {'connecting' if use_neo4j else 'in-memory only'}")
    print(f"  LLM backend:   {args.llm} ({'skipped' if skip_llm else 'enabled'})")

    _section("Phase 1   Ingestion & Normalization")
    families = normalize(input_path, include_low=args.include_low)
    if not families:
        log.warning("No vulnerability families to process. Exiting.")
        return
    print(f"   → {len(families)} CWE families identified")

    with open(input_path, "r", encoding="utf-8") as fh:
        trivy_vulns = json.load(fh)

    cve_to_pkg = _cve_id_to_package(trivy_vulns)
    cve_ids = sorted(cve_to_pkg.keys())
    print(f"   Trivy CVEs available: {len(cve_ids)}")

    _section("Phase 2   Patch Intelligence (preload for sink rules)")
    print(f"   Loading patches for {len(cve_ids)} CVEs (offline-cached)…")
    patches = fetch_patches_batch(
        [{"cve_id": c, "package": cve_to_pkg.get(c)} for c in cve_ids],
        max_workers=4,
    )
    patches_path = os.path.join(output_dir, "patches.json")
    with open(patches_path, "w", encoding="utf-8") as fh:
        json.dump(patches, fh, indent=2)
    n_with_symbols = sum(1 for p in patches.values() if p.get("vulnerable_symbols"))
    print(f"   → {len(patches)} patches loaded, {n_with_symbols} with vulnerable symbols")

    _section("Phase 3   Triple-Check Rule Resolution")
    language = detect_language(project_dir)
    print(f"   Detected language: {language}")
    registry_index = load_registry_index()
    print(f"   Registry loaded:   {len(registry_index)} CWEs indexed")
    resolved_rules = await resolve_rules(
        families, language, registry_index, api_key,
        rules_dir, max_concurrent=4,
        llm_backend=args.llm, ollama_model=args.ollama_model,
        skip_llm=skip_llm, demo_mode=demo_mode,
    )
    print(f"   → {len(resolved_rules)} rules resolved")

    resolved_rules = enrich_rules_with_patch_sinks(
        families, resolved_rules, patches, cve_to_pkg, rules_dir, language,
    )

    _section("Phase 4   Parallel Semgrep Execution")
    scan_results = run_scans(resolved_rules, project_dir, max_workers=4)
    if demo_mode:
        overlay_path = os.path.join("data", "demo", "semgrep_matches.json")
        if os.path.exists(overlay_path):
            with open(overlay_path, "r", encoding="utf-8") as fh:
                overlay = json.load(fh)
            for family, matches in overlay.items():
                if matches:
                    scan_results[family] = matches
            print("   [demo] Applied pre-computed Semgrep overlay")
    print(f"   → {sum(len(m) for m in scan_results.values())} Semgrep matches")

    _section("Phase 5   Reporting (Semgrep side)")
    report = build_report(families, resolved_rules, scan_results)
    save_report(report, output_dir)
    print_summary(report)

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
        print("   (no vulnerable symbols extracted; skipping)")
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
        print(f"   Files scanned:           {stats.get('files_scanned', 0)}")
        print(f"   Total findings:          {stats.get('total_findings', 0)}")
        print(f"   Reachable CVEs:          {len(summary.get('reachable_cves', []))}")
        print(f"   Unreachable (filtered):  {len(summary.get('unreachable_cves', []))}")
        print(f"   Noise reduction:         {summary.get('noise_reduction_percent', 0):.1f}%")

    reachable_cves = set(symbol_findings.get("summary", {}).get("reachable_cves", []))

    _section("Phase 7   Upgrade Simulation")
    upgrade_sim: Optional[dict[str, Any]] = None
    upgrade_sim_path: Optional[str] = None
    if not reachable_cves:
        print("   (no reachable CVEs; nothing to upgrade)")
    else:
        try:
            from src.project_deps import DependencyDiscoveryError, discover_dependency_pins

            try:
                current_reqs, dep_label = discover_dependency_pins(project_dir)
            except DependencyDiscoveryError as exc:
                print(f"   ({exc}; skipping)")
                current_reqs = None
            if current_reqs:
                print(f"   Parsed {len(current_reqs)} pinned packages from {dep_label}")
                targets = _pick_upgrade_targets(trivy_vulns, reachable_cves)
                if not targets:
                    print("   (no fixed_versions available for reachable CVEs)")
                else:
                    print(f"   Simulating {len(targets)} upgrade(s):")
                    for t in targets:
                        print(f"     - {t['package']} → {t['target_version']}")
                    upgrade_sim = simulate_upgrade(
                        current_requirements=current_reqs,
                        target_upgrades=targets,
                        cve_data_source={"vulnerabilities": trivy_vulns},
                    )
                    upgrade_sim_path = os.path.join(output_dir, "upgrade_simulation.json")
                    with open(upgrade_sim_path, "w", encoding="utf-8") as fh:
                        json.dump(upgrade_sim, fh, indent=2)
                    up_summary = upgrade_sim.get("summary", {})
                    print(f"   → Verdict: {up_summary.get('verdict', '?')}")
                    print(f"   → Conflicts detected: {len(upgrade_sim.get('conflicts', []))}")
                    print(
                        f"   → Cascade length: "
                        f"{len(upgrade_sim.get('cascade', {}).get('chain', []))}"
                    )
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
        print(f"   Packages:  {graph_summary['packages']}")
        print(f"   CVEs:      {graph_summary['cves']}")
        print(f"   Functions: {graph_summary['functions']}")
        print(f"   Services:  {graph_summary['services']}")
        print(f"   Edges:     {graph_summary['edges']}")
        print(
            f"   Neo4j:     "
            f"{'connected' if graph_meta['neo4j_connected'] else 'in-memory only'}"
        )

        _section("Phase 9   Graph Queries (reachability, blast radius)")
        if use_neo4j:
            driver = get_neo4j_driver()
        elif graph_meta["neo4j_connected"]:
            driver = get_neo4j_driver()
        svc_names = [s["name"] for s in snapshot.get("nodes", {}).get("services", [])]
        graph_evidence = run_all_queries(driver, snapshot, cve_ids, svc_names)
        print(f"   Reachability rows:  {len(graph_evidence['reachability'])}")
        print(f"   Dependency chains:  {len(graph_evidence['dependency_chains'])}")
        print(f"   Blast-radius keys:  {len(graph_evidence['blast_radius'])}")
    else:
        print("\n   (Graph phases 8–9 skipped: --no-graph)")

    _merge_symbol_reachability(graph_evidence, symbol_findings, reachable_cves)

    _section("Phase 10  Risk Scoring (deterministic v1.0.0)")
    assessment = score_cves(trivy_vulns, graph_evidence)
    save_assessment(assessment, output_dir)
    summary = assessment["summary"]
    print(f"   Overall recommendation: {summary['overall_recommendation']}")
    print(f"   Overall risk score:     {summary['overall_raw_risk']}/100")
    print(f"   CVEs analyzed:          {len(assessment.get('cves', []))}")

    _section("Phase 11  Template Explanations")
    explanations = explain_risk(assessment)
    save_explanations(explanations, output_dir)
    print(f"   Generated {len(explanations.get('per_cve', []))} per-CVE summaries")

    _section("Phase 12  Tabbed HTML Report")
    symbol_scan_path = args.symbol_scan or (
        symbol_path if os.path.exists(symbol_path) else None
    )
    upgrade_path = args.upgrade_sim or upgrade_sim_path
    render_html(
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

    _section("Pipeline Complete")
    print(f"   Outputs in {output_dir}:")
    for name in (
        "pipeline_a_report.json",
        "patches.json",
        "symbol_scan.json",
        "upgrade_simulation.json",
        "graph_snapshot.json",
        "risk_assessment.json",
        "explanations.json",
        "risk_report.html",
    ):
        p = os.path.join(output_dir, name)
        marker = "✓" if os.path.exists(p) else "·"
        print(f"     [{marker}] {name}")
    print(f"\n   Open the HTML report:\n     {os.path.join(output_dir, 'risk_report.html')}\n")


def main() -> None:
    p = argparse.ArgumentParser(
        description="Pipeline A — Pre-Upgrade Risk Detection (fully integrated)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--input", default="enriched_trivy_output.json",
                   help="Trivy enriched JSON (ignored when --demo; live scan if missing)")
    p.add_argument("--project-dir", default=".", help="Target project to analyze")
    p.add_argument("--output-dir", default=None, help="Artifact output directory (default: cwd)")
    p.add_argument("--services", default="services.yaml", help="Service entry-points YAML")
    p.add_argument("--api-key", default=None, help="Gemini API key (overrides GOOGLE_API_KEY)")
    p.add_argument("--llm", default="ollama", choices=["gemini", "ollama"])
    p.add_argument("--ollama-model", default="qwen2.5:3b")
    p.add_argument("--include-low", action="store_true", help="Include LOW severity CVEs")
    p.add_argument("--skip-llm", action="store_true", help="Skip LLM rule generation (Phase 2)")
    p.add_argument("--demo", action="store_true",
                   help="Demo mode: frozen Trivy input, skip LLM, overlay Semgrep matches")
    p.add_argument("--no-graph", action="store_true", help="Skip graph phases 8–9")
    p.add_argument("--neo4j", action="store_true",
                   help="Connect to Neo4j at bolt://localhost:7687")
    p.add_argument("--offline", action="store_true",
                   help="Inline JS/CSS vendor assets in HTML report")
    p.add_argument("--symbol-scan", default=None, help="Override symbol_scan.json for HTML report")
    p.add_argument("--upgrade-sim", default=None, help="Override upgrade_simulation.json for HTML")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    main()
