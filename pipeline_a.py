#!/usr/bin/env python3
"""Pipeline A — Vulnerability Verification via Semgrep + Risk Assessment.

Phases 1–4 (original):
  1. Ingestion & Normalization   (src/normalizer.py)
  2. Triple-Check Rule Strategy  (src/rule_resolver.py)
  3. Parallel Semgrep Execution  (src/executor.py)
  4. Reporting & Handover        (src/reporter.py)

Phases 5–9 (extended):
  5. Graph Ingestion             (src/graph_builder.py)
  6. Graph Queries               (src/graph_queries.py)
  7. Risk Scoring                (src/scorer.py)
  8. Template Explanations       (src/explainer.py)
  9. HTML Report                 (src/html_reporter.py)

Usage:
  python pipeline_a.py --demo --project-dir ./test --services services.yaml
"""

import argparse
import asyncio
import json
import os
import sys

from dotenv import load_dotenv

# Fix Windows console encoding for Unicode output
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
else:
    sys.stdout.reconfigure(line_buffering=True)

load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from src.normalizer       import normalize
from src.registry_matcher import load_registry_index
from src.rule_resolver    import resolve_rules
from src.executor         import run_scans
from src.reporter         import build_report, save_report, print_summary
from src.utils            import detect_language
from src.graph_builder    import build_graph
from src.graph_queries    import get_neo4j_driver, run_all_queries
from src.scorer           import score_cves, save_assessment
from src.explainer        import explain_risk, save_explanations
from src.html_reporter    import render_html


async def run_pipeline(args):
    """Execute pipeline phases in sequence."""
    project_dir = os.path.abspath(args.project_dir)
    output_dir  = os.path.abspath(args.output_dir) if args.output_dir else os.getcwd()
    os.makedirs(output_dir, exist_ok=True)

    demo_mode = args.demo
    skip_llm  = args.skip_llm or demo_mode
    no_graph  = args.no_graph

    if demo_mode:
        input_path = os.path.join("data", "demo", "enriched_trivy_output.json")
    else:
        input_path = _resolve_input(args.input, project_dir)

    api_key      = args.api_key or os.environ.get("GOOGLE_API_KEY")
    rules_dir    = os.path.join(output_dir, "semgrep_rules")
    services_path = args.services or "services.yaml"
    llm_backend  = args.llm
    ollama_model = args.ollama_model

    print(f"[*] Project dir : {project_dir}")
    print(f"[*] Input file  : {input_path}")
    print(f"[*] Output dir  : {output_dir}")
    print(f"[*] Demo mode   : {demo_mode}")
    print(f"[*] Skip LLM    : {skip_llm}")
    print(f"[*] LLM backend : {llm_backend}")

    # ── Phase 1: Ingestion & Normalization ──────────────────────
    print("\n>>> Starting Phase 1: Ingestion & Normalization...")
    families = normalize(input_path, include_low=args.include_low)
    if not families:
        print("No vulnerability families to process. Exiting.")
        return
    print(f">>> Phase 1 complete: {len(families)} families identified.")

    # ── Phase 2: Triple-Check Rule Resolution ───────────────────
    print("\n>>> Starting Phase 2: Triple-Check Rule Resolution...")
    language = detect_language(project_dir)
    print(f"  Detected project language: {language}")
    registry_index = load_registry_index()
    print(f"  Registry loaded: {len(registry_index)} CWEs indexed.")

    resolved_rules = await resolve_rules(
        families, language, registry_index, api_key,
        rules_dir, max_concurrent=4,
        llm_backend=llm_backend, ollama_model=ollama_model,
        skip_llm=skip_llm, demo_mode=demo_mode,
    )
    print(f">>> Phase 2 complete: {len(resolved_rules)} rules resolved.")

    # ── Phase 3: Parallel Semgrep Execution ─────────────────────
    print("\n>>> Starting Phase 3: Parallel Semgrep Execution...")
    scan_results = run_scans(resolved_rules, project_dir, max_workers=4)

    if demo_mode:
        overlay_path = os.path.join("data", "demo", "semgrep_matches.json")
        if os.path.exists(overlay_path):
            with open(overlay_path, "r", encoding="utf-8") as f:
                overlay = json.load(f)
            for family, matches in overlay.items():
                if matches:
                    scan_results[family] = matches
            print(f"  [demo] Applied pre-computed Semgrep overlay ({overlay_path})")

    print(f">>> Phase 3 complete: {sum(len(m) for m in scan_results.values())} total matches.")

    # ── Phase 4: Reporting & Handover ───────────────────────────
    print("\n>>> Starting Phase 4: Reporting & Handover...")
    report = build_report(families, resolved_rules, scan_results)
    save_report(report, output_dir)
    print_summary(report)

    # Load raw Trivy for scoring
    with open(input_path, "r", encoding="utf-8") as f:
        trivy_vulns = json.load(f)

    snapshot_path = os.path.join(output_dir, "graph_snapshot.json")
    graph_meta = {"neo4j_connected": False, "snapshot_path": snapshot_path}
    snapshot = None
    driver = None

    if not no_graph:
        # ── Phase 5: Graph Ingestion ──────────────────────────────
        print("\n>>> Starting Phase 5: Graph Ingestion...")
        graph_summary, snapshot = build_graph(
            input_path, report, services_path, project_dir,
            families=families,
            snapshot_path=snapshot_path,
        )
        graph_meta["neo4j_connected"] = graph_summary.get("neo4j_connected", False)
        print(f">>> Phase 5 complete: {graph_summary['packages']} packages, "
              f"{graph_summary['cves']} CVEs, {graph_summary['functions']} functions, "
              f"{graph_summary['services']} services, {graph_summary['edges']} edges.")

        # ── Phase 6: Graph Queries ────────────────────────────────
        print("\n>>> Starting Phase 6: Graph Queries...")
        driver = get_neo4j_driver() if graph_meta["neo4j_connected"] else None
        cve_ids = list({v.get("cve") for v in trivy_vulns if v.get("cve")})
        svc_names = [s["name"] for s in snapshot.get("nodes", {}).get("services", [])]
        graph_evidence = run_all_queries(driver, snapshot, cve_ids, svc_names)
        print(f"  Reachability rows : {len(graph_evidence['reachability'])}")
        print(f"  Dependency chains : {len(graph_evidence['dependency_chains'])}")
        print(">>> Phase 6 complete.")
    else:
        print("\n>>> Phases 5–6 skipped (--no-graph).")
        graph_evidence = {"reachability": [], "blast_radius": {}, "dependency_chains": []}

    # ── Phase 7: Risk Scoring ───────────────────────────────────
    print("\n>>> Starting Phase 7: Risk Scoring...")
    assessment = score_cves(trivy_vulns, graph_evidence)
    save_assessment(assessment, output_dir)
    print(f">>> Phase 7 complete: {assessment['summary']['overall_recommendation']} "
          f"({assessment['summary']['overall_raw_risk']}/100)")

    # ── Phase 8: Template Explanations ──────────────────────────
    print("\n>>> Starting Phase 8: Template Explanations...")
    explanations = explain_risk(assessment)
    save_explanations(explanations, output_dir)
    print(">>> Phase 8 complete.")

    # ── Phase 9: HTML Report ────────────────────────────────────
    print("\n>>> Starting Phase 9: HTML Report...")
    symbol_scan_path = getattr(args, "symbol_scan", None)
    if not symbol_scan_path:
        for candidate in (
            os.path.join(output_dir, "symbol_scan.json"),
            os.path.join("examples", "symbol_scan_output.json"),
        ):
            if os.path.isfile(candidate):
                symbol_scan_path = candidate
                break
    upgrade_sim_path = getattr(args, "upgrade_sim", None)
    render_html(
        assessment,
        explanations,
        graph_meta,
        output_dir,
        symbol_scan_path=symbol_scan_path,
        upgrade_sim_path=upgrade_sim_path,
        project_dir=project_dir,
        target_repo=os.path.basename(project_dir) or "project",
        offline=getattr(args, "offline", False),
    )
    print(">>> Phase 9 complete.")

    if driver:
        driver.close()

    print("\n>>> Pipeline A finished.")
    print(f"    JSON report : {os.path.join(output_dir, 'pipeline_a_report.json')}")
    print(f"    Risk scores : {os.path.join(output_dir, 'risk_assessment.json')}")
    print(f"    HTML report : {os.path.join(output_dir, 'risk_report.html')}")


def _resolve_input(raw, project_dir):
    """Turn a --input value into an absolute path."""
    if os.path.isabs(raw):
        return raw
    if os.path.exists(raw):
        return os.path.abspath(raw)
    return os.path.join(project_dir, raw)


def main():
    p = argparse.ArgumentParser(description="Pipeline A: Vulnerability Verification + Risk Assessment")
    p.add_argument("--input",       default="enriched_trivy_output.json")
    p.add_argument("--project-dir", default=".")
    p.add_argument("--output-dir",  default=None)
    p.add_argument("--services",    default="services.yaml",
                   help="Path to services.yaml entry points")
    p.add_argument("--api-key",      default=None)
    p.add_argument("--llm",          default="ollama", choices=["gemini", "ollama"])
    p.add_argument("--ollama-model", default="qwen2.5:7b")
    p.add_argument("--include-low",  action="store_true")
    p.add_argument("--skip-llm",     action="store_true",
                   help="Skip LLM rule generation (registry/cache/demo only)")
    p.add_argument("--demo",         action="store_true",
                   help="Demo mode: frozen Trivy input, demo rules, skip LLM, overlay matches")
    p.add_argument("--no-graph",     action="store_true",
                   help="Skip Neo4j graph phases 5–6")
    p.add_argument("--offline",      action="store_true",
                   help="Self-contained HTML report (inline vendor JS/CSS)")
    p.add_argument("--symbol-scan",  default=None,
                   help="Path to symbol_scan JSON for reachability in HTML report")
    p.add_argument("--upgrade-sim",  default=None,
                   help="Path to upgrade_simulation JSON for HTML report")
    p.add_argument("--verbose",      action="store_true")
    args = p.parse_args()

    asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    main()
