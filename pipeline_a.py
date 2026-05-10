#!/usr/bin/env python3
"""Pipeline A — Vulnerability Verification via Semgrep.

Thin orchestrator that chains four phases:
  1. Ingestion & Normalization   (src/normalizer.py)
  2. Triple-Check Rule Strategy  (src/rule_resolver.py)
  3. Parallel Semgrep Execution  (src/executor.py)
  4. Reporting & Handover        (src/reporter.py)

Usage:
  python pipeline_a.py --input enriched_trivy_output.json --project-dir ./test
"""

import argparse
import asyncio
import os
import sys

from dotenv import load_dotenv

# Fix Windows console encoding for Unicode output
# Force immediate output (no buffering) + UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
else:
    # Git Bash / Unix: force line buffering so output isn't swallowed
    sys.stdout.reconfigure(line_buffering=True)

# Load .env from CWD and script directory
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# ── Pipeline modules ────────────────────────────────────────────────
from src.normalizer       import normalize
from src.registry_matcher import load_registry_index
from src.rule_resolver    import resolve_rules
from src.executor         import run_scans
from src.reporter         import build_report, save_report, print_summary
from src.utils            import detect_language


async def run_pipeline(args):
    """Execute the four pipeline phases in sequence."""
    project_dir = os.path.abspath(args.project_dir)
    output_dir  = os.path.abspath(args.output_dir) if args.output_dir else os.getcwd()
    input_path  = _resolve_input(args.input, project_dir)
    api_key     = args.api_key or os.environ.get("GOOGLE_API_KEY")
    rules_dir   = os.path.join(output_dir, "semgrep_rules")
    llm_backend = args.llm
    ollama_model = args.ollama_model

    print(f"[*] Project dir : {project_dir}")
    print(f"[*] Input file  : {input_path}")
    print(f"[*] Output dir  : {output_dir}")
    print(f"[*] LLM backend : {llm_backend}")
    if llm_backend == "gemini":
        print(f"[*] API key     : {'set' if api_key else 'NOT SET'}")
    else:
        print(f"[*] Ollama model: {ollama_model}")

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
    print("  Loading official Semgrep registry index...")
    registry_index = load_registry_index()
    print(f"  Registry loaded: {len(registry_index)} CWEs indexed.")

    resolved_rules = await resolve_rules(
        families, language, registry_index, api_key,
        rules_dir, max_concurrent=4,
        llm_backend=llm_backend, ollama_model=ollama_model,
    )
    print(f">>> Phase 2 complete: {len(resolved_rules)} rules resolved.")

    # ── Phase 3: Parallel Semgrep Execution ─────────────────────
    print("\n>>> Starting Phase 3: Parallel Semgrep Execution...")
    scan_results = run_scans(resolved_rules, project_dir, max_workers=4)
    print(f">>> Phase 3 complete: {sum(len(m) for m in scan_results.values())} total matches.")

    # ── Phase 4: Reporting & Handover ───────────────────────────
    print("\n>>> Starting Phase 4: Reporting & Handover...")
    report = build_report(families, resolved_rules, scan_results)
    save_report(report, output_dir)
    print_summary(report)
    print("\n>>> Pipeline A finished.")


# ── CLI ─────────────────────────────────────────────────────────────

def _resolve_input(raw, project_dir):
    """Turn a --input value into an absolute path."""
    if os.path.isabs(raw):
        return raw
    if os.path.exists(raw):
        return os.path.abspath(raw)
    return os.path.join(project_dir, raw)


def main():
    p = argparse.ArgumentParser(description="Pipeline A: Vulnerability Verification")
    p.add_argument("--input",       default="enriched_trivy_output.json")
    p.add_argument("--project-dir", default=".")
    p.add_argument("--output-dir",  default=None)
    p.add_argument("--api-key",      default=None)
    p.add_argument("--llm",          default="ollama", choices=["gemini", "ollama"],
                   help="LLM backend: 'gemini' or 'ollama' (default: ollama)")
    p.add_argument("--ollama-model", default="qwen2.5:7b",
                   help="Ollama model name (default: qwen2.5:7b)")
    p.add_argument("--include-low",  action="store_true")
    p.add_argument("--verbose",      action="store_true")
    args = p.parse_args()

    asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    main()