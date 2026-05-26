"""Phase 3 — Parallel Semgrep Execution.

Runs Semgrep scans for every resolved family concurrently using a
ThreadPoolExecutor.  Each family gets its own subprocess so we
max-out CPU cores instead of waiting one-by-one.
"""

import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.semgrep_tools import (
    check_semgrep_available,
    semgrep_cmd,
    validate_rule_file,
)
from src.utils import tool_subprocess_env


def run_scans(resolved_rules, project_dir, max_workers=4):
    """Run Semgrep for all families in parallel.

    Returns { family_name: [match_dict, ...] }.
    """
    ok, detail, semgrep_exe = check_semgrep_available()
    if not ok:
        print(f"  ERROR: {detail}")
        return {}

    print("\n" + "=" * 60)
    print("PHASE 3: Parallel Semgrep Execution")
    print("=" * 60)
    print(f"  Semgrep: {detail}")

    scannable = {}
    skipped = 0
    for family, info in resolved_rules.items():
        rule_path = info.get("rule_path", "")
        if not rule_path:
            skipped += 1
            continue
        valid, err = validate_rule_file(rule_path, semgrep_exe=semgrep_exe)
        if not valid:
            print(f"  [!] Skipping {family}: invalid rule — {err}")
            skipped += 1
            continue
        scannable[family] = info

    if skipped:
        print(f"  {skipped} famil{'y' if skipped == 1 else 'ies'} skipped (missing/invalid rules)")

    if not scannable:
        print("  No valid Semgrep rules to scan.")
        return {}

    print(f"  Scanning {len(scannable)} families across {max_workers} threads...")
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {}
        for family, info in scannable.items():
            print(f"  [>] Queued: {family} ({os.path.basename(info.get('rule_path', '?'))})")
            future_map[pool.submit(_scan_one, semgrep_exe, family, info, project_dir)] = family

        for future in as_completed(future_map):
            family = future_map[future]
            try:
                matches, warning = future.result()
                results[family] = matches
                if warning:
                    print(f"  ✗ {family}: {warning}")
                elif matches:
                    print(f"  ✓ {family}: {len(matches)} match(es)")
                else:
                    print(f"  ○ {family}: no matches")
            except Exception as e:
                print(f"  ✗ {family}: error — {e}")
                results[family] = []

    return results


def _scan_one(semgrep_exe, family, rule_info, project_dir):
    """Run a single Semgrep scan and return (matches, warning_or_none)."""
    rule_path = rule_info.get("rule_path", "")

    cmd = semgrep_cmd(semgrep_exe) + ["--config", rule_path, project_dir, "--json", "--quiet"]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        env=tool_subprocess_env(),
    )

    if proc.returncode == 2:
        detail = (proc.stderr or proc.stdout or "").strip()
        first_lines = "\n".join(detail.splitlines()[:3])
        return [], f"rule/scan error — {first_lines or 'semgrep exit 2'}"

    if proc.returncode not in (0, 1):
        detail = (proc.stderr or proc.stdout or "").strip()
        return [], f"semgrep failed (exit {proc.returncode}): {detail[:200]}"

    output = json.loads(proc.stdout) if proc.stdout.strip() else {}
    matches = [
        {
            "file":       r.get("path", ""),
            "line_start": r.get("start", {}).get("line", 0),
            "line_end":   r.get("end", {}).get("line", 0),
            "snippet":    r.get("extra", {}).get("lines", "").strip(),
            "rule_id":    r.get("check_id", ""),
        }
        for r in output.get("results", [])
    ]
    return matches, None
