"""Phase 3 — Parallel Semgrep Execution.

Runs Semgrep scans for every resolved family concurrently using a
ThreadPoolExecutor.  Each family gets its own subprocess so we
max-out CPU cores instead of waiting one-by-one.
"""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.utils import find_tool, tool_subprocess_env


def run_scans(resolved_rules, project_dir, max_workers=4):
    """Run Semgrep for all families in parallel.

    Returns { family_name: [match_dict, ...] }.
    """
    semgrep_exe = _find_semgrep()
    if not semgrep_exe:
        print("  ERROR: semgrep not found.  Install with: pip install semgrep")
        print("         If already installed, ensure Python Scripts is on PATH:")
        for d in _semgrep_search_paths():
            print(f"           {d}")
        return {}

    print("\n" + "=" * 60)
    print("PHASE 3: Parallel Semgrep Execution")
    print("=" * 60)

    print(f"  Scanning {len(resolved_rules)} families across {max_workers} threads...")
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {}
        for family, info in resolved_rules.items():
            print(f"  [>] Queued: {family} ({os.path.basename(info.get('rule_path','?'))})")
            future_map[pool.submit(_scan_one, semgrep_exe, family, info, project_dir)] = family

        for future in as_completed(future_map):
            family = future_map[future]
            try:
                matches = future.result()
                results[family] = matches
                if matches:
                    print(f"  ✓ {family}: {len(matches)} match(es)")
                else:
                    print(f"  ○ {family}: no matches")
            except Exception as e:
                print(f"  ✗ {family}: error — {e}")
                results[family] = []

    return results


# ── Private helpers ─────────────────────────────────────────────────

def _semgrep_search_paths():
    from src.utils import python_scripts_dirs

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return [
        os.path.join(base, "venv", "Scripts", "semgrep.exe"),
        os.path.join(base, "venv", "bin", "semgrep"),
        *python_scripts_dirs(),
    ]


def _find_semgrep():
    """Locate the semgrep binary."""
    return find_tool("semgrep", _semgrep_search_paths()[:2])


def _semgrep_cmd(semgrep_exe):
    """Build argv for Semgrep; fall back to ``python -m semgrep`` when needed."""
    if semgrep_exe:
        return [semgrep_exe]
    return [sys.executable, "-m", "semgrep"]


def _scan_one(semgrep_exe, family, rule_info, project_dir):
    """Run a single Semgrep scan and return a list of match dicts."""
    rule_path = rule_info.get("rule_path", "")
    if not rule_path or not os.path.exists(rule_path):
        return []

    cmd = _semgrep_cmd(semgrep_exe) + ["--config", rule_path, project_dir, "--json", "--quiet"]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        env=tool_subprocess_env(),
    )

    if proc.returncode == 2:
        # Rule parse error — not our fault, skip silently
        return []

    output = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return [
        {
            "file":       r.get("path", ""),
            "line_start": r.get("start", {}).get("line", 0),
            "line_end":   r.get("end", {}).get("line", 0),
            "snippet":    r.get("extra", {}).get("lines", "").strip(),
            "rule_id":    r.get("check_id", ""),
        }
        for r in output.get("results", [])
    ]
