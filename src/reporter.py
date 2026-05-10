"""Phase 4 — Reporting & Handover.

Cleans up raw Semgrep results into ``pipeline_a_report.json``.
The key output is the ``ready_for_codeql`` flag on each family: if
Semgrep found *any* match, CodeQL reachability analysis is worth doing.
"""

import json
import os


def build_report(families, resolved_rules, scan_results):
    """Build the final report list — one entry per family."""
    report = []
    for name, cluster in families.items():
        rule_info = resolved_rules.get(name, {})
        matches = scan_results.get(name, [])

        report.append({
            "family":          name,
            "cwe_ids":         sorted(cluster.cwe_ids),
            "cves":            [v["cve"] for v in cluster.cves],
            "packages":        sorted(cluster.packages),
            "rule_source":     rule_info.get("source", "none"),
            "rule_path":       rule_info.get("rule_path", ""),
            "semgrep_matches": matches,
            "ready_for_codeql": len(matches) > 0,
        })

    # Sort: families with matches first, then alphabetically
    report.sort(key=lambda r: (not r["ready_for_codeql"], r["family"]))
    return report


def save_report(report, output_dir):
    """Write the report JSON to disk."""
    path = os.path.join(output_dir, "pipeline_a_report.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n  [+] Report saved to: {path}")
    return path


def print_summary(report):
    """Print a compact console summary table."""
    print("\n" + "=" * 60)
    print("PHASE 4: Summary Report")
    print("=" * 60)

    header = f"{'FAMILY':<30} {'SOURCE':<10} {'HITS':<6} {'CODEQL?'}"
    print(f"  {header}")
    print(f"  {'─' * len(header)}")

    for r in report:
        hits = len(r["semgrep_matches"])
        codeql = "YES" if r["ready_for_codeql"] else "—"
        print(f"  {r['family']:<30} {r['rule_source']:<10} {hits:<6} {codeql}")

    total_families = len(report)
    actionable = sum(1 for r in report if r["ready_for_codeql"])
    print(f"\n  {actionable}/{total_families} families ready for CodeQL analysis")
