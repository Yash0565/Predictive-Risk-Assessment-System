"""
scan_from_report.py
────────────────────
Standalone tool: load an existing impact_report.json and re-scan
a project directory without re-downloading or re-diffing packages.

Usage:
    python scan_from_report.py <impact_report.json> <project_dir>

Example:
    python scan_from_report.py test_environment/impact_report.json ./my_project
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from smart_scanner import scan_project, print_findings, findings_to_report_dicts


# ──────────────────────────────────────────────
# Load APIChange from JSON (no impact_analyzer import needed)
# ──────────────────────────────────────────────

@dataclass
class APIChange:
    change_type: str
    symbol: str
    module: str
    old_signature: Optional[str] = None
    new_signature: Optional[str] = None
    detail: str = ""
    severity: str = "HIGH"


def load_changes_from_report(report_path: str) -> tuple[str, str, str, list[APIChange]]:
    with open(report_path, "r") as f:
        data = json.load(f)

    package = data.get("package", "unknown")
    old_ver = data.get("old_version", "?")
    new_ver = data.get("new_version", "?")

    changes = []
    for c in data.get("api_changes", []):
        changes.append(APIChange(
            change_type=c.get("change_type", ""),
            symbol=c.get("symbol", ""),
            module=c.get("module", ""),
            old_signature=c.get("old_signature"),
            new_signature=c.get("new_signature"),
            detail=c.get("detail", ""),
            severity=c.get("severity", "MEDIUM"),
        ))

    return package, old_ver, new_ver, changes


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    report_path = sys.argv[1]
    project_dir = sys.argv[2]

    if not Path(report_path).exists():
        print(f"✗ Report not found: {report_path}")
        sys.exit(1)

    if not Path(project_dir).exists():
        print(f"✗ Project directory not found: {project_dir}")
        sys.exit(1)

    package, old_ver, new_ver, changes = load_changes_from_report(report_path)

    print(f"\n{'='*60}")
    print(f"  AST IMPACT SCAN")
    print(f"  Package : {package}  ({old_ver} → {new_ver})")
    print(f"  Project : {project_dir}")
    print(f"  Changes : {len(changes)} API changes loaded from report")
    print(f"{'='*60}\n")

    # Only scan for HIGH and MEDIUM
    breaking = [c for c in changes if c.severity in ("HIGH", "MEDIUM")]
    print(f"  Scanning for {len(breaking)} breaking change(s)...\n")

    findings = scan_project(project_dir, breaking)
    print_findings(findings)

    # Summary
    print(f"{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  Total findings    : {len(findings)}")

    by_sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    print(f"  High severity     : {by_sev['HIGH']}")
    print(f"  Medium severity   : {by_sev['MEDIUM']}")
    impacted = sorted(set(f.file for f in findings))
    print(f"  Impacted files    : {len(impacted)}")

    if impacted:
        print(f"\n  Files that need attention:")
        for f in impacted:
            print(f"    • {f}")

    if not findings:
        risk = "🟢 LOW — no usages of changed APIs detected"
    elif by_sev["HIGH"] > 0:
        risk = "🔴 HIGH — your code directly uses removed/broken APIs"
    else:
        risk = "🟡 MEDIUM — your code uses APIs with signature changes"

    print(f"\n  Upgrade Risk: {risk}")
    print(f"{'='*60}\n")

    # Save updated report
    out_path = Path(report_path).parent / "scan_results.json"
    result_data = {
        "package": package,
        "old_version": old_ver,
        "new_version": new_ver,
        "findings": findings_to_report_dicts(findings),
        "impacted_files": impacted,
        "summary": {
            "total_findings": len(findings),
            "high": by_sev["HIGH"],
            "medium": by_sev["MEDIUM"],
        }
    }
    with open(out_path, "w") as f:
        json.dump(result_data, f, indent=2)
    print(f"  Scan results saved → {out_path}")


if __name__ == "__main__":
    main()