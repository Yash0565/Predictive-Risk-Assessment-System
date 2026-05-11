"""Phase 1 — Ingestion & Normalization.

Turns raw Trivy output into a clean dict of CWE *families*, each
grouping every CVE that shares the same vulnerability pattern.

    enriched_trivy_output.json  →  { "sql_injection": FamilyCluster, ... }
"""

import json
from dataclasses import dataclass, field

from src.config import CWE_FAMILY_MAP


# ── Data structure ──────────────────────────────────────────────────

@dataclass
class FamilyCluster:
    """One vulnerability family (e.g. sql_injection) and all CVEs in it."""
    family:   str
    cwe_ids:  set   = field(default_factory=set)
    cves:     list  = field(default_factory=list)
    packages: set   = field(default_factory=set)


# ── Public API ──────────────────────────────────────────────────────

def normalize(input_path, include_low=False):
    """Main entry point for Phase 1.

    Returns { family_name: FamilyCluster }.
    """
    vulns = _load(input_path)
    filtered = _filter(vulns, include_low)
    families = _cluster(filtered)
    _print_stats(len(vulns), len(filtered), families)
    return families


# ── Private helpers ─────────────────────────────────────────────────

def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _filter(vulns, include_low):
    """Drop LOW / NEGLIGIBLE severity and entries with no CWE data."""
    drop = set() if include_low else {"LOW", "NEGLIGIBLE"}
    return [
        v for v in vulns
        if v.get("cwe") and v.get("severity", "").upper() not in drop
    ]


def _family_for_cwe(cwe_id):
    """Map a CWE to its family name, falling back to the CWE itself."""
    return CWE_FAMILY_MAP.get(cwe_id, cwe_id.lower().replace("-", "_"))


def _cluster(vulns):
    """Group filtered vulns into families by CWE."""
    families = {}
    for v in vulns:
        cwe_id = v["cwe"][0]  # primary CWE
        family_name = _family_for_cwe(cwe_id)

        if family_name not in families:
            families[family_name] = FamilyCluster(family=family_name)

        cluster = families[family_name]
        cluster.cwe_ids.add(cwe_id)
        cluster.cves.append(v)
        cluster.packages.add(v.get("package", "unknown"))

    return families


def _print_stats(total, filtered, families):
    unique_cwes = set()
    for fc in families.values():
        unique_cwes.update(fc.cwe_ids)

    print("\n" + "=" * 60)
    print("PHASE 1: Ingestion & Normalization")
    print("=" * 60)
    print(f"  Total vulnerabilities loaded   : {total}")
    print(f"  After severity filter          : {filtered}")
    print(f"  Unique CWEs                    : {len(unique_cwes)}")
    print(f"  Vulnerability families         : {len(families)}")
    for name, fc in families.items():
        print(f"    • {name:30s}  {len(fc.cves)} CVEs, CWEs: {sorted(fc.cwe_ids)}")
