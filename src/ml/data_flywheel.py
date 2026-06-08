"""Privacy-safe aggregate data flywheel for cross-scan learning.

Each pipeline run contributes anonymized outcome statistics (reachability rates,
upgrade feasibility, score distributions) to a local aggregate store. In a SaaS
deployment these aggregates would be privacy-preserving rolled-up metrics across
tenants, improving reachability priors, breakage prediction, and KEV models as
adoption grows.

This module is the portable, file-backed version of that network effect.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_STORE = _REPO_ROOT / "data" / "flywheel_aggregate.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_store(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {
            "version": "1.0",
            "updated_at": None,
            "total_scans": 0,
            "reachability": {"reachable": 0, "unreachable": 0, "rate": 0.0},
            "recommendations": {"BLOCK": 0, "REVIEW": 0, "PROCEED": 0},
            "upgrade_outcomes": {"feasible": 0, "blocked": 0, "safe": 0},
            "packages_seen": {},
            "cve_reachability": {},
        }
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return _load_store(Path("/nonexistent"))


def _save_store(path: Path, store: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    store["updated_at"] = _utc_now()
    with path.open("w", encoding="utf-8") as fh:
        json.dump(store, fh, indent=2, sort_keys=True)
        fh.write("\n")


def record_scan_outcome(
    assessment: dict[str, Any],
    symbol_findings: Optional[dict[str, Any]] = None,
    upgrade_sim: Optional[dict[str, Any]] = None,
    *,
    store_path: Optional[str] = None,
) -> dict[str, Any]:
    """Merge one scan's outcomes into the aggregate flywheel store.

    Returns the updated aggregate snapshot (no PII: only counts and rates).
    """
    path = Path(store_path) if store_path else _DEFAULT_STORE
    store = _load_store(path)
    store["total_scans"] = int(store.get("total_scans", 0)) + 1

    sym = symbol_findings or {}
    summary = sym.get("summary") or {}
    reach_n = len(summary.get("reachable_cves") or [])
    unreach_n = len(summary.get("unreachable_cves") or [])
    r = store.setdefault("reachability", {"reachable": 0, "unreachable": 0, "rate": 0.0})
    r["reachable"] = int(r.get("reachable", 0)) + reach_n
    r["unreachable"] = int(r.get("unreachable", 0)) + unreach_n
    total_r = r["reachable"] + r["unreachable"]
    r["rate"] = round(r["reachable"] / total_r, 4) if total_r else 0.0

    recs = store.setdefault("recommendations", {"BLOCK": 0, "REVIEW": 0, "PROCEED": 0})
    for cve in assessment.get("cves", []):
        rec = cve.get("recommendation", "PROCEED")
        if rec in recs:
            recs[rec] = int(recs.get(rec, 0)) + 1
        pkg = (cve.get("package") or "").lower()
        if pkg:
            pkgs = store.setdefault("packages_seen", {})
            pkgs[pkg] = int(pkgs.get(pkg, 0)) + 1

    if upgrade_sim:
        verdict = (upgrade_sim.get("summary") or {}).get("verdict", "")
        uo = store.setdefault("upgrade_outcomes", {"feasible": 0, "blocked": 0, "safe": 0})
        if "BLOCK" in verdict:
            uo["blocked"] = int(uo.get("blocked", 0)) + 1
        elif verdict == "SAFE":
            uo["safe"] = int(uo.get("safe", 0)) + 1
        else:
            uo["feasible"] = int(uo.get("feasible", 0)) + 1

    cve_reach = store.setdefault("cve_reachability", {})
    for cve_id in summary.get("reachable_cves") or []:
        cve_reach[cve_id] = int(cve_reach.get(cve_id, 0)) + 1

    _save_store(path, store)
    return store


def get_aggregate_stats(store_path: Optional[str] = None) -> dict[str, Any]:
    """Return the current flywheel aggregate (for dashboard / ML feature priors)."""
    path = Path(store_path) if store_path else _DEFAULT_STORE
    return _load_store(path)
