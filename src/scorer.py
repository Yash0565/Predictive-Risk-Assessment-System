"""Phase 7 — Deterministic risk scoring engine (v1.0.0).

Pure Python, versioned, no LLM involvement in upgrade decisions.
"""

import json
import os
from datetime import datetime, timezone

SCORER_VERSION = "1.0.0"
THRESHOLDS = {"BLOCK": 70, "REVIEW": 40}

_EPSS_PATH = os.path.join("data", "epss_snapshot.json")
_KEV_PATH = os.path.join("data", "kev_snapshot.json")


def score_cves(trivy_vulns, graph_evidence, epss_path=None, kev_path=None):
    """Score each unique CVE and return risk_assessment dict.

    Args:
        trivy_vulns: list of enriched Trivy vulnerability dicts
        graph_evidence: output from graph_queries.run_all_queries()
        epss_path: optional override for EPSS snapshot
        kev_path: optional override for KEV snapshot

    Returns:
        risk_assessment dict with per-CVE scores and summary
    """
    epss = _load_json(epss_path or _EPSS_PATH)
    kev_catalog = set(_load_json(kev_path or _KEV_PATH).get("catalog", []))

    reach_by_cve = _index_reachability(graph_evidence.get("reachability", []))
    blast_by_cve = graph_evidence.get("blast_radius", {})
    chains_by_cve = _index_chains(graph_evidence.get("dependency_chains", []))

    seen = set()
    cve_scores = []

    for v in trivy_vulns:
        cve_id = v.get("cve", "")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)

        cvss = float(v.get("cvss_score") or 0.0)
        severity_score = _clamp(round(cvss * 4), 0, 40)

        epss_data = epss.get(cve_id, {})
        epss_val = epss_data.get("epss", 0.0)
        in_kev = cve_id in kev_catalog
        exploit_score = _exploit_score(epss_val, in_kev)

        reach_rows = reach_by_cve.get(cve_id, [])
        reachability_score, reach_kind, reach_evidence = _reachability_score(
            reach_rows, v, blast_by_cve.get(cve_id, {}),
        )

        blast = blast_by_cve.get(cve_id, {})
        impacted = blast.get("impacted_services", 0)
        service_names = blast.get("service_names", [])
        blast_radius_score = min(15, 2 * impacted)

        raw_risk = (
            severity_score + exploit_score +
            reachability_score + blast_radius_score
        )
        recommendation = _recommendation(raw_risk)

        cve_scores.append({
            "cve_id": cve_id,
            "package": v.get("package", ""),
            "severity": v.get("severity", ""),
            "cvss_score": cvss,
            "cwe": v.get("cwe", []),
            "scores": {
                "severity_score": severity_score,
                "exploit_score": exploit_score,
                "reachability_score": reachability_score,
                "blast_radius_score": blast_radius_score,
                "raw_risk": raw_risk,
            },
            "recommendation": recommendation,
            "evidence": {
                "epss": epss_val,
                "epss_percentile": epss_data.get("percentile", 0.0),
                "in_kev": in_kev,
                "reachability_kind": reach_kind,
                "reachable_paths": reach_evidence,
                "impacted_services": impacted,
                "service_names": service_names,
                "dependency_chains": chains_by_cve.get(cve_id, []),
            },
        })

    cve_scores.sort(
        key=lambda x: (-x["scores"]["raw_risk"],
                       -x["scores"]["reachability_score"],
                       x["cve_id"]),
    )

    overall = cve_scores[0]["scores"]["raw_risk"] if cve_scores else 0
    overall_rec = _recommendation(overall)

    return {
        "scorer_version": SCORER_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "thresholds": THRESHOLDS,
        "summary": {
            "overall_recommendation": overall_rec,
            "overall_raw_risk": overall,
            "total_cves_scored": len(cve_scores),
            "block_count": sum(1 for c in cve_scores if c["recommendation"] == "BLOCK"),
            "review_count": sum(1 for c in cve_scores if c["recommendation"] == "REVIEW"),
        },
        "upgrade_order": [c["cve_id"] for c in cve_scores],
        "cves": cve_scores,
    }


def save_assessment(assessment, output_dir):
    """Write risk_assessment.json to output_dir."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "risk_assessment.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(assessment, f, indent=2)
    try:
        from src.pipeline_console import print_artifact_saved
        print_artifact_saved("Risk assessment saved", path)
    except Exception:
        print(f"  [+] Risk assessment saved to: {path}")
    return path


# ── Scoring helpers ──────────────────────────────────────────────────

def _clamp(val, lo, hi):
    return max(lo, min(hi, val))


def _exploit_score(epss, in_kev):
    score = 0
    if epss >= 0.5:
        score += 12
    elif epss >= 0.1:
        score += 8
    elif epss > 0:
        score += 4
    if in_kev:
        score += 8
    return min(20, score)


def _reachability_score(reach_rows, vuln, blast):
    """25 = direct code path; 10 = package/transitive; 0 = none."""
    if reach_rows:
        evidence = []
        for r in reach_rows:
            evidence.append({
                "service": r.get("service", ""),
                "vuln_fn": r.get("vuln_fn", ""),
                "file": r.get("file", ""),
                "line": r.get("line_start", 0),
                "hops": r.get("hops", 0),
            })
        return 25, "direct", evidence

    if blast.get("impacted_services", 0) > 0:
        return 10, "transitive", [{
            "note": "package or entry-level exposure without call-graph path",
            "services": blast.get("service_names", []),
        }]

    pkg = vuln.get("package", "")
    if pkg:
        return 10, "transitive", [{"note": f"package {pkg} affected, no code path"}]

    return 0, "none", []


def _recommendation(raw_risk):
    if raw_risk >= THRESHOLDS["BLOCK"]:
        return "BLOCK"
    if raw_risk >= THRESHOLDS["REVIEW"]:
        return "REVIEW"
    return "PROCEED"


def _load_json(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _index_reachability(rows):
    out = {}
    for r in rows:
        cid = r.get("cve_id", "")
        out.setdefault(cid, []).append(r)
    return out


def _index_chains(rows):
    out = {}
    for r in rows:
        cid = r.get("cve_id", "")
        out.setdefault(cid, []).append(r)
    return out
