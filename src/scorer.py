"""Phase 10 - Probabilistic risk scoring engine (v2.0.0).

Replaces the previous additive point heuristic (summing fixed point values)
with a mathematically motivated expected-loss model:

    Risk = Exploitability x Impact x Reachability_eff x Asset x Blast

where each factor is normalized to a principled range and every parameter lives
in the versioned, externally-editable model file ``data/scoring_model.json``
(no magic numbers in code).

Factor definitions
------------------
- Exploitability E in [0,1]: noisy-OR fusion of independent exploit signals
  E = 1 - (1-EPSS)(1-KEV*p_kev)(1-exploit_evidence). EPSS is already a calibrated
  probability; KEV is observed-in-the-wild evidence; exploit_evidence is reserved
  for public-PoC signals.
- Impact I in [0,1]: CVSS environmental impact from parsed CIA components, else
  cvss_base/10.
- Reachability R in [0,1]: confirmed call-graph path decays with hop distance,
  R = c_res * exp(-lambda*(hops-1)) * (1+taint); no path -> low prior.
- Reachability_eff: confidence-blended, Phi*R + (1-Phi)*prior (absence of a path
  is not proof of unreachability).
- Asset A: criticality multiplier (default 1.0).
- Blast B in [1,1+beta]: bounded amplifier from impacted-service saturation
  (graph centrality replaces this in a later phase).
- Confidence Phi in [0,1]: geometric mean of evidence confidences, reported with
  every score so a low-confidence BLOCK is distinguishable from a high-confidence one.

Output keeps the historical schema (``scores``/``evidence`` blocks) for backward
compatibility and adds a ``probabilistic`` block with the full factor trace.
"""

from __future__ import annotations

import json
import math
import os
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Optional

SCORER_VERSION = "2.0.0"

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_EPSS_PATH = os.path.join(_DATA_DIR, "epss_snapshot.json")
_KEV_PATH = os.path.join(_DATA_DIR, "kev_snapshot.json")
_MODEL_PATH = os.path.join(_DATA_DIR, "scoring_model.json")

# Fallback model used only if the on-disk model file is missing/corrupt, so the
# engine never silently reverts to undocumented constants.
_DEFAULT_MODEL: dict[str, Any] = {
    "model_version": SCORER_VERSION,
    "methodology": "expected-loss",
    "exploitability": {
        "kev_probability": 0.99,
        "exploit_evidence_default": 0.0,
        "use_ml_model": True,
        "epss_floor": 0.0,
        "cvss_prior_ceiling": 0.85,
        "av_weight": {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2},
        "pr_weight": {"none": 0.85, "low": 0.62, "high": 0.27},
        "ui_weight": {"none": 0.85, "required": 0.62},
    },
    "impact": {
        "cia_magnitude": {"high": 1.0, "low": 0.5, "none": 0.0},
        "weights": {"confidentiality": 0.3334, "integrity": 0.3333, "availability": 0.3333},
    },
    "reachability": {
        "hop_decay_lambda": 0.5,
        "max_call_hops": 10,
        "resolution_confidence_numeric": {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3},
        "taint_boost": 0.0,
        "transitive_estimate": 0.15,
        "no_path_prior": 0.05,
        "default_path_confidence": "HIGH",
    },
    "blast": {"beta": 0.5, "saturation_rate": 0.5},
    "asset": {"default_criticality": 1.0, "min": 0.5, "max": 2.0},
    "confidence": {
        "weight_has_epss": 1.0,
        "weight_missing_epss": 0.7,
        "weight_has_path": 1.0,
        "weight_no_path": 0.6,
    },
    "thresholds": {
        "BLOCK": 70,
        "REVIEW": 40,
        "provisional": True,
        # A confirmed-reachable CVE at or above this CVSS is floored to REVIEW
        # even when EPSS is missing/zero, so a reachable medium-severity finding
        # is never silently classed PROCEED purely for lack of an EPSS score.
        "reachable_review_min_cvss": 4.0,
    },
}


@lru_cache(maxsize=4)
def load_model(model_path: str | None = None) -> dict[str, Any]:
    """Load the versioned scoring model (cached). Falls back to the embedded default."""
    path = model_path or _MODEL_PATH
    try:
        with open(path, "r", encoding="utf-8") as fh:
            model = json.load(fh)
        if isinstance(model, dict) and "exploitability" in model:
            return model
    except (OSError, json.JSONDecodeError):
        pass
    return _DEFAULT_MODEL


def score_cves(trivy_vulns, graph_evidence, epss_path=None, kev_path=None, model_path=None):
    """Score each unique CVE with the probabilistic model.

    Args:
        trivy_vulns: list of enriched Trivy vulnerability dicts.
        graph_evidence: output from graph_queries.run_all_queries().
        epss_path / kev_path: optional snapshot overrides.
        model_path: optional scoring-model override.

    Returns:
        risk_assessment dict (historical schema + ``probabilistic`` block).
    """
    model = load_model(model_path)
    thresholds = {
        "BLOCK": model["thresholds"]["BLOCK"],
        "REVIEW": model["thresholds"]["REVIEW"],
    }

    epss = _load_json(epss_path or _EPSS_PATH)
    kev_catalog = set(_load_json(kev_path or _KEV_PATH).get("catalog", []))

    reach_by_cve = _index_reachability(graph_evidence.get("reachability", []))
    blast_by_cve = graph_evidence.get("blast_radius", {})
    chains_by_cve = _index_chains(graph_evidence.get("dependency_chains", []))

    seen: set[str] = set()
    cve_scores: list[dict[str, Any]] = []

    for v in trivy_vulns:
        cve_id = v.get("cve", "") or v.get("cve_id", "")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)

        epss_data = epss.get(cve_id, {})
        epss_val = float(epss_data.get("epss", 0.0) or 0.0)
        in_kev = cve_id in kev_catalog
        reach_rows = reach_by_cve.get(cve_id, [])
        blast = blast_by_cve.get(cve_id, {})

        factors = _compute_factors(v, epss_val, in_kev, reach_rows, blast, model, epss_data)
        raw_risk = factors["score_0_100"]
        recommendation = _recommendation(raw_risk, thresholds)

        cvss = float(v.get("cvss_score") or 0.0)
        # Reachability floor: a confirmed-reachable, medium+ severity CVE warrants
        # at least human REVIEW even if the expected-loss score is low (e.g. EPSS
        # absent). Reachability is this pipeline's core triage signal; it must not
        # be discarded just because no EPSS probability is published. Never
        # downgrades a BLOCK.
        reach_min = float(model["thresholds"].get("reachable_review_min_cvss", 4.0))
        if (
            recommendation == "PROCEED"
            and reach_rows
            and cvss >= reach_min
        ):
            recommendation = "REVIEW"
        # Backward-compatible "points" (derived from factors) for legacy consumers.
        legacy_scores = {
            "severity_score": round(factors["impact"] * 40),
            "exploit_score": round(factors["exploitability"] * 20),
            "reachability_score": round(factors["reachability_eff"] * 25),
            "blast_radius_score": round(factors["blast_normalized"] * 15),
            "raw_risk": raw_risk,
        }

        cve_scores.append({
            "cve_id": cve_id,
            "package": v.get("package", ""),
            "severity": v.get("severity", ""),
            "cvss_score": cvss,
            "cwe": v.get("cwe", []),
            "scores": legacy_scores,
            "recommendation": recommendation,
            "confidence": round(factors["confidence"], 3),
            "probabilistic": factors,
            "evidence": {
                "epss": epss_val,
                "epss_percentile": epss_data.get("percentile", 0.0),
                "in_kev": in_kev,
                "reachability_kind": factors["reachability_kind"],
                "reachable_paths": factors["reachable_paths"],
                "impacted_services": blast.get("impacted_services", 0),
                "service_names": blast.get("service_names", []),
                "dependency_chains": chains_by_cve.get(cve_id, []),
            },
        })

    cve_scores.sort(
        key=lambda x: (-x["scores"]["raw_risk"],
                       -x["scores"]["reachability_score"],
                       x["cve_id"]),
    )

    overall = cve_scores[0]["scores"]["raw_risk"] if cve_scores else 0
    overall_rec = _recommendation(overall, thresholds)
    mean_conf = (
        round(sum(c["confidence"] for c in cve_scores) / len(cve_scores), 3)
        if cve_scores else 0.0
    )

    return {
        "scorer_version": SCORER_VERSION,
        "model_version": model.get("model_version", SCORER_VERSION),
        "methodology": model.get("methodology", "expected-loss"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "thresholds": thresholds,
        "summary": {
            "overall_recommendation": overall_rec,
            "overall_raw_risk": overall,
            "overall_confidence": mean_conf,
            "total_cves_scored": len(cve_scores),
            "block_count": sum(1 for c in cve_scores if c["recommendation"] == "BLOCK"),
            "review_count": sum(1 for c in cve_scores if c["recommendation"] == "REVIEW"),
        },
        "upgrade_order": [c["cve_id"] for c in cve_scores],
        "cves": cve_scores,
    }


def score_single(vuln, epss_val=0.0, in_kev=False, reach_rows=None, blast=None,
                 model_path=None):
    """Score a single CVE with the production model (used by tooling/benchmarks).

    Returns the full factor trace plus the calibrated score and recommendation,
    so callers exercise exactly the same math as the batch pipeline.
    """
    model = load_model(model_path)
    factors = _compute_factors(vuln, float(epss_val), bool(in_kev),
                               reach_rows or [], blast or {}, model)
    thresholds = {
        "BLOCK": model["thresholds"]["BLOCK"],
        "REVIEW": model["thresholds"]["REVIEW"],
    }
    score = factors["score_0_100"]
    return {
        "factors": factors,
        "raw_risk": score,
        "risk_unit": factors["risk_unit"],
        "recommendation": _recommendation(score, thresholds),
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


# -- Probabilistic factor computation --------------------------------------

def _compute_factors(vuln, epss_val, in_kev, reach_rows, blast, model,
                     epss_data: Optional[dict] = None) -> dict[str, Any]:
    """Compute all risk factors and the calibrated 0-100 score for one CVE."""
    epss_data = epss_data or {"epss": epss_val}
    expl = _exploitability(epss_val, in_kev, vuln, model, epss_data)
    impact = _impact(vuln, model)
    reach, reach_kind, reach_conf, reach_evidence = _reachability(reach_rows, blast, vuln, model)
    asset = float(model["asset"]["default_criticality"])
    blast_factor, blast_norm = _blast(blast, model)

    phi = _confidence(epss_val, reach_rows, reach_conf, model)
    prior = float(model["reachability"]["no_path_prior"])
    reach_eff = phi * reach + (1.0 - phi) * prior

    # Expected loss in [0,1] then amplified (and clamped) by asset/blast modifiers.
    base = expl * impact * reach_eff
    risk_unit = _clamp(base * asset * blast_factor, 0.0, 1.0)
    score = round(100 * risk_unit)

    return {
        "exploitability": round(expl, 4),
        "impact": round(impact, 4),
        "reachability": round(reach, 4),
        "reachability_eff": round(reach_eff, 4),
        "reachability_kind": reach_kind,
        "reachable_paths": reach_evidence,
        "asset_criticality": round(asset, 4),
        "blast_factor": round(blast_factor, 4),
        "blast_normalized": round(blast_norm, 4),
        "confidence": round(phi, 4),
        "expected_loss": round(base, 4),
        "risk_unit": round(risk_unit, 4),
        "score_0_100": score,
        "formula": "100 * clamp(E * I * (Phi*R + (1-Phi)*prior) * A * B, 0, 1)",
        "dominant_factor": _dominant_factor(expl, impact, reach_eff),
    }


def _ml_exploit_probability(vuln, epss_val: float, epss_data: dict, model: dict) -> float:
    """Optional ML exploit prediction (trained model, noisy-OR input)."""
    if not model.get("exploitability", {}).get("use_ml_model", True):
        return 0.0
    try:
        from src.ml.model_store import predict_exploit_probability
        cve_id = vuln.get("cve", "") or vuln.get("cve_id", "")
        cvss = float(vuln.get("cvss_score") or 0.0)
        cwe = vuln.get("cwe") or []
        return predict_exploit_probability(
            cve_id,
            cvss,
            float(epss_val),
            float(epss_data.get("percentile", 0.0) or 0.0),
            len(cwe) if isinstance(cwe, list) else 0,
        )
    except Exception:
        return 0.0


def _exploitability(epss_val, in_kev, vuln, model, epss_data=None) -> float:
    cfg = model["exploitability"]
    epss = max(float(cfg.get("epss_floor", 0.0)), float(epss_val))
    kev_p = float(cfg["kev_probability"]) if in_kev else 0.0
    ev = float(cfg.get("exploit_evidence_default", 0.0))
    cvss_prior = _cvss_exploit_prior(vuln, cfg)
    ml_p = _ml_exploit_probability(vuln, epss_val, epss_data or {}, model)
    # Noisy-OR over independent signals. The always-available CVSS prior ensures a
    # missing EPSS score cannot collapse a genuinely exploitable CVE to zero.
    return _clamp(
        1.0 - (1.0 - epss) * (1.0 - kev_p) * (1.0 - ev) * (1.0 - cvss_prior) * (1.0 - ml_p),
        0.0, 1.0,
    )


def _cvss_exploit_prior(vuln, cfg) -> float:
    """Intrinsic exploitability prior from the CVSS exploitability metrics.

    Uses Attack Vector / Privileges Required / User Interaction (the components
    in the parsed vector) normalized to [0,1] and capped by ``cvss_prior_ceiling``.
    Falls back to cvss_base/10 when the vector is unavailable.
    """
    ceiling = float(cfg.get("cvss_prior_ceiling", 0.85))
    parsed = vuln.get("parsed_cvss") or {}
    av = parsed.get("attack_vector") if isinstance(parsed, dict) else None
    pr = parsed.get("privileges_required") if isinstance(parsed, dict) else None
    ui_required = bool(parsed.get("user_interaction")) if isinstance(parsed, dict) else None

    if av or pr:
        avw = cfg["av_weight"].get(av or "network", cfg["av_weight"]["network"])
        prw = cfg["pr_weight"].get(pr or "none", cfg["pr_weight"]["none"])
        uiw = cfg["ui_weight"]["required"] if ui_required else cfg["ui_weight"]["none"]
        best = cfg["av_weight"]["network"] * cfg["pr_weight"]["none"] * cfg["ui_weight"]["none"]
        norm = (avw * prw * uiw) / best if best else 0.0
        return _clamp(norm, 0.0, 1.0) * ceiling

    cvss = float(vuln.get("cvss_score") or 0.0)
    return _clamp(cvss / 10.0, 0.0, 1.0) * ceiling


def _impact(vuln, model) -> float:
    cfg = model["impact"]
    mags = cfg["cia_magnitude"]
    w = cfg["weights"]
    parsed = vuln.get("parsed_cvss") or {}
    impact_map = parsed.get("impact") if isinstance(parsed, dict) else None
    if isinstance(impact_map, dict) and any(impact_map.get(k) for k in ("confidentiality", "integrity", "availability")):
        c = mags.get((impact_map.get("confidentiality") or "none"), 0.0)
        i = mags.get((impact_map.get("integrity") or "none"), 0.0)
        a = mags.get((impact_map.get("availability") or "none"), 0.0)
        return _clamp(
            w["confidentiality"] * c + w["integrity"] * i + w["availability"] * a,
            0.0, 1.0,
        )
    cvss = float(vuln.get("cvss_score") or 0.0)
    return _clamp(cvss / 10.0, 0.0, 1.0)


def _reachability(reach_rows, blast, vuln, model):
    """Return (R, kind, resolution_confidence, evidence_list)."""
    cfg = model["reachability"]
    conf_map = cfg["resolution_confidence_numeric"]
    lam = float(cfg["hop_decay_lambda"])
    taint_active = any(r.get("tainted") for r in reach_rows)
    taint = float(cfg["taint_boost"]) if taint_active else 0.0

    if reach_rows:
        evidence = []
        best_conf = 0.0
        best_r = 0.0
        for r in reach_rows:
            hops = max(1, int(r.get("hops", 1) or 1))
            c_res = conf_map.get(str(r.get("confidence", cfg["default_path_confidence"])).upper(),
                                 conf_map[cfg["default_path_confidence"]])
            r_path = math.exp(-lam * (hops - 1))
            r_val = _clamp(c_res * r_path * (1.0 + taint), 0.0, 1.0)
            best_r = max(best_r, r_val)
            best_conf = max(best_conf, c_res)
            evidence.append({
                "service": r.get("service", ""),
                "vuln_fn": r.get("vuln_fn", ""),
                "file": r.get("file", ""),
                "line": r.get("line_start", 0),
                "hops": hops,
            })
        return best_r, "direct", best_conf, evidence

    if blast.get("impacted_services", 0) > 0:
        est = float(cfg["transitive_estimate"])
        return est, "transitive", conf_map["LOW"], [{
            "note": "package or entry-level exposure without call-graph path",
            "services": blast.get("service_names", []),
        }]

    pkg = vuln.get("package", "")
    if pkg:
        return float(cfg["no_path_prior"]), "transitive", conf_map["LOW"], [
            {"note": f"package {pkg} affected, no code path"}
        ]

    return 0.0, "none", conf_map["LOW"], []


def _blast(blast, model):
    """Return (blast_factor in [1,1+beta], normalized in [0,1]).

    Combines impacted-service saturation with graph PageRank centrality (when
    available), so a CVE in a highly-central dependency is amplified even before
    services are explicitly linked.
    """
    cfg = model["blast"]
    beta = float(cfg["beta"])
    rate = float(cfg["saturation_rate"])
    impacted = int(blast.get("impacted_services", 0) or 0)
    service_saturation = 1.0 - math.exp(-rate * impacted)  # 0 services -> 0, grows -> 1
    centrality = float(blast.get("centrality", 0.0) or 0.0)
    saturation = max(service_saturation, _clamp(centrality, 0.0, 1.0))
    return 1.0 + beta * saturation, saturation


def _confidence(epss_val, reach_rows, reach_conf, model) -> float:
    cfg = model["confidence"]
    c_epss = float(cfg["weight_has_epss"]) if epss_val > 0 else float(cfg["weight_missing_epss"])
    c_path = float(cfg["weight_has_path"]) if reach_rows else float(cfg["weight_no_path"])
    c_res = reach_conf if reach_conf > 0 else 0.5
    # Geometric mean keeps confidence conservative if any evidence source is weak.
    return _clamp((c_epss * c_path * c_res) ** (1.0 / 3.0), 0.0, 1.0)


def _dominant_factor(expl, impact, reach_eff) -> str:
    pairs = {"exploitability": expl, "impact": impact, "reachability": reach_eff}
    return max(pairs, key=pairs.get)


# -- helpers ----------------------------------------------------------------

def _clamp(val, lo, hi):
    return max(lo, min(hi, val))


def _recommendation(raw_risk, thresholds):
    if raw_risk >= thresholds["BLOCK"]:
        return "BLOCK"
    if raw_risk >= thresholds["REVIEW"]:
        return "REVIEW"
    return "PROCEED"


def _load_json(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _index_reachability(rows):
    out: dict[str, list[Any]] = {}
    for r in rows:
        cid = r.get("cve_id", "")
        out.setdefault(cid, []).append(r)
    return out


def _index_chains(rows):
    out: dict[str, list[Any]] = {}
    for r in rows:
        cid = r.get("cve_id", "")
        out.setdefault(cid, []).append(r)
    return out
