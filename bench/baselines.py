"""Prioritization strategies evaluated by the benchmark.

Each strategy maps a labeled case to ``(predicted_must_fix, probability)``.
The reachability-aware strategy is the production engine; the others are the
naive baselines real teams use today, so the benchmark can quantify how much
noise reachability + probabilistic scoring removes.
"""

from __future__ import annotations

from typing import Callable

from bench.corpus import LabeledCase
from src.scorer import score_single

# A prediction is (must_fix: bool, probability: float in [0,1]).
Prediction = tuple[bool, float]
Strategy = Callable[[LabeledCase], Prediction]


def severity_only(case: LabeledCase, cvss_threshold: float = 7.0) -> Prediction:
    """Treat any CVSS >= threshold as must-fix (typical scanner default)."""
    prob = max(0.0, min(1.0, case.cvss / 10.0))
    return case.cvss >= cvss_threshold, prob


def epss_threshold(case: LabeledCase, threshold: float = 0.1) -> Prediction:
    """Prioritize purely by EPSS exploit probability."""
    return case.epss >= threshold, max(0.0, min(1.0, case.epss))


def kev_only(case: LabeledCase) -> Prediction:
    """Prioritize only CVEs in CISA KEV."""
    return case.in_kev, 1.0 if case.in_kev else 0.0


def reachability_aware(case: LabeledCase) -> Prediction:
    """Production engine: probabilistic score gated by reachability evidence."""
    vuln = {
        "cve": case.cve_id,
        "package": case.package,
        "cvss_score": case.cvss,
        "installed_version": case.installed_version,
    }
    reach_rows = []
    if case.reachable:
        reach_rows = [{
            "cve_id": case.cve_id,
            "service": "/entry",
            "vuln_fn": "vulnerable_symbol",
            "file": f"{case.package}_call.py",
            "line_start": 1,
            "hops": 1,
            "confidence": "HIGH",
        }]
    result = score_single(vuln, epss_val=case.epss, in_kev=case.in_kev,
                          reach_rows=reach_rows)
    must_fix = result["recommendation"] in ("BLOCK", "REVIEW")
    return must_fix, result["risk_unit"]


STRATEGIES: dict[str, Strategy] = {
    "severity_only": severity_only,
    "epss_threshold": epss_threshold,
    "kev_only": kev_only,
    "reachability_aware": reachability_aware,
}
