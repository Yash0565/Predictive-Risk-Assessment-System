from __future__ import annotations

from collections import defaultdict

from cve_scanner.models import CVEFinding, ReachabilityResult, RiskScore


def compute_risk_score(
    finding: CVEFinding,
    reachability: ReachabilityResult | None,
    blast_radius: int,
) -> RiskScore:
    severity_score = finding.cvss_score * 5.0
    exploit_score = (finding.epss_score * 10.0) + (10.0 if finding.kev_listed else 0.0)
    reachable = reachability.reachable if reachability else False
    reachability_score = 20.0 if reachable else 0.0
    blast_radius_score = min(blast_radius * 2.0, 10.0)

    raw_score = severity_score + exploit_score + reachability_score + blast_radius_score
    total_score = min(raw_score, 100.0)

    if total_score >= 70.0:
        verdict = "BLOCK"
    elif total_score >= 40.0:
        verdict = "REVIEW"
    else:
        verdict = "PROCEED"

    return RiskScore(
        package_name=finding.package_name,
        cve_ids=[finding.cve_id],
        severity_score=severity_score,
        exploit_score=exploit_score,
        reachability_score=reachability_score,
        blast_radius_score=blast_radius_score,
        total_score=total_score,
        verdict=verdict,
    )


def aggregate_package_scores(scores: list[RiskScore]) -> list[RiskScore]:
    grouped: dict[str, list[RiskScore]] = defaultdict(list)
    for score in scores:
        grouped[score.package_name].append(score)

    aggregated: list[RiskScore] = []
    for package_name, items in grouped.items():
        cve_ids = [cve_id for item in items for cve_id in item.cve_ids]
        max_total = max(item.total_score for item in items)
        max_severity = max(item.severity_score for item in items)
        max_exploit = max(item.exploit_score for item in items)
        max_reach = max(item.reachability_score for item in items)
        max_blast = max(item.blast_radius_score for item in items)

        if max_total >= 70.0:
            verdict = "BLOCK"
        elif max_total >= 40.0:
            verdict = "REVIEW"
        else:
            verdict = "PROCEED"

        aggregated.append(
            RiskScore(
                package_name=package_name,
                cve_ids=cve_ids,
                severity_score=max_severity,
                exploit_score=max_exploit,
                reachability_score=max_reach,
                blast_radius_score=max_blast,
                total_score=max_total,
                verdict=verdict,
            )
        )

    return aggregated


def overall_verdict(scores: list[RiskScore]) -> str:
    if any(score.verdict == "BLOCK" for score in scores):
        return "BLOCK"
    if any(score.verdict == "REVIEW" for score in scores):
        return "REVIEW"
    return "PROCEED"
