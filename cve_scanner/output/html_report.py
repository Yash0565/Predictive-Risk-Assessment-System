from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cve_scanner.models import CVEFinding, ReachabilityResult, RiskScore, ScanResult


def _readiness_color(score: float) -> str:
    if score >= 70:
        return "#3fb950"
    if score >= 40:
        return "#e3b341"
    return "#f85149"


def _guess_upgrade_command(finding: CVEFinding) -> str:
    target = finding.defined_in.lower()
    if "package" in target or "yarn" in target or "pnpm" in target:
        if finding.fixed_version:
            return f"npm install {finding.package_name}@{finding.fixed_version}"
        return f"npm install {finding.package_name}@latest"
    if "requirements" in target or "pyproject" in target or "pipfile" in target:
        if finding.fixed_version:
            return f"pip install {finding.package_name}=={finding.fixed_version}"
        return f"pip install --upgrade {finding.package_name}"
    if finding.fixed_version:
        return f"Upgrade {finding.package_name} to {finding.fixed_version}"
    return f"Upgrade {finding.package_name} to a patched version"


def build_html_report(scan_result: ScanResult, repo_name: str) -> str:
    base_dir = Path(__file__).parent
    template_path = base_dir / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_path)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("risk_report.html")

    reachability_map: dict[str, ReachabilityResult] = {
        entry.cve_id: entry for entry in scan_result.reachability
    }
    scores_by_package: dict[str, RiskScore] = {score.package_name: score for score in scan_result.risk_scores}

    if scan_result.risk_scores:
        total_risk_score = max(score.total_score for score in scan_result.risk_scores)
    else:
        total_risk_score = 0.0
    if scan_result.cve_findings:
        worst_finding = max(scan_result.cve_findings, key=lambda item: item.cvss_score)
    else:
        worst_finding = None
    readiness_score = max(0.0, 100.0 - total_risk_score)

    dimension_scores = {
        "Severity": max((score.severity_score for score in scan_result.risk_scores), default=0.0),
        "Exploitability": max((score.exploit_score for score in scan_result.risk_scores), default=0.0),
        "Reachability": max((score.reachability_score for score in scan_result.risk_scores), default=0.0),
        "Blast radius": max((score.blast_radius_score for score in scan_result.risk_scores), default=0.0),
    }

    remediation_commands = sorted({_guess_upgrade_command(f) for f in scan_result.cve_findings})

    findings_by_package: dict[str, list[CVEFinding]] = defaultdict(list)
    for finding in scan_result.cve_findings:
        findings_by_package[finding.package_name].append(finding)

    context = {
        "repo_name": repo_name,
        "scan_timestamp": scan_result.scan_timestamp,
        "overall_verdict": scan_result.overall_verdict,
        "summary": scan_result.summary,
        "meta_package": worst_finding.package_name if worst_finding else "None",
        "meta_upgrade_path": worst_finding.fixed_version if worst_finding else "Unknown",
        "meta_worst_cve": worst_finding.cve_id if worst_finding else "None",
        "meta_cvss": worst_finding.cvss_score if worst_finding else 0.0,
        "meta_epss": worst_finding.epss_score if worst_finding else 0.0,
        "meta_verdict": scan_result.overall_verdict,
        "readiness_score": readiness_score,
        "readiness_color": _readiness_color(readiness_score),
        "dimension_scores": dimension_scores,
        "cve_findings": scan_result.cve_findings,
        "reachability": reachability_map,
        "scores_by_package": scores_by_package,
        "remediation_commands": remediation_commands,
        "findings_by_package": findings_by_package,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "break_checks": scan_result.break_checks,
    }

    return template.render(**context)
