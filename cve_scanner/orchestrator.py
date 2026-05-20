from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from cve_scanner.config import get_settings
from cve_scanner.checkers.api_compat_checker import (
    build_api_compat_rules,
    get_breaking_changes,
    run_tests_in_sandbox,
)
from cve_scanner.checkers.sandbox_checker import simulate_npm_upgrade, simulate_upgrade
from cve_scanner.db import init_db, save_job
from cve_scanner.explainer.claude_explainer import generate_explanation, template_fallback
from cve_scanner.models import (
    ApiCompatResult,
    BreakCheckResult,
    CVEFinding,
    ReachabilityResult,
    RiskScore,
    SandboxResult,
    ScanResult,
    TestResult,
)
from cve_scanner.scanners.semgrep_scanner import (
    check_reachability,
    run_custom_rules,
    run_semgrep_ci,
)
from cve_scanner.scanners.trivy_scanner import run_grype, run_trivy
from cve_scanner.scoring.risk_engine import (
    aggregate_package_scores,
    compute_risk_score,
    overall_verdict,
)

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _blast_radius(findings: list[CVEFinding], reachability: list[ReachabilityResult]) -> dict[str, int]:
    cve_to_package = {finding.cve_id: finding.package_name for finding in findings}
    packages: dict[str, set[str]] = defaultdict(set)
    for entry in reachability:
        if not entry.reachable:
            continue
        package = cve_to_package.get(entry.cve_id)
        if not package:
            continue
        for chain in entry.call_chain:
            path = chain.split(":", 1)[0]
            packages[package].add(path)
    return {package: len(paths) for package, paths in packages.items()}


def _detect_ecosystem(repo_path: str) -> str:
    repo = Path(repo_path)
    if (repo / "requirements.txt").exists() or (repo / "pyproject.toml").exists():
        return "python"
    if (repo / "package.json").exists():
        return "npm"
    return "unknown"


async def _run_break_checks(
    repo_path: str,
    findings: list[CVEFinding],
    risk_scores: list[RiskScore],
) -> list[BreakCheckResult]:
    settings = get_settings()
    ecosystem = _detect_ecosystem(repo_path)
    break_results: list[BreakCheckResult] = []

    for score in risk_scores:
        if score.verdict not in {"REVIEW", "BLOCK"}:
            continue

        finding = next((item for item in findings if item.package_name == score.package_name), None)
        target_version = finding.fixed_version if finding else ""
        if not finding or not target_version:
            break_results.append(
                BreakCheckResult(
                    package_name=score.package_name,
                    target_version=target_version or "unknown",
                    upgrade_safe=False,
                )
            )
            continue

        sandbox_result: SandboxResult | None = None
        api_result: ApiCompatResult | None = None
        test_result: TestResult | None = None

        if ecosystem == "python":
            with TemporaryDirectory() as tmpdir:
                sandbox_dict = await simulate_upgrade(
                    repo_path,
                    finding.package_name,
                    target_version,
                    tmpdir=tmpdir,
                    timeout=settings.SANDBOX_TIMEOUT,
                )
                sandbox_result = SandboxResult(**sandbox_dict)

                if settings.RUN_TESTS:
                    tests_dict = await run_tests_in_sandbox(tmpdir, repo_path, ecosystem)
                    test_result = TestResult(**tests_dict)
                else:
                    test_result = TestResult(skipped=True, reason="RUN_TESTS disabled")
        elif ecosystem == "npm":
            sandbox_dict = await simulate_npm_upgrade(
                repo_path,
                finding.package_name,
                target_version,
                timeout=settings.SANDBOX_TIMEOUT,
            )
            sandbox_result = SandboxResult(
                success=sandbox_dict.get("success", False),
                exit_code=sandbox_dict.get("exit_code", 1),
                raw_output=sandbox_dict.get("raw_output", ""),
                conflict_output="",
                conflicting_packages=[],
            )
            if settings.RUN_TESTS:
                tests_dict = await run_tests_in_sandbox(None, repo_path, ecosystem)
                test_result = TestResult(**tests_dict)
            else:
                test_result = TestResult(skipped=True, reason="RUN_TESTS disabled")
        else:
            sandbox_result = SandboxResult(
                success=False,
                exit_code=2,
                raw_output="Unknown ecosystem",
                conflict_output="",
                conflicting_packages=[],
            )
            test_result = TestResult(skipped=True, reason="Unknown ecosystem")

        rules = build_api_compat_rules(finding.package_name, target_version)
        api_breaks: list[str] = []
        if rules:
            hits = await run_custom_rules(repo_path, rules)
            api_breaks = [hit.get("message", "") for hit in hits if hit.get("message")]

        breaking_changes = await get_breaking_changes(
            finding.package_name,
            finding.installed_version,
            target_version,
            ecosystem="pypi" if ecosystem == "python" else "npm",
        )

        api_result = ApiCompatResult(
            breaking_changes=breaking_changes,
            api_breaks=api_breaks,
        )

        tests_failed = test_result is not None and test_result.passed is False
        upgrade_safe = bool(sandbox_result and sandbox_result.success) and not api_breaks and not tests_failed

        break_results.append(
            BreakCheckResult(
                package_name=finding.package_name,
                target_version=target_version,
                sandbox=sandbox_result,
                api_compat=api_result,
                tests=test_result,
                upgrade_safe=upgrade_safe,
            )
        )

    return break_results


def _apply_break_penalties(
    scores: list[RiskScore],
    break_checks: list[BreakCheckResult],
) -> list[RiskScore]:
    penalty_by_package: dict[str, int] = {}
    for check in break_checks:
        penalty = 0
        if check.sandbox and not check.sandbox.success:
            penalty += 10
        if check.api_compat and check.api_compat.api_breaks:
            penalty += 10
        if penalty:
            penalty_by_package[check.package_name] = penalty

    updated: list[RiskScore] = []
    for score in scores:
        penalty = penalty_by_package.get(score.package_name, 0)
        total = min(score.total_score + penalty, 100.0)
        if total >= 70.0:
            verdict = "BLOCK"
        elif total >= 40.0:
            verdict = "REVIEW"
        else:
            verdict = "PROCEED"

        updated.append(
            RiskScore(
                package_name=score.package_name,
                cve_ids=score.cve_ids,
                severity_score=score.severity_score,
                exploit_score=score.exploit_score,
                reachability_score=score.reachability_score,
                blast_radius_score=score.blast_radius_score,
                total_score=total,
                verdict=verdict,
                scoring_version=score.scoring_version,
            )
        )

    return updated


def _mock_scan_result(repo_path: str) -> ScanResult:
    from cve_scanner.models import CVEFinding, ReachabilityResult, Severity
    from cve_scanner.scoring.risk_engine import aggregate_package_scores, compute_risk_score, overall_verdict

    findings = [
        CVEFinding(
            cve_id="CVE-2024-55565",
            package_name="nanoid",
            installed_version="3.3.6",
            fixed_version="3.3.8",
            severity=Severity.MODERATE,
            cvss_score=5.3,
            epss_score=0.18,
            kev_listed=False,
            defined_in="package-lock.json",
            description="Mock vulnerability for UI testing.",
        ),
        CVEFinding(
            cve_id="CVE-2023-99999",
            package_name="requests",
            installed_version="2.28.0",
            fixed_version="2.31.0",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            epss_score=0.72,
            kev_listed=True,
            defined_in="requirements.txt",
            description="Mock vulnerability for UI testing.",
        ),
    ]
    reachability = [
        ReachabilityResult(
            cve_id="CVE-2024-55565",
            reachable=True,
            call_chain=["src/utils/id.ts:14", "node_modules/nanoid/index.js:18"],
            sink_label="nanoid() call",
            semgrep_rule_id="reach-CVE-2024-55565",
        ),
        ReachabilityResult(
            cve_id="CVE-2023-99999",
            reachable=True,
            call_chain=["src/api/client.py:72", "requests/api.py:58"],
            sink_label="requests.get() call",
            semgrep_rule_id="reach-CVE-2023-99999",
        ),
    ]
    blast_radius_map = _blast_radius(findings, reachability)
    per_finding_scores = []
    for finding in findings:
        reach = next((r for r in reachability if r.cve_id == finding.cve_id), None)
        blast_radius = blast_radius_map.get(finding.package_name, 0)
        per_finding_scores.append(compute_risk_score(finding, reach, blast_radius))

    scores = aggregate_package_scores(per_finding_scores)
    verdict = overall_verdict(scores)

    scan_result = ScanResult(
        repo_path=repo_path,
        scan_timestamp=_now_iso(),
        cve_findings=findings,
        reachability=reachability,
        risk_scores=scores,
        overall_verdict=verdict,
        summary="",
    )
    return scan_result


async def analyze_repo(
    repo_path: str,
    dry_run: bool = False,
    mock: bool = False,
    mock_llm: bool = False,
) -> ScanResult:
    settings = get_settings()
    await init_db(settings.DB_PATH)
    started_at = _now_iso()

    if mock:
        scan_result = _mock_scan_result(repo_path)
        if scan_result.overall_verdict in {"REVIEW", "BLOCK"} and mock_llm and not dry_run:
            scan_result.summary = await generate_explanation(scan_result)
        else:
            scan_result.summary = template_fallback(scan_result)
        await save_job(
            settings.DB_PATH,
            job_id=str(uuid.uuid4()),
            repo_path=repo_path,
            started_at=started_at,
            completed_at=_now_iso(),
            verdict=scan_result.overall_verdict,
            result_json=scan_result.model_dump_json(),
        )
        return scan_result

    semgrep_ci_task = asyncio.create_task(run_semgrep_ci(repo_path))
    try:
        findings = await run_trivy(repo_path)
    except RuntimeError as exc:
        logger.warning("Trivy failed (%s); falling back to Grype.", exc)
        findings = await run_grype(repo_path)

    reachability = await check_reachability(repo_path, findings, run_ci=False)
    await semgrep_ci_task
    blast_radius_map = _blast_radius(findings, reachability)

    per_finding_scores = []
    for finding in findings:
        reach = next((r for r in reachability if r.cve_id == finding.cve_id), None)
        blast_radius = blast_radius_map.get(finding.package_name, 0)
        per_finding_scores.append(compute_risk_score(finding, reach, blast_radius))

    aggregated_scores = aggregate_package_scores(per_finding_scores)
    break_checks = await _run_break_checks(repo_path, findings, aggregated_scores)
    adjusted_scores = _apply_break_penalties(aggregated_scores, break_checks)
    verdict = overall_verdict(adjusted_scores)

    scan_result = ScanResult(
        repo_path=repo_path,
        scan_timestamp=_now_iso(),
        cve_findings=findings,
        reachability=reachability,
        risk_scores=adjusted_scores,
        overall_verdict=verdict,
        summary="",
        break_checks=break_checks,
    )

    if not dry_run:
        summary = await generate_explanation(scan_result)
    else:
        summary = template_fallback(scan_result)
    scan_result.summary = summary

    await save_job(
        settings.DB_PATH,
        job_id=str(uuid.uuid4()),
        repo_path=repo_path,
        started_at=started_at,
        completed_at=_now_iso(),
        verdict=scan_result.overall_verdict,
        result_json=scan_result.model_dump_json(),
    )

    return scan_result
