from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    CRITICAL = "Critical"


class CVEFinding(BaseModel):
    cve_id: str = Field(..., examples=["CVE-2024-55565"])
    package_name: str = Field(..., examples=["nanoid"])
    installed_version: str = Field(..., examples=["3.3.6"])
    fixed_version: str = Field(..., examples=["3.3.8"])
    severity: Severity
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    epss_score: float = Field(..., ge=0.0, le=1.0)
    kev_listed: bool
    defined_in: str
    description: str


class ReachabilityResult(BaseModel):
    cve_id: str
    reachable: bool
    call_chain: list[str] = Field(default_factory=list)
    sink_label: str
    semgrep_rule_id: str


class RiskScore(BaseModel):
    package_name: str
    cve_ids: list[str]
    severity_score: float
    exploit_score: float
    reachability_score: float
    blast_radius_score: float
    total_score: float
    verdict: Literal["PROCEED", "REVIEW", "BLOCK"]
    scoring_version: str = Field(default="v1.0.0")


class SandboxResult(BaseModel):
    success: bool
    exit_code: int
    raw_output: str
    conflict_output: str
    conflicting_packages: list[str] = Field(default_factory=list)


class ApiCompatResult(BaseModel):
    breaking_changes: list[str] = Field(default_factory=list)
    api_breaks: list[str] = Field(default_factory=list)


class TestResult(BaseModel):
    skipped: bool = False
    reason: str | None = None
    passed: bool | None = None
    exit_code: int | None = None
    output: str | None = None
    failed_tests: list[str] = Field(default_factory=list)


class BreakCheckResult(BaseModel):
    package_name: str
    target_version: str
    sandbox: SandboxResult | None = None
    api_compat: ApiCompatResult | None = None
    tests: TestResult | None = None
    upgrade_safe: bool = False


class ScanResult(BaseModel):
    repo_path: str
    scan_timestamp: str
    cve_findings: list[CVEFinding]
    reachability: list[ReachabilityResult]
    risk_scores: list[RiskScore]
    overall_verdict: Literal["PROCEED", "REVIEW", "BLOCK"]
    summary: str
    break_checks: list[BreakCheckResult] = Field(default_factory=list)
