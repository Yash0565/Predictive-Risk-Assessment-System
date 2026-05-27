"""Whitelisted tool wrappers for the ReAct agent."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field, ValidationError, field_validator

from src.explainer import explain_risk
from src.html_reporter import build_report_data, generate_report
from src.patch_fetcher import fetch_patch, fetch_patches_batch
from src.scorer import score_cves
from src.symbol_scanner import scan_symbols
from src.project_deps import DependencyDiscoveryError, discover_dependency_pins
from src.upgrade_simulator import simulate_upgrade

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

ALLOWED_TOOLS = frozenset({
    "list_dependencies",
    "scan_vulnerabilities",
    "fetch_patch",
    "find_symbol_usage",
    "simulate_upgrade",
    "compute_score",
    "generate_report",
    "finish",
})

EXEMPT_ENTITY_TOOLS = frozenset({"list_dependencies", "scan_vulnerabilities", "finish"})

REPO_SCOPED_TOOLS = frozenset({
    "list_dependencies",
    "scan_vulnerabilities",
    "find_symbol_usage",
    "simulate_upgrade",
})


def apply_target_repo_path(
    tool_name: str,
    args: dict[str, Any],
    target_repo: str,
) -> dict[str, Any]:
    """Force repo_path to the investigation target (LLM cannot point elsewhere)."""
    if tool_name not in REPO_SCOPED_TOOLS:
        return args
    out = dict(args)
    out["repo_path"] = str(Path(target_repo).resolve())
    return out


class ToolError(Exception):
    """Raised when a tool cannot run due to missing prerequisites."""


# ── Pydantic arg models ──────────────────────────────────────────────


class RepoPathArgs(BaseModel):
    repo_path: str


class FetchPatchArgs(BaseModel):
    cve_id: str

    @field_validator("cve_id")
    @classmethod
    def upper_cve(cls, v: str) -> str:
        return v.upper()


class FindSymbolArgs(BaseModel):
    repo_path: str
    vulnerable_symbols: list[Any] = Field(default_factory=list)


class SimulateUpgradeArgs(BaseModel):
    repo_path: str
    package: str
    target_version: str


class CollectedDataArgs(BaseModel):
    collected_data: dict[str, Any] = Field(default_factory=dict)


class FinishArgs(BaseModel):
    summary: str


# ── Trivy scan helper ────────────────────────────────────────────────


def _parse_cvss_vector(vector: Optional[str]) -> Optional[dict[str, Any]]:
    if not vector:
        return None
    parts = vector.split("/")
    metrics: dict[str, str] = {}
    for item in parts:
        if ":" in item:
            key, value = item.split(":", 1)
            metrics[key] = value
    attack_vector_map = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
    privileges_map = {"N": "none", "L": "low", "H": "high"}
    impact_map = {"H": "high", "L": "low", "N": "none"}
    return {
        "attack_vector": attack_vector_map.get(metrics.get("AV")),
        "privileges_required": privileges_map.get(metrics.get("PR")),
        "user_interaction": metrics.get("UI") == "R",
        "impact": {
            "confidentiality": impact_map.get(metrics.get("C")),
            "integrity": impact_map.get(metrics.get("I")),
            "availability": impact_map.get(metrics.get("A")),
        },
    }


def _enrich_trivy_vuln(vuln: dict[str, Any]) -> dict[str, Any]:
    cvss = vuln.get("CVSS", {}) or {}
    nvd_data = cvss.get("nvd") or cvss.get("ghsa") or {}
    vector = nvd_data.get("V3Vector")
    score = nvd_data.get("V3Score")
    refs = vuln.get("References") or []
    return {
        "cve": vuln.get("VulnerabilityID"),
        "cve_id": vuln.get("VulnerabilityID"),
        "package": vuln.get("PkgName"),
        "installed_version": vuln.get("InstalledVersion"),
        "fixed_version": vuln.get("FixedVersion"),
        "severity": vuln.get("Severity"),
        "cvss_vector": vector,
        "cvss_score": score,
        "parsed_cvss": _parse_cvss_vector(vector),
        "cwe": vuln.get("CweIDs", []),
        "commit_urls": [r for r in refs if "commit" in r],
        "primary_url": vuln.get("PrimaryURL"),
    }


def run_trivy_on_repo(repo_path: str) -> tuple[list[dict[str, Any]], str]:
    """Run Trivy filesystem scan. Returns (enriched_cves, mode_label).

    mode_label is ``trivy`` for a live scan, or ``trivy_unavailable`` /
    ``trivy_empty`` when the scan cannot produce CVE rows.
    """
    repo = Path(repo_path).resolve()
    try:
        result = subprocess.run(
            ["trivy", "fs", str(repo), "--format", "json", "--scanners", "vuln"],
            capture_output=True,
            text=True,
            check=True,
            timeout=55,
        )
        output = json.loads(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        logger.warning("Trivy scan failed (%s); install Trivy for live CVE discovery", exc)
        return [], "trivy_unavailable"

    enriched: list[dict[str, Any]] = []
    for target in output.get("Results", []):
        for vuln in target.get("Vulnerabilities") or []:
            row = _enrich_trivy_vuln(vuln)
            if row.get("cve"):
                enriched.append(row)
    if enriched:
        return enriched, "trivy"
    return [], "trivy_empty"


def _symbol_scan_to_graph_evidence(symbol_findings: dict[str, Any]) -> dict[str, Any]:
    findings = symbol_findings.get("findings_by_cve")
    if findings is None and isinstance(symbol_findings.get("symbol_findings"), dict):
        findings = symbol_findings["symbol_findings"].get("findings_by_cve")
    findings = findings or {}
    reachability: list[dict[str, Any]] = []
    for cve_id, finding in findings.items():
        if not finding.get("is_reachable"):
            continue
        for ref in finding.get("references") or []:
            ep = ref.get("entry_point_info") or {}
            reachability.append({
                "cve_id": cve_id,
                "service": ep.get("route") or ref.get("file", ""),
                "vuln_fn": ref.get("enclosing_function") or finding.get("vulnerable_symbol", ""),
                "file": ref.get("file", ""),
                "line_start": ref.get("line", 0),
                "hops": 1 if ref.get("in_entry_point") else 2,
            })
    return {"reachability": reachability, "blast_radius": {}, "dependency_chains": []}


def _patches_to_symbol_input(patches: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for cve_id, patch in patches.items():
        if patch.get("vulnerable_symbols"):
            out[cve_id] = patch
    return out


def _normalize_vulnerable_symbols(raw: Any, state: dict[str, Any]) -> dict[str, Any]:
    if isinstance(raw, dict) and raw:
        return raw
    patches = state.get("collected_data", {}).get("patches") or {}
    if isinstance(raw, list) and raw:
        out: dict[str, Any] = {}
        for item in raw:
            if isinstance(item, dict) and item.get("cve_id"):
                out[str(item["cve_id"]).upper()] = item
            elif isinstance(item, str):
                cid = item.upper()
                if cid in patches:
                    out[cid] = patches[cid]
        if out:
            return out
    return _patches_to_symbol_input(patches)


# ── Tool implementations ─────────────────────────────────────────────


def tool_list_dependencies(args: dict[str, Any], state: dict[str, Any]) -> tuple[Any, str]:
    parsed = RepoPathArgs.model_validate(args)
    try:
        deps, label = discover_dependency_pins(parsed.repo_path)
    except DependencyDiscoveryError as exc:
        raise ToolError(str(exc)) from exc
    state["collected_data"]["dependencies"] = deps
    names = ", ".join(f"{k} {v}" for k, v in list(deps.items())[:6])
    extra = f" (+{len(deps) - 6} more)" if len(deps) > 6 else ""
    return deps, f"Found {len(deps)} packages from {label}: {names}{extra}"


def tool_scan_vulnerabilities(args: dict[str, Any], state: dict[str, Any]) -> tuple[Any, str]:
    parsed = RepoPathArgs.model_validate(args)
    cves, scan_mode = run_trivy_on_repo(parsed.repo_path)
    state["collected_data"]["cves"] = cves
    state["collected_data"]["cve_scan_mode"] = scan_mode
    sev_high = sum(1 for c in cves if (c.get("severity") or "").upper() in ("HIGH", "CRITICAL"))
    note = ""
    if scan_mode != "trivy":
        note = f" — source={scan_mode} (install Trivy CLI for live filesystem CVE data)"
    return cves, f"Found {len(cves)} CVEs ({sev_high} high/critical){note}"


def tool_fetch_patch(args: dict[str, Any], state: dict[str, Any]) -> tuple[Any, str]:
    parsed = FetchPatchArgs.model_validate(args)
    cves = state["collected_data"].get("cves") or []
    if cves and not any(
        (c.get("cve") or c.get("cve_id", "")).upper() == parsed.cve_id for c in cves
    ):
        raise ToolError(
            f"{parsed.cve_id} not in scan results; run scan_vulnerabilities first"
        )
    pkg = next(
        (
            c.get("package")
            for c in cves
            if (c.get("cve") or c.get("cve_id", "")).upper() == parsed.cve_id
        ),
        None,
    )
    patch = fetch_patch(parsed.cve_id, package=pkg)
    patches = state["collected_data"].setdefault("patches", {})
    patches[parsed.cve_id] = patch
    sym_count = len(patch.get("vulnerable_symbols") or [])
    return patch, f"Patch {parsed.cve_id}: status={patch.get('status')}, {sym_count} symbols"


def tool_find_symbol_usage(args: dict[str, Any], state: dict[str, Any]) -> tuple[Any, str]:
    parsed = FindSymbolArgs.model_validate(args)
    sym_input = _normalize_vulnerable_symbols(parsed.vulnerable_symbols, state)
    if not sym_input:
        patches = state["collected_data"].get("patches") or {}
        if not patches:
            raise ToolError("No patches loaded; fetch_patch first or pass vulnerable_symbols")
        sym_input = _patches_to_symbol_input(patches)
    findings = scan_symbols(parsed.repo_path, sym_input)
    state["collected_data"]["symbol_findings"] = findings
    summary = findings.get("summary") or {}
    reachable = len(summary.get("reachable_cves") or [])
    unreachable = len(summary.get("unreachable_cves") or [])
    return findings, f"Reachable {reachable}, unreachable {unreachable} CVEs"


def tool_simulate_upgrade(args: dict[str, Any], state: dict[str, Any]) -> tuple[Any, str]:
    parsed = SimulateUpgradeArgs.model_validate(args)
    deps = state["collected_data"].get("dependencies")
    if not deps:
        try:
            deps, _ = discover_dependency_pins(parsed.repo_path)
            state["collected_data"]["dependencies"] = deps
        except DependencyDiscoveryError as exc:
            raise ToolError(str(exc)) from exc
    pkg = parsed.package
    if pkg.lower() not in {k.lower() for k in deps}:
        raise ToolError(f"Package {pkg} not in dependencies")
    cve_src = {"vulnerabilities": state["collected_data"].get("cves") or []}
    report = simulate_upgrade(
        deps,
        [{"package": pkg, "target_version": parsed.target_version}],
        cve_data_source=cve_src,
    )
    key = f"{pkg}@{parsed.target_version}"
    sims = state["collected_data"].setdefault("upgrade_simulations", {})
    sims[key] = report
    verdict = (report.get("summary") or {}).get("verdict", "unknown")
    return report, f"Upgrade {pkg}→{parsed.target_version}: {verdict}"


def tool_compute_score(args: dict[str, Any], state: dict[str, Any]) -> tuple[Any, str]:
    _ = CollectedDataArgs.model_validate(args)
    data = state["collected_data"]
    cves = data.get("cves") or []
    if not cves:
        raise ToolError("No CVEs collected; run scan_vulnerabilities first")
    graph_evidence = _symbol_scan_to_graph_evidence(data.get("symbol_findings") or {})
    assessment = score_cves(cves, graph_evidence)
    data["scores"] = assessment
    explanations = explain_risk(assessment)
    data["explanations"] = explanations
    rec = assessment.get("summary", {}).get("overall_recommendation", "?")
    n = assessment.get("summary", {}).get("total_cves_scored", 0)
    return assessment, f"Scored {n} CVEs; overall {rec}"


def tool_generate_report(args: dict[str, Any], state: dict[str, Any]) -> tuple[Any, str]:
    _ = CollectedDataArgs.model_validate(args)
    data = state["collected_data"]
    assessment = data.get("scores")
    if not assessment:
        raise ToolError("No scores; run compute_score first")
    repo = state["target_repo"]
    report_data = build_report_data(
        assessment,
        explanations=data.get("explanations"),
        symbol_scan=data.get("symbol_findings"),
        upgrade_simulation=_first_upgrade_sim(data.get("upgrade_simulations")),
        target_repo=Path(repo).name,
        project_dir=repo,
    )
    out_dir = Path(state.get("output_dir") or _REPO_ROOT / "data")
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "report.html"
    path = generate_report(report_data, output_path=str(report_path), offline=True)
    data["report_data"] = report_data
    state["report_path"] = path
    return {"path": path}, f"Report written to {path}"


def tool_finish(args: dict[str, Any], state: dict[str, Any]) -> tuple[Any, str]:
    parsed = FinishArgs.model_validate(args)
    state["final_summary"] = parsed.summary
    return {"summary": parsed.summary}, parsed.summary


def _first_upgrade_sim(sims: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if not sims:
        return None
    return next(iter(sims.values()))


TOOL_REGISTRY: dict[str, Callable[[dict[str, Any], dict[str, Any]], tuple[Any, str]]] = {
    "list_dependencies": tool_list_dependencies,
    "scan_vulnerabilities": tool_scan_vulnerabilities,
    "fetch_patch": tool_fetch_patch,
    "find_symbol_usage": tool_find_symbol_usage,
    "simulate_upgrade": tool_simulate_upgrade,
    "compute_score": tool_compute_score,
    "generate_report": tool_generate_report,
    "finish": tool_finish,
}


def execute_tool(
    tool_name: str,
    args: dict[str, Any],
    state: dict[str, Any],
) -> tuple[Any, str]:
    """Run a whitelisted tool. Returns (result, summary_string)."""
    if tool_name not in TOOL_REGISTRY:
        raise ToolError(f"Tool '{tool_name}' is not whitelisted")
    return TOOL_REGISTRY[tool_name](args, state)


def validate_tool_args(tool_name: str, args: dict[str, Any]) -> tuple[bool, str]:
    """Validate tool arguments with Pydantic before execution."""
    validators: dict[str, type[BaseModel]] = {
        "list_dependencies": RepoPathArgs,
        "scan_vulnerabilities": RepoPathArgs,
        "fetch_patch": FetchPatchArgs,
        "find_symbol_usage": FindSymbolArgs,
        "simulate_upgrade": SimulateUpgradeArgs,
        "compute_score": CollectedDataArgs,
        "generate_report": CollectedDataArgs,
        "finish": FinishArgs,
    }
    model = validators.get(tool_name)
    if not model:
        return False, f"Unknown tool: {tool_name}"
    try:
        model.model_validate(args)
        return True, ""
    except ValidationError as exc:
        return False, str(exc)
