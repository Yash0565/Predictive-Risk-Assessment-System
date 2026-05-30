"""ReAct agent — LLM-driven orchestration with strict tool and schema guardrails."""

from __future__ import annotations

import argparse
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from pydantic import BaseModel, Field, ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.tree import Tree

from src.agent_prompt import STRICT_RETRY_SUFFIX, build_user_prompt
from src.tool_registry import (
    ALLOWED_TOOLS,
    EXEMPT_ENTITY_TOOLS,
    ToolError,
    apply_target_repo_path,
    execute_tool,
    fetch_patches_batch,
    validate_tool_args,
)

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TRACE_PATH = _REPO_ROOT / "data" / "agent_trace.json"
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_TOOL_TIMEOUT_S = 60
_LLM_TIMEOUT_S = 30

console = Console()


class LLMResponseError(Exception):
    """Raised when the LLM returns unusable output."""


class ActionModel(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class AgentStepResponse(BaseModel):
    thought: str
    action: ActionModel
    done: bool = False


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _strip_json_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _ollama_transport_failure(message: str) -> bool:
    """True when Ollama is down, overloaded, or returned a server error."""
    low = message.lower()
    return any(
        token in low
        for token in (
            "unreachable",
            "500",
            "502",
            "503",
            "connection",
            "timeout",
            "refused",
            "internal server error",
        )
    )


def _ollama_post(endpoint: str, payload: dict[str, Any]) -> str:
    """POST to Ollama and return raw text from the response body."""
    url = f"http://localhost:11434/api/{endpoint}"
    try:
        resp = requests.post(url, json=payload, timeout=_LLM_TIMEOUT_S)
        resp.raise_for_status()
    except requests.HTTPError as exc:
        detail = ""
        if exc.response is not None and exc.response.text:
            detail = exc.response.text[:300]
        raise LLMResponseError(
            f"Ollama {endpoint} failed: {exc}" + (f" — {detail}" if detail else "")
        ) from exc
    except requests.RequestException as exc:
        raise LLMResponseError(f"Ollama {endpoint} unreachable: {exc}") from exc

    body = resp.json()
    if endpoint == "chat":
        return (body.get("message") or {}).get("content") or body.get("response") or ""
    return body.get("response") or ""


def call_llm(prompt: str, model: str, *, provider: str = "ollama") -> dict[str, Any]:
    """Single LLM call. Returns parsed JSON dict or raises LLMResponseError."""
    if provider != "ollama":
        raise LLMResponseError(f"Unsupported provider: {provider}")

    options = {"num_predict": 768, "temperature": 0.1}
    attempts: list[tuple[str, dict[str, Any]]] = [
        (
            "chat",
            {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "format": "json",
                "options": options,
            },
        ),
        (
            "generate",
            {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": options,
            },
        ),
    ]

    errors: list[str] = []
    raw = ""
    for endpoint, payload in attempts:
        try:
            raw = _ollama_post(endpoint, payload)
            if raw:
                break
            errors.append(f"{endpoint}: empty response")
        except LLMResponseError as exc:
            errors.append(str(exc))
            if not _ollama_transport_failure(str(exc)):
                break

    if not raw:
        raise LLMResponseError(
            errors[-1] if errors else "Empty LLM response"
        )

    try:
        return json.loads(_strip_json_fences(raw))
    except json.JSONDecodeError as exc:
        raise LLMResponseError(f"Invalid JSON: {exc}") from exc


def parse_agent_response(raw: dict[str, Any]) -> AgentStepResponse:
    """Parse and validate LLM JSON with Pydantic."""
    return AgentStepResponse.model_validate(raw)


def extract_entities_from_state(state: dict[str, Any]) -> dict[str, set[str]]:
    """Collect CVE IDs, packages, and versions known from collected data."""
    data = state.get("collected_data") or {}
    cves: set[str] = set()
    packages: set[str] = set()
    versions: set[str] = set()

    for row in data.get("cves") or []:
        cid = row.get("cve") or row.get("cve_id")
        if cid:
            cves.add(str(cid).upper())
        if row.get("package"):
            packages.add(str(row["package"]).lower())
        if row.get("installed_version"):
            versions.add(str(row["installed_version"]))
        if row.get("fixed_version"):
            versions.add(str(row["fixed_version"]))

    for cid in (data.get("patches") or {}):
        cves.add(str(cid).upper())

    for pkg, ver in (data.get("dependencies") or {}).items():
        packages.add(str(pkg).lower())
        versions.add(str(ver))

    repo = state.get("target_repo", "")
    return {"cves": cves, "packages": packages, "versions": versions, "repo_path": {repo}}


def _entities_in_text(text: str) -> tuple[set[str], set[str], set[str]]:
    cve_ids = {m.group(0).upper() for m in _CVE_RE.finditer(text)}
    return cve_ids, set(), set()


def _entities_in_args(tool: str, args: dict[str, Any]) -> tuple[set[str], set[str], set[str]]:
    cves: set[str] = set()
    packages: set[str] = set()
    versions: set[str] = set()

    if tool == "fetch_patch" and args.get("cve_id"):
        cves.add(str(args["cve_id"]).upper())
    if tool == "simulate_upgrade":
        if args.get("package"):
            packages.add(str(args["package"]).lower())
        if args.get("target_version"):
            versions.add(str(args["target_version"]))
    if tool == "find_symbol_usage":
        raw = args.get("vulnerable_symbols")
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str) and _CVE_RE.match(item):
                    cves.add(item.upper())
                elif isinstance(item, dict) and item.get("cve_id"):
                    cves.add(str(item["cve_id"]).upper())
        elif isinstance(raw, dict):
            cves.update(k.upper() for k in raw)

    blob = json.dumps(args)
    cves.update(m.group(0).upper() for m in _CVE_RE.finditer(blob))
    return cves, packages, versions


def validate_response(
    response: dict[str, Any],
    scratchpad: list[dict[str, Any]],
    allowed_tools: list[str],
    state: dict[str, Any],
) -> tuple[bool, str]:
    """Validate schema + entity whitelist. Returns (valid, error_msg)."""
    try:
        parsed = parse_agent_response(response)
    except ValidationError as exc:
        return False, f"Schema error: {exc}"

    tool = parsed.action.tool
    if tool not in allowed_tools:
        return False, f"Tool '{tool}' is not in the whitelist"

    ok, err = validate_tool_args(tool, parsed.action.args)
    if not ok:
        return False, f"Args validation: {err}"

    if tool in EXEMPT_ENTITY_TOOLS:
        return True, ""

    known = extract_entities_from_state(state)
    arg_cves, arg_pkgs, arg_vers = _entities_in_args(tool, parsed.action.args)

    for cid in arg_cves:
        if known["cves"] and cid not in known["cves"]:
            return False, f"Unknown CVE '{cid}' not in investigation data"
        if not known["cves"] and tool not in EXEMPT_ENTITY_TOOLS:
            return False, f"CVE '{cid}' not yet discovered (run scan_vulnerabilities first)"

    for pkg in arg_pkgs:
        if pkg not in known["packages"] and known["packages"]:
            return False, f"Unknown package '{pkg}'"

    for ver in arg_vers:
        if ver not in known["versions"] and known["versions"]:
            return False, f"Unknown version '{ver}'"

    if not scratchpad and tool not in ("list_dependencies", "scan_vulnerabilities", "finish"):
        return False, "Start with list_dependencies or scan_vulnerabilities"

    return True, ""


def compress_scratchpad(scratchpad: list[dict[str, Any]], max_chars: int = 8000) -> str:
    """Compress old scratchpad entries; keep last 5 verbatim."""
    if not scratchpad:
        return "(empty — no steps yet)"

    lines: list[str] = []
    early = scratchpad[:-5] if len(scratchpad) > 5 else []
    recent = scratchpad[-5:]

    for entry in early:
        lines.append(
            f"Step {entry['step']}: {entry['action']['tool']} → {entry.get('result_summary', '')[:120]}"
        )
    for entry in recent:
        lines.append(
            f"Step {entry['step']}:\n"
            f"  Thought: {entry.get('thought', '')}\n"
            f"  Action: {entry['action']['tool']}({json.dumps(entry['action'].get('args', {}))})\n"
            f"  Result: {entry.get('result_summary', '')}"
        )

    text = "\n".join(lines)
    if len(text) > max_chars:
        return text[: max_chars - 20] + "\n…(truncated)"
    return text


def _detect_loop(scratchpad: list[dict[str, Any]]) -> Optional[str]:
    if len(scratchpad) < 2:
        return None
    prev, cur = scratchpad[-2], scratchpad[-1]
    if (
        prev["action"]["tool"] == cur["action"]["tool"]
        and prev["action"].get("args") == cur["action"].get("args")
    ):
        tool = cur["action"]["tool"]
        return (
            f"You already called {tool} with these args. Pick a different action."
        )
    return None


def _format_known_cves_hint(state: dict[str, Any], limit: int = 25) -> str:
    """Short list of CVE IDs from the latest scan for the LLM prompt."""
    cves = (state.get("collected_data") or {}).get("cves") or []
    ids = sorted(
        {
            str(c.get("cve") or c.get("cve_id", "")).upper()
            for c in cves
            if c.get("cve") or c.get("cve_id")
        }
    )
    if not ids:
        return ""
    shown = ids[:limit]
    suffix = f" … ({len(ids)} total)" if len(ids) > limit else ""
    return (
        "CVE IDs from scan (use only these in fetch_patch / find_symbol_usage args): "
        + ", ".join(shown)
        + suffix
    )


def _workflow_hints(state: dict[str, Any], scratchpad: list[dict[str, Any]]) -> str:
    """Nudge the LLM after common mistakes (re-scan, wrong next step)."""
    hints: list[str] = []
    loop = _detect_loop(scratchpad)
    if loop:
        hints.append(loop)

    tools_done = {e["action"]["tool"] for e in scratchpad if e.get("action")}
    data = state.get("collected_data") or {}
    cves = data.get("cves") or []

    if cves and "scan_vulnerabilities" in tools_done:
        if "fetch_patch" not in tools_done and "find_symbol_usage" not in tools_done:
            sample = [
                str(c.get("cve") or c.get("cve_id", "")).upper()
                for c in cves[:5]
                if c.get("cve") or c.get("cve_id")
            ]
            hints.append(
                f"Scan finished ({len(cves)} CVEs). Do not call scan_vulnerabilities again. "
                f"Next: fetch_patch(cve_id) for CVEs such as {', '.join(sample)}."
            )

    cve_hint = _format_known_cves_hint(state)
    if cve_hint and ("fetch_patch" in tools_done or "find_symbol_usage" in tools_done):
        hints.append(cve_hint)

    return "\n".join(hints)


def _entity_retry_suffix(state: dict[str, Any], last_err: str) -> str:
    """Extra guidance when the model picks an unknown CVE/package in tool args."""
    if "Unknown CVE" not in last_err and "not yet discovered" not in last_err:
        return STRICT_RETRY_SUFFIX
    cve_hint = _format_known_cves_hint(state, limit=20)
    extra = f"\n{cve_hint}" if cve_hint else ""
    return (
        STRICT_RETRY_SUFFIX
        + "\nUse a cve_id from the scan results only. Do not invent CVE IDs."
        + extra
    )


def _run_tool_with_timeout(tool: str, args: dict[str, Any], state: dict[str, Any]) -> tuple[Any, str]:
    with ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(execute_tool, tool, args, state)
        try:
            return fut.result(timeout=_TOOL_TIMEOUT_S)
        except FuturesTimeout:
            raise ToolError(f"Tool {tool} timed out after {_TOOL_TIMEOUT_S}s")


def _display_step(
    step: int,
    max_steps: int,
    thought: str,
    tool: str,
    args: dict[str, Any],
    summary: str,
    *,
    error: bool = False,
) -> None:
    console.print(Rule(f"[bold]Step {step}/{max_steps}[/bold]"))
    console.print(f"[cyan]Thought:[/cyan] {thought}")
    console.print(f"[yellow]Action:[/yellow] {tool}({json.dumps(args)})")
    if error:
        console.print(f"[red]Result:[/red] {summary}")
    else:
        console.print(f"[green]Result:[/green] {summary}")


def _display_header(target_repo: str, model: str, *, fallback: bool) -> None:
    mode = "scripted fallback" if fallback else f"LLM ({model})"
    console.print(
        Panel.fit(
            f"[bold]Pre-Upgrade Risk Agent[/bold]\n"
            f"Target: [cyan]{target_repo}[/cyan]\n"
            f"Mode: {mode}",
            border_style="blue",
        )
    )


def _display_final(state: dict[str, Any], metadata: dict[str, Any]) -> None:
    tree = Tree("[bold]Investigation complete[/bold]")
    data = state.get("collected_data") or {}
    tree.add(f"CVEs: {len(data.get('cves') or [])}")
    tree.add(f"Patches: {len(data.get('patches') or {})}")
    sym = data.get("symbol_findings") or {}
    if sym.get("summary"):
        tree.add(f"Reachable: {len(sym['summary'].get('reachable_cves') or [])}")
    if state.get("report_path"):
        tree.add(f"Report: {state['report_path']}")
    tree.add(f"Status: {metadata.get('status')}")
    console.print(tree)


def _empty_collected_data() -> dict[str, Any]:
    return {
        "dependencies": {},
        "cves": [],
        "patches": {},
        "symbol_findings": {},
        "upgrade_simulations": {},
        "scores": {},
    }


def _build_result(
    state: dict[str, Any],
    trace: list[dict[str, Any]],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "agent_metadata": metadata,
        "trace": trace,
        "collected_data": state.get("collected_data", {}),
        "final_summary": state.get("final_summary", ""),
        "report_path": state.get("report_path", ""),
        "status": metadata.get("status", "completed_normally"),
    }


def _save_trace(result: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _force_finalize(state: dict[str, Any], trace: list[dict[str, Any]], step: int) -> None:
    """Run scorer + reporter when max steps hit."""
    data = state["collected_data"]
    if not data.get("scores") and data.get("cves"):
        try:
            _, summary = _run_tool_with_timeout("compute_score", {"collected_data": data}, state)
            trace.append({
                "step": step,
                "timestamp": _utc_now_iso(),
                "thought": "(forced)",
                "action": {"tool": "compute_score", "args": {"collected_data": {}}},
                "result_summary": summary,
                "duration_ms": 0,
                "forced": True,
            })
        except ToolError as exc:
            logger.warning("Forced compute_score failed: %s", exc)
    if not state.get("report_path") and data.get("scores"):
        try:
            _, summary = _run_tool_with_timeout("generate_report", {"collected_data": data}, state)
            trace.append({
                "step": step + 1,
                "timestamp": _utc_now_iso(),
                "thought": "(forced)",
                "action": {"tool": "generate_report", "args": {"collected_data": {}}},
                "result_summary": summary,
                "duration_ms": 0,
                "forced": True,
            })
        except ToolError as exc:
            logger.warning("Forced generate_report failed: %s", exc)


def scripted_fallback(
    target_repo: str,
    *,
    verbose: bool = True,
    output_dir: Optional[str] = None,
    report_version: str = "final",
) -> dict[str, Any]:
    """Run the hard-coded pipeline when the agent fails."""
    started = time.perf_counter()
    started_at = _utc_now_iso()
    state: dict[str, Any] = {
        "target_repo": str(Path(target_repo).resolve()),
        "output_dir": output_dir or str(_REPO_ROOT / "data"),
        "report_version": report_version,
        "collected_data": _empty_collected_data(),
    }
    trace: list[dict[str, Any]] = []
    max_steps = 15
    step = 0

    if verbose:
        _display_header(state["target_repo"], "scripted", fallback=True)

    def record(tool: str, args: dict[str, Any], thought: str) -> None:
        nonlocal step
        step += 1
        t0 = time.perf_counter()
        try:
            result, summary = _run_tool_with_timeout(tool, args, state)
            err = False
        except ToolError as exc:
            result, summary, err = None, str(exc), True
        ms = int((time.perf_counter() - t0) * 1000)
        trace.append({
            "step": step,
            "timestamp": _utc_now_iso(),
            "thought": thought,
            "action": {"tool": tool, "args": args},
            "result_summary": summary,
            "duration_ms": ms,
        })
        if verbose:
            _display_step(step, max_steps, thought, tool, args, summary, error=err)
        if tool == "finish":
            return

    repo = state["target_repo"]
    record("list_dependencies", {"repo_path": repo}, "Discover dependency pins")
    record("scan_vulnerabilities", {"repo_path": repo}, "Scan for known CVEs")

    cves = state["collected_data"].get("cves") or []
    batch_items = [
        {"cve_id": (c.get("cve") or c.get("cve_id")), "package": c.get("package")}
        for c in cves[:10]
        if c.get("cve") or c.get("cve_id")
    ]
    if batch_items:
        patches = fetch_patches_batch(batch_items)
        state["collected_data"]["patches"] = patches
        step += 1
        trace.append({
            "step": step,
            "timestamp": _utc_now_iso(),
            "thought": "Batch-fetch patches for discovered CVEs",
            "action": {"tool": "fetch_patches_batch", "args": {"count": len(batch_items)}},
            "result_summary": f"Fetched {len(patches)} patches",
            "duration_ms": 0,
        })
        if verbose:
            _display_step(
                step, max_steps, "Batch-fetch patches", "fetch_patches_batch",
                {"count": len(batch_items)}, f"Fetched {len(patches)} patches",
            )

    sym_input = {
        cid: p for cid, p in (state["collected_data"].get("patches") or {}).items()
        if p.get("vulnerable_symbols")
    }
    if sym_input:
        record(
            "find_symbol_usage",
            {"repo_path": repo, "vulnerable_symbols": list(sym_input.keys())},
            "Check reachability of vulnerable symbols",
        )

    findings = (state["collected_data"].get("symbol_findings") or {}).get("findings_by_cve") or {}
    reachable_pkgs: set[str] = set()
    for cid, f in findings.items():
        if f.get("is_reachable"):
            for c in cves:
                if (c.get("cve") or c.get("cve_id", "")).upper() == cid:
                    if c.get("package"):
                        reachable_pkgs.add(str(c["package"]).lower())

    deps = state["collected_data"].get("dependencies") or {}
    if "requests" in {k.lower() for k in deps} or "requests" in reachable_pkgs:
        fixed = next((c.get("fixed_version") for c in cves if (c.get("package") or "").lower() == "requests"), "2.31.0")
        record(
            "simulate_upgrade",
            {"repo_path": repo, "package": "requests", "target_version": fixed or "2.31.0"},
            "Simulate requests upgrade",
        )

    record("compute_score", {"collected_data": {}}, "Deterministic risk scoring")
    record("generate_report", {"collected_data": {}}, "Generate HTML report")

    n_cves = len(cves)
    sym_summary = (state["collected_data"].get("symbol_findings") or {}).get("summary") or {}
    n_reach = len(sym_summary.get("reachable_cves") or [])
    summary = f"Found {n_cves} CVEs, {n_reach} reachable (fallback pipeline)."
    state["final_summary"] = summary
    record("finish", {"summary": summary}, "Investigation complete")

    duration = round(time.perf_counter() - started, 1)
    metadata = {
        "started_at": started_at,
        "completed_at": _utc_now_iso(),
        "duration_seconds": duration,
        "steps_taken": len(trace),
        "max_steps": max_steps,
        "llm_model": "none",
        "fallback_used": True,
        "schema_violations": 0,
        "entity_violations": 0,
    }
    metadata["status"] = "completed_with_fallback"
    result = _build_result(state, trace, metadata)
    _save_trace(result, _TRACE_PATH)
    if verbose:
        _display_final(state, metadata)
    return result


def run_agent(
    target_repo: str,
    llm_provider: str = "ollama",
    llm_model: str = "qwen2.5:3b",
    max_steps: int = 15,
    verbose: bool = True,
    fallback_on_error: bool = True,
    *,
    no_llm: bool = False,
    output_dir: Optional[str] = None,
    trace_path: Optional[str] = None,
    report_version: str = "final",
) -> dict[str, Any]:
    """Main entry point. Returns the agent output schema."""
    target = str(Path(target_repo).resolve())
    if no_llm:
        return scripted_fallback(
            target, verbose=verbose, output_dir=output_dir,
            report_version=report_version,
        )

    started = time.perf_counter()
    started_at = _utc_now_iso()
    state: dict[str, Any] = {
        "target_repo": target,
        "output_dir": output_dir or str(_REPO_ROOT / "data"),
        "report_version": report_version,
        "collected_data": _empty_collected_data(),
    }
    scratchpad: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    schema_violations = 0
    entity_violations = 0
    consecutive_invalid = 0
    status = "completed_normally"

    if verbose:
        _display_header(target, llm_model, fallback=False)

    for step in range(1, max_steps + 1):
        workflow_hint = _workflow_hints(state, scratchpad)
        known_cves = _format_known_cves_hint(state)
        prompt = build_user_prompt(
            compress_scratchpad(scratchpad),
            target_repo=target,
            loop_hint=workflow_hint,
            known_cves_hint=known_cves,
        )

        response_raw: Optional[dict[str, Any]] = None
        parsed: Optional[AgentStepResponse] = None
        last_err = ""

        for attempt in range(2):
            try:
                suffix = ""
                if attempt:
                    suffix = _entity_retry_suffix(state, last_err)
                response_raw = call_llm(
                    prompt + suffix,
                    llm_model,
                    provider=llm_provider,
                )
                valid, err = validate_response(
                    response_raw, scratchpad, list(ALLOWED_TOOLS), state,
                )
                if not valid:
                    if "Schema" in err or "Args" in err:
                        schema_violations += 1
                    else:
                        entity_violations += 1
                    last_err = err
                    continue
                parsed = parse_agent_response(response_raw)
                consecutive_invalid = 0
                break
            except LLMResponseError as exc:
                last_err = str(exc)
                schema_violations += 1
                if fallback_on_error and _ollama_transport_failure(last_err):
                    if verbose:
                        console.print(
                            f"[red]Ollama error:[/red] {last_err}\n"
                            "[yellow]Falling back to scripted pipeline…[/yellow]"
                        )
                    fb = scripted_fallback(
                        target, verbose=verbose, output_dir=output_dir,
                        report_version=report_version,
                    )
                    fb["agent_metadata"]["schema_violations"] = schema_violations
                    fb["agent_metadata"]["entity_violations"] = entity_violations
                    fb["agent_metadata"]["llm_model"] = llm_model
                    fb["status"] = "completed_with_fallback"
                    return fb
            except ValidationError as exc:
                last_err = str(exc)
                schema_violations += 1

        if parsed is None:
            consecutive_invalid += 1
            if verbose:
                console.print(f"[red]Invalid LLM response:[/red] {last_err}")
            scratchpad.append({
                "step": step,
                "thought": f"(invalid response: {last_err})",
                "action": {"tool": "none", "args": {}},
                "result_summary": last_err,
            })
            if consecutive_invalid >= 2 and fallback_on_error:
                if verbose:
                    console.print("[yellow]Falling back to scripted pipeline…[/yellow]")
                fb = scripted_fallback(
                    target, verbose=verbose, output_dir=output_dir,
                    report_version=report_version,
                )
                fb["agent_metadata"]["schema_violations"] = schema_violations
                fb["agent_metadata"]["entity_violations"] = entity_violations
                return fb
            continue

        tool = parsed.action.tool
        args = apply_target_repo_path(tool, dict(parsed.action.args), target)

        t0 = time.perf_counter()
        try:
            if tool == "finish":
                _, summary = execute_tool(tool, args, state)
                result_summary = summary
            else:
                _, result_summary = _run_tool_with_timeout(tool, args, state)
            tool_err = False
        except ToolError as exc:
            result_summary = f"ERROR: {exc}"
            tool_err = True

        ms = int((time.perf_counter() - t0) * 1000)
        entry = {
            "step": step,
            "timestamp": _utc_now_iso(),
            "thought": parsed.thought,
            "action": {"tool": tool, "args": args},
            "result_summary": result_summary,
            "duration_ms": ms,
        }
        scratchpad.append(entry)
        trace.append(entry)

        if verbose:
            _display_step(
                step, max_steps, parsed.thought, tool, args,
                result_summary, error=tool_err,
            )

        if tool == "finish" or parsed.done:
            state["final_summary"] = args.get("summary", result_summary)
            break
    else:
        status = "max_steps_reached"
        _force_finalize(state, trace, max_steps)
        state.setdefault(
            "final_summary",
            "Max steps reached; scored and reported with collected data.",
        )

    duration = round(time.perf_counter() - started, 1)
    metadata = {
        "started_at": started_at,
        "completed_at": _utc_now_iso(),
        "duration_seconds": duration,
        "steps_taken": len(trace),
        "max_steps": max_steps,
        "llm_model": llm_model,
        "fallback_used": False,
        "schema_violations": schema_violations,
        "entity_violations": entity_violations,
        "status": status,
    }
    result = _build_result(state, trace, metadata)
    _save_trace(result, Path(trace_path) if trace_path else _TRACE_PATH)
    if verbose:
        _display_final(state, metadata)
    return result


def main() -> None:
    """CLI entry point for python -m src.agent."""
    parser = argparse.ArgumentParser(description="ReAct security analysis agent")
    parser.add_argument("--target", required=True, help="Path to target repository")
    parser.add_argument("--model", default="qwen2.5:3b", help="Ollama model name")
    parser.add_argument("--provider", default="ollama", choices=["ollama"])
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--quiet", action="store_true", help="Disable rich output")
    parser.add_argument("--no-llm", action="store_true", help="Scripted fallback only")
    parser.add_argument("--no-fallback", action="store_true", help="Do not fall back on LLM errors")
    parser.add_argument("--output-dir", default=None, help="Directory for risk_report.html")
    parser.add_argument("--trace", default=None, help="Path for agent trace JSON")
    parser.add_argument(
        "--report-version", default="final", choices=["v1", "v2", "final"],
        help="HTML report layout: final (default, tabbed) / v2 / v1",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    result = run_agent(
        args.target,
        llm_provider=args.provider,
        llm_model=args.model,
        max_steps=args.max_steps,
        verbose=not args.quiet,
        fallback_on_error=not args.no_fallback,
        no_llm=args.no_llm,
        output_dir=args.output_dir,
        trace_path=args.trace,
        report_version=args.report_version,
    )
    console.print(f"\n[bold]Report:[/bold] {result.get('report_path') or '—'}")
    console.print(f"[bold]Summary:[/bold] {result.get('final_summary') or '—'}")


if __name__ == "__main__":
    main()
