"""Semgrep discovery, health checks, and rule validation."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from typing import Any

import yaml

from src.utils import find_tool, tool_subprocess_env

logger = logging.getLogger(__name__)

# Process-wide caches and circuit breakers.
# Once `semgrep --version` or `--validate` hits a TimeoutExpired/OSError we
# stop trying to spawn the subprocess and fall back to schema-only validation
# for the remainder of the run — this prevents Windows page-file failures
# from cascading into 15+ redundant timeouts (one per family × retry).
_AVAILABILITY_CACHE: tuple[bool, str, str | None] | None = None
_SUBPROCESS_DISABLED: bool = False
_SUBPROCESS_DISABLED_REASON: str = ""


def _disable_subprocess(reason: str) -> None:
    """Trip the subprocess circuit breaker; later calls skip the shell-out."""
    global _SUBPROCESS_DISABLED, _SUBPROCESS_DISABLED_REASON
    if _SUBPROCESS_DISABLED:
        return
    _SUBPROCESS_DISABLED = True
    _SUBPROCESS_DISABLED_REASON = reason
    hint = ""
    if "WinError 1455" in reason or "paging file" in reason.lower():
        hint = (
            " · Windows page file exhausted; close Ollama/Neo4j or run with "
            "--skip-llm to skip Phase 3 LLM rule generation."
        )
    logger.warning(
        "Semgrep subprocess disabled for remainder of run: %s%s", reason, hint,
    )

_PATTERN_KEYS = frozenset({
    "pattern",
    "patterns",
    "pattern-either",
    "pattern-regex",
    "pattern-sources",
    "pattern-sinks",
    "match",
    "matches",
})


def semgrep_search_paths() -> list[str]:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return [
        os.path.join(base, "venv", "Scripts", "semgrep.exe"),
        os.path.join(base, "venv", "bin", "semgrep"),
    ]


def find_semgrep() -> str | None:
    """Locate the semgrep binary."""
    return find_tool("semgrep", semgrep_search_paths())


def semgrep_cmd(semgrep_exe: str | None = None) -> list[str]:
    """Build argv for Semgrep; fall back to ``python -m semgrep`` when needed."""
    if semgrep_exe:
        return [semgrep_exe]
    return [sys.executable, "-m", "semgrep"]


def check_semgrep_available() -> tuple[bool, str, str | None]:
    """Verify Semgrep is installed and responds to ``--version``.

    Returns ``(ok, detail_message, semgrep_exe)``.

    The result is cached for the lifetime of the process so callers can probe
    cheaply inside hot loops (rule generation, retries) without re-spawning
    a subprocess every time.
    """
    global _AVAILABILITY_CACHE
    if _AVAILABILITY_CACHE is not None:
        return _AVAILABILITY_CACHE

    semgrep_exe = find_semgrep()
    if not semgrep_exe:
        paths = semgrep_search_paths()
        hint = "\n".join(f"           {p}" for p in paths)
        result = (
            False,
            "semgrep not found. Install with: pip install semgrep\n"
            "         If already installed, ensure Python Scripts is on PATH:\n"
            f"{hint}",
            None,
        )
        _AVAILABILITY_CACHE = result
        return result

    if _SUBPROCESS_DISABLED:
        result = (
            False,
            f"semgrep subprocess disabled: {_SUBPROCESS_DISABLED_REASON}",
            semgrep_exe,
        )
        _AVAILABILITY_CACHE = result
        return result

    cmd = semgrep_cmd(semgrep_exe) + ["--version"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            env=tool_subprocess_env(),
        )
    except subprocess.TimeoutExpired as exc:
        _disable_subprocess(f"semgrep --version timed out after {exc.timeout}s")
        result = (False, f"semgrep --version timed out after {exc.timeout}s", semgrep_exe)
        _AVAILABILITY_CACHE = result
        return result
    except OSError as exc:
        _disable_subprocess(f"semgrep --version failed to spawn: {exc}")
        result = (False, f"semgrep --version failed to spawn: {exc}", semgrep_exe)
        _AVAILABILITY_CACHE = result
        return result

    detail = (proc.stdout or proc.stderr or "").strip()
    if proc.returncode != 0:
        # Detect Windows paging-file errors in stderr and trip the breaker so
        # we don't retry 15× more.
        if "WinError 1455" in detail or "paging file" in detail.lower():
            _disable_subprocess(detail.splitlines()[0] if detail else "WinError 1455")
        result = (
            False,
            f"semgrep found at {semgrep_exe} but --version failed "
            f"(exit {proc.returncode}): {detail or 'no output'}",
            semgrep_exe,
        )
        _AVAILABILITY_CACHE = result
        return result
    version_line = detail.splitlines()[0] if detail else "unknown version"
    result = (True, version_line, semgrep_exe)
    _AVAILABILITY_CACHE = result
    return result


def reset_semgrep_cache() -> None:
    """Clear cached availability + circuit breaker (used in tests)."""
    global _AVAILABILITY_CACHE, _SUBPROCESS_DISABLED, _SUBPROCESS_DISABLED_REASON
    _AVAILABILITY_CACHE = None
    _SUBPROCESS_DISABLED = False
    _SUBPROCESS_DISABLED_REASON = ""


def validate_rule_schema(parsed: Any) -> tuple[bool, str]:
    """Fast structural check before invoking the Semgrep CLI."""
    if not isinstance(parsed, dict):
        return False, "top-level YAML must be a mapping"

    rules = parsed.get("rules")
    if not isinstance(rules, list) or not rules:
        return False, "missing non-empty top-level 'rules' list"

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            return False, f"rules[{idx}] must be a mapping"

        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            return False, f"rules[{idx}] missing string 'id'"

        languages = rule.get("languages")
        if not isinstance(languages, list) or not languages:
            return False, f"rules[{idx}] ({rule_id}) missing non-empty 'languages' list"

        if rule.get("mode") == "taint":
            if not rule.get("pattern-sources") and not rule.get("pattern-sinks"):
                return False, (
                    f"rules[{idx}] ({rule_id}) taint mode requires "
                    "pattern-sources or pattern-sinks"
                )
            continue

        if not any(key in rule for key in _PATTERN_KEYS):
            return False, (
                f"rules[{idx}] ({rule_id}) missing a Semgrep pattern "
                "(pattern, patterns, pattern-either, ...)"
            )

    return True, ""


def validate_rule_yaml(raw: str) -> tuple[bool, str]:
    """Validate raw Semgrep rule YAML text (schema only)."""
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        return False, f"invalid YAML: {exc}"
    if not parsed:
        return False, "empty YAML output"
    return validate_rule_schema(parsed)


def validate_rule_file(
    rule_path: str,
    semgrep_exe: str | None = None,
) -> tuple[bool, str]:
    """Validate a rule file with schema checks and ``semgrep --validate``."""
    if not rule_path or not os.path.exists(rule_path):
        return False, f"rule file not found: {rule_path}"

    try:
        with open(rule_path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        return False, f"cannot read rule file: {exc}"

    ok, err = validate_rule_yaml(raw)
    if not ok:
        return False, err

    exe = semgrep_exe or find_semgrep()
    if not exe:
        return False, "semgrep not installed (cannot run --validate)"

    # Circuit breaker: if a previous spawn failed due to OS-level resource
    # exhaustion (e.g. Windows paging file), don't keep trying — fall back
    # to the schema check we already ran above.
    if _SUBPROCESS_DISABLED:
        return True, f"schema-only (subprocess disabled: {_SUBPROCESS_DISABLED_REASON})"

    cmd = semgrep_cmd(exe) + ["--validate", "--config", rule_path]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            env=tool_subprocess_env(),
        )
    except subprocess.TimeoutExpired as exc:
        _disable_subprocess(f"semgrep --validate timed out after {exc.timeout}s")
        return True, f"schema-only (semgrep --validate timed out after {exc.timeout}s)"
    except OSError as exc:
        _disable_subprocess(f"semgrep --validate failed to spawn: {exc}")
        return True, f"schema-only (semgrep --validate failed to spawn: {exc})"

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        if "WinError 1455" in detail or "paging file" in detail.lower():
            _disable_subprocess(detail.splitlines()[0] if detail else "WinError 1455")
            return True, "schema-only (Windows paging file exhausted)"
        first_lines = "\n".join(detail.splitlines()[:5])
        return False, f"semgrep --validate failed: {first_lines or 'no output'}"

    return True, ""


def semgrep_example_template(rule_id: str, language: str) -> str:
    """Return a minimal valid Semgrep rule template for LLM prompts."""
    return (
        "rules:\n"
        f"  - id: {rule_id}\n"
        f"    languages: [{language}]\n"
        "    message: Detect vulnerable pattern\n"
        "    severity: ERROR\n"
        "    pattern: $FUNC(...)\n"
    )
