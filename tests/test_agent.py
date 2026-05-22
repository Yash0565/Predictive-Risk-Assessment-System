"""Tests for the ReAct agent (mocked LLM — no Ollama required)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from src.agent import (
    LLMResponseError,
    compress_scratchpad,
    parse_agent_response,
    run_agent,
    scripted_fallback,
    validate_response,
    _detect_loop,
)
from src.tool_registry import ALLOWED_TOOLS, apply_target_repo_path, execute_tool

TASKFLOW = Path(__file__).resolve().parent.parent / "vulnerable-task-tracker"


def _valid_step(tool: str, args: dict, thought: str = "reasoning", done: bool = False) -> dict:
    return {
        "thought": thought,
        "action": {"tool": tool, "args": args},
        "done": done,
    }


@pytest.fixture
def agent_state(tmp_path: Path) -> dict:
    return {
        "target_repo": str(TASKFLOW.resolve()),
        "output_dir": str(tmp_path),
        "collected_data": {
            "dependencies": {"requests": "2.20.0", "flask": "0.12"},
            "cves": [
                {
                    "cve": "CVE-2023-32681",
                    "cve_id": "CVE-2023-32681",
                    "package": "requests",
                    "installed_version": "2.20.0",
                    "fixed_version": "2.31.0",
                    "cvss_score": 6.1,
                }
            ],
            "patches": {},
            "symbol_findings": {},
            "upgrade_simulations": {},
            "scores": {},
        },
    }


def test_parse_agent_response_valid() -> None:
    raw = _valid_step("list_dependencies", {"repo_path": "/tmp/proj"})
    parsed = parse_agent_response(raw)
    assert parsed.action.tool == "list_dependencies"
    assert parsed.done is False


def test_validate_response_rejects_unknown_tool(agent_state: dict) -> None:
    raw = _valid_step("run_arbitrary_shell", {"cmd": "rm -rf /"})
    ok, err = validate_response(raw, [], list(ALLOWED_TOOLS), agent_state)
    assert not ok
    assert "whitelist" in err.lower() or "not in" in err.lower()


def test_validate_response_entity_whitelist(agent_state: dict) -> None:
    raw = _valid_step(
        "fetch_patch",
        {"cve_id": "CVE-9999-00000"},
        thought="Fetching CVE-9999-00000",
    )
    ok, err = validate_response(raw, [{"step": 1}], list(ALLOWED_TOOLS), agent_state)
    assert not ok
    assert "CVE-9999" in err or "Unknown" in err


def test_validate_response_ignores_hallucinated_cve_in_thought_only(agent_state: dict) -> None:
    """Thought text is not entity-checked; only tool args are."""
    raw = _valid_step(
        "fetch_patch",
        {"cve_id": "CVE-2023-32681"},
        thought="Also consider CVE-2019-1000001 which is not real",
    )
    ok, err = validate_response(raw, [{"step": 1}], list(ALLOWED_TOOLS), agent_state)
    assert ok, err


def test_apply_target_repo_path_overrides_placeholder(agent_state: dict) -> None:
    target = agent_state["target_repo"]
    fixed = apply_target_repo_path(
        "list_dependencies",
        {"repo_path": "path/to/project"},
        target,
    )
    assert Path(fixed["repo_path"]).resolve() == Path(target).resolve()


@mock.patch("src.agent.call_llm")
def test_llm_placeholder_repo_path_still_scans_target(
    mock_llm: mock.MagicMock,
    tmp_path: Path,
) -> None:
    if not TASKFLOW.is_dir():
        pytest.skip("TaskFlow demo not present")
    repo = str(TASKFLOW.resolve())
    mock_llm.side_effect = [
        _valid_step("list_dependencies", {"repo_path": "path/to/project"}, "deps"),
        _valid_step("finish", {"summary": "stop early"}, "done", done=True),
    ]
    result = run_agent(
        repo,
        verbose=False,
        fallback_on_error=False,
        max_steps=5,
        output_dir=str(tmp_path),
    )
    trace = result["trace"]
    assert trace[0]["action"]["args"]["repo_path"] == repo
    assert result["collected_data"].get("dependencies")


def test_validate_response_allows_exempt_tools(agent_state: dict) -> None:
    raw = _valid_step("list_dependencies", {"repo_path": str(TASKFLOW)})
    ok, err = validate_response(raw, [], list(ALLOWED_TOOLS), agent_state)
    assert ok, err


def test_compress_scratchpad_keeps_recent_verbatim() -> None:
    pad = []
    for i in range(8):
        pad.append({
            "step": i + 1,
            "thought": f"thought {i}",
            "action": {"tool": "fetch_patch", "args": {"cve_id": f"CVE-2020-{i:05d}"}},
            "result_summary": f"result {i}",
        })
    text = compress_scratchpad(pad)
    assert "thought 7" in text
    assert "Step 1: fetch_patch" in text or "Step 1:" in text


def test_detect_loop() -> None:
    pad = [
        {"action": {"tool": "fetch_patch", "args": {"cve_id": "CVE-2023-32681"}}},
        {"action": {"tool": "fetch_patch", "args": {"cve_id": "CVE-2023-32681"}}},
    ]
    hint = _detect_loop(pad)
    assert hint is not None
    assert "already called" in hint


def test_list_dependencies_tool(agent_state: dict) -> None:
    if not TASKFLOW.is_dir():
        pytest.skip("TaskFlow demo not present")
    _, summary = execute_tool(
        "list_dependencies",
        {"repo_path": str(TASKFLOW)},
        agent_state,
    )
    assert "packages" in summary.lower() or "Found" in summary
    assert agent_state["collected_data"]["dependencies"]


def test_scripted_fallback_produces_report(tmp_path: Path) -> None:
    if not TASKFLOW.is_dir():
        pytest.skip("TaskFlow demo not present")
    result = scripted_fallback(str(TASKFLOW), verbose=False, output_dir=str(tmp_path))
    assert result["agent_metadata"]["fallback_used"] is True
    assert result["status"] == "completed_with_fallback"
    assert result["trace"]
    report = result.get("report_path") or ""
    if report:
        assert Path(report).is_file()


@mock.patch("src.agent.call_llm")
def test_mock_llm_complete_loop(mock_llm: mock.MagicMock, tmp_path: Path) -> None:
    if not TASKFLOW.is_dir():
        pytest.skip("TaskFlow demo not present")
    repo = str(TASKFLOW.resolve())
    sequence = [
        _valid_step("list_dependencies", {"repo_path": repo}, "Need deps"),
        _valid_step("scan_vulnerabilities", {"repo_path": repo}, "Need CVEs"),
        _valid_step("fetch_patch", {"cve_id": "CVE-2018-18074"}, "Patch for requests"),
        _valid_step(
            "find_symbol_usage",
            {"repo_path": repo, "vulnerable_symbols": ["CVE-2018-18074"]},
            "Check usage",
        ),
        _valid_step(
            "simulate_upgrade",
            {"repo_path": repo, "package": "requests", "target_version": "2.31.0"},
            "Simulate upgrade",
        ),
        _valid_step("compute_score", {"collected_data": {}}, "Score"),
        _valid_step("generate_report", {"collected_data": {}}, "Report"),
        _valid_step("finish", {"summary": "Done"}, "Finish", done=True),
    ]
    mock_llm.side_effect = sequence

    result = run_agent(
        repo,
        verbose=False,
        fallback_on_error=False,
        output_dir=str(tmp_path),
        max_steps=12,
    )
    assert result["agent_metadata"]["fallback_used"] is False
    assert mock_llm.call_count >= 7
    assert result.get("final_summary")


@mock.patch(
    "src.agent.call_llm",
    side_effect=LLMResponseError(
        "Ollama chat failed: 500 Server Error: Internal Server Error for url: "
        "http://localhost:11434/api/chat"
    ),
)
def test_ollama_500_falls_back_immediately(mock_llm: mock.MagicMock, tmp_path: Path) -> None:
    if not TASKFLOW.is_dir():
        pytest.skip("TaskFlow demo not present")
    result = run_agent(
        str(TASKFLOW),
        verbose=False,
        output_dir=str(tmp_path),
        max_steps=15,
    )
    assert result["agent_metadata"]["fallback_used"] is True
    assert mock_llm.call_count >= 1


@mock.patch("src.agent.call_llm", side_effect=LLMResponseError("down"))
def test_llm_unreachable_falls_back(mock_llm: mock.MagicMock, tmp_path: Path) -> None:
    if not TASKFLOW.is_dir():
        pytest.skip("TaskFlow demo not present")
    result = run_agent(
        str(TASKFLOW),
        verbose=False,
        output_dir=str(tmp_path),
        max_steps=3,
    )
    assert result["agent_metadata"]["fallback_used"] is True


def test_adversarial_tool_rejected(agent_state: dict) -> None:
    raw = {
        "thought": "I will delete files",
        "action": {"tool": "os_system", "args": {"cmd": "format c:"}},
        "done": False,
    }
    ok, msg = validate_response(raw, [], list(ALLOWED_TOOLS), agent_state)
    assert not ok
