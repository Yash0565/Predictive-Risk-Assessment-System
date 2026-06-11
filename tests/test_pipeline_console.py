"""Tests for Rich pipeline terminal output."""

from __future__ import annotations

from src.pipeline_console import configure, print_semgrep_report_table, verdict_style


def test_verdict_style_colors() -> None:
    assert "red" in verdict_style("BLOCK")
    assert "yellow" in verdict_style("REVIEW")
    assert "green" in verdict_style("PROCEED")


def test_print_semgrep_report_table_plain(capsys) -> None:
    configure(plain=True)
    report = [
        {
            "family": "xss",
            "rule_source": "symbol",
            "semgrep_matches": [{"file": "a.py"}],
            "ready_for_codeql": True,
        },
        {
            "family": "injection",
            "rule_source": "registry",
            "semgrep_matches": [],
            "ready_for_codeql": False,
        },
    ]
    print_semgrep_report_table(report)
    out = capsys.readouterr().out
    assert "xss" in out
    assert "Semgrep" in out
