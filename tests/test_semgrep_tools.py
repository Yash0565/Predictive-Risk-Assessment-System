"""Tests for Semgrep discovery and rule validation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.semgrep_tools import (
    check_semgrep_available,
    validate_rule_file,
    validate_rule_schema,
    validate_rule_yaml,
)

GOOD_RULE = """\
rules:
  - id: test-yaml-load
    languages: [python]
    message: Unsafe yaml.load
    severity: ERROR
    pattern: yaml.load(...)
"""

BAD_RULE_NO_RULES_KEY = """\
detect-test:
  languages: [python]
  pattern: foo(...)
"""

BAD_RULE_MISSING_PATTERN = """\
rules:
  - id: incomplete-rule
    languages: [python]
    message: missing pattern
    severity: ERROR
"""


def test_validate_rule_schema_accepts_minimal_rule() -> None:
    import yaml

    parsed = yaml.safe_load(GOOD_RULE)
    ok, err = validate_rule_schema(parsed)
    assert ok, err


def test_validate_rule_schema_rejects_non_semgrep_yaml() -> None:
    import yaml

    parsed = yaml.safe_load(BAD_RULE_NO_RULES_KEY)
    ok, err = validate_rule_schema(parsed)
    assert not ok
    assert "rules" in err


def test_validate_rule_schema_rejects_rule_without_pattern() -> None:
    import yaml

    parsed = yaml.safe_load(BAD_RULE_MISSING_PATTERN)
    ok, err = validate_rule_schema(parsed)
    assert not ok
    assert "pattern" in err.lower()


def test_validate_rule_yaml_good_and_bad() -> None:
    ok, err = validate_rule_yaml(GOOD_RULE)
    assert ok, err

    ok, err = validate_rule_yaml(BAD_RULE_NO_RULES_KEY)
    assert not ok


def test_validate_rule_file_demo_rule(tmp_path: Path) -> None:
    ok, _, semgrep_exe = check_semgrep_available()
    if not semgrep_exe:
        pytest.skip("semgrep not installed")

    demo_rule = Path("demo_rules/deserialization_python.yaml")
    if not demo_rule.exists():
        pytest.skip("demo_rules/deserialization_python.yaml missing")

    ok, err = validate_rule_file(str(demo_rule), semgrep_exe=semgrep_exe)
    assert ok, err


def test_validate_rule_file_rejects_invalid_yaml(tmp_path: Path) -> None:
    ok, _, semgrep_exe = check_semgrep_available()
    if not semgrep_exe:
        pytest.skip("semgrep not installed")

    bad_path = tmp_path / "bad_rule.yaml"
    bad_path.write_text(BAD_RULE_NO_RULES_KEY, encoding="utf-8")

    ok, err = validate_rule_file(str(bad_path), semgrep_exe=semgrep_exe)
    assert not ok
    assert err


def test_check_semgrep_available() -> None:
    ok, detail, exe = check_semgrep_available()
    if ok:
        assert exe
        assert os.path.isfile(exe)
        assert detail
    else:
        assert "semgrep not found" in detail.lower() or "failed" in detail.lower()
