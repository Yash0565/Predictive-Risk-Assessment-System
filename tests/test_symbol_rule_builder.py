"""Tests for patch-aware Semgrep sink rule generation."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.semgrep_tools import check_semgrep_available
from src.symbol_rule_builder import (
    build_symbol_rule_yaml,
    collect_sink_patterns,
    enrich_rules_with_patch_sinks,
    import_alias_to_pattern,
    normalize_package,
    write_symbol_rule,
)


def test_normalize_package() -> None:
    assert normalize_package("PyYAML") == "pyyaml"
    assert normalize_package("requests") == "requests"


def test_import_alias_to_pattern() -> None:
    assert import_alias_to_pattern("from yaml import load") == "load(...)"
    assert import_alias_to_pattern("from requests.utils import rebuild_auth") == "rebuild_auth(...)"


def test_collect_sink_patterns_from_packages_and_aliases() -> None:
    cluster = SimpleNamespace(
        cves=[
            {"cve": "CVE-2020-1747", "package": "PyYAML"},
            {"cve": "CVE-2023-32681", "package": "requests"},
        ],
    )
    patches = {
        "CVE-2020-1747": {
            "import_aliases": ["from yaml import load"],
            "vulnerable_symbols": [],
        },
        "CVE-2023-32681": {
            "import_aliases": ["from requests.utils import rebuild_auth"],
            "vulnerable_symbols": [],
        },
    }
    cve_to_pkg = {
        "CVE-2020-1747": "PyYAML",
        "CVE-2023-32681": "requests",
    }
    patterns = collect_sink_patterns(cluster, patches, cve_to_pkg)
    assert "yaml.load(...)" in patterns
    assert "load(...)" in patterns
    assert "rebuild_auth(...)" in patterns


def test_build_symbol_rule_yaml_structure() -> None:
    raw = build_symbol_rule_yaml("deserialization", "python", ["yaml.load(...)"])
    assert "rules:" in raw
    assert "pattern-either:" in raw
    assert "yaml.load(...)" in raw


def test_write_symbol_rule_validates_with_semgrep(tmp_path) -> None:
    ok, _, semgrep_exe = check_semgrep_available()
    if not semgrep_exe:
        pytest.skip("semgrep not installed")

    path = write_symbol_rule(
        "deserialization",
        "python",
        ["yaml.load(...)"],
        str(tmp_path),
    )
    assert path
    assert path.endswith("_sinks.yaml")


def test_enrich_rules_replaces_registry_with_symbol_rules(tmp_path) -> None:
    ok, _, semgrep_exe = check_semgrep_available()
    if not semgrep_exe:
        pytest.skip("semgrep not installed")

    families = {
        "input_validation": SimpleNamespace(
            cwe_ids={"CWE-20"},
            cves=["CVE-2020-1747"],
            packages={"PyYAML"},
        ),
    }
    resolved = {
        "input_validation": {
            "source": "registry",
            "rule_path": "semgrep-rules\\fake.yaml",
            "cwe_ids": ["CWE-20"],
        },
    }
    patches = {"CVE-2020-1747": {"import_aliases": ["from yaml import load"]}}
    cve_to_pkg = {"CVE-2020-1747": "PyYAML"}

    enriched = enrich_rules_with_patch_sinks(
        families,
        resolved,
        patches,
        cve_to_pkg,
        str(tmp_path),
        "python",
    )
    assert enriched["input_validation"]["source"] == "symbol"
    assert enriched["input_validation"]["rule_path"].endswith("_sinks.yaml")
