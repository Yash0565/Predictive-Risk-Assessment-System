"""Integrity guard: fail CI if curated/demo overlays or magic constants return.

This test encodes the core promise of the redesign -- that risk intelligence is
derived from live sources and a versioned model, not hand-maintained answer keys
or package-specific heuristics. If any of these patterns reappear, the build
breaks and the contradiction with the documentation is caught immediately.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"


def _read(name: str) -> str:
    return (SRC / name).read_text(encoding="utf-8")


# (file, forbidden regex, human reason)
FORBIDDEN = [
    ("patch_fetcher.py", r"_DEMO_API_SYMBOLS", "curated per-CVE symbol answer-key"),
    ("patch_fetcher.py", r"_DEMO_COMMIT_HINTS", "curated per-CVE commit answer-key"),
    ("patch_fetcher.py", r"_PACKAGE_IMPORT_ROOT\s*[:=]", "hardcoded package->import map"),
    ("upgrade_simulator.py", r"order_hint\s*=", "hardcoded cascade ordering allow-list"),
    ("upgrade_simulator.py", r"sample_versions\s*=\s*\[", "hardcoded sample version list"),
    ("scorer.py", r"(?:risk|score)\s*\+=\s*\d", "additive point heuristic"),
]


@pytest.mark.parametrize("filename,pattern,reason", FORBIDDEN)
def test_no_forbidden_overlay(filename: str, pattern: str, reason: str) -> None:
    src = _read(filename)
    assert not re.search(pattern, src), (
        f"{filename}: reintroduced {reason!r} (pattern /{pattern}/). "
        "Risk intelligence must come from live sources / the versioned model, "
        "not curated overlays."
    )


def test_no_package_specific_versions_in_upgrade_logic() -> None:
    """No package-name + literal-version pairs baked into cascade/resolution code."""
    src = _read("upgrade_simulator.py")
    # e.g. 'boto3' ... "1.26.0" or "to": "1.28.0" hardcoded next to a known package name.
    offenders = re.findall(r'"(?:boto3|botocore|urllib3|s3transfer)"\s*[,:]\s*"\d+\.\d+', src)
    assert not offenders, f"Hardcoded package->version literals found: {offenders}"


def test_scorer_loads_external_model() -> None:
    """Scoring parameters must come from the versioned model file, not literals."""
    src = _read("scorer.py")
    assert "load_model" in src
    assert "scoring_model.json" in src


def test_scoring_model_file_exists_and_is_versioned() -> None:
    model_path = SRC.parent / "data" / "scoring_model.json"
    assert model_path.is_file(), "data/scoring_model.json must exist"
    import json

    model = json.loads(model_path.read_text(encoding="utf-8"))
    assert "model_version" in model
    for section in ("exploitability", "impact", "reachability", "blast", "asset", "thresholds"):
        assert section in model, f"scoring model missing '{section}' section"


def test_graph_hop_limit_is_model_driven() -> None:
    """Reachability search depth must come from the model, not magic literals."""
    src = _read("graph_queries.py")
    assert "max_call_hops" in src, "graph hop depth must be model-driven"
    # The Neo4j Cypher must use the sentinel, not a baked-in numeric depth.
    assert "*0..__HOPS__" in src
    assert "*0..10" not in src and "*0..15" not in src, (
        "graph hop depth literals must be substituted from the scoring model"
    )

    model_path = SRC.parent / "data" / "scoring_model.json"
    import json

    model = json.loads(model_path.read_text(encoding="utf-8"))
    assert "max_call_hops" in model["reachability"], (
        "scoring model 'reachability' must define max_call_hops"
    )


def test_report_formula_matches_probabilistic_model() -> None:
    """The report's audit formula must describe the live multiplicative model."""
    src = _read("html_reporter_v2.py")
    # Stale additive scorer text must not return.
    assert "sum of components" not in src
    assert "severity_score    = clamp" not in src
    # And it must reference the expected-loss / risk_unit model.
    assert "risk_unit" in src
