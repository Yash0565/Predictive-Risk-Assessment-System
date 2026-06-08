"""Tests for the cross-file call graph and reachability path-finding."""

from __future__ import annotations

from pathlib import Path

from src.call_graph import build_call_graph, reachable_to_symbol

FIXT = Path(__file__).resolve().parent / "fixtures" / "call_graph"


def test_cross_file_edges_resolved() -> None:
    cg = build_call_graph(str(FIXT))
    assert "app.run_job" in cg.nodes
    assert "helpers.process" in cg.nodes
    # Cross-module edge: app.run_job -> helpers.process
    assert "helpers.process" in cg.successors("app.run_job")
    # Same-module edge: helpers.process -> helpers.load_config
    assert "helpers.load_config" in cg.successors("helpers.process")


def test_entry_points_marked() -> None:
    cg = build_call_graph(str(FIXT))
    assert cg.nodes["app.run_job"].is_entry_point
    assert cg.nodes["app.run_job"].route == "/run"
    assert cg.nodes["app.run_job"].method == "POST"


def test_reachable_to_external_symbol_with_taint() -> None:
    cg = build_call_graph(str(FIXT))
    paths = reachable_to_symbol(cg, "yaml.load")
    assert paths, "expected a reachable path from an entry point to yaml.load"
    p = paths[0]
    assert p["entry_point"] == "app.run_job"
    assert p["path"][0] == "app.run_job"
    assert p["path"][-1] == "ext::yaml.load"
    assert p["hops"] == 3
    # Entry-point inputs are attacker-controlled -> path is tainted.
    assert p["tainted"] is True


def test_unreachable_symbol_returns_no_path() -> None:
    cg = build_call_graph(str(FIXT))
    # yaml.safe_load is only called from unused_safe(), which no entry point reaches.
    assert reachable_to_symbol(cg, "yaml.safe_load") == []
