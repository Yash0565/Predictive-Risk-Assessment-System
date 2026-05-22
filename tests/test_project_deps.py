"""Tests for src.project_deps dependency discovery."""

from __future__ import annotations

import textwrap

import pytest

from src.project_deps import DependencyDiscoveryError, discover_dependency_pins


def test_discover_requirements_txt(tmp_path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\n# comment\nflask==3.0.0\n",
        encoding="utf-8",
    )
    pins, src = discover_dependency_pins(tmp_path)
    assert src == "requirements.txt"
    assert pins["requests"] == "2.31.0"
    assert pins["flask"] == "3.0.0"


def test_pyproject_used_when_no_requirements(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        textwrap.dedent(
            """\
            [project]
            name = "demo"
            version = "0.1.0"
            dependencies = [
              "requests==2.31.0",
            ]
            """
        ),
        encoding="utf-8",
    )
    pins, src = discover_dependency_pins(tmp_path)
    assert "pyproject" in src
    assert pins["requests"] == "2.31.0"


def test_requirements_txt_wins_over_pyproject(tmp_path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.20.0\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\nversion="1"\ndependencies=["requests==9.9.9"]\n',
        encoding="utf-8",
    )
    pins, src = discover_dependency_pins(tmp_path)
    assert src == "requirements.txt"
    assert pins["requests"] == "2.20.0"


def test_raises_when_no_dependency_files(tmp_path) -> None:
    with pytest.raises(DependencyDiscoveryError):
        discover_dependency_pins(tmp_path)
