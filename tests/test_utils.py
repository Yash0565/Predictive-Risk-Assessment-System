"""Tests for shared utility helpers."""

from __future__ import annotations

import os
import sys

from src.utils import find_tool, python_scripts_dirs, tool_subprocess_env


def test_python_scripts_dirs_includes_user_scripts_on_windows() -> None:
    dirs = python_scripts_dirs()
    assert dirs
    if sys.platform == "win32":
        assert any(d.lower().endswith("\\scripts") for d in dirs)


def test_find_tool_discovers_semgrep_in_python_scripts() -> None:
    exe = find_tool("semgrep")
    if exe is None:
        return
    assert os.path.isfile(exe)
    assert exe.lower().endswith(("semgrep", "semgrep.exe"))


def test_tool_subprocess_env_prepends_scripts_to_path() -> None:
    env = tool_subprocess_env()
    path = env.get("PATH", "")
    scripts = python_scripts_dirs()
    if scripts:
        assert scripts[0] in path.split(os.pathsep)
