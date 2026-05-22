"""Small, reusable helpers shared across pipeline modules."""

import os
import shutil
import site
import sys
import sysconfig

from src.config import LANG_MAP, SKIP_DIRS


def python_scripts_dirs() -> list[str]:
    """Return likely ``Scripts`` directories for the active Python install."""
    dirs: list[str] = []
    scripts = sysconfig.get_path("scripts")
    if scripts and os.path.isdir(scripts):
        dirs.append(scripts)
    try:
        user_site = site.getusersitepackages()
        user_scripts = os.path.join(os.path.dirname(user_site), "Scripts")
        if os.path.isdir(user_scripts):
            dirs.append(user_scripts)
    except Exception:
        pass
    deduped: list[str] = []
    for d in dirs:
        norm = os.path.normcase(os.path.abspath(d))
        if norm not in {os.path.normcase(x) for x in deduped}:
            deduped.append(d)
    return deduped


def find_tool(name: str, fallback_paths: list[str] | None = None) -> str | None:
    """Locate a CLI tool on PATH, then Python Scripts dirs, then fallbacks."""
    found = shutil.which(name)
    if found:
        return found

    for scripts in python_scripts_dirs():
        for candidate in (
            os.path.join(scripts, name),
            os.path.join(scripts, f"{name}.exe"),
        ):
            if os.path.isfile(candidate):
                return candidate

    for p in fallback_paths or []:
        if os.path.exists(p):
            return p
    return None


def tool_subprocess_env() -> dict[str, str]:
    """Copy the environment with Python ``Scripts`` dirs prepended to PATH."""
    env = os.environ.copy()
    extra = os.pathsep.join(python_scripts_dirs())
    if extra:
        env["PATH"] = extra + os.pathsep + env.get("PATH", "")
    return env


def detect_language(project_dir):
    """Detect the dominant language by counting source-file extensions."""
    counts = {}
    for root, _, files in os.walk(project_dir):
        if any(skip in root for skip in SKIP_DIRS):
            continue
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in LANG_MAP:
                lang = LANG_MAP[ext]
                counts[lang] = counts.get(lang, 0) + 1
    return max(counts, key=counts.get) if counts else "python"
