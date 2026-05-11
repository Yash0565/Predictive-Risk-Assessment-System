"""Small, reusable helpers shared across pipeline modules."""

import os
import shutil

from src.config import LANG_MAP, SKIP_DIRS


def find_tool(name, fallback_paths=None):
    """Locate a CLI tool on PATH, then try fallback paths."""
    found = shutil.which(name)
    if found:
        return found
    for p in (fallback_paths or []):
        if os.path.exists(p):
            return p
    return None


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
