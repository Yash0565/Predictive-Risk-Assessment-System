"""Resolve PyPI distribution names to their importable top-level module roots.

Replaces the previously hardcoded ``_PACKAGE_IMPORT_ROOT`` map in
``patch_fetcher.py``. Import roots are derived, in order of preference, from:

1. Installed distribution metadata (``top_level.txt`` / ``RECORD``) via
   ``importlib.metadata`` -- the authoritative source for the local environment.
2. The reverse of ``importlib.metadata.packages_distributions()``.
3. An on-disk learned cache (``data/import_roots.json``) so a root discovered
   once (online or in another environment) is reused offline.
4. A PEP 503 name-normalization fallback (``Foo-Bar`` -> ``foo_bar``).

No package-specific rules are baked into the code.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CACHE_PATH = _REPO_ROOT / "data" / "import_roots.json"

_lock = threading.Lock()
_cache: Optional[dict[str, list[str]]] = None
_reverse_index: Optional[dict[str, list[str]]] = None


def _normalize(name: str) -> str:
    """PEP 503 normalization (lowercase, runs of -_. collapse to a single -)."""
    return re.sub(r"[-_.]+", "-", name or "").lower().strip("-")


def _name_fallback(package: str) -> str:
    """Best-effort import name when no metadata is available."""
    return _normalize(package).replace("-", "_")


def _load_disk_cache() -> dict[str, list[str]]:
    if not _CACHE_PATH.is_file():
        return {}
    try:
        with _CACHE_PATH.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return {k: list(v) for k, v in data.items() if isinstance(v, list)}
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read import-root cache: %s", exc)
    return {}


def _save_disk_cache(cache: dict[str, list[str]]) -> None:
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _CACHE_PATH.open("w", encoding="utf-8") as fh:
            json.dump(dict(sorted(cache.items())), fh, indent=2, sort_keys=True)
            fh.write("\n")
    except OSError as exc:
        logger.warning("Could not write import-root cache: %s", exc)


def _build_reverse_index() -> dict[str, list[str]]:
    """Map normalized distribution name -> [import roots] from the live env."""
    index: dict[str, set[str]] = {}
    # packages_distributions(): import_name -> [dist_names] (Python 3.10+).
    try:
        for import_name, dists in importlib_metadata.packages_distributions().items():
            top = import_name.split(".")[0]
            for dist in dists:
                index.setdefault(_normalize(dist), set()).add(top)
    except Exception as exc:  # pragma: no cover - environment dependent
        logger.debug("packages_distributions() unavailable: %s", exc)
    return {k: sorted(v) for k, v in index.items()}


def _roots_from_top_level(package: str) -> list[str]:
    """Read top-level module names straight from the distribution's metadata."""
    try:
        dist = importlib_metadata.distribution(package)
    except importlib_metadata.PackageNotFoundError:
        return []
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("distribution(%s) failed: %s", package, exc)
        return []

    roots: list[str] = []
    try:
        top_level = dist.read_text("top_level.txt")
    except Exception:
        top_level = None
    if top_level:
        for line in top_level.splitlines():
            mod = line.strip()
            if mod and not mod.startswith("_") and "/" not in mod:
                roots.append(mod.split(".")[0])

    if not roots:
        # Derive from RECORD: any first path segment that ships an __init__.py
        try:
            for record_file in dist.files or []:
                parts = record_file.parts
                if len(parts) >= 2 and parts[-1] == "__init__.py":
                    seg = parts[0]
                    if not seg.endswith((".dist-info", ".data")) and not seg.startswith("_"):
                        roots.append(seg)
        except Exception:  # pragma: no cover - defensive
            pass

    # Stable de-dup preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for r in roots:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def import_roots(package: str) -> list[str]:
    """Return the importable top-level module names for a PyPI distribution.

    Always returns at least one candidate (the normalized fallback) so callers
    never have to special-case an empty result.
    """
    global _cache, _reverse_index
    norm = _normalize(package)
    if not norm:
        return []

    with _lock:
        if _cache is None:
            _cache = _load_disk_cache()
        if norm in _cache and _cache[norm]:
            return list(_cache[norm])

        roots = _roots_from_top_level(package)

        if not roots:
            if _reverse_index is None:
                _reverse_index = _build_reverse_index()
            roots = list(_reverse_index.get(norm, []))

        if not roots:
            roots = [_name_fallback(package)]
        else:
            _cache[norm] = roots
            _save_disk_cache(_cache)

        return list(roots)


def primary_import_root(package: str) -> str:
    """Return the single most likely import root (first candidate)."""
    roots = import_roots(package)
    return roots[0] if roots else _name_fallback(package)
