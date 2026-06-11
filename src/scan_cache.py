"""Incremental, content-addressed scan cache.

Scan results are keyed by the SHA-256 of the file's bytes combined with the tool
name and tool version. Unchanged files (identical content) hit the cache, so
re-scanning a large repo only does work for what actually changed -- the basis
for fast incremental CI runs and for a content-addressed result store in a SaaS
backend. Because the key is content (not path/mtime), a moved or reverted file
reuses prior results correctly.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Callable, Iterable


def file_digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def cache_key(path: str, tool: str, tool_version: str) -> str:
    digest = file_digest(path)
    return hashlib.sha256(f"{tool}@{tool_version}:{digest}".encode("utf-8")).hexdigest()


class ScanCache:
    def __init__(self, cache_dir: str) -> None:
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def _entry_path(self, key: str) -> str:
        return os.path.join(self.cache_dir, f"{key}.json")

    def get(self, key: str) -> Any:
        p = self._entry_path(key)
        if not os.path.exists(p):
            return None
        try:
            with open(p, "r", encoding="utf-8") as fh:
                return json.load(fh)["result"]
        except (json.JSONDecodeError, KeyError, OSError):
            return None

    def put(self, key: str, result: Any) -> None:
        with open(self._entry_path(key), "w", encoding="utf-8") as fh:
            json.dump({"key": key, "result": result}, fh, indent=2)

    def scan_incremental(
        self,
        paths: Iterable[str],
        tool: str,
        tool_version: str,
        scan_fn: Callable[[str], Any],
    ) -> dict[str, Any]:
        """Scan only changed files; reuse cached results for unchanged content.

        Returns a report with per-file results and hit/miss statistics.
        """
        results: dict[str, Any] = {}
        hits = misses = 0
        for path in paths:
            if not os.path.isfile(path):
                continue
            key = cache_key(path, tool, tool_version)
            cached = self.get(key)
            if cached is not None:
                hits += 1
                results[path] = cached
            else:
                misses += 1
                result = scan_fn(path)
                self.put(key, result)
                results[path] = result
        total = hits + misses
        return {
            "results": results,
            "stats": {
                "files": total,
                "cache_hits": hits,
                "cache_misses": misses,
                "hit_rate": round(hits / total, 4) if total else 0.0,
            },
        }
