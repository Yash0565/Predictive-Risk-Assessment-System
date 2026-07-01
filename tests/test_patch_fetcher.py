"""Tests for src.patch_fetcher — offline-first patch discovery and symbol extraction."""

from __future__ import annotations

import time
from unittest import mock

import pytest

from src.patch_fetcher import (
    fetch_patch,
    fetch_patches_batch,
    get_vulnerable_symbols,
    load_cache,
)

DEMO_CVES = [
    ("CVE-2023-32681", "requests"),
    ("CVE-2019-10906", "jinja2"),
    ("CVE-2020-1747", "pyyaml"),
    ("CVE-2020-5313", "pillow"),
    ("CVE-2018-1000656", "flask"),
    ("CVE-2019-11324", "urllib3"),
    ("CVE-2020-26137", "urllib3"),
    ("CVE-2020-25659", "cryptography"),
]


@pytest.mark.parametrize("cve_id,package", DEMO_CVES)
def test_sample_cve_status_ok_or_partial(cve_id: str, package: str) -> None:
    """Each sample CVE must resolve to ok or partial (never crash)."""
    result = fetch_patch(cve_id, package=package, force_refresh=False)
    assert result["cve_id"] == cve_id
    assert result["status"] in ("ok", "partial")
    assert "vulnerable_symbols" in result
    assert isinstance(result["files_changed"], list)


def test_cve_2023_32681_rebuild_proxies() -> None:
    # The upstream fix (psf/requests 74ea7cf) hardens rebuild_proxies, which is
    # the symbol that leaks Proxy-Authorization across redirects.
    result = fetch_patch("CVE-2023-32681", package="requests", force_refresh=False)
    names = {s["short_name"] for s in result["vulnerable_symbols"]}
    assert "rebuild_proxies" in names


def test_cve_2020_1747_constructor() -> None:
    # PyYAML fix (0cedb2a) replaces the unsafe Constructor with a FullConstructor
    # to stop yaml.load() from building arbitrary Python objects.
    result = fetch_patch("CVE-2020-1747", package="pyyaml", force_refresh=False)
    names = {s["short_name"] for s in result["vulnerable_symbols"]}
    assert "Constructor" in names
    assert "FullConstructor" in names


def test_second_run_uses_cache_and_is_faster() -> None:
    """Second fetch must hit disk cache (no HTTP) and finish quickly."""
    cve_id = "CVE-2023-32681"
    fetch_patch(cve_id, package="requests", force_refresh=False)

    with mock.patch("src.patch_fetcher.requests.get") as mocked_get:
        start = time.perf_counter()
        fetch_patch(cve_id, package="requests", force_refresh=False)
        cached_elapsed = time.perf_counter() - start
        mocked_get.assert_not_called()

    assert cached_elapsed < 0.5


def test_get_vulnerable_symbols_from_cache() -> None:
    symbols = get_vulnerable_symbols("CVE-2020-26137")
    assert isinstance(symbols, list)
    # urllib3 CRLF-injection fix touches the connection path (connect / DummyConnection).
    assert any(s.get("short_name") == "connect" for s in symbols)


def test_fetch_patches_batch() -> None:
    batch = fetch_patches_batch(["CVE-2023-32681", "CVE-2020-1747"], max_workers=2)
    assert "CVE-2023-32681" in batch
    assert "CVE-2020-1747" in batch
    assert batch["CVE-2023-32681"]["status"] in ("ok", "partial")


def test_load_cache_missing() -> None:
    assert load_cache("CVE-0000-00000") is None
