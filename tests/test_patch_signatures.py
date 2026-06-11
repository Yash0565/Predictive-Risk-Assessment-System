"""Tests for automated vulnerability signatures on cached patches."""

from __future__ import annotations

from src.patch_fetcher import fetch_patch


def test_cached_patch_has_vulnerability_signature() -> None:
    result = fetch_patch("CVE-2020-1747", package="pyyaml", force_refresh=False)
    sig = result.get("vulnerability_signature")
    assert sig is not None
    assert "changed_fqns" in sig
    assert "structural_hash" in sig
    assert len(sig["structural_hash"]) == 16


def test_cached_patch_has_exploitability_fingerprint() -> None:
    result = fetch_patch("CVE-2020-1747", package="pyyaml", force_refresh=False)
    fp = result.get("exploitability_fingerprint")
    assert fp is not None
    assert "hardened_symbols" in fp
    assert "guard_absent_state" in fp
