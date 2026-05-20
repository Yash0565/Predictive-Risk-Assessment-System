"""Tests for src.symbol_scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.symbol_scanner import (
    build_symbol_index,
    detect_entry_points,
    load_patches_from_cache,
    scan_file,
    scan_symbols,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "symbol_scanner"
TASKFLOW = Path(__file__).resolve().parent.parent / "vulnerable-task-tracker"
GOLDEN = Path(__file__).resolve().parent.parent / "examples" / "symbol_scan_output.json"


def _requests_index() -> dict:
  return {
    "CVE-TEST": {
      "package": "requests",
      "vulnerable_symbols": [
        {
          "fully_qualified_name": "requests.utils.rebuild_auth",
          "short_name": "rebuild_auth",
          "kind": "function",
          "change_classification": "HARDENED_ONLY",
        }
      ],
    }
  }


def _index():
  return build_symbol_index(_requests_index())


@pytest.mark.parametrize(
    "filename",
    [
      "direct_import.py",
      "aliased_import.py",
      "module_attr.py",
      "full_path_import.py",
      "module_alias.py",
    ],
)
def test_alias_resolution_high_confidence(filename: str) -> None:
    findings = scan_file(str(FIXTURES / filename), _index(), project_root=str(FIXTURES))
    calls = [f for f in findings if f["kind"] == "call"]
    assert len(calls) == 1
    assert calls[0]["confidence"] == "HIGH"
    assert calls[0]["target"].cve_id == "CVE-TEST"


def test_star_import_medium_confidence() -> None:
    findings = scan_file(str(FIXTURES / "star_import.py"), _index(), project_root=str(FIXTURES))
    calls = [f for f in findings if f["kind"] == "call"]
    assert calls
    assert calls[0]["confidence"] == "MEDIUM"


def test_conditional_import_recorded() -> None:
    findings = scan_file(
        str(FIXTURES / "conditional_import.py"), _index(), project_root=str(FIXTURES)
    )
    imports = [f for f in findings if f["kind"] == "import"]
    calls = [f for f in findings if f["kind"] == "call"]
    assert imports
    assert calls and calls[0]["confidence"] == "HIGH"


def test_syntax_error_skipped() -> None:
    findings = scan_file(
        str(FIXTURES / "broken_syntax.py"), _index(), project_root=str(FIXTURES)
    )
    assert findings == []


def test_flask_entry_point_detection() -> None:
    source = (FIXTURES / "flask_route.py").read_text(encoding="utf-8")
    tree = __import__("ast").parse(source)
    eps = detect_entry_points("flask_route.py", tree)
    assert "login_user" in eps
    assert eps["login_user"].framework == "flask"
    assert eps["login_user"].route == "/auth/login"
    assert eps["login_user"].method == "POST"


def test_fastapi_entry_point_detection() -> None:
    source = (FIXTURES / "fastapi_route.py").read_text(encoding="utf-8")
    tree = __import__("ast").parse(source)
    eps = detect_entry_points("fastapi_route.py", tree)
    assert eps["read_item"].framework == "fastapi"
    assert eps["read_item"].method == "GET"
    assert eps["read_item"].route == "/items/{item_id}"


def test_django_urls_entry_point() -> None:
    source = (FIXTURES / "django_urls.py").read_text(encoding="utf-8")
    tree = __import__("ast").parse(source)
    eps = detect_entry_points("django_urls.py", tree)
    assert "admin_view" in eps
    assert eps["admin_view"].framework == "django"


def test_pil_image_open_chain() -> None:
    idx = build_symbol_index({
        "CVE-PIL": {
            "package": "pillow",
            "vulnerable_symbols": [
                {
                    "fully_qualified_name": "PIL.Image.open",
                    "short_name": "open",
                    "kind": "function",
                    "change_classification": "INTERNAL_CHANGE",
                }
            ],
        }
    })
    findings = scan_file(str(FIXTURES / "pil_open.py"), idx, project_root=str(FIXTURES))
    calls = [f for f in findings if f["kind"] == "call"]
    assert calls
    assert calls[0]["target"].cve_id == "CVE-PIL"


@pytest.mark.skipif(not TASKFLOW.is_dir(), reason="TaskFlow demo not present")
def test_taskflow_integration() -> None:
    patches = load_patches_from_cache()
    assert len(patches) >= 8
    result = scan_symbols(str(TASKFLOW), patches)

    summary = result["summary"]
    assert summary["noise_reduction_percent"] == 37.5
    assert set(summary["reachable_cves"]) == {
        "CVE-2023-32681",
        "CVE-2019-10906",
        "CVE-2020-1747",
        "CVE-2020-5313",
        "CVE-2018-1000656",
    }
    assert set(summary["unreachable_cves"]) == {
        "CVE-2019-11324",
        "CVE-2020-26137",
        "CVE-2020-25659",
    }

    cve_auth = result["findings_by_cve"]["CVE-2023-32681"]
    assert cve_auth["is_reachable"]
    calls = [r for r in cve_auth["references"] if r["kind"] == "call"]
    assert any(r["file"] == "auth.py" and r["enclosing_function"] == "login_user" for r in calls)
    ep_calls = [r for r in calls if r.get("entry_point_info")]
    assert ep_calls
    assert ep_calls[0]["entry_point_info"]["route"] == "/auth/login"
    assert ep_calls[0]["entry_point_info"]["method"] == "POST"

    cve_jinja = result["findings_by_cve"]["CVE-2019-10906"]
    assert any(
        r["file"] == "tasks.py" and r["kind"] == "call"
        for r in cve_jinja["references"]
    )

    cve_yaml = result["findings_by_cve"]["CVE-2020-1747"]
    assert any(
        r["file"] == "config_loader.py" and "yaml.load" in r["source"]
        for r in cve_yaml["references"]
        if r["kind"] == "call"
    )

    cve_pil = result["findings_by_cve"]["CVE-2020-5313"]
    assert any(
        r["file"] == "uploads.py" and "Image.open" in r["source"]
        for r in cve_pil["references"]
        if r["kind"] == "call"
    )

    assert not result["findings_by_cve"]["CVE-2020-25659"]["is_reachable"]
    assert not result["findings_by_cve"]["CVE-2019-11324"]["is_reachable"]


@pytest.mark.skipif(not GOLDEN.is_file(), reason="golden output missing")
def test_golden_output_matches_taskflow() -> None:
    patches = load_patches_from_cache()
    result = scan_symbols(str(TASKFLOW), patches)
    with GOLDEN.open(encoding="utf-8") as fh:
        golden = json.load(fh)
    assert result["summary"] == golden["summary"]
    assert set(result["findings_by_cve"]) == set(golden["findings_by_cve"])
