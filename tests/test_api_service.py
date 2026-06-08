"""Tests for the multi-tenant RBAC authorization core and audited service."""

from __future__ import annotations

import pytest

from src.api.authz import (
    AuthenticationError,
    AuthorizationError,
    Principal,
    is_allowed,
)
from src.api.service import RiskService

API_KEYS = {
    "key-acme-owner":   {"actor": "alice", "tenant": "acme", "role": "owner"},
    "key-acme-viewer":  {"actor": "carol", "tenant": "acme", "role": "viewer"},
    "key-globex-admin": {"actor": "dave",  "tenant": "globex", "role": "admin"},
}

ASSESSMENT = {"summary": {"overall_recommendation": "BLOCK", "overall_raw_risk": 100},
              "cves": []}


def _svc(tmp_path) -> RiskService:
    return RiskService(str(tmp_path), API_KEYS)


def test_authz_deny_by_default() -> None:
    viewer = Principal("c", "acme", "viewer")
    assert is_allowed(viewer, "assessment:read")
    assert not is_allowed(viewer, "assessment:create")
    assert not is_allowed(viewer, "assessment:delete")
    unknown = Principal("x", "acme", "nonexistent-role")
    assert not is_allowed(unknown, "assessment:read")


def test_authz_tenant_isolation() -> None:
    p = Principal("a", "acme", "owner")
    assert is_allowed(p, "assessment:read", resource_tenant="acme")
    assert not is_allowed(p, "assessment:read", resource_tenant="globex")


def test_invalid_api_key_rejected(tmp_path) -> None:
    svc = _svc(tmp_path)
    with pytest.raises(AuthenticationError):
        svc.submit_assessment("nope", ASSESSMENT)


def test_viewer_cannot_create(tmp_path) -> None:
    svc = _svc(tmp_path)
    with pytest.raises(AuthorizationError):
        svc.submit_assessment("key-acme-viewer", ASSESSMENT)


def test_cross_tenant_read_is_not_found(tmp_path) -> None:
    svc = _svc(tmp_path)
    created = svc.submit_assessment("key-acme-owner", ASSESSMENT, repo="acme/app")
    # Another tenant cannot read it (looks like it does not exist).
    with pytest.raises(KeyError):
        svc.get_assessment("key-globex-admin", created["scan_id"])


def test_owner_full_lifecycle_and_audit(tmp_path) -> None:
    svc = _svc(tmp_path)
    created = svc.submit_assessment("key-acme-owner", ASSESSMENT, repo="acme/app")
    got = svc.get_assessment("key-acme-owner", created["scan_id"])
    assert got["repo"] == "acme/app"
    listed = svc.list_assessments("key-acme-viewer")  # viewer can list its tenant
    assert any(x["scan_id"] == created["scan_id"] for x in listed)

    audit = svc.read_audit("key-acme-owner")
    assert audit["verification"]["valid"] is True
    actions = {e["action"] for e in audit["entries"]}
    assert {"assessment:create", "assessment:read"} <= actions


def test_viewer_cannot_read_audit(tmp_path) -> None:
    svc = _svc(tmp_path)
    with pytest.raises(AuthorizationError):
        svc.read_audit("key-acme-viewer")


def test_vex_as_a_service_scoped_to_tenant(tmp_path) -> None:
    svc = _svc(tmp_path)
    created = svc.submit_assessment("key-acme-owner", ASSESSMENT, repo="acme/app")
    vex = svc.get_vex("key-acme-owner", created["scan_id"])
    assert vex["@context"].startswith("https://openvex.dev/")
    # Other tenant cannot obtain VEX for it.
    with pytest.raises(KeyError):
        svc.get_vex("key-globex-admin", created["scan_id"])
