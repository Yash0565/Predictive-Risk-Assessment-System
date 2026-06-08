"""Audited, multi-tenant risk-assessment service (framework-agnostic core).

Ties together API-key authentication, RBAC authorization, hard tenant isolation,
and a hash-chained audit trail. Every state-changing or read action is checked
against the policy engine and recorded in the audit log. An HTTP adapter only
needs to map requests to these methods.

Storage here is a simple JSON-on-disk store for portability; the same interface
backs onto Postgres (rows scoped by tenant_id) + a graph DB in production.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any, Optional

from src.api.authz import (
    AuthenticationError,
    Principal,
    require,
)
from src.audit_log import AuditLog


class RiskService:
    def __init__(self, data_dir: str, api_keys: dict[str, dict[str, str]]):
        """``api_keys`` maps secret -> {"actor","tenant","role"}."""
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self._store_path = os.path.join(data_dir, "assessments.json")
        self._api_keys = api_keys
        self.audit = AuditLog(os.path.join(data_dir, "audit.jsonl"))

    # -- auth -------------------------------------------------------------
    def authenticate(self, api_key: str) -> Principal:
        info = self._api_keys.get(api_key)
        if not info:
            raise AuthenticationError("invalid API key")
        return Principal(actor=info["actor"], tenant=info["tenant"], role=info["role"])

    # -- storage ----------------------------------------------------------
    def _load(self) -> dict[str, Any]:
        if not os.path.exists(self._store_path):
            return {}
        with open(self._store_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _save(self, store: dict[str, Any]) -> None:
        with open(self._store_path, "w", encoding="utf-8") as fh:
            json.dump(store, fh, indent=2)

    # -- operations -------------------------------------------------------
    def submit_assessment(self, api_key: str, assessment: dict[str, Any],
                          repo: str = "") -> dict[str, Any]:
        principal = self.authenticate(api_key)
        require(principal, "assessment:create")
        scan_id = uuid.uuid4().hex
        store = self._load()
        record = {
            "scan_id": scan_id,
            "tenant": principal.tenant,
            "repo": repo,
            "created_by": principal.actor,
            "summary": assessment.get("summary", {}),
            "assessment": assessment,
        }
        store[scan_id] = record
        self._save(store)
        self.audit.append("assessment:create", actor=principal.actor,
                          tenant=principal.tenant, details={"scan_id": scan_id, "repo": repo})
        return {"scan_id": scan_id, "tenant": principal.tenant}

    def get_assessment(self, api_key: str, scan_id: str) -> dict[str, Any]:
        principal = self.authenticate(api_key)
        store = self._load()
        record = store.get(scan_id)
        # Tenant isolation: a record in another tenant is indistinguishable from
        # a missing one (no cross-tenant existence leak).
        if not record or record["tenant"] != principal.tenant:
            require(principal, "assessment:read", resource_tenant=principal.tenant)
            raise KeyError("assessment not found")
        require(principal, "assessment:read", resource_tenant=record["tenant"])
        self.audit.append("assessment:read", actor=principal.actor,
                          tenant=principal.tenant, details={"scan_id": scan_id})
        return record

    def list_assessments(self, api_key: str) -> list[dict[str, Any]]:
        principal = self.authenticate(api_key)
        require(principal, "assessment:list")
        store = self._load()
        out = [
            {"scan_id": r["scan_id"], "repo": r.get("repo", ""),
             "summary": r.get("summary", {})}
            for r in store.values() if r["tenant"] == principal.tenant
        ]
        self.audit.append("assessment:list", actor=principal.actor,
                          tenant=principal.tenant, details={"count": len(out)})
        return out

    def delete_assessment(self, api_key: str, scan_id: str) -> None:
        principal = self.authenticate(api_key)
        store = self._load()
        record = store.get(scan_id)
        if not record or record["tenant"] != principal.tenant:
            raise KeyError("assessment not found")
        require(principal, "assessment:delete", resource_tenant=record["tenant"])
        del store[scan_id]
        self._save(store)
        self.audit.append("assessment:delete", actor=principal.actor,
                          tenant=principal.tenant, details={"scan_id": scan_id})

    def get_vex(self, api_key: str, scan_id: str) -> dict[str, Any]:
        """VEX-as-a-service: return an OpenVEX document for a stored assessment."""
        record = self.get_assessment(api_key, scan_id)  # enforces authz + isolation
        from src.exporters import to_openvex
        return to_openvex(record["assessment"])

    def read_audit(self, api_key: str) -> dict[str, Any]:
        principal = self.authenticate(api_key)
        require(principal, "audit:read")
        return {"verification": self.audit.verify(),
                "entries": [e for e in self.audit.read_all()
                            if e.get("tenant") == principal.tenant]}
