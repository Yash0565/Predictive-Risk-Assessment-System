"""Tamper-evident, hash-chained audit log (append-only JSONL).

Each record embeds the hash of the previous record, forming a chain: altering or
deleting any past entry breaks every subsequent hash, which ``verify`` detects.
This is the audit primitive an enterprise/compliance reviewer expects (who did
what, when, and proof the trail was not edited after the fact).

Storage is a local JSONL file by default; the same interface can back onto an
append-only object store or WORM bucket in production.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Optional

GENESIS_HASH = "0" * 64


def _canonical(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _hash_entry(payload: dict[str, Any], prev_hash: str) -> str:
    return hashlib.sha256((prev_hash + _canonical(payload)).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)

    def _last_hash(self) -> str:
        last = GENESIS_HASH
        if not os.path.exists(self.path):
            return last
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)["entry_hash"]
                    except (json.JSONDecodeError, KeyError):
                        continue
        return last

    def append(
        self,
        action: str,
        actor: str,
        tenant: str = "default",
        details: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Append an event and return the written record (with its chain hash)."""
        with self._lock:
            prev_hash = self._last_hash()
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tenant": tenant,
                "actor": actor,
                "action": action,
                "details": details or {},
                "prev_hash": prev_hash,
            }
            entry_hash = _hash_entry(payload, prev_hash)
            record = {**payload, "entry_hash": entry_hash}
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(_canonical(record) + "\n")
            return record

    def read_all(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def verify(self) -> dict[str, Any]:
        """Recompute the chain; report the first tampered index if any."""
        prev_hash = GENESIS_HASH
        records = self.read_all()
        for i, rec in enumerate(records):
            stated = rec.get("entry_hash")
            payload = {k: rec[k] for k in rec if k != "entry_hash"}
            if payload.get("prev_hash") != prev_hash:
                return {"valid": False, "broken_at": i, "reason": "prev_hash mismatch"}
            recomputed = _hash_entry(payload, prev_hash)
            if recomputed != stated:
                return {"valid": False, "broken_at": i, "reason": "entry_hash mismatch"}
            prev_hash = stated
        return {"valid": True, "entries": len(records), "head": prev_hash}
