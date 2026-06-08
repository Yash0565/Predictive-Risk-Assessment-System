"""Tests for the hash-chained audit log and the incremental scan cache."""

from __future__ import annotations

import json

from src.audit_log import AuditLog
from src.scan_cache import ScanCache, cache_key


def test_audit_chain_appends_and_verifies(tmp_path) -> None:
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    log.append("scan.start", actor="alice", tenant="acme", details={"repo": "x"})
    log.append("scan.finish", actor="alice", tenant="acme", details={"cves": 12})
    r = log.append("report.export", actor="bob", tenant="acme")
    result = log.verify()
    assert result["valid"] is True
    assert result["entries"] == 3
    assert result["head"] == r["entry_hash"]


def test_audit_detects_tampering(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    log.append("a", actor="x")
    log.append("b", actor="x")
    log.append("c", actor="x")

    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["details"] = {"tampered": True}  # mutate a past entry, keep its hash
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = log.verify()
    assert result["valid"] is False
    assert result["broken_at"] == 1


def test_scan_cache_incremental_hits(tmp_path) -> None:
    f1 = tmp_path / "a.py"
    f2 = tmp_path / "b.py"
    f1.write_text("print(1)\n", encoding="utf-8")
    f2.write_text("print(2)\n", encoding="utf-8")
    cache = ScanCache(str(tmp_path / "cache"))

    calls = {"n": 0}

    def scan_fn(path):
        calls["n"] += 1
        return {"path": path, "findings": 0}

    r1 = cache.scan_incremental([str(f1), str(f2)], "trivy", "0.50.0", scan_fn)
    assert r1["stats"]["cache_misses"] == 2
    assert calls["n"] == 2

    # Second run: nothing changed -> all hits, scan_fn not called again.
    r2 = cache.scan_incremental([str(f1), str(f2)], "trivy", "0.50.0", scan_fn)
    assert r2["stats"]["cache_hits"] == 2
    assert r2["stats"]["hit_rate"] == 1.0
    assert calls["n"] == 2

    # Change one file -> exactly one miss.
    f1.write_text("print(999)\n", encoding="utf-8")
    r3 = cache.scan_incremental([str(f1), str(f2)], "trivy", "0.50.0", scan_fn)
    assert r3["stats"]["cache_misses"] == 1
    assert calls["n"] == 3


def test_cache_key_changes_with_tool_version(tmp_path) -> None:
    f = tmp_path / "a.py"
    f.write_text("x=1\n", encoding="utf-8")
    assert cache_key(str(f), "trivy", "1.0") != cache_key(str(f), "trivy", "2.0")
