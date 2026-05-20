from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import aiosqlite


SCHEMA_STATEMENTS = [
    """
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  repo_path TEXT,
  started_at TEXT,
  completed_at TEXT,
  verdict TEXT,
  result_json TEXT
);
""",
    """
CREATE TABLE IF NOT EXISTS cve_cache (
  cve_id TEXT PRIMARY KEY,
  data_json TEXT,
  cached_at TEXT
);
""",
    """
CREATE TABLE IF NOT EXISTS epss_cache (
  cve_id TEXT PRIMARY KEY,
  epss_score REAL,
  cached_at TEXT
);
""",
    """
CREATE TABLE IF NOT EXISTS depdev_cache (
  package_name TEXT PRIMARY KEY,
  ecosystem TEXT,
  data_json TEXT,
  cached_at TEXT
);
""",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_expired(cached_at: str, ttl_hours: int) -> bool:
    try:
        cached_dt = datetime.fromisoformat(cached_at)
    except ValueError:
        return True
    return cached_dt + timedelta(hours=ttl_hours) < datetime.now(timezone.utc)


async def init_db(db_path: str) -> None:
    async with aiosqlite.connect(db_path) as conn:
        for statement in SCHEMA_STATEMENTS:
            await conn.execute(statement)
        await conn.commit()


async def get_cached_cve(db_path: str, cve_id: str, ttl_hours: int) -> dict[str, Any] | None:
    query = "SELECT data_json, cached_at FROM cve_cache WHERE cve_id = ?"
    async with aiosqlite.connect(db_path) as conn:
        async with conn.execute(query, (cve_id,)) as cursor:
            row = await cursor.fetchone()
    if not row:
        return None
    data_json, cached_at = row
    if _is_expired(cached_at, ttl_hours):
        return None
    try:
        return json.loads(data_json)
    except json.JSONDecodeError:
        return None


async def set_cached_cve(db_path: str, cve_id: str, data: dict[str, Any]) -> None:
    payload = json.dumps(data)
    query = "REPLACE INTO cve_cache (cve_id, data_json, cached_at) VALUES (?, ?, ?)"
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(query, (cve_id, payload, _now_iso()))
        await conn.commit()


async def get_cached_epss(db_path: str, cve_id: str, ttl_hours: int) -> float | None:
    query = "SELECT epss_score, cached_at FROM epss_cache WHERE cve_id = ?"
    async with aiosqlite.connect(db_path) as conn:
        async with conn.execute(query, (cve_id,)) as cursor:
            row = await cursor.fetchone()
    if not row:
        return None
    epss_score, cached_at = row
    if _is_expired(cached_at, ttl_hours):
        return None
    return float(epss_score)


async def set_cached_epss(db_path: str, cve_id: str, score: float) -> None:
    query = "REPLACE INTO epss_cache (cve_id, epss_score, cached_at) VALUES (?, ?, ?)"
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(query, (cve_id, score, _now_iso()))
        await conn.commit()


async def save_job(
    db_path: str,
    job_id: str,
    repo_path: str,
    started_at: str,
    completed_at: str,
    verdict: str,
    result_json: str,
) -> None:
    query = (
        "REPLACE INTO jobs (id, repo_path, started_at, completed_at, verdict, result_json) "
        "VALUES (?, ?, ?, ?, ?, ?)"
    )
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(query, (job_id, repo_path, started_at, completed_at, verdict, result_json))
        await conn.commit()
