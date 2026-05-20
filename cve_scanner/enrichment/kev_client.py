from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from cve_scanner.config import get_settings

logger = logging.getLogger(__name__)


def _cache_paths() -> tuple[Path, Path]:
    settings = get_settings()
    cache_dir = Path(settings.DB_PATH).parent
    cache_dir.mkdir(parents=True, exist_ok=True)
    data_path = cache_dir / "kev_cache.json"
    meta_path = cache_dir / "kev_cache_meta.json"
    return data_path, meta_path


def _is_cache_valid(meta_path: Path, ttl_hours: int) -> bool:
    if not meta_path.exists():
        return False
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        cached_at = datetime.fromisoformat(meta.get("cached_at"))
    except Exception:
        return False
    return cached_at + timedelta(hours=ttl_hours) > datetime.now(timezone.utc)


async def _download_kev_feed() -> dict:
    settings = get_settings()
    timeout = settings.HTTP_TIMEOUT_SECONDS
    retries = settings.HTTP_RETRY_COUNT
    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(retries + 1):
            try:
                response = await client.get(settings.KEV_FEED_URL)
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("KEV feed fetch failed (attempt %s): %s", attempt + 1, exc)
                continue
    return {"vulnerabilities": []}


async def is_in_kev(cve_id: str) -> bool:
    settings = get_settings()
    data_path, meta_path = _cache_paths()

    if _is_cache_valid(meta_path, settings.KEV_CACHE_TTL_HOURS) and data_path.exists():
        try:
            payload = json.loads(data_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {"vulnerabilities": []}
    else:
        payload = await _download_kev_feed()
        data_path.write_text(json.dumps(payload), encoding="utf-8")
        meta_path.write_text(
            json.dumps({"cached_at": datetime.now(timezone.utc).isoformat()}),
            encoding="utf-8",
        )

    entries = payload.get("vulnerabilities") or []
    return any(item.get("cveID") == cve_id for item in entries)
