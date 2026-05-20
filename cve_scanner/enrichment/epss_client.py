from __future__ import annotations

import logging

import httpx

from cve_scanner.config import get_settings
from cve_scanner.db import get_cached_epss, set_cached_epss

logger = logging.getLogger(__name__)


async def get_epss(cve_id: str) -> float:
    settings = get_settings()
    cached = await get_cached_epss(settings.DB_PATH, cve_id, settings.CVE_CACHE_TTL_HOURS)
    if cached is not None:
        return cached

    params = {"cve": cve_id}
    retries = settings.HTTP_RETRY_COUNT
    timeout = settings.HTTP_TIMEOUT_SECONDS

    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(retries + 1):
            try:
                response = await client.get(settings.EPSS_API_URL, params=params)
                response.raise_for_status()
                payload = response.json()
                data = payload.get("data") or []
                if not data:
                    return 0.0
                score = float(data[0].get("epss", 0.0))
                await set_cached_epss(settings.DB_PATH, cve_id, score)
                return score
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("EPSS fetch failed for %s (attempt %s): %s", cve_id, attempt + 1, exc)
                continue

    return 0.0
