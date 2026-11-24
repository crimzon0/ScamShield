"""Shared helpers for intel sources: cache-wrapped fetch with status recording, HTTP client factory."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

import httpx

from scamshield.core import db
from scamshield.core.config import DATA_DIR, settings

log = logging.getLogger("scamshield.intel")

FEEDS_DIR = DATA_DIR / "feeds"
UA = "ScamShield/0.1 (UAE anti-scam research; passive lookups)"

HOUR = 3600
DAY = 24 * HOUR


def client(timeout: Optional[float] = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout or settings.http_timeout, follow_redirects=True, headers={"User-Agent": UA}
    )


async def run_source(
    sources: dict[str, str], name: str, key: str, fetch: Callable[[], Awaitable[Any]], ttl: Any
) -> Any:
    """Return cached value or fetch it. Records sources[name] = cached|ok|unavailable|offline. Never raises."""
    try:
        v = db.cache_get(key)
    except Exception:  # pragma: no cover - db broken
        v = None
    if v is not None:
        sources[name] = "cached"
        return v
    if settings.offline:
        sources[name] = "offline"
        return None
    try:
        v = await fetch()
    except Exception as e:
        log.info("intel source %s failed: %r", name, e)
        v = None
    if v is None:
        sources[name] = "unavailable"
        return None
    try:
        db.cache_set(key, v, ttl(v) if callable(ttl) else ttl)
    except Exception:  # pragma: no cover
        pass
    sources[name] = "ok"
    return v


def parse_dt(v: Any) -> Optional[datetime]:
    """Parse ISO-ish / datetime / list-of-datetime into tz-aware UTC."""
    if v is None or v == "":
        return None
    if isinstance(v, (list, tuple)):
        ds = [d for d in (parse_dt(x) for x in v) if d]
        return min(ds) if ds else None
    if isinstance(v, datetime):
        d = v
    else:
        s = str(v).strip()
        d = None
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d"):
                try:
                    d = datetime.strptime(s[: len(fmt) + 4].strip(), fmt)
                    break
                except ValueError:
                    continue
        if d is None:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)
