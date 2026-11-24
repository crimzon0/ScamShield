"""crt.sh certificate transparency: first-seen for a domain and pattern search (used by radar).
Rate limited to ~1 req/s process-wide, backs off on 429/5xx."""
from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from scamshield.core import db
from scamshield.core.config import settings

from ._common import DAY, HOUR, UA, log, parse_dt

CRTSH = "https://crt.sh/"
_lock = threading.Lock()
_last = [0.0]


async def _throttle() -> None:
    while True:
        with _lock:
            wait = _last[0] + 1.1 - time.monotonic()
            if wait <= 0:
                _last[0] = time.monotonic()
                return
        await asyncio.sleep(wait)


COOLDOWN_KEY = "intel:crtsh_cooldown"


class RateLimited(Exception):
    pass


def _cooldown(seconds: float) -> None:
    db.cache_set(COOLDOWN_KEY, True, int(min(max(seconds, 60), 900)))


async def _get(params: dict, timeout: float, retries: int) -> Optional[list]:
    if db.cache_get(COOLDOWN_KEY):
        raise RateLimited("crt.sh cooldown active")
    delay = 2.0
    async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": UA}, follow_redirects=True) as c:
        for attempt in range(retries + 1):
            await _throttle()
            r = await c.get(CRTSH, params=params)
            if r.status_code == 200:
                txt = r.text.strip()
                return r.json() if txt else []
            if r.status_code == 429:
                try:
                    ra = float(r.headers.get("Retry-After", "300"))
                except ValueError:
                    ra = 300
                _cooldown(ra)  # every caller in this process (and others sharing the DB) backs off
                raise RateLimited(f"crt.sh 429, retry-after {ra}")
            if r.status_code >= 500 and attempt < retries:
                await asyncio.sleep(delay)
                delay *= 2
                continue
            log.info("crt.sh %s -> HTTP %s", params, r.status_code)
            return None
    return None


CERTSPOTTER = "https://api.certspotter.com/v1/issuances"


async def _certspotter(domain: str, timeout: float = 8.0, max_pages: int = 3) -> Optional[dict]:
    """Fallback. Cert Spotter's free API lists only unexpired certs, so first_seen is a lower bound
    ('seen since at least'); for new domains it equals the real first cert."""
    rows: list = []
    after = None
    async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": UA}) as c:
        for _ in range(max_pages):
            params = {"domain": domain, "include_subdomains": "true"}
            if after:
                params["after"] = after
            r = await c.get(CERTSPOTTER, params=params)
            if r.status_code != 200:
                break
            page = r.json()
            rows += page
            if len(page) < 100:
                break
            after = page[-1]["id"]
    if not rows and r.status_code != 200:
        return None
    nbs = [d for d in (parse_dt(x.get("not_before")) for x in rows) if d]
    return {"first_seen": min(nbs).isoformat() if nbs else None, "count": len(rows), "via": "certspotter"}


async def fetch_first_seen(domain: str, timeout: float = 10.0) -> Optional[dict]:
    """{'first_seen': iso|None, 'count': int, 'via': 'crtsh'|'certspotter'}. crt.sh first, Cert Spotter fallback."""
    try:
        rows = await _get({"q": domain, "output": "json"}, timeout, retries=0)
        if rows is not None:
            nbs = [d for d in (parse_dt(r.get("not_before")) for r in rows) if d]
            return {"first_seen": min(nbs).isoformat() if nbs else None,
                    "count": len({r.get("id") for r in rows}), "via": "crtsh"}
    except Exception as e:
        log.info("crt.sh failed for %s: %r", domain, e)
    return await _certspotter(domain)


async def crtsh_search(pattern: str, days: int = 30, timeout: float = 30.0) -> list[dict]:
    """Identity search on crt.sh, e.g. pattern='%emiratesnbd%'. Returns certs whose not_before is within
    `days`: [{name_value, not_before, issuer_name, id}] newest first. Cached 1 h. Never raises ([] on failure)."""
    key = f"intel:crtsh_search:{pattern}:{days}"
    try:
        v = db.cache_get(key)
        if v is not None:
            return v
        if settings.offline:
            return []
        params = {"q": pattern, "output": "json"}
        if days <= 90:
            params["exclude"] = "expired"
        rows = await _get(params, timeout, retries=2)
        if rows is None:
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        out, seen = [], set()
        for r in rows:
            nb = parse_dt(r.get("not_before"))
            if not nb or nb < cutoff or r.get("id") in seen:
                continue
            seen.add(r.get("id"))
            out.append({"name_value": r.get("name_value", ""), "not_before": nb.isoformat(),
                        "issuer_name": r.get("issuer_name", ""), "id": r.get("id")})
        out.sort(key=lambda x: x["not_before"], reverse=True)
        db.cache_set(key, out, HOUR)
        return out
    except Exception as e:
        log.info("crtsh_search %s failed: %r", pattern, e)
        return []


CRTSH_TTL = DAY
