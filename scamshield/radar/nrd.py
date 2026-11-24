"""Newly registered domains: WhoisDS free daily list (zip of one day's new registrations, ~70-150k names).
URL: https://www.whoisds.com/whois-database/newly-registered-domains/<base64("YYYY-MM-DD.zip")>/nrd
(the free tier exposes the last ~4 days). first_seen = the list date (00:00 UTC of the registration day).
The zip is treated as untrusted data: only read as text lines, never extracted to disk or executed."""
from __future__ import annotations

import base64
import io
import logging
import zipfile
from datetime import date, datetime, timedelta, timezone
from typing import Iterable, Optional

from scamshield.core.config import DATA_DIR, settings
from scamshield.core.schemas import RadarHit

from .common import hit_from_match, scan_hits, store_hit
from .watchlist import hit_domain, match_detail, registrable_of

log = logging.getLogger("scamshield.radar")

NRD_DIR = DATA_DIR / "radar" / "nrd"
BASE = "https://www.whoisds.com/whois-database/newly-registered-domains/{token}/nrd"
UA = "Mozilla/5.0 (ScamShield-radar/0.1; passive NRD monitoring)"
STATUS: dict = {}


def nrd_url(d: date) -> str:
    token = base64.b64encode(f"{d.isoformat()}.zip".encode()).decode()
    return BASE.format(token=token)


def parse_nrd_zip(blob: bytes) -> list[str]:
    out: list[str] = []
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for name in z.namelist():
            if name.endswith("/") or z.getinfo(name).file_size > 200_000_000:
                continue
            with z.open(name) as f:
                for line in io.TextIOWrapper(f, encoding="utf-8", errors="ignore"):
                    s = line.strip().lower()
                    if s and "." in s and " " not in s:
                        out.append(s)
    return out


def match_domains(domains: Iterable[str], list_date: date) -> list[RadarHit]:
    first_seen = datetime(list_date.year, list_date.month, list_date.day, tzinfo=timezone.utc)
    hits: dict[str, RadarHit] = {}
    for d in domains:
        m = match_detail(d)
        if not m:
            continue
        reg = hit_domain(m)
        if reg not in hits:
            hits[reg] = hit_from_match(reg, "nrd", first_seen, m, extra={
                "nrd_list": list_date.isoformat(), "nrd_feed": "whoisds", "first_seen_basis": "nrd_list_date", "scan_host": m["host"]})
    return list(hits.values())


async def fetch_day(d: date) -> Optional[bytes]:
    """Cached on disk in data/radar/nrd/<date>.zip."""
    p = NRD_DIR / f"{d.isoformat()}.zip"
    if p.exists() and p.stat().st_size > 1000:
        return p.read_bytes()
    if settings.offline:
        return None
    import httpx

    try:
        async with httpx.AsyncClient(timeout=60, headers={"User-Agent": UA}, follow_redirects=True) as c:
            r = await c.get(nrd_url(d))
        if r.status_code != 200 or not r.content.startswith(b"PK"):
            log.info("NRD %s -> HTTP %s (%d bytes)", d, r.status_code, len(r.content))
            return None
        NRD_DIR.mkdir(parents=True, exist_ok=True)
        p.write_bytes(r.content)
        return r.content
    except Exception as e:
        log.info("NRD %s failed: %r", d, e)
        return None


async def collect_nrd(days: int = 4, scan: bool = True, limit: Optional[int] = None) -> list[RadarHit]:
    """Yesterday back to `days` days. Never raises."""
    out: list[RadarHit] = []
    try:
        today = datetime.now(timezone.utc).date()
        for i in range(1, days + 1):
            d = today - timedelta(days=i)
            blob = await fetch_day(d)
            if not blob:
                STATUS[d.isoformat()] = "unavailable"
                continue
            try:
                names = parse_nrd_zip(blob)
            except Exception as e:
                STATUS[d.isoformat()] = f"bad_zip:{e!r}"[:80]
                continue
            hits = match_domains(names, d)
            STATUS[d.isoformat()] = f"ok:{len(names)} domains, {len(hits)} hits"
            log.info("NRD %s: %d domains -> %d hits", d, len(names), len(hits))
            out += hits
        # one hit per domain (earliest list wins)
        best: dict[str, RadarHit] = {}
        for h in sorted(out, key=lambda h: h.first_seen):
            best.setdefault(h.domain, h)
        out = sorted(best.values(), key=lambda h: h.first_seen, reverse=True)
        if limit:
            out = out[:limit]
        out = [store_hit(h) for h in out]
        if scan:
            todo = [h for h in out if not h.scan_id]
            out = [h for h in out if h.scan_id] + await scan_hits(todo)
    except Exception as e:
        log.warning("collect_nrd failed: %r", e)
    return out
