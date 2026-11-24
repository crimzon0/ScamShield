"""crt.sh backfill: certificates issued in the last N days whose names match the watchlist.

Polite + resumable: one query at a time, >= QUERY_GAP seconds apart, honours (and sets) intel's shared
crt.sh cooldown key on 429, retries 5xx/timeouts with backoff, persists every raw response to
data/radar/crtsh/<term>.json and a per-term state file, so one good pass is enough and reruns resume."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from scamshield.core import db
from scamshield.core.config import DATA_DIR, settings
from scamshield.core.schemas import RadarHit, utcnow

from .common import hit_from_match, parse_dt, scan_hits, store_hit
from .watchlist import match_detail, query_terms, registrable_of

log = logging.getLogger("scamshield.radar")

RAW_DIR = DATA_DIR / "radar" / "crtsh"
STATE_PATH = RAW_DIR / "_state.json"
CRTSH = "https://crt.sh/"
COOLDOWN_KEY = "intel:crtsh_cooldown"  # shared with scamshield.intel.crtsh
QUERY_GAP = 5.0
TIMEOUT = 20.0
FRESH_HOURS = 6  # a term fetched OK within this window is not re-queried (resume)
UA = "ScamShield-radar/0.1 (hackathon research; passive CT monitoring)"


# ------------------------------------------------------------------ parsing (pure, tested offline)
def split_names(name_value: str) -> list[str]:
    out = []
    for line in re.split(r"[\n\s,]+", name_value or ""):
        n = line.strip().lower().rstrip(".")
        while n.startswith("*."):
            n = n[2:]
        if n and "." in n and "@" not in n and " " not in n:
            out.append(n)
    return out


def parse_crtsh(rows: list[dict], days: int = 30, now: Optional[datetime] = None,
                include_fictional: bool = False) -> dict[str, dict]:
    """crt.sh JSON rows -> {registrable: {first_seen, hosts, cert_ids, issuers, match}} for rows whose
    not_before is within `days`. first_seen = earliest not_before seen for that registrable domain."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    out: dict[str, dict] = {}
    for r in rows or []:
        nb = parse_dt(r.get("not_before"))
        if nb is None or nb < cutoff:
            continue
        names = split_names(r.get("name_value", "")) + split_names(r.get("common_name", ""))
        for n in dict.fromkeys(names):
            m = match_detail(n, include_fictional=include_fictional)
            if not m:
                continue
            reg = registrable_of(m["host"])
            e = out.setdefault(reg, {"first_seen": nb, "hosts": [], "cert_ids": [], "issuers": [], "match": m})
            if nb < e["first_seen"]:
                e["first_seen"] = nb
            if m["host"] not in e["hosts"]:
                e["hosts"].append(m["host"])
            cid = r.get("id")
            if cid is not None and cid not in e["cert_ids"]:
                e["cert_ids"].append(cid)
            iss = r.get("issuer_name", "")
            if iss and iss not in e["issuers"]:
                e["issuers"].append(iss)
    return out


# ------------------------------------------------------------------ fetching
def _safe(term: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "_", term.lower()).strip("_") or "term"


def _load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(st: dict) -> None:
    try:
        RAW_DIR.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(st, indent=1, default=str), encoding="utf-8")
    except Exception as e:
        log.debug("state save failed: %s", e)


def load_raw(term: str) -> Optional[list]:
    try:
        return json.loads((RAW_DIR / f"{_safe(term)}.json").read_text(encoding="utf-8"))["rows"]
    except Exception:
        return None


async def fetch_pattern(pattern: str, exclude_expired: bool = True, retries: int = 3) -> tuple[str, Optional[list]]:
    """-> (status, rows). status: ok | empty | rate_limited | cooldown | error | offline."""
    if settings.offline:
        return "offline", None
    if db.cache_get(COOLDOWN_KEY):
        return "cooldown", None
    import httpx

    params = {"q": pattern, "output": "json"}
    if exclude_expired:
        params["exclude"] = "expired"
    delay = 4.0
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": UA}, follow_redirects=True) as c:
            for attempt in range(retries + 1):
                try:
                    r = await c.get(CRTSH, params=params)
                except (httpx.TimeoutException, httpx.TransportError) as e:
                    if attempt < retries:
                        await asyncio.sleep(delay)
                        delay *= 2
                        continue
                    return f"error:{type(e).__name__}", None
                if r.status_code == 200:
                    try:
                        rows = r.json() if r.text.strip() else []
                    except Exception:
                        return "error:bad_json", None
                    return ("ok" if rows else "empty"), rows
                if r.status_code == 429:
                    try:
                        ra = float(r.headers.get("Retry-After", "300"))
                    except ValueError:
                        ra = 300.0
                    db.cache_set(COOLDOWN_KEY, True, int(min(max(ra, 60), 900)))
                    return "rate_limited", None
                if r.status_code >= 500 and attempt < retries:
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                return f"error:http_{r.status_code}", None
    except Exception as e:
        return f"error:{type(e).__name__}", None
    return "error", None


async def collect_terms(days: int = 30, limit_terms: Optional[int] = None, force: bool = False,
                        terms: Optional[list[str]] = None, wait_cooldown: bool = True,
                        max_wait: float = 900.0) -> dict:
    """Query crt.sh for every strong term (resumable). Returns {term: status}."""
    st = _load_state()
    tl = terms or [e["term"] for e in query_terms()]
    if limit_terms:
        tl = tl[:limit_terms]
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    statuses: dict[str, str] = {}
    waited = 0.0
    for i, t in enumerate(tl):
        prev = st.get(t, {})
        fresh = prev.get("status") in ("ok", "empty") and time.time() - prev.get("ts", 0) < FRESH_HOURS * 3600
        if fresh and not force:
            statuses[t] = "cached:" + prev["status"]
            continue
        while True:
            status, rows = await fetch_pattern(f"%{t}%", exclude_expired=days <= 90)
            if status in ("cooldown", "rate_limited") and wait_cooldown and waited < max_wait:
                log.warning("crt.sh cooling down; waiting 60 s (term %s)", t)
                await asyncio.sleep(60)
                waited += 60
                continue
            break
        statuses[t] = status
        log.info("crt.sh %-22s %s %s", t, status, len(rows) if rows else 0)
        if rows is not None:
            try:
                (RAW_DIR / f"{_safe(t)}.json").write_text(json.dumps(
                    {"term": t, "pattern": f"%{t}%", "fetched_at": utcnow().isoformat(), "rows": rows}),
                    encoding="utf-8")
            except Exception as e:
                log.debug("raw save failed: %s", e)
        st[t] = {"status": status, "ts": time.time(), "n": len(rows) if rows else 0}
        _save_state(st)
        if status in ("cooldown", "rate_limited"):
            break  # give up politely; rerun resumes from here
        if i < len(tl) - 1:
            await asyncio.sleep(QUERY_GAP)
    return statuses


def hits_from_raw(days: int = 30, terms: Optional[list[str]] = None) -> list[RadarHit]:
    """Re-parse every persisted raw crt.sh response (no network) into RadarHits (not yet stored)."""
    rows: list[dict] = []
    files = [RAW_DIR / f"{_safe(t)}.json" for t in terms] if terms else sorted(RAW_DIR.glob("*.json"))
    for f in files:
        if f.name.startswith("_"):
            continue
        try:
            rows += json.loads(f.read_text(encoding="utf-8")).get("rows", [])
        except Exception:
            continue
    parsed = parse_crtsh(rows, days=days)
    hits = []
    for reg, e in parsed.items():
        host = next((h for h in e["hosts"] if h == reg), None) or e["hosts"][0]
        hits.append(hit_from_match(reg, "crtsh", e["first_seen"], e["match"], extra={
            "hosts": e["hosts"][:20], "cert_ids": e["cert_ids"][:20], "issuers": e["issuers"][:5],
            "scan_host": host, "crtsh_url": f"https://crt.sh/?id={e['cert_ids'][0]}" if e["cert_ids"] else ""}))
    hits.sort(key=lambda h: h.first_seen, reverse=True)
    return hits


async def backfill_crtsh(days: int = 30, scan: bool = True, limit: Optional[int] = None,
                         limit_terms: Optional[int] = None, force: bool = False,
                         fetch: bool = True) -> list[RadarHit]:
    """Fetch (resumable) -> parse -> store hits (source 'crtsh', first_seen = earliest cert not_before)
    -> scan each through the pipeline (concurrency 3). Never raises."""
    try:
        if fetch:
            await collect_terms(days=days, limit_terms=limit_terms, force=force)
        hits = hits_from_raw(days=days)
        if limit:
            hits = hits[:limit]
        stored = [store_hit(h) for h in hits]
        if scan:
            todo = [h for h in stored if not h.scan_id]
            stored = [h for h in stored if h.scan_id] + await scan_hits(todo)
        return stored
    except Exception as e:
        log.warning("backfill_crtsh failed: %r", e)
        return []
