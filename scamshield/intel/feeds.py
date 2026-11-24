"""Phishing blocklist feeds (OpenPhish community, phishunt) and the Tranco top-1M list.
Files live in data/feeds/. Feeds refresh at most hourly, Tranco at most weekly. Lookups read local files only,
so they work offline; refreshes are skipped when settings.offline."""
from __future__ import annotations

import io
import logging
import os
import sqlite3
import threading
import time
import zipfile
from pathlib import Path
from typing import Optional

import httpx

from scamshield.core.config import settings
from scamshield.core.domains import host_of, is_shared_host, registrable

from . import _common
from ._common import DAY, HOUR, UA

log = logging.getLogger("scamshield.intel")

FEEDS = {
    # openphish.com/feed.txt 302-redirects here (checked 2026-11-24)
    "openphish": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    "phishunt": "https://phishunt.io/feed.txt",
}
FEED_TTL = HOUR
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_TTL = 7 * DAY
# A domain this popular is never flagged just because one of its subdomains/paths is on a feed
POPULAR_RANK = 100_000

_lock = threading.Lock()
_attempts: dict[str, float] = {}  # name -> last attempt (avoid hammering after failures)
_index: dict[str, tuple] = {}  # name -> (mtime, urls(list), url_set, host_set, reg_set)


def feeds_dir() -> Path:
    d = _common.FEEDS_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(name: str) -> Path:
    return feeds_dir() / f"{name}.txt"


def _fresh(p: Path, ttl: int) -> bool:
    return p.exists() and time.time() - p.stat().st_mtime < ttl


def _norm_url(u: str) -> str:
    u = u.strip()
    return u.rstrip("/").lower()


# ------------------------------------------------------------------ feeds
def refresh_feed(name: str, force: bool = False) -> bool:
    """Download one feed if older than 1 h. Returns True if a usable local file exists afterwards."""
    p = _path(name)
    if settings.offline or (not force and _fresh(p, FEED_TTL)):
        return p.exists()
    with _lock:
        if not force and time.time() - _attempts.get(name, 0) < 300:
            return p.exists()
        _attempts[name] = time.time()
    try:
        r = httpx.get(FEEDS[name], timeout=settings.http_timeout, follow_redirects=True, headers={"User-Agent": UA})
        r.raise_for_status()
        lines = [ln.strip() for ln in r.text.splitlines() if ln.strip().startswith(("http://", "https://"))]
        if not lines:
            raise ValueError("empty feed")
        tmp = p.with_suffix(".tmp")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.replace(tmp, p)
    except Exception as e:
        log.info("feed %s refresh failed: %r", name, e)
    return p.exists()


def refresh_feeds(force: bool = False) -> dict[str, str]:
    """Returns name -> 'ok' | 'cached' | 'unavailable' | 'offline'."""
    out = {}
    for name in FEEDS:
        p = _path(name)
        before = p.stat().st_mtime if p.exists() else None
        ok = refresh_feed(name, force)
        after = p.stat().st_mtime if p.exists() else None
        if not ok:
            out[name] = "offline" if settings.offline else "unavailable"
        elif after != before:
            out[name] = "ok"
        else:
            out[name] = "cached"
    return out


def _load(name: str) -> Optional[tuple]:
    p = _path(name)
    if not p.exists():
        return None
    mt = p.stat().st_mtime
    cur = _index.get(name)
    if cur and cur[0] == mt:
        return cur
    urls = [ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    url_set = {_norm_url(u) for u in urls}
    hosts = {host_of(u) for u in urls} - {""}
    regs = {registrable(h) for h in hosts if not is_shared_host(h)}
    _index[name] = (mt, urls, url_set, hosts, regs)
    return _index[name]


def _strip_www(h: str) -> str:
    return h[4:] if h.startswith("www.") else h


def hits(url_or_host: str, registrable_level: Optional[bool] = None) -> list[str]:
    """Feed names listing this exact URL or host. With registrable_level (default: when the registrable domain
    is not popular per Tranco and not a shared host), a listed sibling subdomain also counts."""
    s = url_or_host.strip()
    h = host_of(s)
    if not h:
        return []
    reg = registrable(h)
    if registrable_level is None:
        rank = tranco_rank(reg)
        registrable_level = not is_shared_host(h) and (rank is None or rank > POPULAR_RANK)
    out = []
    for name in FEEDS:
        idx = _load(name)
        if not idx:
            continue
        _, _, url_set, hosts, regs = idx
        if ("://" in s and _norm_url(s) in url_set) or h in hosts or _strip_www(h) in hosts or "www." + h in hosts:
            out.append(name)
        elif registrable_level and reg in regs:
            out.append(name)
    return out


def listed_hosts(reg: str, limit: int = 3) -> list[str]:
    """Hosts under registrable domain `reg` that appear in local feeds (used to find an A record when the
    apex has none)."""
    out: list[str] = []
    for name in FEEDS:
        idx = _load(name)
        if idx:
            out += sorted(h for h in idx[3] if h != reg and h.endswith("." + reg))
    return list(dict.fromkeys(out))[:limit]


def feed_urls(limit: int = 200) -> dict[str, list[str]]:
    """Most recent URLs per feed (feeds list newest first). Refreshes if stale and online. Never raises."""
    out: dict[str, list[str]] = {}
    for name in FEEDS:
        try:
            refresh_feed(name)
            idx = _load(name)
            out[name] = list(idx[1][:limit]) if idx else []
        except Exception as e:
            log.info("feed_urls %s: %r", name, e)
            out[name] = []
    return out


# ------------------------------------------------------------------ tranco
_tranco_lock = threading.Lock()
_tranco_thread: Optional[threading.Thread] = None


def _tranco_db() -> Path:
    return feeds_dir() / "tranco.sqlite"


def refresh_tranco(force: bool = False) -> bool:
    """Download the Tranco top-1M zip and index it into data/feeds/tranco.sqlite (blocking, ~10 s)."""
    dbp = _tranco_db()
    if settings.offline or (not force and _fresh(dbp, TRANCO_TTL)):
        return dbp.exists()
    try:
        r = httpx.get(TRANCO_URL, timeout=60, follow_redirects=True, headers={"User-Agent": UA})
        r.raise_for_status()
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        csvname = next(n for n in zf.namelist() if n.endswith(".csv"))
        tmp = dbp.with_suffix(".building")
        if tmp.exists():
            tmp.unlink()
        con = sqlite3.connect(tmp)
        con.execute("CREATE TABLE tranco(domain TEXT PRIMARY KEY, rank INTEGER) WITHOUT ROWID")
        con.execute("CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT)")

        def rows():
            with zf.open(csvname) as f:
                for line in io.TextIOWrapper(f, encoding="utf-8"):
                    rank, _, dom = line.strip().partition(",")
                    if dom:
                        yield dom.lower(), int(rank)

        con.executemany("INSERT OR IGNORE INTO tranco VALUES (?,?)", rows())
        con.execute("INSERT INTO meta VALUES ('downloaded', ?)", (str(time.time()),))
        con.commit()
        con.close()
        os.replace(tmp, dbp)
        return True
    except Exception as e:
        log.info("tranco refresh failed: %r", e)
        return dbp.exists()


def ensure_tranco_background() -> None:
    """Kick off a Tranco download in a daemon thread if missing/stale (non-blocking)."""
    global _tranco_thread
    if settings.offline or _fresh(_tranco_db(), TRANCO_TTL):
        return
    with _tranco_lock:
        if _tranco_thread and _tranco_thread.is_alive():
            return
        if time.time() - _attempts.get("tranco", 0) < 600:
            return
        _attempts["tranco"] = time.time()
        _tranco_thread = threading.Thread(target=refresh_tranco, name="tranco-refresh", daemon=True)
        _tranco_thread.start()


def tranco_available() -> bool:
    return _tranco_db().exists()


def tranco_rank(domain: str) -> Optional[int]:
    dbp = _tranco_db()
    if not dbp.exists():
        return None
    try:
        con = sqlite3.connect(f"file:{dbp.as_posix()}?mode=ro", uri=True)
        try:
            for d in (domain.lower(), registrable(domain)):
                row = con.execute("SELECT rank FROM tranco WHERE domain=?", (d,)).fetchone()
                if row:
                    return int(row[0])
        finally:
            con.close()
    except Exception as e:
        log.info("tranco lookup failed: %r", e)
    return None


if __name__ == "__main__":  # prefetch: python -m scamshield.intel.feeds
    print(refresh_feeds(force=True))
    print("tranco:", refresh_tranco(force=True))
