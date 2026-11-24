"""SQLite (WAL) storage + generic cache. Owned by the lead."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .config import settings

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
  key TEXT PRIMARY KEY, value TEXT NOT NULL, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY, url TEXT NOT NULL, created_at TEXT NOT NULL,
  score INTEGER, label TEXT, result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_url ON scans(url);
CREATE TABLE IF NOT EXISTS radar_hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, source TEXT NOT NULL,
  first_seen TEXT NOT NULL, flagged_at TEXT NOT NULL, hit_json TEXT NOT NULL,
  UNIQUE(domain, source)
);
CREATE TABLE IF NOT EXISTS phone_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, brand_id TEXT, number_e164 TEXT, source TEXT,
  status TEXT, found_at TEXT NOT NULL, finding_json TEXT NOT NULL,
  UNIQUE(brand_id, number_e164, source, finding_json)
);
CREATE TABLE IF NOT EXISTS cases (
  scan_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, case_json TEXT NOT NULL
);
"""


def connect(path: Optional[Path] = None) -> sqlite3.Connection:
    """Per-thread connection. Pass a path for tests."""
    p = str(path or settings.db_path)
    conns = getattr(_local, "conns", None)
    if conns is None:
        conns = _local.conns = {}
    if p not in conns:
        c = sqlite3.connect(p, timeout=30, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.executescript(SCHEMA)
        conns[p] = c
    return conns[p]


# ------------------------------------------------------------------ cache
def cache_get(key: str) -> Any:
    row = connect().execute("SELECT value, expires FROM cache WHERE key=?", (key,)).fetchone()
    if row and row["expires"] > time.time():
        return json.loads(row["value"])
    return None


def cache_set(key: str, value: Any, ttl: Optional[int] = None) -> None:
    c = connect()
    c.execute(
        "INSERT OR REPLACE INTO cache(key, value, expires) VALUES (?,?,?)",
        (key, json.dumps(value, default=str), time.time() + (ttl or settings.cache_ttl)),
    )
    c.commit()


def cached(key: str, fn: Callable[[], Any], ttl: Optional[int] = None) -> Any:
    """Sync helper: return cached value or compute+store. Exceptions propagate (caller decides)."""
    v = cache_get(key)
    if v is not None:
        return v
    v = fn()
    if v is not None:
        cache_set(key, v, ttl)
    return v


async def acached(key: str, coro_fn, ttl: Optional[int] = None) -> Any:
    v = cache_get(key)
    if v is not None:
        return v
    v = await coro_fn()
    if v is not None:
        cache_set(key, v, ttl)
    return v


# ------------------------------------------------------------------ scans
def save_scan(result) -> None:  # result: ScanResult
    c = connect()
    c.execute(
        "INSERT OR REPLACE INTO scans(scan_id,url,created_at,score,label,result_json) VALUES (?,?,?,?,?,?)",
        (
            result.scan_id,
            result.url,
            result.created_at.isoformat(),
            result.verdict.score,
            result.verdict.label,
            result.model_dump_json(),
        ),
    )
    c.commit()


def get_scan(scan_id: str):
    from .schemas import ScanResult

    row = connect().execute("SELECT result_json FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    return ScanResult.model_validate_json(row["result_json"]) if row else None


def list_scans(limit: int = 50) -> list[dict]:
    rows = connect().execute(
        "SELECT scan_id,url,created_at,score,label FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------ radar
def save_radar_hit(hit) -> int:  # hit: RadarHit
    c = connect()
    cur = c.execute(
        """INSERT INTO radar_hits(domain,source,first_seen,flagged_at,hit_json) VALUES (?,?,?,?,?)
           ON CONFLICT(domain,source) DO UPDATE SET hit_json=excluded.hit_json""",
        (hit.domain, hit.source, hit.first_seen.isoformat(), hit.flagged_at.isoformat(), hit.model_dump_json()),
    )
    c.commit()
    row = c.execute("SELECT id FROM radar_hits WHERE domain=? AND source=?", (hit.domain, hit.source)).fetchone()
    return row["id"]


def list_radar_hits(limit: int = 200):
    from .schemas import RadarHit

    rows = connect().execute(
        "SELECT id, hit_json FROM radar_hits ORDER BY flagged_at DESC LIMIT ?", (limit,)
    ).fetchall()
    out = []
    for r in rows:
        h = RadarHit.model_validate_json(r["hit_json"])
        h.id = r["id"]
        out.append(h)
    return out


# ------------------------------------------------------------------ helpline
def save_phone_finding(f) -> None:  # f: PhoneFinding
    c = connect()
    c.execute(
        "INSERT OR IGNORE INTO phone_findings(brand_id,number_e164,source,status,found_at,finding_json) VALUES (?,?,?,?,?,?)",
        (f.brand_id, f.number_e164, f.source, f.status, f.found_at.isoformat(), f.model_dump_json(exclude={"found_at", "id"})),
    )
    c.commit()


def list_phone_findings(limit: int = 500):
    from .schemas import PhoneFinding

    rows = connect().execute(
        "SELECT id, finding_json, found_at FROM phone_findings ORDER BY found_at DESC LIMIT ?", (limit,)
    ).fetchall()
    out = []
    for r in rows:
        f = PhoneFinding.model_validate_json(r["finding_json"])
        f.id, f.found_at = r["id"], r["found_at"]
        out.append(f)
    return out


# ------------------------------------------------------------------ cases
def save_case(case) -> None:
    c = connect()
    c.execute(
        "INSERT OR REPLACE INTO cases(scan_id,created_at,case_json) VALUES (?,?,?)",
        (case.scan_id, case.created_at.isoformat(), case.model_dump_json()),
    )
    c.commit()
