"""Shared radar plumbing: build/store hits (keeping the earliest first_seen and the original flagged_at),
push hits through the one pipeline with bounded concurrency, time-to-detection helpers for the dashboard."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from scamshield.core import db
from scamshield.core.schemas import RadarHit, utcnow

log = logging.getLogger("scamshield.radar")

SCAN_CONCURRENCY = 3
SCAN_TIMEOUT = 150.0  # seconds per pipeline.scan_url (detonate + enrich)


def _aware(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def parse_dt(v: Any) -> Optional[datetime]:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return _aware(v)
    try:
        s = str(v).strip().replace("Z", "+00:00")
        if len(s) == 10:  # date only
            s += "T00:00:00+00:00"
        return _aware(datetime.fromisoformat(s))
    except Exception:
        return None


def existing_hit(domain: str, source: str) -> Optional[RadarHit]:
    try:
        row = db.connect().execute(
            "SELECT id, hit_json FROM radar_hits WHERE domain=? AND source=?", (domain, source)).fetchone()
        if not row:
            return None
        h = RadarHit.model_validate_json(row["hit_json"])
        h.id = row["id"]
        return h
    except Exception:
        return None


def store_hit(hit: RadarHit) -> RadarHit:
    """Upsert. A re-sighting never moves flagged_at forward and keeps the earliest first_seen,
    so time-to-detection stays honest across reruns."""
    try:
        old = existing_hit(hit.domain, hit.source)
        if old is not None:
            hit.flagged_at = min(_aware(old.flagged_at), _aware(hit.flagged_at))
            nb, ob = hit.extra.get("first_seen_basis"), old.extra.get("first_seen_basis")
            if nb and nb != ob:  # the basis changed (e.g. not_before -> ct_log): trust the new measurement
                hit.first_seen = _aware(hit.first_seen)
            else:
                hit.first_seen = min(_aware(old.first_seen), _aware(hit.first_seen))
            if hit.scan_id is None and old.scan_id:
                hit.scan_id, hit.score, hit.label = old.scan_id, old.score, old.label
            merged = dict(old.extra)
            merged.update(hit.extra)
            hit.extra = merged
        hit.extra["time_to_detection_seconds"] = time_to_detection_seconds(hit)
        hit.id = db.save_radar_hit(hit)
    except Exception as e:
        log.warning("store_hit %s failed: %s", hit.domain, e)
    return hit


def time_to_detection_seconds(hit: Any) -> Optional[int]:
    """flagged_at - first_seen in seconds (RadarHit or dict). None if unknown."""
    try:
        fs = parse_dt(hit["first_seen"] if isinstance(hit, dict) else hit.first_seen)
        fa = parse_dt(hit["flagged_at"] if isinstance(hit, dict) else hit.flagged_at)
        if fs and fa:
            return int((fa - fs).total_seconds())
    except Exception:
        pass
    return None


def humanize_seconds(s: Optional[int]) -> str:
    if s is None:
        return "?"
    s = max(0, int(s))
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h{(s % 3600) // 60:02d}m"
    return f"{s // 86400}d{(s % 86400) // 3600}h"


def hit_from_match(domain: str, source: str, first_seen: datetime, m: dict, extra: Optional[dict] = None,
                   flagged_at: Optional[datetime] = None) -> RadarHit:
    ex = {"match_kind": m.get("kind"), "host": m.get("host")}
    for k in ("fuzzer", "official", "theme", "lang"):
        if m.get(k):
            ex[k] = m[k]
    if m.get("registrable") and domain != m["registrable"]:
        ex["subdomain_only"] = True  # brand term only in a subdomain of someone else's domain (lower prior)
        try:  # ...unless it is the classic 'emiratesnbd.com-verify.bond' official-domain-as-prefix trick
            from .watchlist import _wl

            host = m.get("host", "")
            for off in _wl()["official_by_brand"].get(m.get("brand_id") or "", []):
                if host.startswith(off + "-") or host.startswith(off + "."):
                    ex["official_prefix"] = off
                    ex["subdomain_only"] = False
                    break
        except Exception:
            pass
    ex.update(extra or {})
    return RadarHit(domain=domain, source=source, matched_term=m.get("term", ""), brand_id=m.get("brand_id"),
                    first_seen=_aware(first_seen), flagged_at=flagged_at or utcnow(), extra=ex)


async def scan_hit(hit: RadarHit, sem: Optional[asyncio.Semaphore] = None, force: bool = False) -> RadarHit:
    """Run the hit through scamshield.pipeline.scan_url and store scan_id/score/label. Never raises."""
    async def _run():
        from scamshield.pipeline import scan_url

        host = hit.extra.get("scan_host") or hit.domain
        kw = {}
        if force:
            import inspect

            if "force" in inspect.signature(scan_url).parameters:
                kw["force"] = True
        target = hit.extra.get("scan_url") or ("https://" + host)  # search hits: the real landing URL
        res = await asyncio.wait_for(scan_url(target, **kw), SCAN_TIMEOUT)
        hit.scan_id = res.scan_id
        hit.score = res.verdict.score
        hit.label = res.verdict.label
        hit.extra["scanned_at"] = utcnow().isoformat()
        hit.extra["scan_mode"] = res.verdict.mode
        if res.verdict.final_url:
            hit.extra["final_url"] = res.verdict.final_url
        hit.extra.pop("scan_error", None)

    try:
        if sem is None:
            await _run()
        else:
            async with sem:
                await _run()
    except Exception as e:
        log.warning("scan %s failed: %r", hit.domain, e)
        hit.extra["scan_error"] = repr(e)[:200]
    return store_hit(hit)


async def scan_hits(hits: Iterable[RadarHit], concurrency: int = SCAN_CONCURRENCY,
                    force: bool = False) -> list[RadarHit]:
    sem = asyncio.Semaphore(concurrency)
    return list(await asyncio.gather(*(scan_hit(h, sem, force=force) for h in hits)))


MEASURED_BASES = ("ct_log", "nrd_list_date")


def ttd_measured(hit: Any) -> bool:
    """True only when first_seen is a measured publication time (CT log entry / NRD list date), not an
    estimate (cert notBefore, LE-backdate adjustment, observation time)."""
    ex = hit.get("extra", {}) if isinstance(hit, dict) else hit.extra
    return ex.get("first_seen_basis") in MEASURED_BASES


def feed(limit: int = 200, source: Optional[str] = None) -> list[dict]:
    """Dashboard helper: hits as dicts incl. time_to_detection_seconds / _human."""
    out = []
    try:
        for h in db.list_radar_hits(limit=limit if not source else limit * 5):
            if source and h.source != source:
                continue
            d = h.model_dump(mode="json")
            d["time_to_detection_seconds"] = time_to_detection_seconds(h)
            d["time_to_detection_human"] = humanize_seconds(d["time_to_detection_seconds"])
            d["first_seen_basis"] = h.extra.get("first_seen_basis", "not_before")
            d["ttd_measured"] = ttd_measured(h)
            out.append(d)
            if len(out) >= limit:
                break
    except Exception as e:
        log.warning("feed failed: %s", e)
    return out
