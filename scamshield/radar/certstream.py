"""Live Certificate Transparency stream (certstream-server-go via docker-compose.yml).
Matches every name of every new certificate against the watchlist, stores a RadarHit (source 'certstream',
first_seen = CT log entry time `data.seen` (not_before kept in extra.cert_not_before), flagged_at = now) and queues it for the pipeline (3 scan workers).
Auto-reconnects with exponential backoff; if the server is unreachable the status file says so and the
collector keeps retrying (or returns when --minutes elapses). Status: data/radar/certstream_status.json."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from scamshield.core.config import DATA_DIR, settings
from scamshield.core.schemas import RadarHit, utcnow

from .common import SCAN_CONCURRENCY, existing_hit, hit_from_match, scan_hit, store_hit
from .watchlist import hit_domain, match_detail, registrable_of

log = logging.getLogger("scamshield.radar")
STATUS_PATH = DATA_DIR / "radar" / "certstream_status.json"


def _write_status(st: dict) -> None:
    try:
        STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATUS_PATH.write_text(json.dumps(st, default=str, indent=1), encoding="utf-8")
    except Exception:
        pass


def status() -> dict:
    """Last collector status ({state: running|unavailable|stopped, ...}) for the dashboard."""
    try:
        return json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"state": "unavailable", "reason": "collector never ran"}


def parse_message(msg: Any) -> list[dict]:
    """certstream JSON -> [{domains, not_before, cert_index, log, issuer, fingerprint}] (pure, tested)."""
    try:
        m = json.loads(msg) if isinstance(msg, (str, bytes)) else msg
    except Exception:
        return []
    if not isinstance(m, dict):
        return []
    t = m.get("message_type")
    data = m.get("data")
    if t == "dns_entries" and isinstance(data, list):
        return [{"domains": data, "not_before": None, "cert_index": None, "log": "", "issuer": "", "fingerprint": ""}]
    if t != "certificate_update" or not isinstance(data, dict):
        return []
    leaf = data.get("leaf_cert") or {}
    nb = leaf.get("not_before")
    nb_dt = None
    try:
        if isinstance(nb, (int, float)):
            nb_dt = datetime.fromtimestamp(float(nb), tz=timezone.utc)
    except Exception:
        nb_dt = None
    issuer = (leaf.get("issuer") or {}).get("aggregated", "") if isinstance(leaf.get("issuer"), dict) else ""
    return [{"domains": leaf.get("all_domains") or [], "not_before": nb_dt, "cert_index": data.get("cert_index"),
             "log": (data.get("source") or {}).get("name", ""), "issuer": issuer,
             "fingerprint": leaf.get("fingerprint", ""), "seen": data.get("seen")}]


def hits_from_message(msg: Any, now: Optional[datetime] = None) -> list[RadarHit]:
    out: dict[str, RadarHit] = {}
    for c in parse_message(msg):
        # first_seen = CT log entry time (data.seen); cert notBefore is backdated (Let's Encrypt: -1 h)
        seen = None
        try:
            if isinstance(c.get("seen"), (int, float)):
                seen = datetime.fromtimestamp(float(c["seen"]), tz=timezone.utc)
        except Exception:
            seen = None
        fs = seen or c["not_before"] or now or utcnow()
        basis = "ct_log" if seen else ("not_before" if c["not_before"] else "observed")
        for d in c["domains"]:
            m = match_detail(str(d))
            if not m:
                continue
            reg = hit_domain(m)
            if reg in out:
                continue
            out[reg] = hit_from_match(reg, "certstream", fs, m, extra={
                "scan_host": m["host"], "hosts": [h for h in c["domains"] if isinstance(h, str)][:20],
                "cert_index": c["cert_index"], "ct_log": c["log"], "issuers": [c["issuer"]] if c["issuer"] else [],
                "fingerprint": c["fingerprint"], "first_seen_basis": basis,
                "cert_not_before": c["not_before"].isoformat() if c["not_before"] else None})
    return list(out.values())


async def run_certstream(minutes: Optional[float] = None, scan: bool = True, url: Optional[str] = None) -> dict:
    """Run the collector (forever if minutes is None). Returns stats. Never raises."""
    url = url or settings.certstream_url
    deadline = time.monotonic() + minutes * 60 if minutes else None
    st = {"state": "starting", "url": url, "started_at": utcnow().isoformat(), "messages": 0, "certs": 0,
          "hits": 0, "new_hits": 0, "reconnects": 0, "last_error": "", "last_hit": None}
    _write_status(st)
    if settings.offline:
        st.update(state="unavailable", last_error="offline mode")
        _write_status(st)
        return st
    try:
        import websockets
    except Exception as e:  # pragma: no cover
        st.update(state="unavailable", last_error=f"websockets missing: {e}")
        _write_status(st)
        return st

    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    seen: set[str] = set()

    async def worker():
        while True:
            h = await q.get()
            try:
                await scan_hit(h)
            finally:
                q.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(SCAN_CONCURRENCY)] if scan else []
    backoff = 2.0
    last_status = 0.0

    def left() -> Optional[float]:
        return None if deadline is None else deadline - time.monotonic()

    try:
        while left() is None or left() > 0:
            try:
                async with websockets.connect(url, max_size=2 ** 23, open_timeout=10, ping_interval=20,
                                              ping_timeout=30) as ws:
                    st.update(state="running", last_error="")
                    log.info("certstream connected: %s", url)
                    backoff = 2.0
                    while left() is None or left() > 0:
                        tmo = 60 if left() is None else max(0.1, min(60, left()))
                        try:
                            msg = await asyncio.wait_for(ws.recv(), tmo)
                        except asyncio.TimeoutError:
                            continue
                        st["messages"] += 1
                        hits = hits_from_message(msg)
                        st["certs"] += 1
                        for h in hits:
                            if h.domain in seen:
                                continue
                            seen.add(h.domain)
                            st["hits"] += 1
                            is_new = existing_hit(h.domain, "certstream") is None
                            h = store_hit(h)
                            st["last_hit"] = {"domain": h.domain, "term": h.matched_term, "at": h.flagged_at}
                            log.info("certstream HIT %s term=%s brand=%s", h.domain, h.matched_term, h.brand_id)
                            if is_new:
                                st["new_hits"] += 1
                                if scan and not q.full():
                                    q.put_nowait(h)
                        if time.monotonic() - last_status > 10:
                            last_status = time.monotonic()
                            st["queue"] = q.qsize()
                            _write_status(st)
            except Exception as e:
                st.update(state="unavailable" if st["messages"] == 0 else "reconnecting",
                          last_error=f"{type(e).__name__}: {e}"[:200])
                st["reconnects"] += 1
                _write_status(st)
                log.warning("certstream %s (%s); retry in %.0fs", st["state"], st["last_error"], backoff)
                wait = backoff if left() is None else min(backoff, max(0, left()))
                await asyncio.sleep(wait)
                backoff = min(backoff * 2, 120)
        if scan and not q.empty():
            try:
                await asyncio.wait_for(q.join(), 600)
            except asyncio.TimeoutError:
                pass
    except Exception as e:
        st["last_error"] = repr(e)[:200]
    finally:
        for w in workers:
            w.cancel()
        st["state"] = "stopped" if st["state"] == "running" else st["state"]
        st["stopped_at"] = utcnow().isoformat()
        _write_status(st)
    return st
