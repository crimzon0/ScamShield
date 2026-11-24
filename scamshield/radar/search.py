"""Search-result radar: sponsored + organic Google results (google.ae) for high-risk EN/AR queries, via SerpApi
only (never scrapes Google). Without settings.serpapi_key the collector records 'unavailable' and returns [].
Ad / result domains that are not official are stored as hits (search_ads / search_organic) with
first_seen = time we saw the result (SerpApi gives no publish date) and scanned through the pipeline."""
from __future__ import annotations

import json
import logging
from typing import Optional

from scamshield.core import db
from scamshield.core.config import DATA_DIR, settings
from scamshield.core.schemas import RadarHit, utcnow

from .common import hit_from_match, scan_hits, store_hit
from .watchlist import _wl, _is_official_fast, decode_host, hit_domain, match_detail, registrable_of

log = logging.getLogger("scamshield.radar")
STATUS_PATH = DATA_DIR / "radar" / "search_status.json"

# (query, hl, brand_id)
QUERIES: list[tuple[str, str, Optional[str]]] = [
    ("UAE PASS login", "en", "uae_pass"),
    ("دخول الهوية الرقمية UAE PASS", "ar", "uae_pass"),
    ("TAMM traffic fine payment", "en", "tamm"),
    ("دفع مخالفات المرور ابوظبي", "ar", "tamm"),
    ("Dubai Police fine payment", "en", "dubai_police"),
    ("دفع مخالفات شرطة دبي", "ar", "dubai_police"),
    ("RTA fine payment online", "en", "rta_dubai"),
    ("Salik recharge online", "en", "salik"),
    ("تعبئة رصيد سالك", "ar", "salik"),
    ("Emirates NBD customer care", "en", "emirates_nbd"),
    ("ADCB customer care number", "en", "adcb"),
    ("Emirates Post parcel delivery fee", "en", "emirates_post"),
    ("بريد الإمارات رسوم توصيل الشحنة", "ar", "emirates_post"),
    ("ICP visa status check", "en", "icp"),
    ("Etisalat bill payment", "en", "etisalat_eand"),
    ("DEWA bill payment", "en", "dewa"),
]


def _status(d: dict) -> None:
    try:
        STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATUS_PATH.write_text(json.dumps(d, default=str, indent=1, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def parse_serp(data: dict, query: str, brand_hint: Optional[str]) -> list[RadarHit]:
    """SerpApi JSON -> hits. Ads: every non-official advertiser link for a brand query is a hit (the query
    itself is the brand context). Organic: only results whose domain matches the watchlist."""
    wl = _wl()
    now = utcnow()
    out: dict[tuple, RadarHit] = {}
    blocks = [("search_ads", a) for a in (data.get("ads") or [])]
    blocks += [("search_ads", a) for a in (data.get("top_ads") or []) + (data.get("bottom_ads") or [])]
    blocks += [("search_organic", r) for r in (data.get("organic_results") or [])]
    for source, item in blocks:
        link = item.get("link") or item.get("tracking_link") or ""
        host = decode_host(item.get("displayed_link") if not link else link)
        if not host or "." not in host:
            continue
        if wl["official"] and _is_official_fast(host, wl["official_set"]):
            continue
        m = match_detail(host)
        if m is None and source == "search_ads" and brand_hint:
            m = {"term": query, "brand_id": brand_hint, "kind": "ad_for_brand_query", "host": host,
                 "registrable": registrable_of(host)}
        if m is None:
            continue
        dom = hit_domain(m) if m.get("kind") != "ad_for_brand_query" else registrable_of(host)
        key = (dom, source)
        if key in out:
            continue
        out[key] = hit_from_match(dom, source, now, m, extra={
            "query": query, "position": item.get("position"), "title": (item.get("title") or "")[:200],
            "snippet": (item.get("snippet") or item.get("description") or "")[:300], "link": link[:500],
            "scan_host": host, "first_seen_basis": "observed (SerpApi has no publish time)"})
    return list(out.values())


async def collect_search(scan: bool = True, limit: Optional[int] = None) -> list[RadarHit]:
    st = {"state": "unavailable", "at": utcnow().isoformat(), "queries": 0, "hits": 0}
    if not settings.serpapi_key:
        st["reason"] = "no SERPAPI_KEY"
        _status(st)
        log.warning("search radar unavailable: no SERPAPI_KEY (we never scrape Google directly)")
        return []
    if settings.offline:
        st["reason"] = "offline"
        _status(st)
        return []
    import httpx

    hits: list[RadarHit] = []
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            for q, hl, bid in QUERIES:
                params = {"engine": "google", "q": q, "google_domain": "google.ae", "gl": "ae", "hl": hl,
                          "num": 20, "api_key": settings.serpapi_key}

                async def _fetch():
                    r = await c.get("https://serpapi.com/search.json", params=params)
                    return r.json() if r.status_code == 200 else None

                try:
                    data = await db.acached(f"radar:serp:{q}:{hl}", _fetch, ttl=6 * 3600)
                except Exception as e:
                    log.info("serpapi %s failed: %r", q, e)
                    data = None
                st["queries"] += 1
                if data:
                    hits += parse_serp(data, q, bid)
        st["state"] = "ok"
        best: dict[tuple, RadarHit] = {}
        for h in hits:
            best.setdefault((h.domain, h.source), h)
        hits = list(best.values())[: limit or None]
        hits = [store_hit(h) for h in hits]
        st["hits"] = len(hits)
        if scan:
            todo = [h for h in hits if not h.scan_id]
            hits = [h for h in hits if h.scan_id] + await scan_hits(todo)
    except Exception as e:
        st["state"], st["reason"] = "error", repr(e)[:200]
    _status(st)
    return hits
