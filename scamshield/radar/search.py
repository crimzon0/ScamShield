"""Search-result radar: sponsored + organic Google results (google.ae) for high-risk EN/AR queries, via SerpApi
only (never scrapes Google). Without settings.serpapi_key the collector records 'unavailable' and returns [].
Ad / result domains that are not official are stored as hits (search_ads / search_organic) with
first_seen = time we saw the result (SerpApi gives no publish date) and scanned through the pipeline."""
from __future__ import annotations

import json
import logging
from collections import Counter
from typing import Optional

from scamshield.core import db
from scamshield.core.config import DATA_DIR, settings
from scamshield.core.schemas import RadarHit, utcnow

from .common import hit_from_match, scan_hits, store_hit
from .watchlist import _wl, _is_official_fast, decode_host, hit_domain, match_detail, registrable_of

log = logging.getLogger("scamshield.radar")
STATUS_PATH = DATA_DIR / "radar" / "search_status.json"

# (query, hl, brand_id). EN + AR high-risk intents: login, card update, fines, parcel fees, bills, helplines.
QUERIES: list[tuple[str, str, Optional[str]]] = [
    ("UAE PASS login", "en", "uae_pass"),
    ("دخول الهوية الرقمية UAE PASS", "ar", "uae_pass"),
    ("TAMM traffic fine payment", "en", "tamm"),
    ("TAMM fines payment Abu Dhabi", "en", "tamm"),
    ("دفع مخالفات المرور ابوظبي", "ar", "tamm"),
    ("دفع مخالفات المرور", "ar", "moi_uae"),
    ("MOI UAE traffic fines inquiry", "en", "moi_uae"),
    ("Dubai Police fine payment", "en", "dubai_police"),
    ("دفع مخالفات شرطة دبي", "ar", "dubai_police"),
    ("Abu Dhabi Police fines payment", "en", "abu_dhabi_police"),
    ("RTA fine payment online", "en", "rta_dubai"),
    ("مخالفات هيئة الطرق والمواصلات دبي دفع", "ar", "rta_dubai"),
    ("Salik recharge online", "en", "salik"),
    ("Salik fine payment", "en", "salik"),
    ("تعبئة رصيد سالك", "ar", "salik"),
    ("Emirates NBD login", "en", "emirates_nbd"),
    ("Emirates NBD customer care", "en", "emirates_nbd"),
    ("Emirates NBD credit card update", "en", "emirates_nbd"),
    ("تجديد بطاقة الإمارات دبي الوطني", "ar", "emirates_nbd"),
    ("ADCB login", "en", "adcb"),
    ("ADCB customer care number", "en", "adcb"),
    ("ADCB card update", "en", "adcb"),
    ("بنك أبوظبي التجاري خدمة العملاء", "ar", "adcb"),
    ("FAB online banking login", "en", "fab"),
    ("FAB customer care number", "en", "fab"),
    ("تحديث بيانات بطاقة بنك أبوظبي الأول", "ar", "fab"),
    ("ADIB card update", "en", "adib"),
    ("ADIB customer care number", "en", "adib"),
    ("تجديد بطاقة مصرف أبوظبي الإسلامي", "ar", "adib"),
    ("Mashreq customer care number", "en", "mashreq"),
    ("Dubai Islamic Bank customer care number", "en", "dubai_islamic_bank"),
    ("RAKBANK customer care number", "en", "rakbank"),
    ("Emirates Post parcel delivery fee", "en", "emirates_post"),
    ("Emirates Post track parcel", "en", "emirates_post"),
    ("بريد الإمارات رسوم توصيل الشحنة", "ar", "emirates_post"),
    ("Aramex delivery fee payment", "en", "aramex"),
    ("Aramex customer care number UAE", "en", "aramex"),
    ("أرامكس دفع رسوم التوصيل", "ar", "aramex"),
    ("Etisalat bill payment", "en", "etisalat_eand"),
    ("دفع فاتورة اتصالات", "ar", "etisalat_eand"),
    ("du bill payment", "en", "du"),
    ("دفع فاتورة دو", "ar", "du"),
    ("Emirates ID renewal online", "en", "icp"),
    ("تجديد الهوية الإماراتية", "ar", "icp"),
    ("ICP visa status check", "en", "icp"),
    ("DEWA bill payment", "en", "dewa"),
    ("دفع فاتورة ديوا", "ar", "dewa"),
]
# scam ads target phones (persona uae_mobile_ad_click): repeat the highest-risk intents with device=mobile
MOBILE_QUERIES: list[tuple[str, str, Optional[str]]] = [
    ("UAE PASS login", "en", "uae_pass"),
    ("TAMM traffic fine payment", "en", "tamm"),
    ("دفع مخالفات المرور", "ar", "moi_uae"),
    ("Dubai Police fine payment", "en", "dubai_police"),
    ("Salik recharge online", "en", "salik"),
    ("Emirates Post parcel delivery fee", "en", "emirates_post"),
    ("Aramex delivery fee payment", "en", "aramex"),
    ("Emirates NBD customer care", "en", "emirates_nbd"),
    ("ADCB customer care number", "en", "adcb"),
    ("Etisalat bill payment", "en", "etisalat_eand"),
]
# hard cap on *live* SerpApi requests made by the radar (cache hits are free); shared free plan = 250/month
SERPAPI_CAP = 100
BUDGET_PATH = DATA_DIR / "radar" / "serpapi_budget.json"
# organic results on very popular domains (news, wikis, social) are not scanned as candidate scams
ORGANIC_POPULAR_RANK = 50_000
AD_BLOCKS = ("ads", "top_ads", "bottom_ads", "shopping_results", "inline_shopping_results", "local_ads")
_NEVER_HOSTS = ("google.", "googleadservices.com", "googlesyndication.com", "doubleclick.net", "gstatic.com")


def budget() -> dict:
    try:
        return json.loads(BUDGET_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"cap": SERPAPI_CAP, "used": 0, "log": []}


def _spend(q: str, hl: str, device: str, ok: bool) -> None:
    b = budget()
    b["cap"] = SERPAPI_CAP
    b["used"] = int(b.get("used", 0)) + 1
    b.setdefault("log", []).append({"at": utcnow().isoformat(), "q": q, "hl": hl, "device": device, "ok": ok})
    try:
        BUDGET_PATH.parent.mkdir(parents=True, exist_ok=True)
        BUDGET_PATH.write_text(json.dumps(b, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception:
        pass


def _status(d: dict) -> None:
    try:
        STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATUS_PATH.write_text(json.dumps(d, default=str, indent=1, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _ad_items(data: dict) -> list[tuple[str, dict]]:
    out = []
    for blk in AD_BLOCKS:
        v = data.get(blk)
        if isinstance(v, dict):  # local_ads: {"ads": [...], ...}
            v = v.get("ads") or v.get("results") or []
        for it in v or []:
            if isinstance(it, dict):
                out.append((blk, it))
    return out


def _popular(reg: str) -> bool:
    try:
        from scamshield.intel.feeds import tranco_rank

        r = tranco_rank(reg)
        return r is not None and r <= ORGANIC_POPULAR_RANK
    except Exception:
        return False


def serp_stats(data: dict) -> dict:
    """Item counts per SERP block (what Google showed), for the report."""
    d: dict = {}
    for blk, _ in _ad_items(data):
        d[blk] = d.get(blk, 0) + 1
    d["organic_results"] = len(data.get("organic_results") or [])
    return d


def parse_serp(data: dict, query: str, brand_hint: Optional[str], device: str = "desktop",
               stats: Optional[dict] = None) -> list[RadarHit]:
    """SerpApi JSON -> hits. Ads (ads/top_ads/bottom_ads/shopping/local_ads): every non-official advertiser for
    a brand query is a hit (the query itself is the brand context). Organic: a non-official result is a hit when
    its domain matches the watchlist, or - for a brand query - when it is not a popular (Tranco top-50k),
    government or academic site."""
    wl = _wl()
    now = utcnow()
    st = stats if stats is not None else {}
    out: dict[tuple, RadarHit] = {}
    blocks = [("search_ads", blk, a) for blk, a in _ad_items(data)]
    blocks += [("search_organic", "organic_results", r) for r in (data.get("organic_results") or [])]
    for source, blk, item in blocks:
        link = item.get("link") or item.get("tracking_link") or ""
        host = decode_host(item.get("displayed_link") if not link else link)
        if host and any(n in host for n in _NEVER_HOSTS) and item.get("displayed_link"):
            host = decode_host(item["displayed_link"])  # tracking redirector: use the advertiser's shown domain
            link = ""
        if not host or "." not in host:
            continue
        st[f"{source}_seen"] = st.get(f"{source}_seen", 0) + 1
        if wl["official"] and _is_official_fast(host, wl["official_set"]):
            st[f"{source}_official"] = st.get(f"{source}_official", 0) + 1
            continue
        if any(n in host for n in _NEVER_HOSTS):
            continue
        m = match_detail(host)
        reg = registrable_of(host)
        if m is None and brand_hint:
            if source == "search_ads":
                m = {"term": query, "brand_id": brand_hint, "kind": "ad_for_brand_query", "host": host,
                     "registrable": reg}
            elif not (reg.endswith((".gov.ae", ".ac.ae", ".gov", ".edu")) or _popular(reg)):
                m = {"term": query, "brand_id": brand_hint, "kind": "organic_for_brand_query", "host": host,
                     "registrable": reg}
            else:
                st["search_organic_skipped_popular_or_gov"] = st.get("search_organic_skipped_popular_or_gov", 0) + 1
        if m is None:
            continue
        dom = reg if m.get("kind") in ("ad_for_brand_query", "organic_for_brand_query") else hit_domain(m)
        key = (dom, source)
        if key in out:
            continue
        st[f"{source}_non_official"] = st.get(f"{source}_non_official", 0) + 1
        scan_url = link if link.startswith("http") and decode_host(link) == host else ""
        out[key] = hit_from_match(dom, source, now, m, extra={
            "query": query, "device": device, "serp_block": blk, "position": item.get("position"),
            "title": (item.get("title") or "")[:200],
            "snippet": (item.get("snippet") or item.get("description") or "")[:300], "link": link[:500],
            "scan_host": host, "scan_url": scan_url[:500],
            "first_seen_basis": "observed (SerpApi has no publish time)"})
    return list(out.values())


def _plan() -> list[tuple[str, str, Optional[str], str]]:
    return [(q, hl, b, "desktop") for q, hl, b in QUERIES] + [(q, hl, b, "mobile") for q, hl, b in MOBILE_QUERIES]


async def collect_search(scan: bool = True, limit: Optional[int] = None,
                         max_live: Optional[int] = None) -> list[RadarHit]:
    """Run every planned query (cached 24h per query/hl/device). Live SerpApi requests are counted in
    data/radar/serpapi_budget.json and never exceed SERPAPI_CAP (or max_live for this run)."""
    st = {"state": "unavailable", "at": utcnow().isoformat(), "queries": 0, "live_requests": 0,
          "cache_hits": 0, "skipped_budget": 0, "hits": 0, "blocks": {}, "per_query": []}
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
    counts: dict = {}
    try:
        async with httpx.AsyncClient(timeout=40) as c:
            for q, hl, bid, device in _plan():
                params = {"engine": "google", "q": q, "google_domain": "google.ae", "gl": "ae", "hl": hl,
                          "location": "United Arab Emirates", "device": device, "num": 20,
                          "api_key": settings.serpapi_key}
                key = f"radar:serp:v2:{q}:{hl}:{device}"
                data = db.cache_get(key)
                if data is not None:
                    st["cache_hits"] += 1
                else:
                    used = int(budget().get("used", 0))
                    if used >= SERPAPI_CAP or (max_live is not None and st["live_requests"] >= max_live):
                        st["skipped_budget"] += 1
                        continue
                    err = None
                    try:
                        r = await c.get("https://serpapi.com/search.json", params=params)
                        data = r.json() if r.status_code == 200 else None
                        if data is None:
                            err = f"http {r.status_code}"
                    except Exception as e:
                        data, err = None, repr(e)[:120]
                    st["live_requests"] += 1
                    _spend(q, hl, device, bool(data) and not (data or {}).get("error"))
                    if data and not data.get("error"):
                        db.cache_set(key, data, 24 * 3600)
                    else:
                        log.info("serpapi %s failed: %s", q, err or (data or {}).get("error"))
                        data = None
                st["queries"] += 1
                if data:
                    qs: dict = {}
                    hs = parse_serp(data, q, bid, device, qs)
                    for h in hs:
                        h.extra["hl"] = hl
                    hits += hs
                    blocks = serp_stats(data)
                    for k, v in list(qs.items()) + [("block_" + k, v) for k, v in blocks.items()]:
                        counts[k] = counts.get(k, 0) + v
                    st["per_query"].append({"q": q, "hl": hl, "device": device, "blocks": blocks,
                                            "hits": [f"{h.source}:{h.domain}" for h in hs]})
        st["state"] = "ok"
        st["blocks"] = counts
        best: dict[tuple, RadarHit] = {}
        for h in hits:
            best.setdefault((h.domain, h.source), h)
        hits = list(best.values())[: limit or None]
        hits = [store_hit(h) for h in hits]
        st["hits"] = len(hits)
        _status(st)
        if scan:
            todo = [h for h in hits if not h.scan_id]
            hits = [h for h in hits if h.scan_id] + await scan_hits(todo)
            st["labels"] = dict(Counter(h.label for h in hits))
    except Exception as e:
        st["state"], st["reason"] = "error", repr(e)[:200]
    st["budget"] = {k: v for k, v in budget().items() if k != "log"}
    _status(st)
    return hits
