"""Owner: intel. Domain intelligence for domain-only verdicts and police evidence.

Public API:
  async enrich(domain) -> Intel          RDAP/WHOIS, DNS, ASN, crt.sh first-seen, blocklists, Tranco, urlscan, Safe Browsing
  blocklist_hits(url) -> list[str]       feed names listing this URL/host (local files only; offline-safe)
  feed_urls(limit=200) -> dict           recent phishing URLs per feed (eval set)
  async crtsh_search(pattern, days=30)   crt.sh identity search for radar

Intel.sources values: ok | cached | unavailable | offline | no_key | not_found (rdap: domain not registered)
| no_ip (asn: domain has no A record).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from scamshield.core import db
from scamshield.core.config import settings
from scamshield.core.domains import host_of, registrable
from scamshield.core.schemas import Intel

from . import feeds as _feeds
from ._common import DAY, HOUR, log, parse_dt, run_source
from . import crtsh as _crtsh
from .crtsh import crtsh_search
from .keyed import fetch_safe_browsing, fetch_urlscan
from .netinfo import fetch_asn, fetch_dns
from .rdap import fetch_ip_rdap, registration

__all__ = ["enrich", "blocklist_hits", "feed_urls", "crtsh_search"]

TOTAL_CAP = 10.0


def blocklist_hits(url: str) -> list[str]:
    """Feed names (openphish, phishunt) listing this URL or its host. Reads local feed files; refreshes them
    (at most hourly) when online. Never raises."""
    try:
        if not settings.offline:
            for name in _feeds.FEEDS:
                _feeds.refresh_feed(name)
        return _feeds.hits(url)
    except Exception as e:
        log.info("blocklist_hits failed: %r", e)
        return []


def feed_urls(limit: int = 200) -> dict[str, list[str]]:
    return _feeds.feed_urls(limit)


CRTSH_FAIL_TTL = 15 * 60
CRTSH_WAIT = 4.5  # how long enrich waits for crt.sh before using the Cert Spotter fallback


def _crtsh_bg(reg: str):
    """Runs in a worker thread with its own loop, so it can outlive enrich's cap. Caches success (1 d) itself;
    failures are remembered for 15 min (429s also set a global crt.sh cooldown) so we don't hammer crt.sh."""
    fail_key = f"intel:crtsh_fail:{reg}"
    if db.cache_get(fail_key):
        return None
    try:
        rows = asyncio.run(_crtsh._get({"q": reg, "output": "json"}, 25.0, retries=0))
    except Exception as e:
        log.info("crt.sh failed for %s: %r", reg, e)
        rows = None
    if rows is None:
        db.cache_set(fail_key, True, CRTSH_FAIL_TTL)
        return None
    nbs = [d for d in (parse_dt(r.get("not_before")) for r in rows) if d]
    v = {"first_seen": min(nbs).isoformat() if nbs else None, "count": len({r.get("id") for r in rows}),
         "via": "crtsh"}
    db.cache_set(f"intel:crtsh:{reg}", v, DAY)
    return v


async def enrich(domain: str, host: str | None = None) -> Intel:
    """Never raises; each source's status is recorded in Intel.sources. Wall time capped at ~10 s.
    `domain` may be a registrable domain, a host or a URL. Pass the actual `host` (e.g. the final URL's host)
    when `domain` is the registrable domain: DNS/ASN, blocklists and Safe Browsing then use the real host."""
    try:
        return await _enrich(host or domain)
    except Exception as e:  # pragma: no cover - last resort
        log.warning("enrich(%s) crashed: %r", domain, e)
        h = host_of(domain) or domain
        return Intel(domain=h, registrable_domain=registrable(h) if h else "", sources={"intel": "unavailable"})


async def _enrich(domain: str) -> Intel:
    host = host_of(domain) or domain.strip().lower()
    reg = registrable(host)
    intel = Intel(domain=host, registrable_domain=reg)
    src: dict[str, str] = {}

    async def do_registration():
        v = await run_source(src, "rdap", f"intel:reg:{reg}", lambda: registration(reg),
                             lambda v: 7 * DAY if v.get("found") else HOUR)
        if not v:
            return
        if v.get("found") is False:
            src["rdap"] = "not_found"
            intel.raw_rdap = {"found": False, "via": v.get("via", "")}
            return
        via = v.get("via", "rdap")
        if via == "whois":
            src["whois"], src["rdap"] = src["rdap"], "unavailable"
        elif via == "rdap+whois":
            src["whois"] = src["rdap"]
        intel.created = parse_dt(v.get("created"))
        if intel.created:
            intel.age_days = max(0, (datetime.now(timezone.utc) - intel.created).days)
        intel.registrar = v.get("registrar") or ""
        intel.abuse_emails = v.get("abuse_emails") or []
        if v.get("nameservers"):
            intel.nameservers = v["nameservers"]
        intel.raw_rdap = {"found": True, "via": via, **(v.get("raw") or {})}

    async def do_dns():
        d = await run_source(src, "dns", f"intel:dns:{host}", lambda: fetch_dns(host, reg), HOUR)
        if not d:
            src.setdefault("asn", "unavailable")
            return
        intel.a_records = d.get("a", [])
        intel.mx_records = d.get("mx", [])
        if d.get("ns") and not intel.nameservers:
            intel.nameservers = d["ns"]
        if not intel.a_records and host == reg and not settings.offline:
            # apex has no A: phishing usually lives on a subdomain; try ones the feeds list
            from .netinfo import _q, _resolver

            for h in _feeds.listed_hosts(reg):
                a, _ = await _q(_resolver(), h, "A")
                if a:
                    intel.a_records = a
                    break
        if not intel.a_records:
            src["asn"] = "no_ip"
            return
        intel.ip = intel.a_records[0]
        a = await run_source(src, "asn", f"intel:asn:{intel.ip}", lambda: fetch_asn(intel.ip), DAY)
        if a:
            intel.asn, intel.asn_org, intel.hosting_country = a.get("asn", ""), a.get("asn_org", ""), a.get("country", "")
        ipr = await run_source(src, "ip_rdap", f"intel:iprdap:{intel.ip}", lambda: fetch_ip_rdap(intel.ip), 7 * DAY)
        if ipr:
            intel.hosting_abuse_emails = ipr.get("abuse_emails") or []
            if not intel.hosting_country:
                intel.hosting_country = ipr.get("country", "")

    async def do_crtsh():
        key = f"intel:crtsh:{reg}"
        v = db.cache_get(key)
        if v is not None:
            src["crtsh"] = "cached"
        elif settings.offline:
            src["crtsh"] = "offline"
        else:
            fut = asyncio.ensure_future(asyncio.to_thread(_crtsh_bg, reg))
            done, _ = await asyncio.wait({fut}, timeout=CRTSH_WAIT)
            v = fut.result() if fut in done and not fut.exception() else None
            src["crtsh"] = "ok" if v else "unavailable"  # thread keeps running and caches a late answer
            if v is None:
                v = await run_source(src, "certspotter", f"intel:certspotter:{reg}",
                                     lambda: asyncio.wait_for(_crtsh._certspotter(reg, 4.0, 1), 4.5), DAY)
        if v:
            intel.cert_first_seen = parse_dt(v.get("first_seen"))
            intel.cert_count = v.get("count")

    async def do_feeds():
        st = await asyncio.to_thread(_feeds.refresh_feeds)
        for name, s in st.items():
            src[name] = s

    async def do_urlscan():
        if not settings.urlscan_key:
            src["urlscan"] = "no_key"
            return
        v = await run_source(src, "urlscan", f"intel:urlscan:{reg}", lambda: fetch_urlscan(reg), 6 * HOUR)
        if v:
            intel.urlscan = v

    async def do_sb():
        if not settings.safe_browsing_key:
            src["safe_browsing"] = "no_key"
            return
        v = await run_source(src, "safe_browsing", f"intel:sb:{host}", lambda: fetch_safe_browsing(host), HOUR)
        if v is not None:
            intel.safe_browsing = v

    jobs = {"rdap": do_registration, "dns": do_dns, "crtsh": do_crtsh, "feeds": do_feeds,
            "urlscan": do_urlscan, "safe_browsing": do_sb}
    tasks = {asyncio.create_task(fn()): name for name, fn in jobs.items()}
    done, pending = await asyncio.wait(tasks, timeout=TOTAL_CAP)
    for t in pending:
        t.cancel()
        src.setdefault(tasks[t], "unavailable")
    for t in done:
        if t.exception():
            log.info("intel job %s failed: %r", tasks[t], t.exception())
            src.setdefault(tasks[t], "unavailable")
    if "dns" in src and "asn" not in src:
        src["asn"] = "unavailable"

    # local lookups (no network)
    try:
        _feeds.ensure_tranco_background()
        if _feeds.tranco_available():
            intel.tranco_rank = _feeds.tranco_rank(reg)
            src["tranco"] = "cached"
        else:
            src["tranco"] = "offline" if settings.offline else "unavailable"
        intel.blocklist_hits = _feeds.hits(host)
        for name in _feeds.FEEDS:
            if name not in src:
                src[name] = "cached" if _feeds._path(name).exists() else ("offline" if settings.offline else "unavailable")
    except Exception as e:
        log.info("local lookups failed: %r", e)
    intel.sources = src
    return intel
