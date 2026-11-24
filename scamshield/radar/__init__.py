"""Owner: radar. Early detection of UAE brand look-alike domains.

Sources (RadarHit.source): crtsh (CT backfill), certstream (live CT), nrd (newly registered domains),
search_ads / search_organic (SerpApi). Every hit stores first_seen (when the source says it appeared) and
flagged_at (when we flagged it) and is pushed through scamshield.pipeline.scan_url.
Dashboard helpers: feed(), time_to_detection_seconds(hit)."""
from __future__ import annotations

from scamshield.core.schemas import RadarHit

from .common import MEASURED_BASES, feed, humanize_seconds, scan_hits, store_hit, time_to_detection_seconds, ttd_measured
from .watchlist import decode_host, match, match_detail, query_terms, skeleton, watchlist


async def backfill_crtsh(days: int = 30, scan: bool = True, limit: int | None = None, **kw) -> list[RadarHit]:
    """Query crt.sh for watchlist terms, save hits (first_seen = earliest cert not_before), scan each via pipeline."""
    from .crtsh import backfill_crtsh as _b

    return await _b(days=days, scan=scan, limit=limit, **kw)


async def run_certstream(minutes: float | None = None, scan: bool = True) -> dict:
    from .certstream import run_certstream as _r

    return await _r(minutes=minutes, scan=scan)


async def collect_nrd(days: int = 4, scan: bool = True, limit: int | None = None) -> list[RadarHit]:
    from .nrd import collect_nrd as _c

    return await _c(days=days, scan=scan, limit=limit)


async def collect_search(scan: bool = True, limit: int | None = None) -> list[RadarHit]:
    from .search import collect_search as _c

    return await _c(scan=scan, limit=limit)


def siblings(domain: str) -> list[dict]:
    """Domains sharing IP / nameserver / cert / favicon hash with domain (from scanned + radar domains in db)."""
    try:
        from .network import siblings as _s

        return _s(domain)
    except Exception:
        return []


__all__ = ["watchlist", "match", "match_detail", "query_terms", "decode_host", "skeleton", "backfill_crtsh",
           "run_certstream", "collect_nrd", "collect_search", "siblings", "feed", "time_to_detection_seconds",
           "humanize_seconds", "store_hit", "scan_hits", "ttd_measured", "MEASURED_BASES"]
