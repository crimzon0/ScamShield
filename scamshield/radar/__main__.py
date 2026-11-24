"""CLI: python -m scamshield.radar {backfill|certstream|nrd|search|watchlist|match|feed|siblings}"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from .common import feed, humanize_seconds, time_to_detection_seconds


def _print_hits(hits, n=40):
    for h in hits[:n]:
        ttd = humanize_seconds(time_to_detection_seconds(h))
        print(f"{h.domain:45.45} {h.source:14} term={h.matched_term:16.16} brand={str(h.brand_id):16.16} "
              f"first_seen={h.first_seen.isoformat()[:19]} flagged_at={h.flagged_at.isoformat()[:19]} "
              f"ttd={ttd:>7} label={h.label} score={h.score} scan={h.scan_id}")


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="python -m scamshield.radar")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backfill", help="crt.sh backfill")
    b.add_argument("--days", type=int, default=30)
    b.add_argument("--limit", type=int, default=None, help="max hits to store/scan")
    b.add_argument("--terms", type=int, default=None, help="max watchlist terms to query")
    b.add_argument("--no-scan", action="store_true")
    b.add_argument("--no-fetch", action="store_true", help="re-parse persisted raw responses only")
    b.add_argument("--force", action="store_true", help="re-query terms fetched recently")
    c = sub.add_parser("certstream", help="live CT stream (needs docker compose up -d)")
    c.add_argument("--minutes", type=float, default=None)
    c.add_argument("--no-scan", action="store_true")
    n = sub.add_parser("nrd", help="newly registered domains (whoisds daily list)")
    n.add_argument("--days", type=int, default=4)
    n.add_argument("--limit", type=int, default=None)
    n.add_argument("--no-scan", action="store_true")
    s = sub.add_parser("search", help="sponsored/organic search results via SerpApi")
    s.add_argument("--limit", type=int, default=None)
    s.add_argument("--no-scan", action="store_true")
    s.add_argument("--max-live", type=int, default=None, help="max live SerpApi requests this run (cap 100 total)")
    sub.add_parser("watchlist", help="print watchlist stats")
    sub.add_parser("prune", help="drop stored hits the current matcher no longer accepts")
    rs = sub.add_parser("rescan", help="re-scan already-scanned hits (force) with the current engine")
    rs.add_argument("--limit", type=int, default=1000)
    sp = sub.add_parser("scan-pending", help="scan stored hits that have no scan yet")
    sp.add_argument("--limit", type=int, default=200)
    m = sub.add_parser("match")
    m.add_argument("domains", nargs="+")
    f = sub.add_parser("feed")
    f.add_argument("--limit", type=int, default=50)
    g = sub.add_parser("siblings")
    g.add_argument("domain")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO if a.verbose or a.cmd in ("backfill", "certstream", "nrd", "search")
                        else logging.WARNING, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for noisy in ("httpx", "httpcore", "websockets"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    if a.cmd == "backfill":
        from .crtsh import backfill_crtsh

        hits = asyncio.run(backfill_crtsh(days=a.days, scan=not a.no_scan, limit=a.limit, limit_terms=a.terms,
                                          force=a.force, fetch=not a.no_fetch))
        print(f"crt.sh backfill: {len(hits)} hits")
        _print_hits(hits)
    elif a.cmd == "certstream":
        from .certstream import run_certstream

        r = asyncio.run(run_certstream(minutes=a.minutes, scan=not a.no_scan))
        print(json.dumps(r, default=str, indent=1))
    elif a.cmd == "nrd":
        from .nrd import collect_nrd

        hits = asyncio.run(collect_nrd(days=a.days, scan=not a.no_scan, limit=a.limit))
        print(f"NRD: {len(hits)} hits")
        _print_hits(hits)
    elif a.cmd == "search":
        from .search import collect_search

        hits = asyncio.run(collect_search(scan=not a.no_scan, limit=a.limit, max_live=a.max_live))
        print(f"search: {len(hits)} hits")
        _print_hits(hits)
    elif a.cmd == "scan-pending":
        from scamshield.core import db

        from .common import scan_hits

        todo = [h for h in db.list_radar_hits(5000) if not h.scan_id and not h.extra.get("scan_error")]
        # registrable look-alikes before brand-in-subdomain hits; newest first
        todo.sort(key=lambda h: (bool(h.extra.get("subdomain_only")), -h.first_seen.timestamp()))
        todo = todo[: a.limit]
        hits = asyncio.run(scan_hits(todo))
        print(f"scanned {len(hits)} hits")
        _print_hits(hits)
    elif a.cmd == "rescan":
        from scamshield.core import db

        from .common import scan_hits

        todo = [h for h in db.list_radar_hits(100000) if h.scan_id][: a.limit]
        hits = asyncio.run(scan_hits(todo, force=True))
        print(f"rescanned {len(hits)} hits")
        _print_hits(hits)
    elif a.cmd == "prune":
        from scamshield.core import db

        from .watchlist import match_detail

        c = db.connect()
        gone = []
        for h in db.list_radar_hits(100000):
            host = h.extra.get("scan_host") or h.extra.get("host") or h.domain
            if h.source in ("crtsh", "certstream", "nrd") and match_detail(host) is None:
                c.execute("DELETE FROM radar_hits WHERE id=?", (h.id,))
                gone.append(h.domain)
        c.commit()
        print(f"pruned {len(gone)}: {gone[:30]}")
    elif a.cmd == "watchlist":
        from collections import Counter

        from .watchlist import query_terms, watchlist

        w = watchlist()
        print(len(w), "entries", dict(Counter(e["kind"] for e in w)))
        print("crt.sh query terms:", [e["term"] for e in query_terms()])
    elif a.cmd == "match":
        from .watchlist import match_detail

        for d in a.domains:
            print(d, json.dumps(match_detail(d), ensure_ascii=False))
    elif a.cmd == "feed":
        for d in feed(a.limit):
            print(json.dumps(d, ensure_ascii=False, default=str))
    elif a.cmd == "siblings":
        from .network import siblings

        print(json.dumps(siblings(a.domain), indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
