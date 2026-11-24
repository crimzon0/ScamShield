"""Backlog drain + blocklist cross-check for the radar feed.

  python -m scamshield.radar.drain scan   [--concurrency 4] [--limit N]   scan every unscanned hit (resume-safe)
  python -m scamshield.radar.drain report [--out data/radar/drain_report_YYYYMMDD]  label stats + blocklist check

Resume-safe: each hit is re-read from the DB right before it is scanned and skipped if someone else (the
refresh loop, a teammate) already scanned it; every result is stored immediately via store_hit.
The report checks scam / likely_scam hits against our feeds (intel.blocklist_hits) and a *fresh* Google Safe
Browsing v4 lookup of the domain, the scanned host and the scanned final URL (not the cached enrich result)."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from scamshield.core import db
from scamshield.core.config import DATA_DIR, settings
from scamshield.core.schemas import RadarHit, utcnow

from .common import existing_hit, humanize_seconds, scan_hit, time_to_detection_seconds, ttd_measured

log = logging.getLogger("scamshield.radar")
DRAIN_STATUS = DATA_DIR / "radar" / "drain_status.json"


def defang(s: str) -> str:
    return (s or "").replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


def pending_hits() -> list[RadarHit]:
    todo = [h for h in db.list_radar_hits(1_000_000) if not h.scan_id]
    # opposite order to `scan-pending` (which takes newest registrable look-alikes first) so concurrent
    # drains meet in the middle instead of racing for the same hits
    todo.sort(key=lambda h: (not bool(h.extra.get("subdomain_only")), h.first_seen.timestamp()))
    return todo


async def drain(concurrency: int = 4, limit: Optional[int] = None) -> dict:
    todo = pending_hits()[: limit or None]
    sem = asyncio.Semaphore(concurrency)
    st = {"started": utcnow().isoformat(), "pending_at_start": len(todo), "scanned": 0, "skipped": 0,
          "errors": 0, "labels": Counter()}

    def _write():
        try:
            DRAIN_STATUS.write_text(json.dumps({**st, "at": utcnow().isoformat()}, default=str, indent=1),
                                    encoding="utf-8")
        except Exception:
            pass

    async def one(h: RadarHit):
        async with sem:
            cur = existing_hit(h.domain, h.source)
            if cur is not None and cur.scan_id:
                st["skipped"] += 1
                return
            h = cur or h
            h.extra.pop("scan_error", None)
            r = await scan_hit(h)  # no inner semaphore: we hold ours
            if r.scan_id:
                st["scanned"] += 1
                st["labels"][r.label] += 1
            else:
                st["errors"] += 1
            if (st["scanned"] + st["errors"]) % 20 == 0:
                _write()
                log.info("drain progress %s", {k: v for k, v in st.items() if k != "labels"})

    await asyncio.gather(*(one(h) for h in todo))
    st["finished"] = utcnow().isoformat()
    _write()
    return st


# ------------------------------------------------------------------ report
async def _sb(domain: str, urls: list[str]) -> Optional[list]:
    """Fresh Safe Browsing lookup (cached only for 1h under a drain-specific key). None = unavailable."""
    if not settings.safe_browsing_key or settings.offline:
        return None
    from scamshield.intel.keyed import fetch_safe_browsing

    urls = sorted({u for u in urls if u})[:20]
    key = "radar:drain:sb:" + "|".join(urls)

    async def _f():
        try:
            r = await asyncio.wait_for(fetch_safe_browsing(domain, urls), 20)
            return {"m": r} if r is not None else None
        except Exception:
            return None

    v = await db.acached(key, _f, ttl=3600)
    return None if v is None else v["m"]


def _scan_row(scan_id: str) -> Optional[dict]:
    try:
        row = db.connect().execute("SELECT result_json FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        return json.loads(row["result_json"]) if row else None
    except Exception:
        return None


async def check_hit(h: RadarHit, sem: asyncio.Semaphore) -> dict:
    from scamshield.intel import blocklist_hits

    host = h.extra.get("scan_host") or h.domain
    final = h.extra.get("final_url") or ""
    res = _scan_row(h.scan_id) if h.scan_id else None
    v = (res or {}).get("verdict") or {}
    final = final or v.get("final_url") or ""
    cached_intel = ((res or {}).get("intel") or {})
    feeds = sorted(set(blocklist_hits("https://" + host + "/")) | set(blocklist_hits(h.domain))
                   | (set(blocklist_hits(final)) if final else set()))
    urls = [f"http://{h.domain}/", f"https://{h.domain}/", f"http://{host}/", f"https://{host}/", final]
    async with sem:
        sb = await _sb(h.domain, urls)
    ttd = time_to_detection_seconds(h)
    return {
        "domain": h.domain, "host": host, "source": h.source, "brand_id": h.brand_id, "label": h.label,
        "score": h.score, "scan_id": h.scan_id, "final_url": final,
        "first_seen": h.first_seen.isoformat(), "flagged_at": h.flagged_at.isoformat(),
        "first_seen_basis": h.extra.get("first_seen_basis", "not_before"), "ttd_measured": ttd_measured(h),
        "lead_time_seconds": ttd, "lead_time_human": humanize_seconds(ttd),
        "feeds": feeds, "safe_browsing": sb, "safe_browsing_cached": cached_intel.get("safe_browsing"),
        "on_any_blocklist": bool(feeds) or bool(sb),
        "subdomain_only": bool(h.extra.get("subdomain_only")), "match_kind": h.extra.get("match_kind"),
        "mode": v.get("mode"),
        "summary_en": v.get("summary_en", ""),
        "reasons_en": [f"{s.get('id')}({s.get('weight')}): {s.get('en', '')}"[:220]
                       for s in (v.get("reasons") or [])][:10],
        "screenshots": [d.get("screenshot_path") for d in ((res or {}).get("detonations") or [])
                        if isinstance(d, dict) and d.get("screenshot_path")][:3],
        "page_titles": sorted({(d.get("title") or "")[:120] for d in ((res or {}).get("detonations") or [])
                               if isinstance(d, dict) and d.get("title")})[:3],
    }


async def report(out_base: Optional[str] = None) -> dict:
    hits = db.list_radar_hits(1_000_000)
    labels = Counter(h.label or "unscanned" for h in hits)
    sem = asyncio.Semaphore(4)
    flagged = [h for h in hits if h.label in ("scam", "likely_scam")]
    rows = await asyncio.gather(*(check_hit(h, sem) for h in flagged))
    scam = [r for r in rows if r["label"] == "scam"]
    likely = [r for r in rows if r["label"] == "likely_scam"]
    sb_avail = any(r["safe_browsing"] is not None for r in rows)

    def nob(rs):
        return [r for r in rs if not r["on_any_blocklist"]]

    def lead(rs):
        v = [r["lead_time_seconds"] for r in rs if r["lead_time_seconds"] is not None]
        return {"n": len(v), "median_seconds": int(statistics.median(v)) if v else None,
                "median_human": humanize_seconds(int(statistics.median(v))) if v else "?"}

    # organic search results are info/blog pages that *mention* a brand: kept, but reported separately and
    # excluded from the early-detection headline (they are not look-alike registrations)
    scam_cand = [r for r in scam if r["source"] != "search_organic"]
    likely_cand = [r for r in likely if r["source"] != "search_organic"]
    srch = [h for h in hits if h.source.startswith("search_")]
    scam_nob = sorted(nob(scam_cand), key=lambda r: (-(r["score"] or 0), r["subdomain_only"], r["domain"]))
    rep = {
        "generated_at": utcnow().isoformat(),
        "total_hits": len(hits), "scanned": sum(1 for h in hits if h.scan_id),
        "by_source": dict(Counter(h.source for h in hits)),
        "label_distribution": dict(labels),
        "safe_browsing_available": sb_avail,
        "scam": {"n": len(scam), "on_feeds": sum(1 for r in scam if r["feeds"]),
                 "on_safe_browsing": sum(1 for r in scam if r["safe_browsing"]),
                 "on_no_blocklist": len(nob(scam))},
        "likely_scam": {"n": len(likely), "on_feeds": sum(1 for r in likely if r["feeds"]),
                        "on_safe_browsing": sum(1 for r in likely if r["safe_browsing"]),
                        "on_no_blocklist": len(nob(likely))},
        "headline_excluding_search_organic": {
            "scam": len(scam_cand), "scam_on_no_blocklist": len(nob(scam_cand)),
            "likely_scam": len(likely_cand), "likely_scam_on_no_blocklist": len(nob(likely_cand))},
        "search": {"hits": len(srch), "by_source": dict(Counter(h.source for h in srch)),
                   "labels": dict(Counter(h.label or "unscanned" for h in srch)),
                   "scam_domains": sorted(defang(h.domain) for h in srch if h.label == "scam")},
        "first_seen_basis_scam": dict(Counter(r["first_seen_basis"] for r in scam)),
        "lead_time_scam_all": lead(scam),
        "lead_time_scam_measured_only": lead([r for r in scam if r["ttd_measured"]]),
        "lead_time_scam_no_blocklist": lead(nob(scam_cand)),
        "examples_scam_no_blocklist": [
            {"domain": defang(r["domain"]), "url": defang(r["final_url"] or "https://" + r["host"]),
             "brand": r["brand_id"], "score": r["score"], "source": r["source"],
             "lead_time": r["lead_time_human"], "first_seen_basis": r["first_seen_basis"]}
            for r in scam_nob[:10]],
        "scam_listed": [{"domain": defang(r["domain"]), "feeds": r["feeds"], "safe_browsing": r["safe_browsing"]}
                        for r in scam if r["on_any_blocklist"]],
        "rows": rows,
    }
    if out_base:
        from pathlib import Path

        p = Path(out_base)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.with_suffix(".json").write_text(json.dumps(rep, default=str, indent=1, ensure_ascii=False),
                                          encoding="utf-8")
        p.with_suffix(".md").write_text(render_md(rep), encoding="utf-8")
    return rep


def render_md(r: dict) -> str:
    s, l = r["scam"], r["likely_scam"]
    L = [f"# Radar drain report ({r['generated_at'][:19]}Z)", "",
         f"- Total radar hits: **{r['total_hits']}** (by source: {r['by_source']})",
         f"- Scanned through `pipeline.scan_url`: **{r['scanned']}**",
         f"- Label distribution: {r['label_distribution']}",
         f"- Google Safe Browsing lookups available: {r['safe_browsing_available']} (fresh v4 lookup of domain,"
         " scanned host and final URL)", "",
         "## Blocklist cross-check", "",
         "| set | n | on our feeds | on Safe Browsing | on **no** blocklist |", "|---|---|---|---|---|",
         f"| scam | {s['n']} | {s['on_feeds']} | {s['on_safe_browsing']} | **{s['on_no_blocklist']}** |",
         f"| likely_scam | {l['n']} | {l['on_feeds']} | {l['on_safe_browsing']} | **{l['on_no_blocklist']}** |", "",
         "Headline (excluding organic search results, which are pages that mention a brand rather than"
         f" look-alike registrations): {r['headline_excluding_search_organic']}", "",
         f"Search radar: {r['search']['hits']} hits {r['search']['by_source']}, labels {r['search']['labels']}", "",
         "## Lead time (flagged_at - first_seen), scam set", "",
         f"- first_seen basis: {r['first_seen_basis_scam']} (not_before = certificate notBefore, an estimate;"
         " ct_log / nrd_list_date = measured)",
         f"- median, all scam: {r['lead_time_scam_all']['median_human']} (n={r['lead_time_scam_all']['n']})",
         f"- median, measured basis only: {r['lead_time_scam_measured_only']['median_human']}"
         f" (n={r['lead_time_scam_measured_only']['n']})",
         f"- median, scam on no blocklist: {r['lead_time_scam_no_blocklist']['median_human']}", "",
         "Note: for not_before hits the lead time measures how long after certificate issuance *we* flagged the"
         " domain (backfill), i.e. it is an upper bound on our latency, not a head start over blocklists. The"
         " head-start claim is the 'on no blocklist' count at report time.", "",
         "## Examples: scam verdicts on no blocklist (defanged)", "",
         "| domain | brand | score | source | lead time | basis |", "|---|---|---|---|---|---|"]
    for e in r["examples_scam_no_blocklist"]:
        L.append(f"| {e['domain']} | {e['brand']} | {e['score']} | {e['source']} | {e['lead_time']} |"
                 f" {e['first_seen_basis']} |")
    if r.get("spot_check"):
        L += ["", "## Spot check (top scam-on-no-blocklist verdicts, read as data)", ""]
        L += [f"- {x}" for x in r["spot_check"]]
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="python -m scamshield.radar.drain")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--concurrency", type=int, default=4)
    s.add_argument("--limit", type=int, default=None)
    r = sub.add_parser("report")
    r.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for noisy in ("httpx", "httpcore", "websockets", "whois", "whois.whois"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    if a.cmd == "scan":
        st = asyncio.run(drain(min(4, max(1, a.concurrency)), a.limit))
        print(json.dumps(st, default=str, indent=1))
    else:
        out = a.out or str(DATA_DIR / "radar" / f"drain_report_{datetime.now(timezone.utc):%Y%m%d}")
        rep = asyncio.run(report(out))
        print(json.dumps({k: v for k, v in rep.items() if k not in ("rows", "scam_listed")}, default=str,
                         indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
