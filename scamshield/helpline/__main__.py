"""CLI: python -m scamshield.helpline [--brand ID] [--live|--synthetic] [--no-landing] [--json]"""
from __future__ import annotations

import argparse
import asyncio
import io
import json
import sys

from . import check_all, check_brand, last_sources


def main(argv: list[str] | None = None) -> int:
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(prog="python -m scamshield.helpline", description="Fake helpline number check")
    ap.add_argument("--brand", help="brand id from data/registry.json (default: all)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--live", dest="live", action="store_true", default=None, help="Google Places (needs key)")
    g.add_argument("--synthetic", dest="live", action="store_false", help="labelled synthetic samples")
    ap.add_argument("--no-landing", action="store_true", help="do not scan listing websites")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.brand:
        fs = asyncio.run(check_brand(a.brand, live=a.live, scan_landing=not a.no_landing))
    else:
        fs = asyncio.run(check_all(live=a.live, scan_landing=not a.no_landing))
    if a.json:
        print(json.dumps([f.model_dump(mode="json") for f in fs], ensure_ascii=False, indent=2))
        return 0
    print(f"sources: {dict(last_sources)}")
    for f in fs:
        tag = {"likely_scam": "LIKELY_SCAM", "unverified": "UNVERIFIED ", "official": "OFFICIAL   "}[f.status]
        print(f"[{tag}] {f.brand_id:13} {f.number_e164:15} raw={f.raw_number!r:18} src={f.source:8} {f.listing_name}")
        if f.second_signals:
            print(f"      signals: {', '.join(f.second_signals)}")
        print(f"      EN: {f.reasons_en}")
        print(f"      AR: {f.reasons_ar}")
    counts = {s: sum(1 for f in fs if f.status == s) for s in ("likely_scam", "unverified", "official")}
    print(f"total={len(fs)} {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
