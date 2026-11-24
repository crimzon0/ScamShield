"""Owner: verdict. STUB batch CLI."""
import argparse
import asyncio
import csv


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scamshield.scan")
    ap.add_argument("input")
    ap.add_argument("--out", default="predictions.csv")
    a = ap.parse_args(argv)
    from scamshield.pipeline import scan_url

    with open(a.input, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "score", "label", "scan_id"])
        for r in rows:
            res = asyncio.run(scan_url(r["url"]))
            w.writerow([r["url"], res.verdict.score, res.verdict.label, res.scan_id])
    return 0
