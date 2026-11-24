"""Owner: verdict. Batch CLI:
python -m scamshield.scan in.csv --out predictions.csv [--concurrency 4] [--personas a b] [--threshold likely_scam]

Input: CSV with a `url` column (else the first column; a header-less file of bare URLs also works).
Output: one row per input row, in input order. Resumable: rows already in --out are skipped; each finished
row is appended and flushed. Never crashes on a bad row.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import os
import sys
import time

OUT_COLS = ["url", "label", "score", "is_scam", "mode", "brand_id", "final_url", "reasons_en", "reasons_ar", "scan_id"]
LABEL_RANK = {"legitimate": 0, "suspicious": 1, "likely_scam": 2, "scam": 3}


def utf8_stdout() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def read_input(path: str) -> tuple[list[str], list[dict], str]:
    """Returns (fieldnames, rows, url_col)."""
    with open(path, newline="", encoding="utf-8-sig") as f:
        text = f.read()
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return ["url"], [], "url"
    first = next(csv.reader([lines[0]]))
    c0 = first[0].strip().lower() if first else ""
    looks_header = "://" not in c0 and "." not in c0
    if not looks_header:
        fields = ["url"] + [f"col{i}" for i in range(1, len(first))]
        rows = [dict(zip(fields, r)) for r in csv.reader(lines)]
        return fields, rows, "url"
    rows = list(csv.DictReader(lines))
    fields = [c for c in first]
    url_col = next((c for c in fields if c.strip().lower() in ("url", "link", "uri")), fields[0])
    return fields, rows, url_col


def is_scam(label: str, threshold: str = "likely_scam") -> int:
    return int(LABEL_RANK.get(label, 0) >= LABEL_RANK.get(threshold, 2))


def result_row(res, threshold: str) -> dict:
    v = res.verdict
    pos = [s for s in v.reasons if s.weight > 0] or v.reasons
    return {
        "label": v.label, "score": v.score, "is_scam": is_scam(v.label, threshold), "mode": v.mode,
        "brand_id": v.brand_id or "", "final_url": v.final_url,
        "reasons_en": " | ".join(s.en for s in pos[:5]), "reasons_ar": " | ".join(s.ar for s in pos[:5]),
        "scan_id": v.scan_id,
    }


def _done_keys(out: str) -> dict[int, dict]:
    """Already-written rows, keyed by input row index (column _row)."""
    done = {}
    if not os.path.exists(out):
        return done
    try:
        with open(out, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                try:
                    done[int(r.get("_row", ""))] = r
                except ValueError:
                    pass
    except Exception:
        pass
    return done


async def run_batch(inp: str, out: str, concurrency: int = 4, personas=None, threshold: str = "likely_scam",
                    force: bool = False, quiet: bool = False) -> list[dict]:
    from scamshield.pipeline import DEFAULT_PERSONAS, scan_url

    personas = tuple(personas or DEFAULT_PERSONAS)
    fields, rows, url_col = read_input(inp)
    extra = [c for c in fields if c not in OUT_COLS and c != url_col and c != "_row"]
    header = OUT_COLS + extra + ["_row"]
    done = _done_keys(out)
    # if existing file has a different header, start over
    if done and os.path.exists(out):
        with open(out, newline="", encoding="utf-8") as f:
            if next(csv.reader(f), []) != header:
                done = {}
                os.remove(out)
    new_file = not os.path.exists(out)
    fh = open(out, "a", newline="", encoding="utf-8")
    w = csv.DictWriter(fh, fieldnames=header, extrasaction="ignore")
    if new_file:
        w.writeheader()
        fh.flush()
    sem = asyncio.Semaphore(max(1, concurrency))
    lock = asyncio.Lock()
    results: dict[int, dict] = dict(done)
    todo = [(i, r) for i, r in enumerate(rows) if i not in done]
    t0 = time.time()
    n = [0]

    async def one(i: int, r: dict):
        url = (r.get(url_col) or "").strip()
        async with sem:
            row = {c: r.get(c, "") for c in extra}
            row.update({"url": url, "_row": i})
            try:
                if not url:
                    raise ValueError("empty url")
                res = await scan_url(url, personas=personas, save=True, force=force)
                row.update(result_row(res, threshold))
            except Exception as e:  # never crash on a bad row
                row.update({"label": "suspicious", "score": 50, "is_scam": is_scam("suspicious", threshold),
                            "mode": "domain_only", "reasons_en": f"Could not analyse: {e}",
                            "reasons_ar": "تعذّر تحليل الرابط", "scan_id": ""})
        async with lock:
            w.writerow(row)
            fh.flush()
            results[i] = row
            n[0] += 1
            if not quiet:
                print(f"[{n[0]}/{len(todo)} {time.time() - t0:5.0f}s] {row['label']:<11} {row['score']:>3} "
                      f"{row['mode']:<11} {url}", flush=True)

    try:
        await asyncio.gather(*[one(i, r) for i, r in todo])
    finally:
        fh.close()
    ordered = [results[i] for i in sorted(results)]
    # rewrite in input order (append order is completion order)
    try:
        tmp = out + ".tmp"
        with open(tmp, "w", newline="", encoding="utf-8") as f:
            ww = csv.DictWriter(f, fieldnames=header, extrasaction="ignore")
            ww.writeheader()
            for r in ordered:
                ww.writerow(r)
        os.replace(tmp, out)
    except Exception as e:
        print(f"warning: could not reorder {out}: {e}", file=sys.stderr)
    return ordered


def configure(concurrency: int, fast: bool) -> None:
    """Browser concurrency + optional fast detonation budget. Never raises."""
    try:
        from scamshield.detonate import set_concurrency

        set_concurrency(max(1, min(16, concurrency)))
    except Exception:
        pass
    if fast:
        from scamshield import pipeline

        pipeline.DETONATE_BUDGET = 10


def main(argv=None) -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(prog="scamshield.scan", description="Batch-scan URLs from a CSV.")
    ap.add_argument("input")
    ap.add_argument("--out", default="predictions.csv")
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--fast", action="store_true", help="10 s detonation budget per URL (batch mode)")
    ap.add_argument("--personas", nargs="+", default=None)
    ap.add_argument("--threshold", default="likely_scam", choices=list(LABEL_RANK),
                    help="lowest label counted as is_scam=1")
    ap.add_argument("--force", action="store_true", help="ignore cached scans")
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args(argv)
    configure(a.concurrency, a.fast)
    t0 = time.time()
    rows = asyncio.run(run_batch(a.input, a.out, a.concurrency, a.personas, a.threshold, a.force, a.quiet))
    from collections import Counter

    c = Counter(r.get("label") for r in rows)
    print(f"done: {len(rows)} rows in {time.time() - t0:.0f}s -> {a.out}  " + " ".join(f"{k}={v}" for k, v in c.items()))
    return 0
