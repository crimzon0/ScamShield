"""Owner: verdict. Evaluate on a labelled CSV (url,label with label scam|legit).

python -m scamshield.cli.eval data/eval/sample.csv [--predictions predictions.csv] [--no-official]
  --predictions: reuse an existing predictions file (rows matched by url); otherwise scans (cached).
Also scans every registry official domain (https://<domain>/) and reports "official domains FP: x/N".
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import os
import sys

from scamshield.cli import LABEL_RANK, is_scam, read_input, run_batch, utf8_stdout

SCAM_LABELS = {"scam", "phish", "phishing", "malicious", "1", "true", "likely_scam"}


def _truth(v: str) -> int:
    return int((v or "").strip().lower() in SCAM_LABELS)


def metrics(pairs: list[tuple[int, int]]) -> dict:
    tp = sum(1 for t, p in pairs if t and p)
    fp = sum(1 for t, p in pairs if not t and p)
    fn = sum(1 for t, p in pairs if t and not p)
    tn = sum(1 for t, p in pairs if not t and not p)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec, f1=f1, fpr=fpr,
                accuracy=(tp + tn) / len(pairs) if pairs else 0.0)


def main(argv=None) -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(prog="scamshield.cli.eval")
    ap.add_argument("labelled")
    ap.add_argument("--predictions", default=None)
    ap.add_argument("--out", default="var/eval_predictions.csv")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--threshold", default="likely_scam", choices=list(LABEL_RANK))
    ap.add_argument("--personas", nargs="+", default=None)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--no-official", action="store_true")
    a = ap.parse_args(argv)

    fields, rows, url_col = read_input(a.labelled)
    lab_col = next((c for c in fields if c.lower() in ("label", "is_scam", "class")), None)
    if not lab_col:
        print("labelled CSV needs a label column (scam|legit)")
        return 2
    truth = {(r.get(url_col) or "").strip(): _truth(r.get(lab_col, "")) for r in rows}

    if a.predictions and os.path.exists(a.predictions):
        with open(a.predictions, newline="", encoding="utf-8") as f:
            preds = list(csv.DictReader(f))
    else:
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        if os.path.exists(a.out):
            os.remove(a.out)
        preds = asyncio.run(run_batch(a.labelled, a.out, a.concurrency, a.personas, a.threshold, a.force, quiet=True))
    pmap = {(p.get("url") or "").strip(): p for p in preds}

    pairs, fps, fns = [], [], []
    for u, t in truth.items():
        p = pmap.get(u)
        if p is None:
            continue
        pr = is_scam(p.get("label", ""), a.threshold)
        pairs.append((t, pr))
        if pr and not t:
            fps.append(p)
        if t and not pr:
            fns.append(p)
    m = metrics(pairs)
    from collections import Counter

    print(f"\n=== ScamShield eval: {a.labelled}  (n={len(pairs)}, is_scam >= {a.threshold}) ===")
    print(f"precision {m['precision']:.3f}  recall {m['recall']:.3f}  F1 {m['f1']:.3f}  "
          f"FPR {m['fpr']:.3f}  accuracy {m['accuracy']:.3f}")
    print("confusion matrix (rows=truth, cols=pred):")
    print(f"              pred_scam  pred_legit")
    print(f"  truth_scam  {m['tp']:>9}  {m['fn']:>10}")
    print(f"  truth_legit {m['fp']:>9}  {m['tn']:>10}")
    modes = Counter(pmap[u].get("mode") for u in truth if u in pmap)
    labels = Counter(pmap[u].get("label") for u in truth if u in pmap)
    print("modes:", dict(modes), " labels:", dict(labels))
    print(f"\nFALSE POSITIVES ({len(fps)}):")
    for p in fps:
        print(f"  [{p.get('label')} {p.get('score')}] {p.get('url')} -> {p.get('final_url')}\n      {p.get('reasons_en')}")
    print(f"\nFALSE NEGATIVES ({len(fns)}):")
    for p in fns:
        print(f"  [{p.get('label')} {p.get('score')} {p.get('mode')}] {p.get('url')}\n      {p.get('reasons_en')}")

    if not a.no_official:
        official_fp(a)
    return 0


def official_fp(a) -> None:
    from scamshield.brand import load_registry

    doms = sorted({d for b in load_registry() if not b.get("fictional") for d in (b.get("official_domains") or [])})
    if not doms:
        print("\nofficial domains FP: 0/0 (registry has no real brands yet)")
        return
    path = "var/eval_official_in.csv"
    os.makedirs("var", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url"])
        for d in doms:
            w.writerow([f"https://{d}/"])
    out = "var/eval_official_pred.csv"
    if os.path.exists(out):
        os.remove(out)
    preds = asyncio.run(run_batch(path, out, a.concurrency, a.personas, a.threshold, a.force, quiet=True))
    bad = [p for p in preds if p.get("label") != "legitimate"]
    flagged = [p for p in preds if is_scam(p.get("label", ""), a.threshold)]
    print(f"\nofficial domains FP: {len(flagged)}/{len(preds)}  (not 'legitimate': {len(bad)})")
    for p in bad:
        print(f"  [{p.get('label')} {p.get('score')}] {p.get('url')} -> {p.get('final_url')}  {p.get('reasons_en')}")


if __name__ == "__main__":
    sys.exit(main())
