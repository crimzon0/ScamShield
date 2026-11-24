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
    ap.add_argument("--out", default="var/verdict_eval_predictions.csv")
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--threshold", default="likely_scam", choices=list(LABEL_RANK))
    ap.add_argument("--personas", nargs="+", default=None)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--no-official", action="store_true")
    ap.add_argument("--rebrand", action="store_true",
                    help="with --rescore: re-run match_brand + lookalike on the stored detonations (current brand code)")
    ap.add_argument("--rescore", action="store_true",
                    help="re-run score() on the stored scans of --predictions (no network) - for threshold tuning")
    ap.add_argument("--ignore-blocklist", action="store_true",
                    help="ablation: ignore feed/blocklist hits (eval scams come from the same feeds)")
    a = ap.parse_args(argv)
    global REBRAND
    REBRAND = bool(a.rebrand)
    if a.ignore_blocklist:
        os.environ["SCAMSHIELD_IGNORE_BLOCKLIST"] = "1"

    from scamshield.cli import configure

    configure(a.concurrency, a.fast)
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
    if a.rescore:
        preds = [rescore(p, a.threshold) for p in preds]
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
    by_thr = {}
    for thr in ("likely_scam", "suspicious"):
        mm = metrics([(t, is_scam(pmap[u].get("label", ""), thr)) for u, t in truth.items() if u in pmap])
        by_thr[thr] = {k: round(mm[k], 4) for k in ("precision", "recall", "f1", "fpr")}
        print(f"  threshold >= {thr:<11}: P {mm['precision']:.3f}  R {mm['recall']:.3f}  F1 {mm['f1']:.3f}  FPR {mm['fpr']:.3f}")
    modes = Counter(pmap[u].get("mode") for u in truth if u in pmap)
    labels = Counter(pmap[u].get("label") for u in truth if u in pmap)
    print("modes:", dict(modes), " labels:", dict(labels))
    print(f"\nFALSE POSITIVES ({len(fps)}):")
    for p in fps:
        print(f"  [{p.get('label')} {p.get('score')}] {p.get('url')} -> {p.get('final_url')}\n      {p.get('reasons_en')}")
    print(f"\nFALSE NEGATIVES ({len(fns)}):")
    for p in fns:
        print(f"  [{p.get('label')} {p.get('score')} {p.get('mode')}] {p.get('url')}\n      {p.get('reasons_en')}")

    # ablation: same stored scans, feed/blocklist hits ignored (eval scams come from the same feeds)
    abl = None
    if not a.ignore_blocklist:
        prev = os.environ.get("SCAMSHIELD_IGNORE_BLOCKLIST")
        os.environ["SCAMSHIELD_IGNORE_BLOCKLIST"] = "1"
        try:
            ab = {(p.get("url") or "").strip(): rescore(p, a.threshold) for p in preds}
            abl_pairs = [(t, is_scam(ab[u].get("label", ""), a.threshold)) for u, t in truth.items() if u in ab]
            abl = metrics(abl_pairs)
            abl_s = metrics([(t, is_scam(ab[u].get("label", ""), "suspicious")) for u, t in truth.items() if u in ab])
            do = [(t, is_scam(ab[u].get("label", ""), a.threshold)) for u, t in truth.items()
                  if u in ab and ab[u].get("mode") == "domain_only"]
            dm = metrics(do)
            print(f"\nABLATION (blocklist ignored): precision {abl['precision']:.3f}  recall {abl['recall']:.3f}  "
                  f"F1 {abl['f1']:.3f}  FPR {abl['fpr']:.3f}  (TP {abl['tp']} FN {abl['fn']} FP {abl['fp']} TN {abl['tn']})")
            print(f"  ablation with threshold >= suspicious: P {abl_s['precision']:.3f}  R {abl_s['recall']:.3f}  "
                  f"F1 {abl_s['f1']:.3f}  FPR {abl_s['fpr']:.3f}")
            print(f"  domain_only subset (n={len(do)}): recall {dm['recall']:.3f}  FPR {dm['fpr']:.3f}  "
                  f"(TP {dm['tp']} FN {dm['fn']} FP {dm['fp']} TN {dm['tn']})")
            for u, t in truth.items():
                if u in ab and t and not is_scam(ab[u].get("label", ""), a.threshold):
                    print(f"  FN w/o blocklist [{ab[u].get('label')} {ab[u].get('score')} {ab[u].get('mode')}] {u}"
                          f"\n      {ab[u].get('reasons_en')}")
        finally:
            if prev is None:
                os.environ.pop("SCAMSHIELD_IGNORE_BLOCKLIST", None)
            else:
                os.environ["SCAMSHIELD_IGNORE_BLOCKLIST"] = prev
    do_all = [(t, is_scam(pmap[u].get("label", ""), a.threshold)) for u, t in truth.items()
              if u in pmap and pmap[u].get("mode") == "domain_only"]
    dm_all = metrics(do_all)
    print(f"domain_only subset with blocklist (n={len(do_all)}): recall {dm_all['recall']:.3f}  FPR {dm_all['fpr']:.3f}")

    off = official_fp(a) if not a.no_official else None
    from datetime import datetime, timezone

    rep = {"generated_at": datetime.now(timezone.utc).isoformat(), "dataset": a.labelled, "n": len(pairs),
           "threshold": a.threshold, **{k: m[k] for k in ("tp", "fp", "fn", "tn")},
           **{k: round(m[k], 4) for k in ("precision", "recall", "f1", "fpr", "accuracy")},
           "blocklist_ignored": bool(a.ignore_blocklist),
           "official_fp": off, "modes": dict(modes), "labels": dict(labels),
           "domain_only": {k: round(dm_all[k], 4) for k in ("recall", "fpr")} | {"n": len(do_all)},
           "false_positives": [{"url": p.get("url"), "label": p.get("label"), "score": p.get("score"),
                                "reasons_en": p.get("reasons_en")} for p in fps[:20]],
           "false_negatives": [{"url": p.get("url"), "label": p.get("label"), "score": p.get("score"),
                                "mode": p.get("mode")} for p in fns[:20]]}
    if abl:
        rep["ablation_no_blocklist"] = {k: round(abl[k], 4) for k in ("precision", "recall", "f1", "fpr")}
        rep["ablation_no_blocklist_suspicious"] = {k: round(abl_s[k], 4) for k in ("precision", "recall", "f1", "fpr")}
    rep["by_threshold"] = by_thr
    try:
        import json

        stem = os.path.splitext(os.path.basename(a.labelled))[0]
        jpath = "data/eval/last_eval.json" if stem == "sample" else f"data/eval/last_eval_{stem}.json"
        with open(jpath, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=2)
        print(f"wrote {jpath}")
    except Exception as e:
        print(f"could not write last_eval.json: {e}")
    return 0


REBRAND = False  # --rebrand: re-run match_brand/lookalike on stored detonations before re-scoring


def rescore(p: dict, threshold: str) -> dict:
    from scamshield.cli import result_row
    from scamshield.core import db
    from scamshield.score import score

    try:
        r = db.get_scan(p.get("scan_id", ""))
        if r is None:
            return p
        extra = [s for s in r.verdict.reasons if s.id == "fake_helpline_on_page"]
        from scamshield.core.schemas import Intel, LookalikeResult

        if REBRAND:
            import asyncio as _a

            from scamshield.brand import lookalike, match_brand
            from scamshield.core.domains import host_of

            ok = [d for d in r.detonations if d.status == "ok"]
            final = next((d.final_url for d in ok if d.final_url), None) or r.verdict.final_url or r.url
            try:
                r.brand = _a.run(match_brand(max(ok, key=lambda d: len(d.visible_text or "")))) if ok else None
            except Exception:
                r.brand = None
            try:
                r.lookalike = lookalike(host_of(final))
            except Exception:
                pass

        stash = db.cache_get(f"scaninput:{r.scan_id}") or {}
        ii = Intel.model_validate(stash["intel"]) if stash.get("intel") else None
        il = LookalikeResult.model_validate(stash["look"]) if stash.get("look") else None
        r.verdict = score(r.scan_id, r.url, r.detonations, r.intel, r.brand, r.lookalike, r.cloak, extra=extra,
                          input_intel=ii, input_look=il)
        return dict(p, **result_row(r, threshold))
    except Exception:
        return p


def official_fp(a) -> dict:
    from scamshield.brand import load_registry

    doms = sorted({d for b in load_registry() if not b.get("fictional") for d in (b.get("official_domains") or [])})
    if not doms:
        print("\nofficial domains FP: 0/0 (registry has no real brands yet)")
        return {"flagged": 0, "total": 0}
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
    return {"flagged": len(flagged), "total": len(preds), "not_legitimate": len(bad)}


if __name__ == "__main__":
    sys.exit(main())
