"""Threshold sweep over stored scores. Usage: sweep.py labelled.csv preds.csv [official_pred.csv] [--json out.json] [--md out.md] [--tag name]"""
import csv, json, sys, argparse
sys.path.insert(0, r"C:\scamshiled")
from scamshield.core.domains import registrable, host_of
from scamshield.brand import load_registry
ap = argparse.ArgumentParser(); ap.add_argument("labelled"); ap.add_argument("preds"); ap.add_argument("--official", default=None)
ap.add_argument("--json"); ap.add_argument("--md"); ap.add_argument("--tag", default="")
a = ap.parse_args()
truth = {r["url"].strip(): r["label"].strip() == "scam" for r in csv.DictReader(open(a.labelled, encoding="utf-8"))}
preds = {p["url"].strip(): p for p in csv.DictReader(open(a.preds, encoding="utf-8"))}
off_doms = {d for b in load_registry() if not b.get("fictional") for d in (b.get("official_domains") or [])}
off_regs = {registrable("https://" + d) for d in off_doms}
def is_off(u): return registrable(u) in off_regs if u else False
offp = list(csv.DictReader(open(a.official, encoding="utf-8"))) if a.official else []
RANK = {"legitimate": 0, "suspicious": 1, "likely_scam": 2, "scam": 3}
def sc(p):
    try: return float(p.get("score") or 0)
    except ValueError: return 0.0
def m(fn):
    tp = fp = fnn = tn = 0; offfp = []
    for u, t in truth.items():
        p = preds.get(u)
        if p is None: continue
        y = fn(p)
        if y and t: tp += 1
        elif y and not t:
            fp += 1
            if is_off(u) or is_off(p.get("final_url", "")): offfp.append(u)
        elif t: fnn += 1
        else: tn += 1
    for p in offp:
        if fn(p): offfp.append(p["url"])
    P = tp / (tp + fp) if tp + fp else 1.0; R = tp / (tp + fnn) if tp + fnn else 0.0
    return dict(tp=tp, fp=fp, fn=fnn, tn=tn, precision=round(P, 4), recall=round(R, 4), f1=round(2*P*R/(P+R), 4) if P+R else 0.0,
                fpr=round(fp / (fp + tn), 4) if fp + tn else 0.0, official_fp=len(offfp), official_fp_urls=offfp)
rows = []
for c in range(30, 95, 5): rows.append(dict(cutoff=f"score>={c}", **m(lambda p, c=c: sc(p) >= c)))
for lab in ("suspicious", "likely_scam", "scam"): rows.append(dict(cutoff=f"label>={lab}", **m(lambda p, lab=lab: RANK.get(p.get("label", ""), 0) >= RANK[lab])))
n = sum(1 for u in truth if u in preds)
hdr = f"### {a.tag} (n={n} scored of {len(truth)}; official-domain sweep n={len(offp)})\n\n| cut-off | P | R | F1 | FPR | TP | FP | FN | TN | official FP |\n|---|---|---|---|---|---|---|---|---|---|\n"
md = hdr + "".join(f"| {r['cutoff']} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} | {r['fpr']:.3f} | {r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} | {r['official_fp']} |\n" for r in rows)
print(md)
if a.json:
    try: allj = json.load(open(a.json, encoding="utf-8"))
    except Exception: allj = {}
    allj[a.tag or a.preds] = {"n": n, "n_labelled": len(truth), "official_sweep_n": len(offp), "rows": rows}
    json.dump(allj, open(a.json, "w", encoding="utf-8"), indent=1)
if a.md:
    open(a.md, "a", encoding="utf-8").write(md + "\n")
