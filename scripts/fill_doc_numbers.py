"""usage: fill2.py OFFICIAL_FP OFFICIAL_N  -- reads data/eval/last_eval*.json, writes README/slides/video results."""
import re,sys,json
OFP,ON=sys.argv[1],sys.argv[2]
S=json.load(open('data/eval/last_eval.json',encoding='utf-8'))
H=json.load(open('data/eval/last_eval_holdout.json',encoding='utf-8'))
f=lambda x:f"{x:.3f}"
def cnt(d,k):
    n_s=d['tp']+d['fn']; return round(d[k]['recall']*n_s), n_s
hs,hn=cnt(H,'ablation_no_blocklist'); ss,sn=cnt(S,'ablation_no_blocklist')
date=max(S['generated_at'],H['generated_at'])[:16].replace('T',' ')+' UTC'
nl=lambda d:d['tn']+d['fp']
A,As,B,Bs=H['ablation_no_blocklist'],H['ablation_no_blocklist_suspicious'],S['ablation_no_blocklist'],S['ablation_no_blocklist_suspicious']
results=f"""Real runs of `make eval` (`python -m scamshield.cli.eval`), latest {date}. `is_scam` = label `likely_scam` or `scam` unless stated. Raw output: `data/eval/last_eval.json`, `data/eval/last_eval_holdout.json`.

| Set | Blocklists | Threshold | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|
| **Held-out, first blind run** (n=79: 37 legit / 42 scam, 2026-11-24 20:18 UTC) | **ignored** | likely_scam | **1.000** | **0.619** | **0.765** | **0.000** |
| Held-out, first blind run | ignored | suspicious | 1.000 | 0.786 | 0.880 | 0.000 |
| Held-out, after one round of generalisation (no longer blind) | ignored | likely_scam | {f(A['precision'])} | {f(A['recall'])} | {f(A['f1'])} | {f(A['fpr'])} |
| Held-out, after generalisation | ignored | suspicious | {f(As['precision'])} | {f(As['recall'])} | {f(As['f1'])} | {f(As['fpr'])} |
| Held-out | used | likely_scam | {f(H['precision'])} | {f(H['recall'])} | {f(H['f1'])} | {f(H['fpr'])} |
| Sample, tuned on (n={S['n']}: {nl(S)} legit / {sn} scam) | ignored | likely_scam | {f(B['precision'])} | {f(B['recall'])} | {f(B['f1'])} | {f(B['fpr'])} |
| Sample | ignored | suspicious | {f(Bs['precision'])} | {f(Bs['recall'])} | {f(Bs['f1'])} | {f(Bs['fpr'])} |
| Sample | used | likely_scam | {f(S['precision'])} | {f(S['recall'])} | {f(S['f1'])} | {f(S['fpr'])} |

**Official-domain sweep:** the home page of every official domain of every real brand in the registry was scanned: **{OFP}/{ON} flagged as scam.**

**How to read this honestly**

- **Headline = first blind run on the held-out set, blocklists ignored: precision 1.000, recall 0.619 (26 of 42 scams), F1 0.765, FPR 0.000.** That is what the page and domain analysis achieved on URLs it had never seen.
- After that run we broadened the global-brand keyword list (from public brand rankings, but informed by the held-out misses). The held-out set is therefore **no longer blind**; on it, recall rose to {f(A['recall'])} ({hs} of {hn}). We show both and treat 0.619 as the honest number.
- **Why we ignore blocklists for the headline:** all scam URLs come from the public OpenPhish and phishunt feeds, and `intel` checks the same feeds. With blocklists on, recall is {f(H['recall'])}, but that mostly measures our feed lookup, not detection. In deployment feeds stay on, so the "used" row is what an analyst would see on already-reported links; the "ignored" row is the fair estimate for brand-new links nobody has reported.
- **No false positives** in any run: not on UAE bank / government / police / telecom pages, not on globally phished brands' real sites (Apple, PayPal, Netflix, Coinbase, Binance, WhatsApp), not on news pages that mention banks, and not on the official-domain sweep.
- The **held-out set** was built after tuning on `sample.csv`, from domains not in the sample. It is not time-split (the feeds had not rotated on 2026-11-25), so "unseen" means unseen domains, not a later time period.
- Feed labels are not hand-verified; sets are small (79 and 127 URLs). These are regression numbers, not a benchmark.
- Most misses without blocklists: old compromised sites hosting a kit in a sub-path, kits that show nothing to our mobile persona, brands outside our registry and global keyword list, and dead pages on registered-but-not-new domains (these usually reach `suspicious`, not `likely_scam`). Details in `data/eval/README.md`.
"""
table=f"""| Held-out set (n={H['n']}) | Precision | Recall | FPR |
|---|---|---|---|
| **First blind run, blocklists ignored (headline)** | **1.000** | **0.619** | **0.000** |
| First blind run, blocklists ignored, >= suspicious | 1.000 | 0.786 | 0.000 |
| After one round of generalisation (not blind) | {f(A['precision'])} | {f(A['recall'])} | {f(A['fpr'])} |
| Blocklists used | {f(H['precision'])} | {f(H['recall'])} | {f(H['fpr'])} |

- **Official UAE domains flagged as scam: {OFP} / {ON}** · zero false positives in every run
- Tuned sample (n={S['n']}), blocklists ignored: precision {f(B['precision'])}, recall {f(B['recall'])}"""
caveat=f"Caveats: small sets ({H['n']} held-out, {S['n']} tuned); scam URLs come from the same public feeds our blocklist uses, so the headline ignores blocklists; feed labels not hand-verified."
video=f"\"Official UAE domains flagged: {OFP}/{ON} · blind held-out: precision 1.000, recall 0.619, no blocklists\""
p='README.md';t=open(p,encoding='utf-8').read()
t=re.sub(r"<!-- RESULTS:BEGIN -->.*<!-- RESULTS:END -->","<!-- RESULTS:BEGIN -->\n"+results+"<!-- RESULTS:END -->",t,flags=re.S)
open(p,'w',encoding='utf-8').write(t)
p='docs/slides.md';t=open(p,encoding='utf-8').read()
t=re.sub(r"<!-- RT:BEGIN -->.*?<!-- RT:END -->","<!-- RT:BEGIN -->\n"+table+"\n<!-- RT:END -->",t,flags=re.S)
t=re.sub(r"^Caveats: .*$",caveat,t,flags=re.M)
t=re.sub(r"Numbers come from `make eval` on [^,]*?, run on .*?\. The official",f"Numbers come from `make eval` on data/eval/holdout.csv and sample.csv, latest run {date}. The official",t)
open(p,'w',encoding='utf-8').write(t)
p='docs/video-script.md';t=open(p,encoding='utf-8').read()
t=re.sub(r"results line \"[^\"]*\"","results line "+video,t)
open(p,'w',encoding='utf-8').write(t)
print("README/slides/video:", f"holdout ignored P {f(A['precision'])} R {f(A['recall'])} F1 {f(A['f1'])} FPR {f(A['fpr'])}; >=susp R {f(As['recall'])}; used R {f(H['recall'])}; sample ignored P {f(B['precision'])} R {f(B['recall'])}; official {OFP}/{ON}; date {date}")
