# Evaluation set (owner: verdict)

`sample.csv` — columns `url,label,source`; `label` is `scam` or `legit`. Built 2026-11-24 (UTC).

- **legit (29)**: UAE bank / government / telecom / airline home pages and deep links on their official
  sites, plus a few big global sites and a news site that mentions banks (brand-mention FP trap).
  Each URL was fetched with curl on 2026-11-24; some return 403/000 to curl (bot protection) — that is
  intentional (a blocked page must still not become a false positive).
- **scam (26)**: random distinct registrable domains from public phishing feeds downloaded on 2026-11-24:
  OpenPhish community feed (https://openphish.com/feed.txt) and phishunt (https://phishunt.io/feed.txt).
  Raw snapshots are in `raw/`. Many feed URLs die within hours, so this set deliberately exercises the
  domain-only path (dead / unreachable pages).
- Feed labels are taken as-is (not hand-verified); a few may be benign clones (e.g. student "clone" projects).

Run: `make scan` (writes predictions.csv) and `make eval` (precision / recall / FPR / confusion matrix,
every FP and FN with reasons, and "official domains FP: x/N" over every registry official domain).
