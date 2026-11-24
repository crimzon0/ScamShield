# Evaluation set (owner: verdict)

`sample.csv` — columns `url,label,source`; `label` is `scam` or `legit`. Built 2026-11-24/25 (UTC). 127 rows.

- **legit (68)**: UAE bank / government / police / telecom / utility / airline home pages and deep links on their
  official sites (domains from data/registry.json), plus big global sites (incl. globally-phished brands: Apple,
  PayPal, Netflix, Coinbase, Binance, WhatsApp) and UAE news/classifieds sites that mention banks (brand-mention
  FP traps). Every URL was fetched with curl on 2026-11-24/25; several return 401/403/000 to curl (bot protection),
  which is intentional: a blocked page must never become a false positive.
- **scam (59)**: random distinct registrable domains from the public phishing feeds downloaded 2026-11-24:
  OpenPhish community feed (https://openphish.com/feed.txt) and phishunt (https://phishunt.io/feed.txt).
  Raw snapshots in `raw/`. Many feed URLs die within hours, so the set exercises the domain-only path
  (dead / NXDOMAIN / platform 404 / unregistered domains). Removed during curation: one URL whose token embedded
  a victim's email address, and two feed entries that looked benign (a real venue, a GitHub project page).
- Feed labels are taken as-is (not hand-verified); a few may be benign clones (e.g. student "clone" projects).
- Because intel's blocklist uses the same feeds, `make eval` also prints an **ablation with blocklist hits ignored**
  (`ablation_no_blocklist` in last_eval.json). Treat the ablation as the headline generalisation number.

Run: `make scan` (writes predictions.csv) and `make eval` (precision / recall / F1 / FPR / confusion matrix,
every FP and FN with reasons, the no-blocklist ablation, the domain-only subset, and "official domains FP: x/N"
over every registry official domain). Results are written to `last_eval.json` for the dashboard.

## Held-out set — `holdout.csv` (79 rows: 37 legit / 42 scam)

Built after all tuning on `sample.csv` was finished, then run **once with no further tuning**.
Scam rows are from the 2026-11-25 OpenPhish/phishunt snapshots (`raw/*_20261125.txt`), restricted to registrable
domains that do not appear in `sample.csv` (the feeds had not rotated since 2026-11-24, so these are unseen-by-tuning
entries rather than time-split ones). URLs embedding tokens/emails were excluded. Legit rows are new UAE bank/gov
deep links plus global sites, verified with curl on 2026-11-25.

## Results (2026-11-25, mobile persona, `is_scam` = scam or likely_scam)

| set | blocklist | P | R | F1 | FPR |
|---|---|---|---|---|---|
| **holdout (headline)** | **ignored** | **1.000** | **0.619** | **0.765** | **0.000** |
| holdout | ignored, threshold >= suspicious | 1.000 | 0.786 | 0.880 | 0.000 |
| holdout | used | 1.000 | 1.000 | 1.000 | 0.000 |
| sample (tuned on) | ignored | 1.000 | 0.746 | 0.854 | 0.000 |
| sample (tuned on) | ignored, threshold >= suspicious | 1.000 | 0.814 | 0.897 | 0.000 |
| sample (tuned on) | used | 1.000 | 1.000 | 1.000 | 0.000 |

Registry official domains (`https://<domain>/`, every non-fictional brand): **official domains FP: 0/109**.

Known limitations (misses without the blocklist):
- Compromised old legitimate sites hosting a phishing kit in a sub-path (procasmexico.com, websiteseguro.com,
  aegtecnoservice.it): domain age and reputation look clean; only feed hits catch them.
- Phishing kits that show no brand, no form and no bait words to our mobile persona (blank landing pages, gated kits).
- Brands outside the UAE registry and the built-in global keyword list (e.g. zoom, trezor, cashapp, spotify, bbva).
- Dead pages whose domain is registered and not new: domain-only signals alone usually reach "suspicious", not "likely".
