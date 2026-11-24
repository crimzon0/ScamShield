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
