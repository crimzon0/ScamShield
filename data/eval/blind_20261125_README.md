# Blind evaluation set — `blind_20261125.csv`

Built 2026-11-24 21:55–22:17 UTC by the "blind" teammate, **before any scan of these URLs**, and frozen:

    sha256(blind_20261125.csv) = 0f18588937dfc53ae4b4f5be5d3b230903d0ba2e49deb49ba1f9b8db252c17a6

Columns: `url,label,source,first_published,basis`. **180 rows: 106 scam / 74 legit.**
No row was added, removed or relabelled after scanning. No scoring code was changed.
Build scripts and intermediate selections: `data/eval/blind_20261125_build/`. Raw feed snapshots:
`data/eval/raw/blind_20261125/` (feed lists only; no scam URL was fetched by us — only the pipeline's headless detonator touches them).

## Scam rows (106) — time-split

Cut-off: feed entry first published **after 2026-11-24T20:57:00Z** (all tuning on sample/holdout pre-dates it).
Feeds pulled 2026-11-24 ~22:00–22:12 UTC, so the window is ~75 minutes of fresh phishing.

| source | feed | timestamp field | eligible after cut-off | selected |
|---|---|---|---|---|
| urlscan.io public search | `task.tags:phishing AND date:[2026-11-24T20:57:00Z TO *]` (484 results, paged by date window) | `task.time` | 134 | 82 |
| CERT Polska warning list | https://hole.cert.pl/domains/v2/domains.json | `InsertDate` (active only, `DeleteDate` null) | 12 | 11 |
| PhishStats | https://api.phishstats.info/api/phishing?_sort=-date | `date` | 10 (15 before dedupe) | 10 |
| PhishTank | http://data.phishtank.com/data/online-valid.csv | `submission_time`, `verified=yes` | 3 | 3 |
| OpenPhish community / phishunt | GitHub feed.txt / phishunt.io/feed.txt (no timestamps) | basis `absent_from_20261124_snapshot` | 0 (no entry absent from earlier snapshots) | 0 |

Tried, unavailable: URLhaus csv_recent (now needs an abuse.ch Auth-Key, HTTP 410), phishstats.info:2096 (522),
phishstats phish_score.csv (404), Phishing.Database NEW-today/last-hour (no phishing entries / empty).

Rules (applied mechanically by `build_scams.py`, in this order):
1. Timestamp strictly after the cut-off (or, for untimestamped feeds, absent from every earlier snapshot).
2. urlscan only (third-party automatic tags, noisiest source): drop results tagged `possiblethreat`; drop `/favicon.ico` scans;
   drop when the registrable domain is in the Tranco top-100k (removes e.g. facebook.com / accounts.google.com / edgeone.dev
   that were tagged "phishing"); drop when a brand tag equals the scanned domain itself (11 dropped:
   fixedfloat.io, *.scotiabank.com, backoffice.cibcbank.com, chainratings.net, keplr.to, castro-cvv.cc — likely the brand's own site).
   *Bias note:* the Tranco filter removes compromised popular sites, which are hard cases for us.
3. Dedupe: URL (case-, trailing-slash- and `www.`-insensitive) not in any earlier snapshot (`data/eval/raw/*.txt`, `data/feeds/*.txt`),
   and neither URL nor **registrable domain** in `sample.csv` / `holdout.csv`; registrable domain / host not in the radar DB (`radar_hits`, 3241 rows).
   Dropped: 2 duplicate URLs, 3 already in earlier snapshots.
4. Privacy: drop URLs embedding an e-mail address (none matched).
5. Selection order: UAE-relevant (UAE brand keywords) first, then brand-impersonation (brand keyword in URL, PhishTank target,
   or urlscan brand tag), then general; round-robin across sources, oldest first. Cap **2 per registrable domain** and 4 per
   ICANN registrable (so one shared host such as pages.dev / workers.dev cannot dominate). 53 rows dropped by the caps.
   Result: 61 brand-impersonation + 45 general. **No UAE-targeted entry appeared in any feed in the 75-minute window**,
   so this set measures generalisation to global phishing (Allegro/OLX/InPost via CERT.pl, crypto-wallet drainers, Meta,
   USAA, AT&T, Zoom, Robinhood, SMS-casino spam, tracking-link redirectors), not UAE brands.
6. Labels are the feeds' labels, not hand-verified. Some urlscan "phishing" tags are automated and may be wrong
   (e.g. spam redirectors, affiliate landers); report per-source numbers.

## Legit rows (74)

Fresh deep pages on official sites, **none in** `sample.csv`, `holdout.csv`, `tests/adversarial/hard_legit.csv`,
`tests/adversarial/legit_deeplinks.csv`. No path was typed by hand: every URL was discovered by
- `build_legit.py`: HTTP GET of the official home page (registry `official_domains[0]` for 32 real brands, plus flydubai.com,
  airarabia.com, noon.com, carrefouruae.com, dha.gov.ae, abudhabi.gov.ae, and global github.com, bbc.com, mozilla.org,
  wikipedia, stackoverflow) and taking same-registrable links whose path has a service keyword
  (login, pay, fine, contact, card, account, track, loan, support, help, customer, booking, manage, visa, ...), max 3 per site
  with distinct keywords (2 for global sites) → 48 rows;
- `sitemap_legit.py`: robots.txt → sitemap `<loc>` entries for official sites whose home page is JS-rendered → 26 rows.
Each picked URL was re-fetched (HTTP 200, or 403 bot-block for cbd.ae — a blocked page must never become an FP).
Removed mechanically: non-200/403 (bbc.com/undefined 404, one aramex 404), sitemap `.xml` files, URLs with `&amp;`,
and a duplicate adpolice contact page. 29 registrable domains: 25 UAE (banks: ENBD, FAB, Mashreq, Liv, Emirates Islamic,
DIB, ADIB, Wio, RAKBANK, CBD; gov: ICP, u.ae, DM, Dubai Police, AD Police, MOI, MOHRE, DHA, abudhabi.gov.ae;
Emirates Post, ADNOC Distribution, du, Aramex; airlines Etihad, flydubai, Air Arabia) + github, bbc, mozilla.

## Measurement protocol

Fresh forced scans, mobile-ad persona default, concurrency 4, blocklists ignored (`--ignore-blocklist` also ignores Safe Browsing):

    SCAMSHIELD_NO_LLM=1 .venv/Scripts/python -m scamshield.cli.eval data/eval/blind_20261125.csv --ignore-blocklist --force --concurrency 4 --out var/eval/blind_nollm.csv

Blocklist-ON reference = same stored scans re-scored without the ignore flag (`blind_20261125_build/rescore_dump.py`).
Threshold sweep: `blind_20261125_build/sweep.py` → `blind_20261125_sweep.json` / `blind_20261125_sweep.md`.
Results are appended below after the run.

## Results (run 2026-11-24 22:20–~23:00 UTC; set frozen before the run, nothing edited afterwards)

Mode (a) **no LLM** (`SCAMSHIELD_NO_LLM=1`), blocklists ignored, fresh forced scans, default 15 s budget, concurrency 4.
Predictions: `var/eval/blind_nollm.csv`; blocklist-ON reference = same scans re-scored: `var/eval/blind_nollm_blocklist_on.csv`
(rescoring with the ignore flag reproduces the stored labels 180/180). Modes: 119 full, 61 domain-only.

| mode | threshold | P | R | F1 | FPR | TP/FP/FN/TN |
|---|---|---|---|---|---|---|
| **no LLM, blocklist ignored (headline)** | likely_scam | **0.960** | **0.226** | **0.366** | **0.014** | 24/1/82/73 |
| no LLM, blocklist ignored | suspicious | 0.983 | 0.547 | 0.703 | 0.014 | 58/1/48/73 |
| no LLM, blocklist ON | likely_scam | 0.964 | 0.255 | 0.403 | 0.014 | 27/1/79/73 |
| no LLM, blocklist ON | suspicious | 0.984 | 0.576 | 0.726 | 0.014 | 61/1/45/73 |

Blocklist ON adds only 3 TPs: our local feed copies pre-date these entries (time split works as intended).
Official domains (every registry domain as `https://<domain>/`): **FP 0/112**. Per-source recall at likely_scam:
cert.pl 2/11, phishstats 4/10, phishtank 2/3, urlscan 16/82 (at suspicious: 9/11, 4/10, 2/3, 43/82).

Only FP: `https://www.airarabia.com/en/airrewards/rakbank-air-arabia-platinum-credit-card` (scam 85) — a real RAKBANK
co-branded card page on Air Arabia's site: "presents itself as RAKBANK, but airarabia.com is not an official RAKBANK domain" +
card/login/OTP/payment form signals. airarabia.com is not in the registry, so this is not an official-domain FP.

Threshold sweep: `blind_20261125_sweep.md` / `.json` (`build/sweep.py`). FN breakdown: `build/fn_groups.py`.
Mode (b) with LLM: pending the lead's go-ahead (LLM FP gate).

Score separation: apart from the airarabia co-brand FP (85), the highest legit score is 5 (flydubai ways-to-pay); every
official-domain page scores 0. On this set any cut-off from 30 to 85 has the same single FP, so the FP is a
brand-rule problem (partner/co-brand pages), not a threshold problem.

## Run (b) — LLM ON (after the lead's LLM corroboration gate), same frozen set

    .venv/Scripts/python -m scamshield.cli.eval data/eval/blind_20261125.csv --ignore-blocklist --force --concurrency 4 --out var/eval/blind_llm.csv

| mode | threshold | P | R | F1 | FPR | TP/FP/FN/TN |
|---|---|---|---|---|---|---|
| **LLM ON, blocklist ignored** | likely_scam | **0.964** | **0.255** | **0.403** | **0.014** | 27/1/79/73 |
| LLM ON, blocklist ignored | suspicious | 0.984 | 0.566 | 0.719 | 0.014 | 60/1/46/73 |
| LLM ON, blocklist ON | likely_scam | 0.968 | 0.283 | 0.438 | 0.014 | 30/1/76/73 |
| LLM ON, blocklist ON | suspicious | 0.984 | 0.594 | 0.741 | 0.014 | 63/1/43/73 |

Official domains FP 0/112. Same single FP (airarabia RAKBANK co-brand page, scam 85).

**Isolating the LLM effect.** Run (b) is a fresh re-scan ~40 min after run (a), so the difference between them is mostly
the live pages changing (7 labels differ: 6 up, 1 down; e.g. rc-attractivite.fr and graceharborltd.com loaded fully the
second time; loravinsaat.com fell from scam 95 to suspicious 40). To measure the LLM alone, the run-(b) scans were
re-scored with `match_brand` re-run under `SCAMSHIELD_NO_LLM=1` on the **same detonations**
(`build/rescore_dump_rebrand.py` → `var/eval/blind_llm_scans_nollm_brand.csv`): the LLM changed **0 labels** and
1 score (mlg-applec-hepl.vip, suspicious 50 → 58). 60/180 scans have `llm` among their brand-match methods; no
`llm_uncorroborated` signal fired.
LLM calls: ~156 blind pages + 112 official pages were eligible; the shared LLM cache gained 530 entries during the run
window (upper bound — other teammates were scanning at the same time).
