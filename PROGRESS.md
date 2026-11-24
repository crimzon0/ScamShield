# PROGRESS

Start (UTC): **2026-11-24 19:41:29** · Budget 3h -> hard stop 22:41 UTC · E2E scan target by 20:56 UTC · cut-check at 21:41 UTC

## Status
- [x] Phase 0 scaffold, core contract, stubs, CLAUDE.md, Makefile (done 19:44:54 UTC, commit c4558db)

## Team log
- 20:21 radar: REAL crt.sh backfill hits (17 from 'uaepass%', scanned): uaepasses.com scam 100 (cert 2026-10-06), uaepass.digital scam 100, uaepass.help scam 97, uaepass.org likely_scam 70, uaepass-auth.directschool.workers.dev likely_scam 72. crt.sh index lags ~40 days (newest not_before 2026-10-15) so backfill parses 120 d; certstream (salik.work, 59 min TTD) + NRD (trafficrta.xyz) cover the fresh window.
- 20:18 verdict FINAL-1 eval (fresh forced scans, mobile persona, is_scam = scam|likely_scam):
  - HELD-OUT holdout.csv n=79 (37 legit / 42 scam, unseen, no tuning): blocklist IGNORED P 1.000 R 0.619 F1 0.765 FPR 0.000 (>=suspicious: R 0.786 FPR 0); with blocklist P 1.000 R 1.000 FPR 0
  - SAMPLE sample.csv n=127 (68/59, tuned): ignored P 1.000 R 0.746 FPR 0; with blocklist P 1 R 1 FPR 0
  - Official domains FP 0/109. Breaker legit deep links 45/45 legitimate.
- 20:16 detonator DONE (19 tests; fast mode 8x concurrency ~1 s/URL). radar: NRD + certstream (docker) live; scanned hits adinwealth.org scam 87, trafficrta.xyz likely_scam 76; crt.sh working query shape found (prefix wildcard).
- 20:09 full offline suite: 252 passed, 46 skipped. intel DONE (16 tests). detonator DONE v2 (17 tests, stealth persona, 16 real URLs p50 7.7s p95 12.5s). breaker: domain suite (V1-V4 fixed by verdict), mechanics 18/19 (shadow DOM -> detonator). docs eval: P1.0 R1.0 FPR0 on n=55 BUT blocklist ablation recall 0.115 -> verdict now working on content-based recall.
- 20:05 brand DONE: 42 tests; 31 UAE brands / 110 official domains / 60 phones; text EN/AR/Arabizi, lookalike incl. subdomain_brand, favicon pHash for 24 brands, LLM hook (mock-tested). 23 TODO facts in data/registry_todo.md. dashboard DONE v1 (9 tests, browser-verified EN/AR RTL, ZIP/PDF export). docs drafts in. radar: crt.sh %kw% queries returning [] / 429; working alternatives.
- **19:57 MILESTONE: real end-to-end scan works** (16 min after start; target was 75 min). Lead integration check:
  - https://www.tamm.abudhabi/ -> legitimate 0 (brand tamm, official_domain), 6.7 s
  - https://this-domain-does-not-exist-sc4m.ae/ -> legitimate 15, domain_only, det=dead (no crash) [takedown signals being added]
  - https://www.careem.com/ -> legitimate 0 (known_site), 5.6 s
  - verdict's first batch (stub brand): 55 rows / 130 s, P 0.929 R 1.000 FPR 0.069 (2 FPs from stub brand, now fixed)
- 19:57 wave 2 spawned: breaker, docs. brand real matcher+lookalike (31 tests). evidence DONE (8 tests, bundle export).
- 19:56 detonator v1 DONE: 13 tests; real Playwright, 3 personas, HTTP/meta/JS chain, shortener expansion, screenshot/DOM/HAR/TLS/favicon, dead/timeout/blank; working on stealth + throughput. helpline DONE v2: 40 tests, phones_on_page() for pipeline. Full suite 83 passed.
- 19:58 brand: registry 32 brands (31 UAE + fictional), unconfirmed facts in data/registry_todo.md. helpline DONE v1: 36 tests, synthetic run 10 findings; live Places untested (no key); now switching to real registry.
- 19:56 evidence DONE (4 tests). verdict: real score engine, concurrent pipeline w/ 40s guard + domain-only fallback, resumable CLI, eval; scan cache keyed by pipeline fingerprint. Lead integration: dead .ae domain -> suspicious 46 domain_only (no crash). tamm still mislabelled because brand is a stub.
- 19:55 evidence: ZIP + bilingual PDF (EN + AR RTL, visually checked) + EN/AR takedown notices + manifest SHA-256; 4 tests pass
- 19:52 helpline: synthetic mode works (10 findings: 7 likely_scam, 1 unverified, 2 official); live Places code written, needs key
- 19:46 UTC wave 1 spawned: detonator, intel, brand, verdict, radar, helpline, evidence, dashboard

## Needs a human
- GOOGLE_PLACES_API_KEY (helpline live Maps mode; synthetic mode used meanwhile)
- SERPAPI_KEY (ads/search radar + snippet check)
- LLM_API_KEY (brand LLM claim analysis; keyword rules used meanwhile)

## Done-when verification
### 1. make test — PASS (20:24-20:29 UTC, no .env / no API keys)
```
273 passed, 45 skipped, 1 warning in 293.60s (0:04:53)
EXIT 0
```
(45 skipped = network-marked tests; breaker ran the network suites separately: 45/45 legit deep links legitimate.)

### 2. Batch scan, no API keys — PASS (20:27-20:30 UTC, fresh output file)
`python -m scamshield.scan data/eval/sample.csv --out predictions.csv --fast`
```
done: 127 rows in 144s -> predictions.csv  legitimate=68 scam=59
real	2m26.414s
EXIT 0
rows 127 labels {'legitimate': 68, 'scam': 59} modes {'full': 92, 'domain_only': 35}
dead/blank/timeout/error detonations: 15
   ('https://www.etisalat.ae/en/', ['timeout'], 'legitimate', '0')
   ('https://stepflow2mt.swedencentral.cloudapp.azure.com/ch/ch_css_mkit/', ['dead'], 'scam', '100')
   ('https://netflix-dashboard-login.8-219-97-148.cpanel.site', ['blank'], 'scam', '100')
   ('http://aktiffkan-paylatterz.jmm.my.id/', ['dead'], 'scam', '100')
   ('https://ac20s.lat/', ['dead'], 'scam', '100')
   ('https://hawkinsinc.microsoft-alerts.org', ['blank'], 'scam', '100')
```
Every input row has a verdict, input order preserved, all rows have EN+AR reasons; 15 dead/blank/timeout pages still got verdicts (domain-only). Note: an earlier run silently resumed a stale predictions.csv; fixed by using a fresh file (verdict adding fingerprint check to resume).

### 5. Radar real crt.sh hits + helpline check — PASS (20:31 UTC)
DB: 478 radar hits {crtsh: 471, certstream: 5, nrd: 2}; 29 scanned so far {scam 10, likely_scam 8, suspicious 8, legitimate 3} (refresh loop scans 25 every 4 min). Real crt.sh look-alikes, e.g.:
```
emiratesnbd.com-verify-net.bond   cert 2026-10-09T06:16  flagged 2026-11-24T20:27  scam 100
emiratesnbd.com-verify-io.bond    cert 2026-10-09T20:04  flagged 2026-11-24T20:27  scam 100
emiratesnbdgov.com                cert 2026-10-12T16:17  flagged 2026-11-24T20:27  likely_scam 70
uaepasses.com                     cert 2026-10-06T12:47  flagged 2026-11-24T20:19  scam 100
```
(crt.sh index lags ~40 d; certstream + NRD cover the fresh window, e.g. trafficrta.xyz registered 2026-11-22.)
Helpline: `python -m scamshield.helpline --brand tamm --live --no-landing` -> `sources: {'places': 'no_key', 'synthetic': 'ok'}`; [LIKELY_SCAM] tamm +971560000301 (SYNTHETIC, labelled) with EN+AR reasons; 16 phone findings in db. Live Google Maps search is implemented but unverified (no key).

### 3. make eval — PASS (20:33-20:39 UTC, engine fingerprint 70b50785066fa4de, before hard-legit fixes)
```
=== ScamShield eval: data/eval/sample.csv  (n=127, is_scam >= likely_scam) ===
precision 1.000  recall 1.000  F1 1.000  FPR 0.000  accuracy 1.000
ABLATION (blocklist ignored): precision 1.000  recall 0.814  F1 0.897  FPR 0.000  (TP 48 FN 11 FP 0 TN 68)
  ablation with threshold >= suspicious: P 1.000  R 0.898  F1 0.946  FPR 0.000
  domain_only subset (n=28): recall 0.826  FPR 0.000
FALSE POSITIVES (0):
official domains FP: 0/112  (not 'legitimate': 0)
EXIT 0
```
Every false negative is listed with reasons in var/verify_eval.log. Will re-run after hard-legit FP fixes.
