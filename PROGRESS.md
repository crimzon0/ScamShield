# PROGRESS

Start (UTC): **2026-11-24 19:41:29** · Budget 3h -> hard stop 22:41 UTC · E2E scan target by 20:56 UTC · cut-check at 21:41 UTC

## Status
- [x] Phase 0 scaffold, core contract, stubs, CLAUDE.md, Makefile (done 19:44:54 UTC, commit c4558db)

## Team log
- 20:50 breaker FINAL: offline adversarial 92 passed / 87 skipped (no xfails); network 87 passed (legit_deeplinks 45/45, hard_legit 42/42). Outstanding failures: none.
- 20:44 verdict FINAL (fingerprint db475dd39c6eb6a5): hard_legit 42/42 legit; holdout no-blocklist P 1.000 R 0.714 F1 0.833 FPR 0 (>=suspicious R 0.857); sample no-blocklist P 1.000 R 0.797 FPR 0; with blocklist 1/1/0 on both. First blind holdout run (20:18): R 0.619.
- 20:48 radar final rescan: crtsh 45 scam / 26 likely / 41 suspicious / 5 legit / 700 pending; certstream 1/0/3/2; nrd 2 scam 1 likely.
- 20:21 radar: REAL crt.sh backfill hits (17 from 'uaepass%', scanned): uaepasses[.]com scam 100 (cert 2026-10-06), uaepass[.]digital scam 100, uaepass[.]help scam 97, uaepass[.]org likely_scam 70, uaepass-auth.directschool.workers[.]dev likely_scam 72. crt.sh index lags ~40 days (newest not_before 2026-10-15) so backfill parses 120 d; certstream (salik[.]work, 59 min TTD) + NRD (trafficrta[.]xyz) cover the fresh window.
- 20:18 verdict FINAL-1 eval (fresh forced scans, mobile persona, is_scam = scam|likely_scam):
  - HELD-OUT holdout.csv n=79 (37 legit / 42 scam, unseen, no tuning): blocklist IGNORED P 1.000 R 0.619 F1 0.765 FPR 0.000 (>=suspicious: R 0.786 FPR 0); with blocklist P 1.000 R 1.000 FPR 0
  - SAMPLE sample.csv n=127 (68/59, tuned): ignored P 1.000 R 0.746 FPR 0; with blocklist P 1 R 1 FPR 0
  - Official domains FP 0/109. Breaker legit deep links 45/45 legitimate.
- 20:16 detonator DONE (19 tests; fast mode 8x concurrency ~1 s/URL). radar: NRD + certstream (docker) live; scanned hits adinwealth[.]org scam 87, trafficrta[.]xyz likely_scam 76; crt.sh working query shape found (prefix wildcard).
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
- GOOGLE_PLACES_API_KEY: live Google Maps helpline search is implemented and unit-tested but has never run live; synthetic, clearly-labelled samples are used meanwhile.
- SERPAPI_KEY: sponsored/organic search-ad collector (radar) and search-snippet helpline check; both report "unavailable" without it.
- LLM_API_KEY (+ LLM_PROVIDER): LLM brand-claim analysis is wired and mock-tested only; keyword rules used meanwhile.
- URLSCAN_API_KEY, SAFE_BROWSING_API_KEY, a Cert Spotter key: optional intel sources (no_key today); crt.sh rate-limits us (429), so cert_first_seen is often empty.
- Registry review: all 33 brands are verified:false; 23+ open facts in data/registry_todo.md (ADCB/Salik/DEWA/ADNOC/Aramex/Emirates/Etihad confirmed only via search extracts; Dubai Police has no E.164 number; moi-cpc.ae; emiratesnbd.com.eg).
- Pilot facts: Aman 8002626 and the u.ae eCrime page are from news/search sources; confirm with Abu Dhabi Police (docs/pilot.md).
- README team names placeholder; Marp render of docs/slides.md not checked; record the 60 s video.
- Stop background processes when done: the demo server on :8000, `docker compose down` (certstream container), and radar's collectors. Radar reported PIDs 23408, 19616, 61584, 59928, 45560, 61036; its own attempt to stop the orphaned loop (23408) was blocked by the permission check, so the lead did not do it on its behalf.
- Open accuracy question: uaepass.uat.finwall[.]studio still scores scam 88 (possibly a legitimate integrator staging host); unverified.

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
   ('hxxp://stepflow2mt.swedencentral.cloudapp.azure[.]com/ch/ch_css_mkit/', ['dead'], 'scam', '100')
   ('hxxp://netflix-dashboard-login.8-219-97-148.cpanel[.]site', ['blank'], 'scam', '100')
   ('hxxp://aktiffkan-paylatterz.jmm.my[.]id/', ['dead'], 'scam', '100')
   ('hxxp://ac20s[.]lat/', ['dead'], 'scam', '100')
   ('hxxp://hawkinsinc.microsoft-alerts[.]org', ['blank'], 'scam', '100')
```
Every input row has a verdict, input order preserved, all rows have EN+AR reasons; 15 dead/blank/timeout pages still got verdicts (domain-only). Note: an earlier run silently resumed a stale predictions.csv; fixed by using a fresh file (verdict adding fingerprint check to resume).

### 5. Radar real crt.sh hits + helpline check — PASS (20:31 UTC)
DB: 478 radar hits {crtsh: 471, certstream: 5, nrd: 2}; 29 scanned so far {scam 10, likely_scam 8, suspicious 8, legitimate 3} (refresh loop scans 25 every 4 min). Real crt.sh look-alikes, e.g.:
```
emiratesnbd.com-verify-net[.]bond   cert 2026-10-09T06:16  flagged 2026-11-24T20:27  scam 100
emiratesnbd.com-verify-io[.]bond    cert 2026-10-09T20:04  flagged 2026-11-24T20:27  scam 100
emiratesnbdgov[.]com                cert 2026-10-12T16:17  flagged 2026-11-24T20:27  likely_scam 70
uaepasses[.]com                     cert 2026-10-06T12:47  flagged 2026-11-24T20:19  scam 100
```
(crt.sh index lags ~40 d; certstream + NRD cover the fresh window, e.g. trafficrta[.]xyz registered 2026-11-22.)
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

### 4. make demo — PASS (20:50-20:56 UTC; dashboard teammate ran it with default flags, lead re-verified endpoints)
```
[demo] scan https://www.tamm.abudhabi/ -> legitimate 0 mode=full id=b7cd4a68580e (0.1s)
[demo] radar: 862 hits in db from collectors {'certstream': 9, 'crtsh': 850, 'nrd': 3}
[demo] helpline: 9 findings across 12 brands
[demo] ScamShield running at http://127.0.0.1:8000  (API docs: http://127.0.0.1:8000/docs)
```
UI scan of hxxp://aramex.p-track-au[.]com/ (holdout scam row) -> scam 100 with EN reasons (+60 openphish, +50 imitates aramex.com subdomain_brand, +30 domain 1 day old) and AR reasons after the toggle (<html dir="rtl" lang="ar">, mirrored layout); screenshot served; redirect chain shown. https://www.rta.ae/ -> legitimate 0 (official domain; brand RTA via arabic+logo_hash+screenshot_hash).
Lead re-check via curl: /api/health ok; / 200 text/html; /api/scans/5c8df41f307d -> 100 scam, 4 reasons with Arabic, screenshot URL; case export: zip 200 application/zip 150582 B, pdf 200 application/pdf 119217 B (%PDF-1.4). ZIP: screenshots, dom, har, favicon, redirect_chain, rdap_whois, dns_hosting, brand_match, verdict, report.pdf, takedown_en/ar, manifest.json + manifest.sha256.

### FINAL re-verification on final engine (fingerprint db475dd39c6eb6a5), 20:44-20:57 UTC, no API keys
make test:
```
300 passed, 87 skipped, 1 warning in 337.16s (0:05:37)
EXIT 0
```
make eval:
```
=== ScamShield eval: data/eval/sample.csv  (n=127, is_scam >= likely_scam) ===
precision 1.000  recall 1.000  F1 1.000  FPR 0.000  accuracy 1.000
FALSE POSITIVES (0):
ABLATION (blocklist ignored): precision 1.000  recall 0.797  F1 0.887  FPR 0.000  (TP 47 FN 12 FP 0 TN 68)
  ablation with threshold >= suspicious: P 1.000  R 0.898  F1 0.946  FPR 0.000
  domain_only subset (n=40): recall 0.826  FPR 0.000
official domains FP: 0/112  (not 'legitimate': 0)
EXIT 0
```
Held-out (verdict, same engine): blocklists ignored P 1.000 R 0.714 F1 0.833 FPR 0; first BLIND run (20:18) R 0.619. Adversarial (breaker): offline 92 pass; network 45/45 official deep links + 42/42 hard-legit pages legitimate.

### 6. Docs — PASS
README.md, docs/slides.md (8 Marp slides), docs/video-script.md (60 s), docs/pilot.md exist; README/slides/video quote the measured numbers above (headline: blind held-out P 1.000 R 0.619 FPR 0, official 0/112).

## 2026-11-25 — keys round (lead)

Keys added to `.env` (gitignored; verified absent from git history and working tree). Smoke test, one real call each: Anthropic LLM 200 OK; Google Places 200 with phone numbers (so the SerpApi Maps fallback was not needed); Safe Browsing 200 (test URL matched SOCIAL_ENGINEERING); SerpApi account OK (Free plan, 250/month).

1. **LLM FP gate** — LLM on, real calls: hard_legit 0/42, deeplinks 0/45, official 0/112 flagged (before and after gate). One LLM-only bump (smilesuae.ae 10 -> 22) -> gate added in `score()`: LLM brand evidence only corroborates a verdict already >= suspicious without it (`llm_uncorroborated` 0-weight signal otherwise). 6 offline tests. `llm.py` retries 429/5xx; `SCAMSHIELD_NO_LLM=1` ablation switch; LLM state is in the pipeline fingerprint.
2. **Fresh blind set** `data/eval/blind_20261125.csv` (106 scam published after 2026-11-24 20:57 UTC / 74 legit), frozen before scanning, sha256 0f185889…. Blocklists ignored:
   - no LLM: likely_scam P 0.960 R 0.226 FPR 0.014; suspicious P 0.983 R 0.547
   - LLM on: likely_scam P 0.964 R 0.255 FPR 0.014; suspicious P 0.984 R 0.566
   - LLM changed 0 labels on identical detonations. Single FP: RAKBANK co-brand page on airarabia.com (scam 85). Official 0/112.
   - Recommended cut-off 35 (suspicious) for alerts; likely_scam for takedown. Sweep: data/eval/blind_20261125_sweep.md.
3. **Helpline live** — 0/33 registry brands are `verified: true`, so the verified-only live run checked 0 listings. Needs a human to verify registry phones first.
7. **Hygiene** — no key in history; plain python next to each make target in README; live scam domains defanged in README/docs/PROGRESS.
Offline `make test`: 308 passed, 88 skipped.
Submission deck: docs/deck/ScamShield_Aegis.pdf. Pushed to https://github.com/crimzon0/ScamShield.
