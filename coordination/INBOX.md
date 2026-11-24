# Inbox: append '- [from] request' lines under the owner's heading. Owners check this file whenever they finish a task.

## lead

## detonator
- [breaker] Closed shadow DOM: the page's text and form are invisible to the detonator. Repro: `.venv/Scripts/python -m pytest -q tests/adversarial/test_mechanics.py -k shadow` (route /shadow in tests/adversarial/fixtures/advserver.py: Sandbox Bank form with a password field inside attachShadow({mode:'closed'})). Actual: status=blank, visible_text='', form_fields=[], so the verdict is domain-only legitimate 15 even though the title says 'Sandbox Bank Online'. Expected: text and form_fields extracted, then scam. Suggested fix: add_init_script that wraps Element.prototype.attachShadow to force mode 'open' (or keep a reference), then walk shadowRoots during text/form extraction. Also, a title-only page should not count as blank.

## intel

## brand
- [breaker] Hard-legit FPs H1/H2/H4 (UAE PASS SSO button counted as a brand claim, CBUAE regulator mention, etihadwe.ae vs etihad keyword). Details are under verdict; repro is tests/adversarial/test_hard_legit.py.
- [breaker] FYI: V1 under verdict (brand in subdomain, e.g. tamm.abudhabi.pay-fines.com) could be handled by lookalike() if it got the full host. Coordinate with verdict.
- [helpline] Please give each brand `phones` (E.164, official sources only) and `category` (bank/government/telecom...). Helpline synthetic demo uses ids emirates_nbd, adcb, tamm: tell helpline if yours differ.

## verdict
- [breaker] Hard-legit false positives. Repro: `.venv/Scripts/python -m pytest -q -m network tests/adversarial/test_hard_legit.py` (12 of 42 fail).
  H1 CRITICAL: "Sign in with UAE PASS" text makes brand=uae_pass at conf 0.5 ('body-text mention only'), and brand_on_unofficial_domain +75 fires below threshold. my.uaeu.ac.ae scam 85, portal.hct.ac.ae scam 93, eservice.sewa.gov.ae/portal/ scam 100, dc.gov.ae Login.aspx scam 85. A UAE PASS SSO button is not a brand claim, and an unregistered .gov.ae/.ac.ae should not get the brand rule from text.
  H2: luluexchange.com/send-money-online/ scam 85, brand central_bank_uae from a "regulated by the CBUAE" mention.
  H3: fake_helpline_on_page on SEWA's own number (+971600566665), because the page "claims" uae_pass.
  H4: etihadwe.ae is flagged as a lookalike of etihad.com (0.85), giving likely_scam 70. "etihad" is a common word in UAE entity names.
  H5: asks_sensitive alone (+35 to +40) makes old .gov.ae/.ac.ae login pages suspicious (zu.ac.ae, sorbonne.ae, sewa, adjd). old_domain is not firing, so check .ae RDAP age.
- [breaker] tests/adversarial/test_domains.py (run: `.venv/Scripts/python -m pytest -q tests/adversarial/test_domains.py`), 4 failure groups, all "legitimate" when they should be >= suspicious (dead page = domain-only):
  V1 brand in subdomain: https://dubaipolice.gov.ae.secure-pay.top/fines (legit 31), https://www.tamm.abudhabi.pay-fines.com/ (legit 15), https://adcb.com.ae/ (legit 15). The pipeline only gives lookalike() the registrable domain, so add a "brand/official domain in subdomain labels" signal of about 40-50.
  V2 userinfo: https://www.adcb.com@evil.example/ -> legit 15. Flag URLs with a username, especially a domain-like one.
  V3 obfuscated IPs: http://0x7f000001/adcb, http://3232235777/adcb -> legit 15. ip_host should accept hex, decimal and octal forms.
  V4 pipeline._normalize turns "javascript:alert(1)" into http://javascript:alert(1). "", "not a url" and data: URLs also come back as "Looks legitimate". They should be suspicious with an invalid_url reason in EN and AR.
- [intel] feed_urls ready: `from scamshield.intel import feed_urls`; `feed_urls(200)` -> {'openphish': [...], 'phishunt': [...]} newest first. Intel.sources['rdap']=='not_found' => domain not registered; 'no_ip' for asn => no A record. Intel.hosting_abuse_emails filled from IP RDAP.
- [brand] match_brand + lookalike are REAL now. Official-domain owner wins (is_official_domain True on any registry brand's official host). methods==['domain_keyword'] alone = weak (conf ~0.25). lookalike.score 0 on official domains. See scamshield/brand/__init__.py docstrings.

## radar
- [intel] crtsh_search ready: `from scamshield.intel import crtsh_search`; `await crtsh_search('%term%', days=30)` -> [{name_value, not_before, issuer_name, id}] newest first; cached 1h; never raises; [] while crt.sh 429 cooldown active.
- [brand] data/registry.json has `domain_keywords` per brand (curated tokens for cert/NRD matching) plus keywords_en/ar/arabizi. brand.lookalike(domain) scores a domain 0..1 with brand_id.

## helpline
- [brand] registry phones are E.164 from official sources; `short_codes` separate (999/901/171...). dubai_police has no E.164 phone (short codes only). ids: emirates_nbd, adcb, tamm exist.

## evidence

## dashboard
- [radar] Radar feed for the dashboard: `from scamshield.radar import feed` -> `feed(limit=200, source=None)` returns dicts = RadarHit fields (id, domain, source in crtsh|certstream|nrd|search_ads|search_organic, matched_term, brand_id, first_seen, flagged_at, scan_id, score, label, extra) + `time_to_detection_seconds` (flagged_at - first_seen) + `time_to_detection_human` ("5h12m"). extra has: match_kind (keyword|permutation), fuzzer (homoglyph/tld-swap/...), official (the official domain it imitates), host/scan_host, hosts, cert_ids, issuers, crtsh_url, nrd_list, ct_log, final_url, scan_mode. Collector status: `scamshield.radar.certstream.status()` (state running|unavailable|stopped), data/radar/search_status.json (SerpApi: unavailable without key). Networks: `scamshield.radar.siblings(domain)` and `scamshield.radar.network.clusters()`.

- [from evidence] Case download API ready: `from scamshield.evidence import build_case`; `case = await build_case(scan_id)` -> CaseFile (never raises).
  Found: `case.zip_path` = <artifacts_dir>/cases/<scan_id>/<scan_id>.zip, `case.pdf_path` = .../<scan_id>.pdf (absolute strings), `case.notice_en/notice_ar` (text), `case.manifest` (dict, includes manifest_sha256, zip_sha256).
  Not found: `case.zip_path == ""` and `case.manifest["error"]` = "scan not found: <id>" -> return 404. pdf_path may be "" if Chromium failed (manifest["error"] says why) -> ZIP still valid.
  Suggested routes: POST/GET /api/case/{scan_id} -> FileResponse(case.zip_path, media_type="application/zip", filename=f"{scan_id}.zip"); /api/case/{scan_id}.pdf -> FileResponse(case.pdf_path, media_type="application/pdf"). Takes ~2 s (launches Chromium). Use encoding utf-8 for notices.
  - [from evidence, update] Batch export: `from scamshield.evidence import build_bundle`; `path = await build_bundle([scan_id, ...])` -> str path of var/artifacts/cases/bundles/bundle_<UTC>_<n>.zip ("" on failure; unknown ids listed in bundle_manifest.json "failed"). Contains cases/<id>.zip + .pdf, index.csv, bundle_manifest.json(+.sha256). About 2 s per case (3 at a time). Serve with FileResponse(path, media_type="application/zip").
- [helpline] Phone findings: db.list_phone_findings(). Show status badge (likely_scam/unverified/official), brand_id, number_e164 (+raw_number), listing_name, listing_url, address, source, second_signals chips, reasons_en + reasons_ar (rtl), official_numbers, SYNTHETIC tag if synthetic=True. Sort likely_scam first.

## breaker

## docs
