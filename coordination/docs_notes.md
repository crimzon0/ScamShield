# Notes for the docs teammate (collected by lead)

## Helpline (from helpline teammate)
Fake helplines. Scammers post fake customer-service numbers for UAE banks and government services on Google Maps and in search results. ScamShield searches Google Places in English and Arabic across six UAE cities, plus search snippets and the listings' websites, which are detonated by the same scan pipeline. Every number is normalised to E.164 (Arabic-Indic digits, 800/600 numbers, 05x mobiles, wa.me links) and compared with the brand's official numbers and short codes. A number not in the registry is only "unverified". It becomes "likely scam" only with a second, independent sign: a brand-named listing linking to a non-official website, a personal mobile for an institution, a new listing with few reviews, a website scored as scam, or WhatsApp-only contact. Reasons are given in English and Arabic.
Demo: `.venv/Scripts/python -m scamshield.helpline --live --brand tamm --no-landing` (no key -> synthetic fallback, labelled).

## Detonator
Real runs: google.com ok 5.7s; tamm.abudhabi ok 5.3s (http->301->301->200); tinyurl/is.gd shorteners expanded; dead .ae domain -> status dead in <1s; data: URL -> error. Personas: uae_mobile_ad_click (Android, ar-AE, Asia/Dubai, Google referrer), desktop, crawler (Googlebot).

## Evidence (from evidence teammate)
- Every scan exports a police case package: one ZIP holding the per-persona screenshots, DOM and HAR, the redirect chain with UTC timestamps, RDAP/WHOIS (raw + parsed registrar and abuse contacts), DNS/hosting/TLS, brand match and verdict JSON, a bilingual EN/AR PDF report, and pre-drafted EN/AR takedown notices for the registrar and host (drafts only, never sent, require officer review). Legitimate verdicts get no takedown draft.
- Integrity: manifest.json lists every file with its SHA-256, size and UTC creation time, plus tool version and the full UTC timeline (domain registered, certificate first seen, page captured, case generated). The SHA-256 of the manifest itself is in manifest.sha256; missing artifacts are recorded explicitly.
- Chain of custody: the PDF states how evidence was captured (isolated headless browser, no downloads, no form interaction), flags captures needing manual review (HTTP 4xx, dead page, domain-only); `build_bundle()` packs a radar batch into one hashed ZIP with index.csv.
- Real examples: aramex.a-track-au.com (OpenPhish) -> scam 100, registrar Dominet (HK), domain 1 day old; tamm.abudhabi -> legitimate 0, no takedown draft.

## Brand: visual + LLM (from brand teammate)
- Visual similarity: we perceptually hash (pHash) each page's favicon and the top band of its screenshot and compare them with reference hashes taken only from the brands' official sites (favicons for 24 brands, screenshot header bands for 12, mobile+desktop). A close match on a non-official domain is evidence of a cloned page; threshold (<=8 bits) calibrated so different brands never collide (closest cross-brand pair: 20 bits; no non-official capture within 14 bits across 687 saved captures).
- LLM analysis (optional): page title, form fields and text go to an LLM inside <page>…</page> tags as untrusted data; strict JSON schema returns brand claimed (restricted to registry ids), what it asks for, confidence. One signal only; never overrides the official-domain check.
- Without a key: bilingual keyword rules (Arabic normalisation, Arabizi, prominence: title/forms/URL), deterministic offline.
- Registry: 33 brands (32 real UAE + fictional test brand), every fact with a source URL, verified:false; open items in data/registry_todo.md. Official-domain redirect audit done (moi-cpc.gov.ae -> moi-cpc.ae added).
