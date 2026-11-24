# Notes for the docs teammate (collected by lead)

## Helpline (from helpline teammate)
Fake helplines. Scammers post fake customer-service numbers for UAE banks and government services on Google Maps and in search results. ScamShield searches Google Places in English and Arabic across six UAE cities, plus search snippets and the listings' websites, which are detonated by the same scan pipeline. Every number is normalised to E.164 (Arabic-Indic digits, 800/600 numbers, 05x mobiles, wa.me links) and compared with the brand's official numbers and short codes. A number not in the registry is only "unverified". It becomes "likely scam" only with a second, independent sign: a brand-named listing linking to a non-official website, a personal mobile for an institution, a new listing with few reviews, a website scored as scam, or WhatsApp-only contact. Reasons are given in English and Arabic.
Demo: `.venv/Scripts/python -m scamshield.helpline --live --brand tamm --no-landing` (no key -> synthetic fallback, labelled).

## Detonator
Real runs: google.com ok 5.7s; tamm.abudhabi ok 5.3s (http->301->301->200); tinyurl/is.gd shorteners expanded; dead .ae domain -> status dead in <1s; data: URL -> error. Personas: uae_mobile_ad_click (Android, ar-AE, Asia/Dubai, Google referrer), desktop, crawler (Googlebot).
