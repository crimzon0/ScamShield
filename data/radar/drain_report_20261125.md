# Radar drain report (2026-11-24T23:37:18Z)

- Total radar hits: **3419** (by source: {'certstream': 45, 'crtsh': 3312, 'search_organic': 59, 'nrd': 3})
- Scanned through `pipeline.scan_url`: **3418**
- Label distribution: {'unscanned': 1, 'legitimate': 271, 'scam': 1136, 'suspicious': 1598, 'likely_scam': 413}
- Google Safe Browsing lookups available: True (fresh v4 lookup of domain, scanned host and final URL)

## Blocklist cross-check

| set | n | on our feeds | on Safe Browsing | on **no** blocklist |
|---|---|---|---|---|
| scam | 1136 | 0 | 17 | **1119** |
| likely_scam | 413 | 0 | 2 | **411** |

Headline (excluding organic search results, which are pages that mention a brand rather than look-alike registrations): {'scam': 1107, 'scam_on_no_blocklist': 1090, 'likely_scam': 408, 'likely_scam_on_no_blocklist': 406}

Search radar: 59 hits {'search_organic': 59}, labels {'suspicious': 7, 'scam': 29, 'legitimate': 18, 'likely_scam': 5}

## Lead time (flagged_at - first_seen), scam set

- first_seen basis: {'ct_log': 6, 'not_before': 1099, 'observed (SerpApi has no publish time)': 29, 'not_before+1h(le_backdate)': 1, 'nrd_list_date': 1} (not_before = certificate notBefore, an estimate; ct_log / nrd_list_date = measured)
- median, all scam: 80d23h (n=1136)
- median, measured basis only: 0m (n=7)
- median, scam on no blocklist: 81d7h

Note: for not_before hits the lead time measures how long after certificate issuance *we* flagged the domain (backfill), i.e. it is an upper bound on our latency, not a head start over blocklists. The head-start claim is the 'on no blocklist' count at report time.

## Examples: scam verdicts on no blocklist (defanged)

| domain | brand | score | source | lead time | basis |
|---|---|---|---|---|---|
| icpsmartservice[.]com | icp | 100 | crtsh | 84d10h | not_before |
| mashreq[.]watch | mashreq | 100 | crtsh | 49d15h | not_before |
| mashreqwatchs[.]com | mashreq | 100 | crtsh | 49d13h | not_before |
| mashreq-ai-net[.]pages[.]dev | mashreq | 100 | crtsh | 82d18h | not_before |
| mashreqinc[.]pages[.]dev | mashreq | 100 | crtsh | 71d1h | not_before |
| fabbankinternational[.]com | fab | 100 | crtsh | 52d1h | not_before |
| emiratesislamicbusiness[.]com | emirates_islamic | 100 | crtsh | 101d9h | not_before |
| aramex-logistics[.]com | aramex | 100 | crtsh | 73d4h | not_before |
| sanadak[.]dev | central_bank_uae | 100 | crtsh | 44d6h | not_before |
| rakbank[.]vercel[.]app | rakbank | 100 | crtsh | 85d14h | not_before |

## Spot check (top scam-on-no-blocklist verdicts, read as data)

- Top 15 (score 100, sorted by domain) reviewed from stored reasons + screenshots; likely false positives / not phishing:
- adib[.]ae[.]portal[.]lunedata[.]io - FP: Lune vendor portal, 'Login with Azure AD' SSO tenant for ADIB (partner/vendor, no ADIB branding)
- aramex-5km[.]pages[.]dev - FP: unrelated 'NEXUS Cloud Business OS' login, no Aramex branding (name coincidence)
- aramex-app[.]org[.]ph, aramex-aatt-appi[.]com[.]ph, aramex-anzamazonbooka[.]com[.]ph, aramex-bing[.]com[.]ph, aramex-bnpparibas-customsupport[.]com[.]ph, aramex-boot-klm[.]com[.]ph, aramex-boot[.]com[.]ph - FP as scored: 'Redirecting...' = ParkLogic parking page, screenshot says 'This domain is available to be registered' (wildcard parking of unregistered .ph names, not live phishing). Should be domain_not_registered, not scam 100
- aramex-albyader[.]com - probable FP: Amman (Jordan) Aramex agent/branch marketing site with phone/contact, no credential or payment capture
- aramex-china[.]cn - probable FP: domain >7 years old, dead page, likely Aramex China agent/defensive
- adib[.]now[.]sh, adib[.]vercel[.]app, adib[.]workers[.]dev - weak: 404/no content, generic short project names; 'platform_takedown' inferred from a plain 404. Treat as suspicious at most
- aramex-asia[.]com - plausible: registry hold (often an abuse action), keep as scam
- Other FP classes seen outside the top 15: aramex[.]bd/[.]ch/[.]site, aramexonline[.]com, aramexpay[.]com titled 'Domain Registered at Safenames' (corporate brand-protection registrar = defensive registrations by the brand); cbdonlineshopping[.]com (CBD oil shop matched to Commercial Bank of Dubai 'cbd'); aramex-nas[.]direct[.]quickconnect[.]to (corporate Synology NAS); emiratesnbd-ai-nonprod[.]workers[.]dev (probably the bank's own non-prod); aramex-mhes--mhespro-maintenance-tracker...hosted[.]app (internal tool).
- Search organic set (59): mostly FP - blogs/guides/aggregators that mention a brand and contain a form are scored 'presents itself as <brand>' (brand_on_unofficial_domain 75), e.g. gcaa[.]ae (UAE GCAA, gov, UAE PASS login button) scam 95, hertz[.]ae / whatson[.]ae Salik guides scam 85-95, emx[.]ae (Emirates Post Group's EMX) scam 100, eandmoney[.]com (e& money) scam 85, emiratesnbd[.]com[.]eg / adcb[.]com[.]eg (Egyptian subsidiaries) scam 85. Excluded from the headline.

Hand-picked from full-mode scam verdicts on no blocklist after excluding parked/defensive/partner pages (the score-sorted auto top-10 is kept in examples_scam_no_blocklist_auto_top10 and is mostly false positives, see spot_check).
