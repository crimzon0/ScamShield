# Radar drain report (2026-11-25T00:31:09Z)

- Total radar hits: **3436** (by source: {'certstream': 62, 'crtsh': 3312, 'search_organic': 59, 'nrd': 3})
- Scanned through `pipeline.scan_url`: **3418**
- Label distribution: {'unscanned': 18, 'legitimate': 358, 'scam': 388, 'suspicious': 2376, 'likely_scam': 296}
- Google Safe Browsing lookups available: True (fresh v4 lookup of domain, scanned host and final URL)

## Blocklist cross-check

| set | n | on our feeds | on Safe Browsing | on **no** blocklist |
|---|---|---|---|---|
| scam | 388 | 0 | 17 | **371** |
| likely_scam | 296 | 0 | 2 | **294** |

Headline (excluding organic search results, which are pages that mention a brand rather than look-alike registrations): {'scam': 384, 'scam_on_no_blocklist': 367, 'likely_scam': 292, 'likely_scam_on_no_blocklist': 290}

Search radar: 59 hits {'search_organic': 59}, labels {'suspicious': 17, 'legitimate': 34, 'scam': 4, 'likely_scam': 4}

## Lead time (flagged_at - first_seen), scam set

- first_seen basis: {'ct_log': 2, 'not_before': 381, 'observed (SerpApi has no publish time)': 4, 'not_before+1h(le_backdate)': 1} (not_before = certificate notBefore, an estimate; ct_log / nrd_list_date = measured)
- median, all scam: 69d20h (n=388)
- median, measured basis only: 0m (n=2)
- median, scam on no blocklist: 69d20h

Note: for not_before hits the lead time measures how long after certificate issuance *we* flagged the domain (backfill), i.e. it is an upper bound on our latency, not a head start over blocklists. The head-start claim is the 'on no blocklist' count at report time.

## Examples: scam verdicts on no blocklist (defanged)

| domain | brand | score | source | lead time | basis |
|---|---|---|---|---|---|
| adib[.]ae[.]portal[.]lunedata[.]io | adib | 100 | crtsh | 63d21h | not_before |
| aramex-5km[.]pages[.]dev | aramex | 100 | crtsh | 69d17h | not_before |
| aramex-asia[.]com | aramex | 100 | crtsh | 63d21h | not_before |
| aramex-china[.]cn | aramex | 100 | crtsh | 119d21h | not_before |
| aramex-eg-hqzme[.]icu | aramex | 100 | crtsh | 89d6h | not_before |
| aramex-express[.]com | aramex | 100 | crtsh | 61d8h | not_before |
| aramex-fast[.]com | aramex | 100 | crtsh | 60d7h | not_before |
| aramex-garne[.]de | aramex | 100 | crtsh | 58d12h | not_before |
| aramex-jo[.]com | aramex | 100 | crtsh | 81d6h | not_before |
| aramex-logistics[.]com | aramex | 100 | crtsh | 73d4h | not_before |
