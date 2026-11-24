# ScamShield: Abu Dhabi Police pilot plan

This is a proposal from a student team. Channel names and numbers below come from public sources (listed at the end) and should be confirmed with Abu Dhabi Police (ADP) before any integration work starts.

## Goal

Cut the time between a UAE brand-impersonation site going live and the moment it is blocked or taken down. Do this without adding false alarms about real banks and government services, and give analysts evidence they can send to a registrar or host the same day.

## What exists today (hackathon build)

- Scan any URL through an isolated headless browser, with a 0-100 score and English/Arabic reasons. Works when the page is dead (domain-only verdict).
- Registry of 31 UAE brands (banks, TAMM, UAE PASS, police, RTA, Salik, ICP, telecoms, couriers) with official domains and numbers, plus source links. Not yet checked by a human (`verified: false`).
- Early-warning radar on Certificate Transparency (crt.sh) with time-to-detection per hit.
- Fake-helpline checker (Google Places, search snippets), synthetic mode without a key.
- Case file export: ZIP + bilingual PDF + English/Arabic takedown notice drafts + SHA-256 manifest. **Notices are drafts; nothing is sent automatically.**

## Phase 0: sandbox on public data (4-6 weeks)

**Scope:** no citizen data, no ADP systems. Runs on one VM inside an ADP-approved network segment, or at 42 Abu Dhabi under supervision.

- Inputs: Certificate Transparency (certstream + crt.sh), public phishing feeds, newly registered domain lists, search ads/organic results for UAE brand queries (SerpApi), Google Maps listings for brand helplines.
- ADP and the brands review the registry: every official domain and number is confirmed and `verified` set to true. This is the most important step for avoiding false positives.
- Daily report to a named ADP contact: new look-alike domains, verdicts, time to detection.
- Measure the baseline: how many UAE-brand phishing domains appear per week, and how early we see them compared with when they reach public feeds.

**Exit criteria:** 0 false positives on the confirmed official-domain list; median time to detection under 24 h for CT-visible domains; analysts agree the reasons are understandable in Arabic and English.

## Phase 1: analyst in the loop (3 months)

**Scope:** ADP cybercrime analysts use the dashboard every day. ScamShield proposes; a person decides.

Workflow per flagged domain:

1. Radar or a reported link produces a scan. Analyst opens the verdict card (score, reasons, screenshots per persona, redirect chain, domain age, hosting).
2. Analyst confirms or rejects. Each decision is stored as a label, which is used to re-tune the weights.
3. On confirm, the analyst exports the case file and sends the pre-drafted notice (EN/AR) through ADP's own mail system to:
   - the **registrar** abuse contact (from RDAP),
   - the **hosting provider / platform** abuse contact (for shared platforms such as free web hosts, their trust & safety team),
   - for `.ae` / `.امارات` domains, the **.ae domain administration (aeDA, part of TDRA)**,
   - the **impersonated brand's** security team,
   - browser blocklists (Google Safe Browsing, Microsoft SmartScreen) and the national CERT (aeCERT) as ADP policy allows.
4. The system re-scans the domain every few hours and records when it goes offline, giving **time to takedown**.
5. Fake helplines: confirmed listings are reported to Google Maps through its report channel and to the telecom provider for the number.

**Exit criteria:** analysts accept at least 90% of `scam` verdicts as correct; median time to takedown measured and falling; no official UAE domain ever labelled scam.

## Phase 2: integration with reporting channels (6+ months)

- Links that citizens report to ADP through its existing channels (the **Aman** service, toll-free 8002626 per public ADP announcements, the ADP smart app) and the federal **eCrime reporting platform** listed on u.ae are scanned automatically, so an analyst sees a verdict and a case file next to the report.
- API for the Aman/eCrime back-office: `POST /api/scan` and `POST /api/batch` already exist; add authentication, audit log, and a queue.
- Network view: domains that share an IP, name server, certificate or favicon hash are grouped into one campaign (`radar.siblings`), so one takedown request can cover a whole cluster.
- Public warnings: confirmed campaigns can feed ADP awareness posts (in Arabic and English) about the brand being impersonated.

## Data handling

- **Phase 0 holds no personal data.** Only domains, URLs, page screenshots and public registration data.
- From Phase 1 a reported URL can contain personal data (a victim's name in a query string, a tracking token). URLs are stored inside ADP infrastructure only; no third-party API receives citizen-reported URLs unless ADP approves that provider (urlscan, Safe Browsing and LLM keys stay off by default for reported URLs).
- LLM use is optional. If enabled, use a provider and region ADP approves, or a locally hosted model. Page text is wrapped and treated as data, never as instructions.
- Evidence integrity: every file in a case has a SHA-256 hash in the manifest; manifest and ZIP are hashed too; all timestamps UTC. Store case files on write-once storage for chain of custody.
- Retention: follow ADP policy; suggested default 12 months for scans, longer for cases referred to prosecution.
- Comply with UAE Federal Decree-Law No. 45 of 2021 on personal data protection where it applies, and with ADP's own information security rules.
- Passive collection only: the detonator visits a page the way a victim would, with downloads disabled, and never submits forms.

## KPIs

| KPI | Definition | Phase 0 target | Phase 1 target |
|---|---|---|---|
| Time to detection | `flagged_at - first_seen` (cert notBefore or registration date), median | < 24 h | < 6 h |
| False positives on official domains | official registry domains labelled `likely_scam` or `scam` | 0 | 0 |
| Analyst precision | share of `scam` verdicts confirmed by analysts | measured | >= 90% |
| Coverage | share of UAE-brand phishing domains in public feeds that the radar saw first | measured | rising |
| Time to takedown | confirm -> domain offline / suspended, median | n/a | measured, then falling |
| Helpline findings | fake numbers confirmed and removed from Maps | n/a | measured |

## What we need

| Item | Why | Estimate |
|---|---|---|
| ADP sponsor + 1-2 analysts (part time) | review registry, confirm verdicts, send notices | in kind |
| Brand contacts (banks, TAMM, UAE PASS, RTA, Salik) | confirm official domains and numbers | in kind |
| 1 VM: 4 vCPU, 16 GB RAM, 200 GB disk, outbound internet | headless browsers, SQLite/Postgres, certstream | ~USD 100-200 / month on a commercial cloud; or ADP infra |
| Google Places API key | helpline checker | pay per request; within Google's free monthly credit at pilot volume is plausible but must be checked |
| SerpApi (or equivalent) | ads / search radar | ~USD 75-150 / month (plan dependent) |
| LLM API (optional) | brand claim and intent reading | ~USD 50-200 / month at pilot volume, or a local model |
| urlscan / Safe Browsing keys (optional) | extra reputation | free tiers |
| Legal | data-processing approval, authority to send takedown requests in ADP's name, agreement with TDRA/aeDA on a fast path | ADP legal |
| Team time | 2 students part-time for maintenance during Phase 0-1 | in kind / internship |

Costs are rough estimates from public list prices and must be confirmed.

## Risks

- **False positive on a real brand:** mitigated by the official-first rule and the human-verified registry; analysts confirm before any notice is sent.
- **Cloaking by geography or IP:** add a UAE residential/mobile egress for the detonator in Phase 1.
- **Scam sites target the scanner:** detonation runs in a disposable container with downloads off and no credentials on the host.
- **API dependency:** every external source has a fallback; the core (detonation, registry, scoring, CT radar) needs no paid key.

## Sources for channel names

- u.ae, "Report cybercrimes online": https://u.ae/en/information-and-services/justice-safety-and-the-law/cyber-safety-and-digital-security/report-cybercrimes-online (lists the MoI eCrime platform, Dubai Police eCrime and Abu Dhabi Police Aman).
- WAM / Gulf News reports of Abu Dhabi Police asking the public to report fraud through Aman on 8002626 (e.g. https://gulfnews.com/uae/crime/abu-dhabi-police-warn-public-about-fake-links-in-search-engines-1.500566188).
