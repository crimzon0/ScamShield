---
marp: true
theme: default
paginate: true
title: ScamShield AI
---

# ScamShield AI
### Catch UAE brand-impersonation scams early, explain them in Arabic and English, hand the police the evidence

42 Abu Dhabi x Abu Dhabi Police hackathon
Five final-year cybersecurity students

**The problem:** fake bank logins, fake TAMM / UAE PASS sign-ins, "unpaid fine" and Salik pages, fake helplines on Google Maps. They arrive by SMS, WhatsApp, ads and sponsored search results, and most are offline within days.

<!--
Speaker notes: Scammers in the UAE copy brands people trust. Abu Dhabi Police already warns about fake links in search engines and fake ads. The hard part is speed and trust: the site is gone in days, and a tool that flags the real bank once is a tool nobody uses.
-->

---

# The solution: one pipeline, three surfaces

| Surface | Finds |
|---|---|
| **Impersonation engine** | any link: which UAE brand it claims to be, and whether it is that brand's official domain |
| **Early-warning radar** | new certificates and domains with UAE brand look-alikes, before victims report them |
| **Helpline checker** | fake customer-service numbers on Maps and in search |

All three feed the same scan pipeline, the same 0-100 score, the same bilingual reasons and the same police case file.

<!--
Speaker notes: We did not build three tools. Every radar hit and every helpline listing's website goes through the same scan_url. One scoring engine, one evidence format.
-->

---

# How it works

```
link -> detonate (headless Chromium, 3 personas: UAE mobile ad click, desktop, crawler)
     -> follow shorteners + HTTP/meta/JS redirects -> final registrable domain
     -> enrich: RDAP age, registrar, hosting, first certificate, feeds
     -> match_brand (EN/AR/Arabizi text, forms, favicon/screenshot hash, optional LLM)
        + lookalike (typosquat, homoglyph, punycode, brand+keyword)
     -> cloak_diff across personas -> score -> case file
```

- **Brand claimed on a non-official domain = scam.** Official domain = legitimate, checked first.
- **Shared hosts never inherit trust** (`foo.vercel.app` is judged on its own).
- **An error is never a verdict:** dead, blank or cloaked page -> domain-only verdict.

<!--
Speaker notes: The core rule is simple and explainable: the page says "Emirates NBD", but the domain is not Emirates NBD's. The registry has 31 real UAE brands, 112 official domains and 59 official numbers, each with a source link. Most feed URLs are dead within hours, so the domain-only path is the normal case.
-->

---

# Early-warning radar

- Watches Certificate Transparency (certstream live, crt.sh backfill) and newly registered domain lists for UAE brand terms and look-alikes: `uaepass`, `tamm-`, `rta-fine`, `salik`, `adpolice`, homoglyphs, punycode
- Every hit is scanned by the same pipeline
- **Time to detection** = flagged time - certificate first-seen, shown per hit on the dashboard

**Real hits, 2026-11-24 (one evening, no API keys):**
- certstream live: `salik[.]work` (TLD swap of salik.ae) flagged in the same hour its certificate was issued
- newly registered domains: `adinwealth[.]org` (look-alike of ADIB's adibwealth.ae) **scam 87**; `trafficrta[.]xyz` **likely scam 70** (4 d 20 h / 2 d 20 h after the list date, mostly because we started watching that day)
- 820+ radar hits in one evening, 71+ scam / likely scam; related domains grouped into networks
- caveat: some `uaepass` hits are real third-party UAE PASS integrations -> analyst review

<!--
Speaker notes: A phishing site needs an HTTPS certificate, and certificates are public. That gives us a window between certificate issue and the first SMS. We record both timestamps, so time to detection is measured, not claimed. Honest note: certificate notBefore is often backdated (Let's Encrypt by one hour), so a ~59-minute reading from certstream really means minutes. Backfill hits are weeks old only because we started watching today.
-->

---

# Explainability and police evidence

- Score 0-100 + label (scam / likely scam / suspicious / legitimate)
- Every reason: **weight + English + Arabic + the evidence it came from**
- Screenshots per persona, full redirect chain, domain age, hosting
- **One click: case file** = ZIP (screenshots, DOM, HAR, redirect chain, RDAP/WHOIS, verdict JSON) + bilingual PDF + EN/AR takedown notice drafts for registrar and host
- **SHA-256 manifest** of every file; UTC ISO 8601 timestamps

<!--
Speaker notes: An analyst should be able to read why, in their own language, and send a takedown the same day. The notices are drafts: the system never sends anything by itself. The hashes let the evidence stand up later.
-->

---

# Built for the UAE

- Registry: Emirates NBD, FAB, ADCB, Mashreq, ADIB, DIB, RAKBANK, CBD, Wio, Liv, CBUAE, **TAMM, UAE PASS**, Abu Dhabi Police, Dubai Police, **RTA, Salik**, ICP, MOI, MOHRE, DEWA, Emirates Post, e&, du, Aramex, Emirates, Etihad ...
- Arabic, English and Arabizi brand keywords; Arabic phishing phrases ("تم إيقاف حسابك", "مخالفة غير مدفوعة")
- Persona = UAE mobile user from a Google ad (`ar-AE`, Asia/Dubai)
- Phone numbers: Arabic-Indic digits, 800/600, 05x mobiles, wa.me -> E.164
- Full Arabic dashboard (RTL), Arabic PDF and takedown notice

<!--
Speaker notes: Fines, tolls, government sign-in and bank OTP pages are the UAE scam themes. We only list official domains and numbers we could confirm from an official source; the rest is in a to-do file, not guessed.
-->

---

# Results (measured)

<!-- RT:BEGIN -->
| Held-out set (n=79) | Precision | Recall | FPR |
|---|---|---|---|
| **First blind run, blocklists ignored (headline)** | **1.000** | **0.619** | **0.000** |
| First blind run, blocklists ignored, >= suspicious | 1.000 | 0.786 | 0.000 |
| After one round of generalisation (not blind) | 1.000 | 0.714 | 0.000 |
| Blocklists used | 1.000 | 1.000 | 0.000 |

- **Official UAE domains flagged as scam: 0 / 112** · zero false positives in every run
- Adversarial: **45/45** UAE official deep links and **42/42** risky-looking real UAE login pages legitimate; 92 offline attack cases pass
- Tuned sample (n=127), blocklists ignored: precision 1.000, recall 0.797
<!-- RT:END -->

Caveats: small sets (79 held-out, 127 tuned); scam URLs come from the same public feeds our blocklist uses, so the headline ignores blocklists; feed labels not hand-verified.

<!--
Speaker notes: Numbers come from `make eval` on data/eval/holdout.csv and sample.csv, latest run 2026-11-24 20:43 UTC (engine fingerprint db475dd39c6eb6a5). The official-domain sweep scans the home page of every official domain in the registry; the target is zero false positives there. The headline is the first blind held-out run (20:18 UTC, recall 0.619). We then broadened the global-brand list with those misses in mind, so the "after generalisation" row is not blind and we say so.
-->

---

# Pilot path and our ask

1. **Phase 0 - sandbox (4-6 weeks):** public feeds + CT only, ADP and brands verify the registry. Exit: 0 FP on official domains, median detection < 24 h.
2. **Phase 1 - analyst in the loop (3 months):** analysts confirm; case files and notices to registrars, hosts, aeDA/TDRA. Measure time to takedown.
3. **Phase 2 - integration:** links reported through Aman / the eCrime platform scanned automatically; campaign grouping.

**Ask:** an ADP sponsor and analyst time, brand contacts to verify official domains, one VM, API keys (Places, search), legal approval to send takedown requests.

<!--
Speaker notes: Phase 0 needs no citizen data and almost no cost. KPIs: time to detection, false positives on official domains, analyst precision, time to takedown. Details in docs/pilot.md.
-->
