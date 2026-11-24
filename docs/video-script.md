# ScamShield: 60-second demo video

Recorded from the real dashboard (`make demo` = `.venv/Scripts/python -m scamshield.api.demo`, http://127.0.0.1:8000). Screen capture at 1920x1080, voice-over recorded separately. Prepare before recording: run the radar backfill and the helpline check once so both tables have rows, and have one scam verdict already in *Recent scans* in case the live scan is slow.

Voice-over: 114 words.

| Time | Shot (what is on screen) | Voice-over |
|---|---|---|
| 0-6 s | Dashboard home, English. Cursor pastes a suspicious link into the scan box ("Paste a suspicious link (SMS, WhatsApp, ad)...") and clicks **Scan link**. Status: "Detonating in isolated browser...". | "A text says your traffic fine is unpaid. Is the link real? Paste it into ScamShield." |
| 6-18 s | Verdict card: big **Scam** label, risk-score gauge, "Why this verdict" list with weights. Zoom on the top reason (brand claimed on a non-official domain) and the Brand box: "Claims to be ...", "NOT an official domain". | "It opens the link in an isolated browser as a UAE phone user, sees which brand the page claims to be, and checks that brand's official domains. Not official: scam." |
| 18-26 s | Scroll: Screenshots tabs (UAE mobile / Desktop / Crawler), cloaking banner if present, then the Redirect chain hop by hop. | "Every redirect and shortener is followed, and each visitor type is compared to catch cloaking." |
| 26-32 s | Click the **العربية** toggle: whole UI flips to Arabic, right-to-left; reasons now in Arabic. | "Every reason is in Arabic and English." |
| 32-40 s | Click **Export police case file**, then **Evidence ZIP** and **Bilingual PDF report**. Show the PDF first page and the manifest with SHA-256 hashes. | "One click builds the police case file: screenshots, redirect chain, registration data, a takedown notice, all hashed." |
| 40-50 s | Nav: **Early-warning radar**. Table of newly seen look-alike domains with "First seen (UTC)", "Flagged (UTC)" and **Time to detection** column highlighted. | "The radar watches new certificates for UAE brand look-alikes and measures how fast we flag them." |
| 50-56 s | Nav: **Fake helplines**. Table with Likely scam / Official badges, number, second-signal chips (SYNTHETIC tag visible if no Places key). | "It also finds fake helpline numbers on Maps." |
| 56-60 s | Title card: "ScamShield AI", results line "Official UAE domains flagged: 0/112 · blind held-out: precision 1.000, recall 0.619, no blocklists", "42 Abu Dhabi x Abu Dhabi Police". | "Fewer victims, faster takedowns. ScamShield." |

## Notes for recording

- Use a real scam URL from the day's public feed only if it is still live and clearly a UAE brand; otherwise use the seeded demo scan. Do not enter anything into the scam page.
- If the helpline table shows the **SYNTHETIC** tag, keep it visible: it is labelled sample data, and the video must not claim it is live.
- The numbers on the title card must match README section 7 and slide 7 exactly.
- Word count check: the voice-over column is 114 words, about 50 s at a calm pace.
