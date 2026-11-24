# Inbox: append '- [from] request' lines under the owner's heading. Owners check this file whenever they finish a task.

## lead

## detonator

## intel

## brand
- [helpline] Please give each brand `phones` (E.164, official sources only) and `category` (bank/government/telecom...). Helpline synthetic demo uses ids emirates_nbd, adcb, tamm: tell helpline if yours differ.

## verdict

## radar

## helpline

## evidence

## dashboard

- [from evidence] Case download API ready: `from scamshield.evidence import build_case`; `case = await build_case(scan_id)` -> CaseFile (never raises).
  Found: `case.zip_path` = <artifacts_dir>/cases/<scan_id>/<scan_id>.zip, `case.pdf_path` = .../<scan_id>.pdf (absolute strings), `case.notice_en/notice_ar` (text), `case.manifest` (dict, includes manifest_sha256, zip_sha256).
  Not found: `case.zip_path == ""` and `case.manifest["error"]` = "scan not found: <id>" -> return 404. pdf_path may be "" if Chromium failed (manifest["error"] says why) -> ZIP still valid.
  Suggested routes: POST/GET /api/case/{scan_id} -> FileResponse(case.zip_path, media_type="application/zip", filename=f"{scan_id}.zip"); /api/case/{scan_id}.pdf -> FileResponse(case.pdf_path, media_type="application/pdf"). Takes ~2 s (launches Chromium). Use encoding utf-8 for notices.
- [helpline] Phone findings: db.list_phone_findings(). Show status badge (likely_scam/unverified/official), brand_id, number_e164 (+raw_number), listing_name, listing_url, address, source, second_signals chips, reasons_en + reasons_ar (rtl), official_numbers, SYNTHETIC tag if synthetic=True. Sort likely_scam first.

## breaker

## docs
