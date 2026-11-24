"""Owner: helpline. Fake-helpline detection (Google Maps listings, search snippets, landing pages).

check_brand(brand_id, live=None): live if a Google Places key is configured (and not offline), else clearly
labelled synthetic samples from data/helpline/synthetic_listings.json. Findings are saved with
core.db.save_phone_finding and shown by the dashboard via core.db.list_phone_findings.
Public functions never raise.
"""
from __future__ import annotations

import json
import logging

from scamshield.core import db
from scamshield.core.config import DATA_DIR, settings
from scamshield.core.domains import is_official, registrable
from scamshield.core.schemas import Detonation, PhoneFinding

from .classify import claims_brand, findings_from_listing, malformed_phones, official_numbers  # noqa: F401
from .phones import extract, normalize  # noqa: F401  (public: normalize)

log = logging.getLogger(__name__)
SYNTHETIC_PATH = DATA_DIR / "helpline" / "synthetic_listings.json"
MAX_LANDING_SCANS = 5

# Last run status per source, e.g. {"places": "ok" | "no_key" | "unavailable" | "offline", ...}
last_sources: dict[str, str] = {}

__all__ = ["check_brand", "check_all", "phones_on_page", "normalize", "extract", "last_sources", "PhoneFinding"]


def _registry() -> list[dict]:
    try:
        from scamshield.brand import load_registry

        return load_registry() or []
    except Exception:
        return []


def _synthetic() -> dict:
    try:
        return json.loads(SYNTHETIC_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"fallback_brands": {}, "listings": []}


def _brand(brand_id: str, synthetic_ok: bool) -> dict | None:
    b = next((x for x in _registry() if x.get("id") == brand_id), None)
    if b is None and synthetic_ok:
        b = _synthetic().get("fallback_brands", {}).get(brand_id)
    return b


def _live_available() -> bool:
    return bool(settings.google_places_key) and not settings.offline


def _mark_synthetic(listing: dict) -> dict:
    l = dict(listing, synthetic=True)
    if not l.get("name", "").startswith("[SYNTHETIC]"):
        l["name"] = "[SYNTHETIC] " + l.get("name", "")
    return l


async def _scan_landing(url: str) -> tuple[str | None, str]:
    """Run the shared pipeline on a listing website. Returns (label, visible_text)."""
    try:
        from scamshield.pipeline import scan_url

        res = await scan_url(url)
        text = "\n".join(d.visible_text for d in res.detonations if d.visible_text)
        return res.verdict.label, text
    except Exception as e:  # pragma: no cover
        log.warning("landing scan failed for %s: %s", url, e)
        return None, ""


async def _live_listings(brand: dict, scan_landing: bool) -> list[dict]:
    from .sources import place_queries, places_search, serp_snippets

    listings: list[dict] = []
    seen: set[str] = set()
    ok = fail = 0
    for q in place_queries(brand):
        res = await places_search(q)
        if res is None:
            fail += 1
            continue
        ok += 1
        for l in res:
            k = l.get("place_id") or (l["name"] + l.get("phone", ""))
            if k not in seen:
                seen.add(k)
                listings.append(l)
    last_sources["places"] = "ok" if ok else "unavailable"

    if settings.serpapi_key:
        snips = await serp_snippets(brand)
        last_sources["serpapi"] = "ok" if snips is not None else "unavailable"
        listings += snips or []
    else:
        last_sources["serpapi"] = "no_key"

    if scan_landing:
        domains = brand.get("official_domains", []) or []
        scanned: dict[str, tuple] = {}
        for l in listings:
            site = l.get("url") or ""
            if not site.startswith("http") or is_official(site, domains) or "wa.me" in site or "whatsapp.com" in site:
                continue
            if not claims_brand(l.get("name", "") + " " + l.get("text", ""), brand):
                continue
            reg = registrable(site)
            if reg not in scanned:
                if len(scanned) >= MAX_LANDING_SCANS:
                    continue
                scanned[reg] = await _scan_landing(site)
                label, text = scanned[reg]
                if text:
                    listings.append({"source": "landing", "query": f"landing page of {reg}", "url": site,
                                     "name": f"Landing page: {reg}", "text": text, "landing_label": label})
            l["landing_label"] = scanned[reg][0]
        last_sources["landing"] = f"scanned {len(scanned)}"
    return listings


async def check_brand(brand_id: str, live: bool | None = None, scan_landing: bool = True,
                      save: bool = True) -> list[PhoneFinding]:
    """Find helpline numbers advertised for a brand and classify them (official / unverified / likely_scam).
    live=None -> live if GOOGLE_PLACES_API_KEY is set (and not offline), else synthetic samples.
    live=True without a key -> sources['places']='no_key' and falls back to synthetic. Never raises."""
    try:
        last_sources.clear()
        use_live = _live_available() if live is None else bool(live)
        if use_live and not _live_available():
            last_sources["places"] = "offline" if settings.offline else "no_key"
            use_live = False
        brand = _brand(brand_id, synthetic_ok=not use_live)
        if brand is None:
            last_sources["registry"] = "unknown_brand"
            return []
        if malformed_phones(brand):
            last_sources["registry"] = "malformed_phones: " + ", ".join(malformed_phones(brand))
        if use_live:
            listings = await _live_listings(brand, scan_landing)
        else:
            last_sources.setdefault("places", "no_key" if not settings.google_places_key else "skipped")
            last_sources["synthetic"] = "ok"
            listings = [_mark_synthetic(l) for l in _synthetic().get("listings", []) if l.get("brand_id") == brand_id]
        findings: list[PhoneFinding] = []
        seen: set[tuple] = set()
        for l in listings:
            for f in findings_from_listing(l, brand):
                k = (f.number_e164, f.listing_name, f.source)
                if k in seen:
                    continue
                seen.add(k)
                findings.append(f)
                if save:
                    try:
                        db.save_phone_finding(f)
                    except Exception as e:  # pragma: no cover
                        log.warning("save_phone_finding failed: %s", e)
        order = {"likely_scam": 0, "unverified": 1, "official": 2}
        findings.sort(key=lambda f: order[f.status])
        return findings
    except Exception as e:  # never raise
        log.warning("check_brand(%s) failed: %s", brand_id, e)
        last_sources["error"] = str(e)[:200]
        return []


async def check_all(live: bool | None = None, scan_landing: bool = True, save: bool = True) -> list[PhoneFinding]:
    """check_brand for every registry brand (plus synthetic-only demo brands in synthetic mode)."""
    use_live = _live_available() if live is None else (bool(live) and _live_available())
    ids = [b.get("id") for b in _registry() if b.get("id")]
    if not use_live:
        ids += [i for i in _synthetic().get("fallback_brands", {}) if i not in ids]
    out: list[PhoneFinding] = []
    for i in ids:
        out += await check_brand(i, live=use_live, scan_landing=scan_landing, save=save)
    return out


def phones_on_page(det: Detonation, brand_id: str | None, label: str | None = None,
                   save: bool = False) -> list[PhoneFinding]:
    """Numbers shown on a detonated page (visible_text, title, form labels/placeholders), classified against
    the claimed brand's official numbers. source="landing", synthetic=False. Pass the page's verdict label
    (scam/likely_scam) as `label` if already known; it adds the landing_page_scam signal. Not saved unless
    save=True. Never raises; returns [] if no brand or no numbers."""
    try:
        if not brand_id or det is None:
            return []
        brand = _brand(brand_id, synthetic_ok=False)
        if brand is None:
            return []
        url = det.final_url or det.url
        parts = [det.title or "", det.visible_text or ""]
        parts += [" ".join(x for x in (f.label, f.placeholder) if x) for f in det.form_fields]
        listing = {"source": "landing", "query": f"detonation of {url}", "url": url,
                   "name": f"Landing page: {registrable(url) if url else ''}", "text": "\n".join(parts),
                   "landing_label": label}
        found = findings_from_listing(listing, brand)
        # The page itself was detonated as this brand's claimed page, so keep findings even if the
        # text does not repeat the brand name (relevance filter is for Maps noise, not pages).
        if not found:
            from .phones import extract as _extract
            from .classify import classify as _classify
            nums = _extract(url + "\n" + listing["text"])
            found = [_classify(dict(listing, force_named=True), brand, raw, e) for raw, e in nums]
        if save:
            for f in found:
                try:
                    db.save_phone_finding(f)
                except Exception as e:  # pragma: no cover
                    log.warning("save_phone_finding failed: %s", e)
        return found
    except Exception as e:
        log.warning("phones_on_page failed: %s", e)
        return []
