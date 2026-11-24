"""Live sources: Google Places API (New) Text Search, SerpApi snippets. Timeouts, SQLite cache, rate limit.
Every function returns None/[] on failure and never raises."""
from __future__ import annotations

import asyncio
import hashlib
import json
import time

import httpx

from scamshield.core import db
from scamshield.core.config import settings

PLACES_URL = "https://places.googleapis.com/v1/places:searchText"
PLACES_FIELDS = ",".join("places." + f for f in (
    "id", "displayName", "formattedAddress", "internationalPhoneNumber", "nationalPhoneNumber",
    "websiteUri", "userRatingCount", "googleMapsUri"))
SERPAPI_URL = "https://serpapi.com/search.json"

# (name_en, name_ar, lat, lng)
CITIES = [
    ("Abu Dhabi", "أبوظبي", 24.4539, 54.3773),
    ("Dubai", "دبي", 25.2048, 55.2708),
    ("Sharjah", "الشارقة", 25.3463, 55.4209),
    ("Al Ain", "العين", 24.2075, 55.7447),
    ("Ajman", "عجمان", 25.4052, 55.5136),
    ("Ras Al Khaimah", "رأس الخيمة", 25.8007, 55.9762),
]

_sem = asyncio.Semaphore(2)
_last_call = 0.0
MIN_INTERVAL = 0.3  # seconds between outbound calls (polite rate limit)


async def _throttle() -> None:
    global _last_call
    wait = _last_call + MIN_INTERVAL - time.monotonic()
    if wait > 0:
        await asyncio.sleep(wait)
    _last_call = time.monotonic()


def _key(prefix: str, payload: dict) -> str:
    return prefix + ":" + hashlib.sha1(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def place_queries(brand: dict) -> list[dict]:
    """EN + AR queries across UAE cities. Each: {text, lang, city, lat, lng}."""
    en, ar = brand.get("name_en", ""), brand.get("name_ar", "")
    qs: list[dict] = []
    for c_en, c_ar, lat, lng in CITIES:
        if en:
            qs.append({"text": f"{en} customer service {c_en}", "lang": "en", "city": c_en, "lat": lat, "lng": lng})
        if ar:
            qs.append({"text": f"{ar} خدمة العملاء {c_ar}", "lang": "ar", "city": c_en, "lat": lat, "lng": lng})
    dubai = CITIES[1]
    if en:
        qs.append({"text": f"{en} call center Dubai", "lang": "en", "city": "Dubai", "lat": dubai[2], "lng": dubai[3]})
    if ar:
        qs.append({"text": f"رقم {ar}", "lang": "ar", "city": "", "lat": 24.4, "lng": 54.6, "radius": 50000.0})
    return qs


async def places_search(q: dict) -> list[dict] | None:
    """One Text Search call -> normalised listings, or None if unavailable."""
    if not settings.google_places_key or settings.offline:
        return None
    body = {
        "textQuery": q["text"], "languageCode": q["lang"], "regionCode": "AE",
        "locationBias": {"circle": {"center": {"latitude": q["lat"], "longitude": q["lng"]},
                                    "radius": float(q.get("radius", 30000.0))}},
    }

    async def fetch():
        async with _sem:
            await _throttle()
            try:
                async with httpx.AsyncClient(timeout=settings.http_timeout) as cl:
                    r = await cl.post(PLACES_URL, json=body, headers={
                        "X-Goog-Api-Key": settings.google_places_key, "X-Goog-FieldMask": PLACES_FIELDS})
                if r.status_code != 200:
                    return None
                return r.json().get("places", [])
            except Exception:
                return None

    raw = await db.acached(_key("helpline:places", body), fetch)
    if raw is None:
        return None
    out = []
    for p in raw:
        out.append({
            "source": "places", "query": q["text"], "place_id": p.get("id", ""),
            "name": (p.get("displayName") or {}).get("text", ""),
            "address": p.get("formattedAddress", ""),
            "phone_intl": p.get("internationalPhoneNumber", ""), "phone": p.get("nationalPhoneNumber", ""),
            "url": p.get("websiteUri", ""), "maps_url": p.get("googleMapsUri", ""),
            "rating_count": p.get("userRatingCount", 0) or 0,
        })
    return out


async def serp_snippets(brand: dict) -> list[dict] | None:
    """SerpApi Google results (organic + local) for helpline queries. None if no key/unavailable."""
    if not settings.serpapi_key or settings.offline:
        return None
    queries = []
    if brand.get("name_en"):
        queries.append((f"{brand['name_en']} customer service number UAE", "en"))
    if brand.get("name_ar"):
        queries.append((f"رقم خدمة عملاء {brand['name_ar']}", "ar"))
    out: list[dict] = []
    any_ok = False
    for text, hl in queries:
        params = {"engine": "google", "q": text, "gl": "ae", "hl": hl, "num": 10}

        async def fetch(params=params):
            async with _sem:
                await _throttle()
                try:
                    async with httpx.AsyncClient(timeout=settings.http_timeout) as cl:
                        r = await cl.get(SERPAPI_URL, params={**params, "api_key": settings.serpapi_key})
                    return r.json() if r.status_code == 200 else None
                except Exception:
                    return None

        data = await db.acached(_key("helpline:serp", params), fetch)
        if not data:
            continue
        any_ok = True
        for res in data.get("organic_results", []) or []:
            out.append({"source": "snippet", "query": text, "name": res.get("title", ""),
                        "url": res.get("link", ""), "text": (res.get("title", "") + "\n" + res.get("snippet", ""))})
        for res in (data.get("local_results") or {}).get("places", []) if isinstance(data.get("local_results"), dict) else []:
            out.append({"source": "snippet", "query": text, "name": res.get("title", ""), "phone": res.get("phone", ""),
                        "url": (res.get("links") or {}).get("website", ""), "address": res.get("address", ""),
                        "rating_count": res.get("reviews")})
    return out if any_ok else None
