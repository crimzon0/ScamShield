"""Listing -> PhoneFinding status logic.

Rules (never flag on one weak signal):
  number in brand's official list           -> "official"
  not in list, no second signal             -> "unverified"
  not in list AND >=1 second signal         -> "likely_scam"
Second signals: brand-named listing on a non-official website, mobile number for an institution helpline,
new listing / very few reviews (brand-named only), landing page scored scam by the pipeline, WhatsApp-only.
"""
from __future__ import annotations

import re
from typing import Any

from scamshield.core.domains import is_official, registrable
from scamshield.core.schemas import PhoneFinding

from .phones import ascii_digits, extract, is_mobile, normalize, whatsapp_numbers

# Categories whose public helplines are landline / 800 / 600 numbers, never personal mobiles.
INSTITUTION_CATEGORIES = {
    "bank", "government", "gov", "police", "telecom", "utility", "exchange", "payments", "payment",
    "fintech", "insurance", "regulator", "fuel", "islamic_bank", "airline", "courier", "delivery", "postal", "health",
}
FEW_REVIEWS = 3

SIGNAL_TEXT = {
    "brand_name_unofficial_website": (
        "Listing uses the brand name but links to a website that is not an official {brand} domain ({site}).",
        "يستخدم الإعلان اسم {brand_ar} لكنه يرتبط بموقع ليس من النطاقات الرسمية ({site}).",
    ),
    "mobile_number_for_institution": (
        "A personal mobile number (05x) is presented as an official {brand} helpline; institutions use landline/800/600 numbers.",
        "رقم هاتف متحرك شخصي (05x) معروض كخط مساعدة رسمي لـ{brand_ar}؛ المؤسسات تستخدم أرقاماً أرضية أو 800/600.",
    ),
    "new_listing_few_reviews": (
        "The listing is new or has very few reviews ({reviews}).",
        "الإعلان جديد أو لديه عدد قليل جداً من التقييمات ({reviews}).",
    ),
    "landing_page_scam": (
        "The listing's website was scanned by ScamShield and scored {label}.",
        "تم فحص موقع الإعلان بواسطة درع الاحتيال وصُنّف: {label_ar}.",
    ),
    "whatsapp_only": (
        "Contact is offered via WhatsApp only, a common pattern for fake helplines.",
        "يتم عرض التواصل عبر واتساب فقط، وهو نمط شائع في خطوط المساعدة المزيفة.",
    ),
}
LABEL_AR = {"scam": "احتيال", "likely_scam": "احتيال محتمل", "suspicious": "مشبوه", "legitimate": "سليم"}

_AR_NORM = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ة": "ه", "ى": "ي", "ـ": None})
_TASHKEEL = re.compile(r"[ً-ْٰ]")


def _norm(s: str) -> str:
    s = _TASHKEEL.sub("", (s or "").lower()).translate(_AR_NORM)
    return re.sub(r"[\s\-_.]+", " ", s).strip()


def brand_terms(brand: dict) -> list[str]:
    terms = [brand.get("name_en", ""), brand.get("name_ar", "")]
    terms += brand.get("keywords_en", []) or []
    terms += brand.get("keywords_ar", []) or []
    terms += brand.get("arabizi", []) or []
    return [t for t in {_norm(t) for t in terms} if len(t) >= 3]


def claims_brand(text: str, brand: dict) -> bool:
    n = _norm(text)
    squashed = n.replace(" ", "")
    return any(t in n or t.replace(" ", "") in squashed for t in brand_terms(brand))


def official_numbers(brand: dict) -> list[str]:
    out = []
    for p in brand.get("phones", []) or []:
        e = normalize(str(p))
        if e and e not in out:
            out.append(e)
    return out


def short_codes(brand: dict) -> list[str]:
    """Official short codes (999, 901, 171...). Not E.164; compared on ASCII digits."""
    return [re.sub(r"\D", "", ascii_digits(str(s))) for s in (brand.get("short_codes", []) or []) if str(s).strip()]


def short_code_of(raw: str, brand: dict) -> str:
    d = re.sub(r"\D", "", ascii_digits(raw or ""))
    return d if d and d in short_codes(brand) else ""


def malformed_phones(brand: dict) -> list[str]:
    return [str(p) for p in (brand.get("phones", []) or []) if not normalize(str(p))]


def classify(listing: dict[str, Any], brand: dict, raw_number: str, number_e164: str) -> PhoneFinding:
    """listing keys: query, source, name, url (website), maps_url, address, rating_count, whatsapp_only,
    landing_label, synthetic."""
    official = official_numbers(brand) + short_codes(brand)
    domains = brand.get("official_domains", []) or []
    name = listing.get("name", "") or ""
    site = listing.get("url", "") or ""
    named = (bool(listing.get("force_named")) or claims_brand(name, brand)
             or claims_brand(listing.get("text", "") or "", brand))
    brand_en = brand.get("name_en") or brand.get("id", "")
    brand_ar = brand.get("name_ar") or brand_en

    signals: list[str] = []
    fmt: dict[str, Any] = {"brand": brand_en, "brand_ar": brand_ar, "site": registrable(site) if site else ""}
    if number_e164 in official:
        status = "official"
        kind = "short code" if not number_e164.startswith("+") else "number"
        en = [f"Number {number_e164} matches an official {brand_en} {kind} in the registry."]
        ar = [f"الرقم {number_e164} يطابق رقماً رسمياً لـ{brand_ar} في السجل."]
    else:
        if named and site and not is_official(site, domains) and not whatsapp_numbers(site):
            signals.append("brand_name_unofficial_website")
        if is_mobile(number_e164) and str(brand.get("category", "")).lower() in INSTITUTION_CATEGORIES:
            signals.append("mobile_number_for_institution")
        rc = listing.get("rating_count")
        if named and (listing.get("new_listing") or (rc is not None and int(rc) <= FEW_REVIEWS)):
            signals.append("new_listing_few_reviews")
            fmt["reviews"] = rc if rc is not None else 0
        label = listing.get("landing_label")
        if label in ("scam", "likely_scam"):
            signals.append("landing_page_scam")
            fmt["label"], fmt["label_ar"] = label, LABEL_AR.get(label, label)
        if listing.get("whatsapp_only") or (site and whatsapp_numbers(site)):
            signals.append("whatsapp_only")
        status = "likely_scam" if signals else "unverified"
        off = ", ".join(official) or "none on file"
        off_ar = ", ".join(official) or "لا يوجد"
        en = [f"Number {number_e164} is not in the official {brand_en} registry (official: {off})."]
        ar = [f"الرقم {number_e164} غير موجود في السجل الرسمي لـ{brand_ar} (الأرقام الرسمية: {off_ar})."]
        for s in signals:
            e_t, a_t = SIGNAL_TEXT[s]
            en.append(e_t.format(**fmt))
            ar.append(a_t.format(**fmt))
        if status == "unverified":
            en.append("No second warning sign: treat as unverified, not as a scam.")
            ar.append("لا توجد علامة تحذير ثانية: يُعامل كرقم غير موثّق وليس احتيالاً.")
        else:
            en.append(f"Do not call this number. Use the official {brand_en} number.")
            ar.append(f"لا تتصل بهذا الرقم. استخدم الرقم الرسمي لـ{brand_ar}.")
    if listing.get("synthetic"):
        en.insert(0, "[SYNTHETIC SAMPLE - not real data]")
        ar.insert(0, "[عينة تجريبية - ليست بيانات حقيقية]")

    return PhoneFinding(
        brand_id=brand.get("id", ""), query=listing.get("query", ""), source=listing.get("source", "places"),
        listing_name=name, listing_url=listing.get("maps_url") or site, address=listing.get("address", ""),
        raw_number=raw_number, number_e164=number_e164, official_numbers=official, status=status,
        second_signals=signals, reasons_en=" ".join(en), reasons_ar=" ".join(ar),
        synthetic=bool(listing.get("synthetic")),
    )


def findings_from_listing(listing: dict[str, Any], brand: dict) -> list[PhoneFinding]:
    """Extract every number from a listing (phone fields, wa.me website, free text) and classify each.
    Listings that neither claim the brand nor use an official site/number are skipped (noise)."""
    nums: list[tuple[str, str]] = []
    for key in ("phone", "phone_intl"):
        raw = listing.get(key) or ""
        e = normalize(raw) or short_code_of(raw, brand)
        if e and e not in [x[1] for x in nums]:
            nums.append((raw, e))
    for raw, e in extract((listing.get("url") or "") + "\n" + (listing.get("text") or "")):
        if e not in [x[1] for x in nums]:
            nums.append((raw, e))
    if not nums:
        return []
    official = official_numbers(brand) + short_codes(brand)
    relevant = (claims_brand(listing.get("name", ""), brand) or claims_brand(listing.get("text", ""), brand)
                or (listing.get("url") and is_official(listing["url"], brand.get("official_domains", []) or []))
                or any(e in official for _, e in nums))
    if not relevant:
        return []
    return [classify(listing, brand, raw, e) for raw, e in nums]
