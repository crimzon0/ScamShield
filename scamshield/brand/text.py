"""Keyword brand matching (EN / AR / Arabizi) and asks_for detection."""
from __future__ import annotations

import re
from functools import lru_cache
from urllib.parse import unquote, urlsplit

from scamshield.core.schemas import Detonation

from .normalize import is_arabic, keyword_pattern, norm

# What the page asks the victim for. EN patterns are word-bounded; AR patterns are substrings of normalised text.
ASKS = {
    "credentials": {
        "en": ["password", "passcode", "username", "user name", "user id", "login id", "sign in", "log in", "login",
               "internet banking id", "customer id"],
        "ar": ["كلمة المرور", "كلمة السر", "اسم المستخدم", "تسجيل الدخول", "رقم المستخدم"],
    },
    "card": {
        "en": ["card number", "cvv", "cvc", "cvv2", "expiry", "expiry date", "expiration", "mm/yy", "mm / yy",
               "credit card", "debit card", "name on card", "cardholder", "atm pin", "card pin"],
        "ar": ["رقم البطاقة", "تاريخ الانتهاء", "تاريخ انتهاء", "رمز الامان", "بطاقة الائتمان", "البطاقة الائتمانية",
               "بطاقة الخصم", "الرقم السري للبطاقة", "اسم حامل البطاقة"],
    },
    "otp": {
        "en": ["otp", "one-time password", "one time password", "verification code", "sms code", "activation code",
               "security code", "6-digit code", "code sent to"],
        "ar": ["رمز التحقق", "رمز التفعيل", "كلمة المرور لمرة واحدة", "الرمز المرسل", "رمز التأكيد", "رمز المرور المؤقت"],
    },
    "emirates_id": {
        "en": ["emirates id", "eid number", "id number", "identity card number"],
        "ar": ["الهوية الإماراتية", "رقم الهوية", "بطاقة الهوية", "الهوية الاماراتية"],
    },
    "payment": {
        "en": ["pay now", "pay fine", "pay your fine", "fine payment", "traffic fine", "traffic fines", "outstanding fine",
               "amount due", "pay the fee", "delivery fee", "customs fee", "payment", "aed",
               "shipment on hold", "redelivery", "re-delivery", "reschedule delivery", "parcel is on hold",
               "unpaid shipping", "shipping fee", "toll", "salik fine"],
        "ar": ["مخالفة", "مخالفات", "غرامة", "سداد", "ادفع", "دفع", "رسوم", "درهم", "المبلغ المستحق",
               "رسوم التوصيل", "رسوم الشحن", "شحنتك معلقة", "اعادة التوصيل", "رسوم جمركية"],
    },
    "personal_info": {
        "en": ["full name", "date of birth", "phone number", "mobile number", "address", "passport number",
               "email address", "nationality"],
        "ar": ["الاسم الكامل", "تاريخ الميلاد", "رقم الهاتف", "رقم الجوال", "رقم الموبايل", "العنوان", "جواز السفر",
               "البريد الالكتروني", "الجنسية"],
    },
}
_EID_RE = re.compile(r"\b784[-\s]?\d{4}[-\s]?\d{7}[-\s]?\d\b")
_FIELD_HINTS = {  # form field name / type fragments
    "credentials": ["password", "passwd", "pwd", "username", "userid", "login"],
    "card": ["card", "cc_", "ccnum", "cvv", "cvc", "expiry", "exp_", "pan"],
    "otp": ["otp", "sms", "verif", "code"],
    "emirates_id": ["emiratesid", "emirates_id", "eid"],
    "personal_info": ["dob", "birth", "phone", "mobile", "address", "passport", "fullname", "email"],
}


@lru_cache(maxsize=1)
def _ask_patterns():
    out = {}
    for k, v in ASKS.items():
        out[k] = [keyword_pattern(p) for p in v["en"] + v["ar"]]
    return out


def detect_asks(text_norm: str, fields) -> list[str]:
    found = set()
    for k, pats in _ask_patterns().items():
        if any(p.search(text_norm) for p in pats):
            found.add(k)
    if _EID_RE.search(text_norm):
        found.add("emirates_id")
    for f in fields or []:
        blob = norm(f"{f.name} {f.label} {f.placeholder}")
        nm = blob.replace(" ", "").replace("-", "_")
        for k, hints in _FIELD_HINTS.items():
            if any(h in nm for h in hints):
                found.add(k)
        for k, pats in _ask_patterns().items():
            if k != "payment" and any(p.search(blob) for p in pats):
                found.add(k)
        if (f.type or "").lower() == "password" and not ({"otp", "card"} & found and re.search(r"otp|pin|code|رمز", blob)):
            found.add("credentials")
    order = ["credentials", "card", "otp", "emirates_id", "payment", "personal_info"]
    return [k for k in order if k in found]


@lru_cache(maxsize=4)
def _brand_patterns(registry_key: int, brands_tuple):
    out = []
    for b in brands_tuple:
        pats = []
        for kind, field in (("text", "keywords_en"), ("arabic", "keywords_ar"), ("arabizi", "arabizi"),
                            ("text", "name_en"), ("arabic", "name_ar")):
            vals = b.get(field) or []
            if isinstance(vals, str):
                vals = [vals]
            for kw in vals:
                k = norm(kw)
                if len(k) < 3 or "(" in k:
                    continue
                kind2 = "arabic" if is_arabic(k) else kind
                pats.append((kind2, kw, keyword_pattern(k), len(k)))
        out.append((b["id"], pats))
    return out


def page_parts(det: Detonation) -> dict[str, str]:
    url = det.final_url or det.url or ""
    try:
        sp = urlsplit(url)
        path = unquote(sp.path + " " + sp.query)
    except Exception:
        path = ""
    path = re.sub(r"[/_\-.=&?+]+", " ", path)
    forms = " ".join(f"{f.label} {f.placeholder} {f.name}" for f in det.form_fields or [])
    return {
        "title": norm(det.title),
        "text": norm(det.visible_text[:200000] if det.visible_text else ""),
        "form": norm(forms),
        "url": norm(path),
    }


PART_W = {"title": 0.45, "text": 0.35, "form": 0.25, "url": 0.25}


def score_brands(parts: dict[str, str], brands: list[dict]) -> list[dict]:
    """Returns [{id, confidence, methods, evidence, hits}] sorted best-first (only brands with hits)."""
    key = hash(tuple(b["id"] for b in brands))
    pats = _brand_patterns(key, tuple(_Frozen(b) for b in brands))
    results = []
    for bid, plist in pats:
        miss = 1.0
        methods, evidence, kws, hit_parts = set(), [], set(), set()
        for kind, kw, pat, ln in plist:
            for part, txt in parts.items():
                if not txt or not pat.search(txt):
                    continue
                w = PART_W[part]
                if ln <= 4:
                    w *= 0.6  # short names (adcb, tamm, dewa) are weaker evidence
                if kind == "arabizi":
                    w *= 0.8
                miss *= (1 - w)
                methods.add(kind)
                hit_parts.add(part)
                if kw not in kws:
                    evidence.append(f"'{kw}' in {part}")
                kws.add(kw)
        if kws:
            results.append({"id": bid, "confidence": round(min(1 - miss, 0.99), 3), "methods": sorted(methods),
                            "evidence": evidence[:8], "hits": len(kws), "parts": sorted(hit_parts)})
    results.sort(key=lambda r: (r["confidence"], r["hits"]), reverse=True)
    return results


class _Frozen(dict):
    """Hashable dict wrapper so registry brands can feed lru_cache."""

    def __hash__(self):
        return hash(self.get("id"))

    def __eq__(self, other):
        return isinstance(other, dict) and self.get("id") == other.get("id") and dict.__eq__(self, other)
