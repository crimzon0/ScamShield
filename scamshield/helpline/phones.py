"""Phone extraction + normalisation (UAE). Pure functions, no network."""
from __future__ import annotations

import re

import phonenumbers
from phonenumbers import PhoneNumberType as T

# Arabic-Indic (U+0660..0669) and Extended/Eastern Arabic-Indic (U+06F0..06F9) -> ASCII
_DIGITS = {ord(c): str(i) for i, c in enumerate("٠١٢٣٤٥٦٧٨٩")}
_DIGITS.update({ord(c): str(i) for i, c in enumerate("۰۱۲۳۴۵۶۷۸۹")})
# Arabic punctuation / invisible marks that break the matcher
_DIGITS.update({ord("٫"): ".", ord("٬"): ",", ord("،"): ",", ord("‎"): None,
                ord("‏"): None, ord("‪"): None, ord("‫"): None, ord("‬"): None,
                ord(" "): " ", ord("‑"): "-", ord("–"): "-", ord("−"): "-"})

# Length-preserving variant (invisible marks -> space) so match offsets map back to the original text.
_DIGITS_SAMELEN = {k: (v if v is not None else " ") for k, v in _DIGITS.items()}

_WA_RE = re.compile(r"(?:wa\.me/|api\.whatsapp\.com/send/?\?phone=|whatsapp\.com/send\?phone=)\+?(\d{8,15})", re.I)


def ascii_digits(text: str) -> str:
    return (text or "").translate(_DIGITS)


def _parse(raw: str, region: str = "AE"):
    s = ascii_digits(raw).strip()
    if not s:
        return None
    s = re.sub(r"^\s*00(?=[1-9])", "+", s)  # 00971... -> +971...
    try:
        n = phonenumbers.parse(s, region)
    except phonenumbers.NumberParseException:
        return None
    return n if phonenumbers.is_valid_number(n) else None


def normalize(raw: str, region: str = "AE") -> str:
    """E.164 string, or '' if not a valid number. Handles Arabic/Eastern digits, 00 prefix, 800/600 numbers."""
    try:
        n = _parse(raw, region)
        return phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164) if n else ""
    except Exception:
        return ""


def extract(text: str, region: str = "AE") -> list[tuple[str, str]]:
    """All phone numbers in free text -> [(raw, e164)] in order, deduplicated. Includes wa.me links."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    try:
        orig = text or ""
        t = orig.translate(_DIGITS_SAMELEN)
        if len(t) != len(orig):
            orig = t
        for m in _WA_RE.finditer(t):
            e = normalize("+" + m.group(1), region)
            if e and e not in seen:
                seen.add(e)
                out.append((m.group(0), e))
        for m in phonenumbers.PhoneNumberMatcher(t, region, leniency=phonenumbers.Leniency.VALID):
            e = phonenumbers.format_number(m.number, phonenumbers.PhoneNumberFormat.E164)
            if e not in seen:
                seen.add(e)
                out.append((orig[m.start:m.end].strip(), e))
    except Exception:
        pass
    return out


def number_kind(e164: str) -> str:
    """'mobile' | 'tollfree' | 'shared_cost' | 'landline' | 'other' | ''."""
    try:
        n = phonenumbers.parse(e164, None)
    except Exception:
        return ""
    t = phonenumbers.number_type(n)
    if t == T.MOBILE:
        return "mobile"
    if t == T.TOLL_FREE:
        return "tollfree"
    if t in (T.SHARED_COST, T.UAN):
        return "shared_cost"
    if t == T.FIXED_LINE:
        return "landline"
    return "other"


def is_mobile(e164: str) -> bool:
    return number_kind(e164) == "mobile"


def whatsapp_numbers(text_or_url: str) -> list[str]:
    return [e for e in (normalize("+" + m.group(1)) for m in _WA_RE.finditer(ascii_digits(text_or_url or ""))) if e]
