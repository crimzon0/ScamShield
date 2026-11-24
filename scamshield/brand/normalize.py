"""Text normalisation for EN / AR / Arabizi matching."""
from __future__ import annotations

import re
import unicodedata

_TASHKEEL = re.compile(r"[ؐ-ًؚ-ٰٟۖ-ۭ]")
_TATWEEL = "ـ"
_AR_MAP = str.maketrans({
    "أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا",
    "ى": "ي", "ة": "ه",
    # Arabic-Indic and Eastern Arabic-Indic digits -> ASCII
    **{chr(0x0660 + i): str(i) for i in range(10)},
    **{chr(0x06F0 + i): str(i) for i in range(10)},
    "‏": " ", "‎": " ", "‌": "", "‍": "", " ": " ",
})
_WS = re.compile(r"\s+")


def norm(text: str) -> str:
    """lowercase + NFKC + Arabic normalisation (tashkeel/tatweel stripped, alef/ya/ta-marbuta unified)."""
    if not text:
        return ""
    t = unicodedata.normalize("NFKC", text).lower()
    t = _TASHKEEL.sub("", t).replace(_TATWEEL, "")
    t = t.translate(_AR_MAP)
    t = t.replace("ابو ظبي", "ابوظبي")
    return _WS.sub(" ", t).strip()


_ARABIC = re.compile(r"[؀-ۿ]")


def is_arabic(s: str) -> bool:
    return bool(_ARABIC.search(s or ""))


def keyword_pattern(kw: str) -> re.Pattern:
    """Word-bounded pattern. Spaces in a keyword match space/-/_/nothing (abu dhabi == abudhabi == abu-dhabi).
    Arabic keywords allow one attached prefix (و ب ل ف ك) and the definite article."""
    k = norm(kw)
    parts = [re.escape(p) for p in k.split(" ") if p]
    body = r"[\s\-_]*".join(parts)
    if is_arabic(k):
        return re.compile(r"(?<![\w])(?:[وبلفك]|وال|بال|لل)?" + body + r"(?![\w])")
    return re.compile(r"(?<![\w])" + body + r"(?![\w])")
