"""Owner: verdict. Rule-based scoring engine: signals -> 0-100 score + bilingual reasons.

Order of rules:
  1. final URL on an official domain of ANY registry brand (not a shared host) => legitimate (<=10)
     unless an explicit blocklist hit. (Checked first so that an official page that merely mentions
     another brand can never be called a scam.)
  2. brand claimed with confidence >= BRAND_THRESHOLD on a non-official domain => scam (>=85),
     unless the site is a long-established high-traffic site that does not ask for secrets.
  3. otherwise: weighted signals on top of BASE.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Optional

from scamshield.core.domains import host_of, is_official, is_shared_host, registrable
from scamshield.core.schemas import BrandMatch, CloakDiff, Detonation, Intel, LookalikeResult, Signal, Verdict

BRAND_THRESHOLD = 0.6
BASE = 10
SCAM, LIKELY, SUSPICIOUS = 80, 60, 35

RISKY_TLDS = {
    "xyz", "top", "icu", "shop", "live", "online", "click", "info", "cfd", "sbs", "buzz", "site", "store",
    "website", "space", "fun", "rest", "monster", "quest", "cyou", "bond", "lol", "mom", "support", "help",
    "tk", "ml", "ga", "cf", "gq", "work", "life", "vip", "win", "loan", "link", "pw", "cc", "ru", "cn", "su",
    "app", "digital", "services", "center", "today", "asia", "club", "biz", "pro", "host", "best", "beauty",
    "hair", "makeup", "skin", "autos", "boats", "yachts", "homes", "motorcycles",
}
SENSITIVE = {"credentials", "card", "otp", "emirates_id", "payment"}
PHISH_WORDS = re.compile(
    r"verify your (account|identity)|account (is |has been )?(suspended|locked|blocked|restricted)|"
    r"confirm your (account|identity|details|payment)|update your (payment|billing|card)|unusual (sign.?in|activity)|"
    r"enter (the )?(otp|one.time|verification code|card number|cvv)|your parcel|delivery (failed|attempt)|"
    r"unpaid (fine|toll|invoice)|pay (the |your )?(fine|fee|customs)|limited time|within 24 hours|"
    r"تحديث بياناتك|تم (إيقاف|تعليق|حظر) حسابك|رمز التحقق|أدخل رقم البطاقة|مخالفة غير مدفوعة|شحنتك|تأكيد هويتك",
    re.I,
)
CRED_FIELD = re.compile(r"pass|pwd|otp|pin|cvv|cvc|card|ccnum|expiry|emirates.?id|iban", re.I)


# ------------------------------------------------------------------ helpers
def _registry_official() -> list[str]:
    try:
        from scamshield.brand import load_registry

        return [d for b in load_registry() for d in (b.get("official_domains") or [])]
    except Exception:
        return []


def _days_since(dt: Optional[datetime]) -> Optional[int]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - dt).days)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _label(s: int) -> str:
    return "scam" if s >= SCAM else "likely_scam" if s >= LIKELY else "suspicious" if s >= SUSPICIOUS else "legitimate"


def _pick_final(url: str, dets: list[Detonation]) -> str:
    for d in dets:
        if d.status == "ok" and d.final_url:
            return d.final_url
    for d in dets:
        if d.final_url:
            return d.final_url
    return url


def _brand_names(brand: Optional[BrandMatch], look: Optional[LookalikeResult]) -> tuple[str, str]:
    if brand and brand.brand_id:
        return brand.name_en or brand.brand_id, brand.name_ar or brand.name_en or brand.brand_id
    bid = look.brand_id if look else None
    if bid:
        try:
            from scamshield.brand import get_brand

            b = get_brand(bid) or {}
            return b.get("name_en", bid), b.get("name_ar", b.get("name_en", bid))
        except Exception:
            pass
        return bid, bid
    return "", ""


ASK_EN = {"credentials": "login credentials", "card": "card details", "otp": "OTP / verification code",
          "emirates_id": "Emirates ID", "payment": "a payment", "personal_info": "personal information"}
ASK_AR = {"credentials": "بيانات الدخول", "card": "بيانات البطاقة", "otp": "رمز التحقق (OTP)",
          "emirates_id": "رقم الهوية الإماراتية", "payment": "دفع مبلغ", "personal_info": "معلومات شخصية"}


# ------------------------------------------------------------------ main
def score(scan_id: str, url: str, dets: list[Detonation], intel: Intel | None, brand: BrandMatch | None,
          look: LookalikeResult | None, cloak: CloakDiff | None = None) -> Verdict:
    """Combine signals into a 0-100 Verdict with bilingual reasons. Works with dets empty/dead (domain-only)."""
    try:
        return _score(scan_id, url, dets or [], intel, brand, look, cloak)
    except Exception as e:  # never raise
        return Verdict(scan_id=scan_id, url=url, final_url=url, registrable_domain=_safe_reg(url), score=50,
                       label="suspicious", mode="domain_only",
                       reasons=[Signal(id="scoring_error", weight=0, en=f"Analysis incomplete ({type(e).__name__}).",
                                       ar="التحليل غير مكتمل بسبب خطأ داخلي.", evidence=str(e)[:200])],
                       summary_en="Suspicious: analysis incomplete, treat with caution.",
                       summary_ar="مشبوه: التحليل غير مكتمل، يرجى الحذر.")


def _safe_reg(url: str) -> str:
    try:
        return registrable(url)
    except Exception:
        return ""


def _score(scan_id, url, dets, intel, brand, look, cloak) -> Verdict:
    final = _pick_final(url, dets)
    host = host_of(final)
    dom = registrable(final)
    ok = [d for d in dets if d.status == "ok"]
    mode = "full" if ok else "domain_only"
    shared = is_shared_host(host)
    sig: list[Signal] = []

    def add(id_, w, en, ar, ev=""):
        sig.append(Signal(id=id_, weight=w, en=en, ar=ar, evidence=str(ev)[:300]))

    official_all = list(_registry_official())
    if brand and brand.official_domains:
        official_all += brand.official_domains
    on_official = bool(host) and is_official(final, official_all)

    bl = []
    if intel:
        bl = list(dict.fromkeys((intel.blocklist_hits or []) + [f"safe_browsing:{t}" for t in intel.safe_browsing or []]))
    tranco = intel.tranco_rank if intel and not shared else None
    age = None
    if intel:
        age = intel.age_days if intel.age_days is not None else _days_since(intel.created)
    asks = set(brand.asks_for) if brand else set()
    for d in ok:
        for f in d.form_fields:
            blob = f"{f.name} {f.type} {f.label} {f.placeholder}"
            if f.type == "password" or re.search(r"pass|pwd", blob, re.I):
                asks.add("credentials")
            elif re.search(r"otp|one.time|verification", blob, re.I):
                asks.add("otp")
            elif re.search(r"card|cvv|cvc|ccnum|expiry", blob, re.I):
                asks.add("card")
            elif re.search(r"emirates.?id", blob, re.I):
                asks.add("emirates_id")
    b_en, b_ar = _brand_names(brand, look)
    brand_conf = brand.confidence if brand and brand.brand_id else 0.0

    # ---------------- rule 1: official domain
    if on_official and not bl:
        add("official_domain", -100, f"The page is on an official domain ({host}) listed in our verified registry.",
            f"الصفحة على نطاق رسمي ({host}) مُدرج في سجلّنا المُتحقَّق منه.", final)
        return _finish(scan_id, url, final, dom, mode, 0, sig, brand, look, forced="legitimate")

    # ---------------- rule 2: brand impersonation
    established = (tranco is not None and tranco <= 100_000) or (age is not None and age > 3 * 365 and not shared)
    big = tranco is not None and tranco <= 10_000
    brand_rule = False
    if brand_conf >= BRAND_THRESHOLD and not on_official:
        ev = "; ".join(brand.evidence[:3]) if brand else ""
        if big or (established and not (asks & SENSITIVE)):
            add("brand_mention_established_site", 10,
                f"Mentions {b_en}, but this is a long-established site that does not ask for sensitive data.",
                f"تذكر الصفحة {b_ar}، لكن الموقع قديم ومعروف ولا يطلب بيانات حساسة.", ev)
        else:
            brand_rule = True
            add("brand_on_unofficial_domain", 75,
                f"The page presents itself as {b_en}, but {dom} is not an official {b_en} domain.",
                f"تدّعي الصفحة أنها تابعة لـ{b_ar}، لكن النطاق {dom} ليس نطاقاً رسمياً لـ{b_ar}.", ev)
    elif brand_conf >= 0.3 and not on_official:
        add("weak_brand_claim", 12, f"The page shows some signs of using the {b_en} name.",
            f"تظهر في الصفحة مؤشرات على استخدام اسم {b_ar}.", "; ".join(brand.evidence[:2]) if brand else "")

    # ---------------- weighted signals
    if bl:
        add("blocklist", 60, f"Listed on threat-intelligence blocklists: {', '.join(bl)}.",
            f"مُدرج في قوائم حظر التهديدات: {', '.join(bl)}.", ", ".join(bl))

    if look and look.score >= 0.2 and not on_official and not brand_rule:
        w = round(45 * look.score) if look.score >= 0.5 else round(20 * look.score)
        tech = ", ".join(look.techniques) or "similarity"
        add("lookalike_domain", w,
            f"The domain {dom} imitates {look.closest_official or b_en} ({tech}).",
            f"النطاق {dom} يقلّد {look.closest_official or b_ar} ({tech}).", f"score={look.score:.2f} distance={look.distance}")

    if age is not None and not shared:
        if age < 7:
            add("very_new_domain", 30, f"The domain was registered only {age} day(s) ago.",
                f"النطاق مسجّل منذ {age} أيام فقط.", f"age_days={age}")
        elif age < 30:
            add("new_domain", 18, f"The domain was registered {age} days ago (less than a month).",
                f"النطاق مسجّل منذ {age} يوماً (أقل من شهر).", f"age_days={age}")
        elif age < 180:
            add("recent_domain", 6, f"The domain is relatively new ({age} days).",
                f"النطاق حديث نسبياً ({age} يوماً).", f"age_days={age}")
        elif age > 5 * 365:
            add("old_domain", -15, f"The domain has existed for over {age // 365} years.",
                f"النطاق موجود منذ أكثر من {age // 365} سنوات.", f"age_days={age}")

    cfs = _days_since(intel.cert_first_seen) if intel else None
    if cfs is not None and cfs < 14 and not shared and (age is None or age >= 7):
        add("new_certificate", 10, f"The first TLS certificate for this domain appeared {cfs} day(s) ago.",
            f"ظهرت أول شهادة أمان لهذا النطاق منذ {cfs} أيام.", f"cert_first_seen={intel.cert_first_seen}")

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        add("risky_tld", 10, f"Uses the .{tld} extension, which is heavily abused by scam sites.",
            f"يستخدم امتداد ‎.{tld}‎ الذي يكثر استخدامه في مواقع الاحتيال.", tld)

    if shared:
        add("shared_host", 12, f"Hosted on a free/shared hosting platform ({host}) where anyone can publish a page.",
            f"مستضاف على منصة استضافة مجانية/مشتركة ({host}) يمكن لأي شخص النشر عليها.", host)

    if _is_ip(host):
        add("ip_host", 25, "The link uses a raw IP address instead of a domain name.",
            "يستخدم الرابط عنوان IP مباشرة بدلاً من اسم نطاق.", host)
    if "xn--" in final.lower() or any(ord(c) > 127 for c in host):
        add("punycode", 15, "The domain uses international characters (punycode) that can disguise a fake address.",
            "يستخدم النطاق أحرفاً دولية (Punycode) قد تُخفي عنواناً مزيفاً.", host)

    sens = sorted(asks & (SENSITIVE | {"personal_info"}))
    if sens and not brand_rule:
        w = 25 if asks & {"card", "otp", "emirates_id"} else 18 if "credentials" in asks else 8
        if big:
            w = 0
        if w:
            add("asks_sensitive", w, f"The page asks for {', '.join(ASK_EN[a] for a in sens)} on an unverified site.",
                f"تطلب الصفحة {('، '.join(ASK_AR[a] for a in sens))} على موقع غير موثّق.", ", ".join(sens))
    elif sens and brand_rule:
        add("asks_sensitive", 10, f"It asks for {', '.join(ASK_EN[a] for a in sens)}.",
            f"وتطلب {('، '.join(ASK_AR[a] for a in sens))}.", ", ".join(sens))

    if "credentials" in asks and final.lower().startswith("http://"):
        add("password_no_https", 20, "A password field is served over an unencrypted (HTTP) connection.",
            "يوجد حقل كلمة مرور عبر اتصال غير مشفّر (HTTP).", final)

    text = " ".join(f"{d.title} {d.visible_text[:5000]}" for d in ok)
    m = PHISH_WORDS.search(text)
    if m and not big:
        add("phishing_language", 10, f"Uses typical scam pressure language (\"{m.group(0)}\").",
            f"تستخدم الصفحة عبارات ضغط احتيالية معتادة («{m.group(0)}»).", m.group(0))

    if cloak and cloak.cloaked:
        add("cloaking", 25, "The site shows different content to different visitors (cloaking), a common scam trick.",
            "يعرض الموقع محتوى مختلفاً لزوار مختلفين (إخفاء)، وهي حيلة احتيال شائعة.", "; ".join(cloak.differences[:3]))

    chain = max((d.redirect_chain for d in dets), key=len, default=[])
    shortener = any(h.kind == "shortener" for h in chain)
    hops = sum(1 for h in chain if h.kind not in ("start", "final"))
    if shortener or hops >= 3:
        add("redirects", 8 if not shortener else 10,
            f"The link hides its destination behind {'a URL shortener' if shortener else f'{hops} redirects'}.",
            f"يُخفي الرابط وجهته الحقيقية عبر {'خدمة اختصار روابط' if shortener else f'{hops} عمليات تحويل'}.",
            " -> ".join(h.url for h in chain[:6]))
    if registrable(url) != dom and dom:
        add("cross_domain_redirect", 3, f"The link redirects to a different domain ({dom}).",
            f"يحوّل الرابط إلى نطاق مختلف ({dom}).", f"{url} -> {final}")

    if tranco is not None:
        if tranco <= 10_000:
            add("popular_site", -45, f"Very popular website (global top-{tranco:,} rank).",
                f"موقع شائع جداً (ضمن الترتيب العالمي {tranco:,}).", f"tranco={tranco}")
        elif tranco <= 100_000:
            add("known_site", -25, f"Well-known website (global rank {tranco:,}).",
                f"موقع معروف (الترتيب العالمي {tranco:,}).", f"tranco={tranco}")
        elif tranco <= 1_000_000:
            add("ranked_site", -10, f"Website appears in the global top-1M list (rank {tranco:,}).",
                f"الموقع ضمن قائمة أفضل مليون موقع عالمياً (الترتيب {tranco:,}).", f"tranco={tranco}")

    if mode == "domain_only":
        st = ", ".join(sorted({d.status for d in dets})) or "not loaded"
        add("page_unavailable", 5, f"The page could not be analysed ({st}); verdict is based on the domain only.",
            f"تعذّر تحليل الصفحة ({st})؛ الحكم مبني على معلومات النطاق فقط.", st)

    total = BASE + sum(s.weight for s in sig)
    if brand_rule:
        total = max(total, 85)
    elif bl:
        total = max(total, 80)
    return _finish(scan_id, url, final, dom, mode, total, sig, brand, look)


def _finish(scan_id, url, final, dom, mode, total, sig, brand, look, forced=None) -> Verdict:
    s = max(0, min(100, int(round(total))))
    if forced == "legitimate":
        s = min(s, 10)
    label = forced or _label(s)
    sig.sort(key=lambda x: -abs(x.weight))
    bid = (brand.brand_id if brand and brand.brand_id else None) or (look.brand_id if look and look.score >= 0.5 else None)
    pos = [x for x in sig if x.weight > 0][:3] if label != "legitimate" else [x for x in sig if x.weight <= 0][:2]
    head_en = {"scam": "SCAM", "likely_scam": "Likely scam", "suspicious": "Suspicious", "legitimate": "Looks legitimate"}[label]
    head_ar = {"scam": "احتيال", "likely_scam": "احتيال مرجّح", "suspicious": "مشبوه", "legitimate": "يبدو موثوقاً"}[label]
    adv_en = {"scam": "Do not enter any information. Report it to Abu Dhabi Police (Aman 8002626).",
              "likely_scam": "Do not enter any information; verify via the official app or website.",
              "suspicious": "Be careful; verify through the organisation's official channels.",
              "legitimate": "No strong scam indicators found."}[label]
    adv_ar = {"scam": "لا تُدخل أي بيانات. أبلغ شرطة أبوظبي (أمان 8002626).",
              "likely_scam": "لا تُدخل أي بيانات؛ تحقّق عبر التطبيق أو الموقع الرسمي.",
              "suspicious": "توخَّ الحذر وتحقّق عبر القنوات الرسمية للجهة.",
              "legitimate": "لم يتم العثور على مؤشرات احتيال قوية."}[label]
    summary_en = f"{head_en} ({s}/100). " + " ".join(x.en for x in pos) + (" " if pos else "") + adv_en
    summary_ar = f"{head_ar} ({s}/100). " + " ".join(x.ar for x in pos) + (" " if pos else "") + adv_ar
    return Verdict(scan_id=scan_id, url=url, final_url=final, registrable_domain=dom, score=s, label=label, mode=mode,
                   reasons=sig, summary_en=summary_en, summary_ar=summary_ar, brand_id=bid)
