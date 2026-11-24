"""Owner: verdict. Rule-based scoring engine: signals -> 0-100 score + bilingual reasons.

Order of rules:
  0. "bounce": an unknown link domain that redirects to a popular/official site is judged on its own domain.
  1. final URL on an official domain of ANY registry brand (not a shared host) => legitimate (<=10)
     unless an explicit blocklist hit.
  2. brand claimed (confidence >= BRAND_THRESHOLD, not only a domain-keyword guess) on a non-official domain
     => scam (>=85), unless the site is long-established/high-traffic and does not ask for secrets.
  3. otherwise: weighted signals on top of BASE.
Pages that returned HTTP >= 400 or a hosting "site not found" page are scored domain-only (content ignored).
`SCAMSHIELD_IGNORE_BLOCKLIST=1` disables feed hits (ablation for evaluation).
"""
from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timezone
from typing import Optional

from scamshield.core.domains import host_of, is_official, is_shared_host, registrable, registrable_icann
from scamshield.core.schemas import BrandMatch, CloakDiff, Detonation, Intel, LookalikeResult, Signal, Verdict

BRAND_THRESHOLD = 0.4
BASE = 10
SCAM, LIKELY, SUSPICIOUS = 80, 60, 35

RISKY_TLDS = {
    "xyz", "top", "icu", "shop", "live", "online", "click", "info", "cfd", "sbs", "buzz", "site", "store",
    "website", "space", "fun", "rest", "monster", "quest", "cyou", "bond", "lol", "mom", "support", "help",
    "tk", "ml", "ga", "cf", "gq", "work", "life", "vip", "win", "loan", "link", "pw", "cc", "ru", "cn", "su",
    "app", "digital", "services", "center", "today", "asia", "club", "biz", "pro", "host", "best", "beauty",
    "hair", "makeup", "skin", "autos", "boats", "yachts", "homes", "motorcycles", "ss", "me", "ws", "top",
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
# Free hosting / site-builder suffixes missing from core SHARED_HOSTS.
EXTRA_SHARED = {
    "gitbook.io", "mybluehost.me", "cpanel.site", "cloudapp.azure.com", "azurestaticapps.net", "web.core.windows.net",
    "blob.core.windows.net", "ipfs.io", "dweb.link", "translate.goog", "framer.website", "webcindario.com",
    "000webhost.com", "hostingersite.com", "myshopify.com", "jimdosite.com", "site123.me",
    "wixstudio.io", "notion.site", "gitlab.io", "codesandbox.io", "csb.app",
    "glide.page", "softr.app", "lovable.app", "start.page", "sharepoint.com", "my.salesforce-sites.com",
    "s3.amazonaws.com", "storage.googleapis.com", "duckdns.org", "no-ip.org", "ddns.net", "zapto.org", "hopto.org",
    "serveo.net", "loca.lt", "workers.dev", "pages.dev", "weeblysite.com", "ukit.me", "tiiny.site",
    "yolasite.com", "webnode.page", "ucoz.net", "github.dev", "vercel.app", "netlify.app", "square.site",
}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
              "s.id", "shorturl.at", "rb.gy", "t.ly", "bitly.com", "lnkd.in", "qrco.de", "flyn.co", "tiny.cc"}
# Globally phished brand keywords -> display name. Only used to spot the name in an address/title that is NOT theirs.
GLOBAL_BRANDS = {
    "paypal": "PayPal", "icloud": "Apple iCloud", "microsoft": "Microsoft", "office365": "Microsoft",
    "outlook": "Microsoft", "onedrive": "Microsoft", "sharepoint": "Microsoft", "netflix": "Netflix",
    "amazon": "Amazon", "coinbase": "Coinbase", "binance": "Binance", "metamask": "MetaMask", "trustwallet": "Trust Wallet",
    "facebook": "Facebook", "instagram": "Instagram", "whatsapp": "WhatsApp", "telegram": "Telegram",
    "google": "Google", "gmail": "Gmail", "youtube": "YouTube", "linkedin": "LinkedIn", "fedex": "FedEx",
    "usps": "USPS", "royalmail": "Royal Mail", "roblox": "Roblox", "steamcommunity": "Steam", "santander": "Santander",
    "allegro": "Allegro", "telekom": "Telekom", "wellsfargo": "Wells Fargo", "hsbc": "HSBC",
    "citibank": "Citibank", "barclays": "Barclays", "docusign": "DocuSign", "dropbox": "Dropbox", "adobe": "Adobe",
    "kraken": "Kraken", "bybit": "Bybit", 
    "careem": "Careem", "talabat": "talabat", "aramex": "Aramex", 
}
_KW_RE = re.compile("|".join(sorted(GLOBAL_BRANDS, key=len, reverse=True)))
HOST_BAIT = re.compile(r"login|log-in|signin|sign-in|verify|verification|secure|account|update|wallet|"
                       r"recover|unlock|billing|payment|refund|claim|bonus|giveaway|reward|helpdesk|webmail|confirm")
NOT_FOUND_PAGE = re.compile(
    r"site not found|page not found|404 not found|deployment (could not be found|not found)|this site can.t be reached|"
    r"there isn.t a github pages site here|no such app|application (error|not found)|this account has been suspended|"
    r"this (site|account|page) (has been|is) (suspended|disabled|removed|deleted)|domain (is )?(for sale|parked)|"
    r"web page not available|this deployment is temporarily paused|project not found|error 1001|dns resolution error|"
    r"site (is )?(unavailable|disabled)|403 forbidden|not found", re.I)
HOLD_STATUS = re.compile(r"client ?hold|server ?hold|redemption ?period|pending ?delete|inactive", re.I)
NXDOMAIN = re.compile(r"ERR_NAME_NOT_RESOLVED|NXDOMAIN|getaddrinfo|Name or service not known|ENOTFOUND", re.I)


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


def _shared(host: str) -> bool:
    return is_shared_host(host) or any(host == x or host.endswith("." + x) for x in EXTRA_SHARED)


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


def _is_gone(d: Detonation) -> bool:
    """Loaded, but the server says the page is gone (HTTP >= 400 or a hosting 'not found/suspended' page)."""
    if d.status != "ok":
        return False
    if d.http_status and d.http_status >= 400:
        return True
    head = f"{d.title} {(d.visible_text or '')[:300]}"
    return not d.form_fields and len((d.visible_text or "").strip()) < 600 and bool(NOT_FOUND_PAGE.search(head))


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
          look: LookalikeResult | None, cloak: CloakDiff | None = None,
          extra: list[Signal] | None = None, input_intel: Intel | None = None,
          input_look: LookalikeResult | None = None) -> Verdict:
    """Combine signals into a 0-100 Verdict with bilingual reasons. Works with dets empty/dead (domain-only).
    extra: pre-built signals (e.g. fake helpline on page). input_intel/input_look: intel for the input URL's
    domain when the link redirected to another domain (used to catch bounce-cloaking)."""
    try:
        dets = dets or []
        b = _bounce(url, dets, intel, input_intel, brand)
        if b is not None:
            fake = [Detonation(url=url, persona=d.persona, status="blank", final_url="", redirect_chain=d.redirect_chain,
                               error="redirected to an unrelated well-known site") for d in dets]
            v = _score(scan_id, url, fake, input_intel, None, input_look, cloak, (extra or []) + [b])
            v.final_url = _pick_final(url, dets)
            return v
        return _score(scan_id, url, dets, intel, brand, look, cloak, extra or [])
    except Exception as e:  # never raise
        return Verdict(scan_id=scan_id, url=url, final_url=url, registrable_domain=_safe_reg(url), score=50,
                       label="suspicious", mode="domain_only",
                       reasons=[Signal(id="scoring_error", weight=0, en=f"Analysis incomplete ({type(e).__name__}).",
                                       ar="التحليل غير مكتمل بسبب خطأ داخلي.", evidence=str(e)[:200])],
                       summary_en="Suspicious: analysis incomplete, treat with caution.",
                       summary_ar="مشبوه: التحليل غير مكتمل، يرجى الحذر.")


def _bounce(url, dets, intel, input_intel, brand) -> Optional[Signal]:
    """Unknown link domain that redirects to a popular or official site (scanner-evasion cloaking)."""
    if input_intel is None:
        return None
    final = _pick_final(url, dets)
    in_host, in_dom, dom = host_of(url), registrable(url), registrable(final)
    if not dom or in_dom == dom or registrable_icann(url) == registrable_icann(final):
        return None
    official = _registry_official() + (brand.official_domains if brand else [])
    if is_official(url, official) or in_dom in SHORTENERS:
        return None
    r_in = input_intel.tranco_rank if not _shared(in_host) else None
    if r_in is not None and r_in <= 1_000_000:
        return None
    f_tr = intel.tranco_rank if intel and not _shared(host_of(final)) else None
    if not (is_official(final, official) or (f_tr is not None and f_tr <= 10_000)):
        return None
    return Signal(id="redirect_to_popular_site", weight=20,
                  en=f"The unknown site {in_dom} immediately sends visitors to the well-known site {dom}, a trick "
                     f"scam links use to hide from scanners.",
                  ar=f"الموقع غير المعروف {in_dom} يحوّل الزوار فوراً إلى الموقع المعروف {dom}، وهي حيلة تستخدمها "
                     f"روابط الاحتيال للتخفي من أدوات الفحص.", evidence=f"{url} -> {final}")


def _safe_reg(url: str) -> str:
    try:
        return registrable(url)
    except Exception:
        return ""


def _score(scan_id, url, dets, intel, brand, look, cloak, extra) -> Verdict:
    final = _pick_final(url, dets)
    host = host_of(final)
    dom = registrable(final)
    gone = [d for d in dets if _is_gone(d)]
    ok = [d for d in dets if d.status == "ok" and not _is_gone(d)]
    mode = "full" if ok else "domain_only"
    if not ok:
        brand = brand if (brand and brand.is_official_domain) else None  # page content unusable
    shared = _shared(host)
    sig: list[Signal] = []

    def add(id_, w, en, ar, ev=""):
        sig.append(Signal(id=id_, weight=w, en=en, ar=ar, evidence=str(ev)[:300]))

    official_all = list(_registry_official())
    if brand and brand.official_domains:
        official_all += brand.official_domains
    on_official = bool(host) and is_official(final, official_all)

    bl = []
    if intel and os.environ.get("SCAMSHIELD_IGNORE_BLOCKLIST") != "1":
        bl = list(dict.fromkeys((intel.blocklist_hits or []) + [f"safe_browsing:{t}" for t in intel.safe_browsing or []]))
    tranco = intel.tranco_rank if intel and not shared else None
    age = None
    if intel and not shared:
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
    strong_brand = bool(brand and brand.brand_id and set(brand.methods or []) - {"domain_keyword"})
    brand_conf = brand.confidence if strong_brand else 0.0

    # ---------------- rule 1: official domain
    if on_official and not bl:
        add("official_domain", -100, f"The page is on an official domain ({host}) listed in our verified registry.",
            f"الصفحة على نطاق رسمي ({host}) مُدرج في سجلّنا المُتحقَّق منه.", final)
        return _finish(scan_id, url, final, dom, mode, 0, sig, brand, look, forced="legitimate")

    # ---------------- rule 2: brand impersonation
    established = (tranco is not None and tranco <= 100_000) or (age is not None and age > 3 * 365)
    big = tranco is not None and tranco <= 10_000
    brand_rule = False
    if brand_conf >= BRAND_THRESHOLD and not on_official:
        ev = "; ".join(brand.evidence[:3])
        if big or (established and not (asks & SENSITIVE)):
            add("brand_mention_established_site", 10,
                f"Mentions {b_en}, but this is a long-established site that does not ask for sensitive data.",
                f"تذكر الصفحة {b_ar}، لكن الموقع قديم ومعروف ولا يطلب بيانات حساسة.", ev)
        else:
            brand_rule = True
            add("brand_on_unofficial_domain", 75,
                f"The page presents itself as {b_en}, but {dom} is not an official {b_en} domain.",
                f"تدّعي الصفحة أنها تابعة لـ{b_ar}، لكن النطاق {dom} ليس نطاقاً رسمياً لـ{b_ar}.", ev)
    elif brand_conf >= 0.2 and not on_official:
        add("weak_brand_claim", 12, f"The page shows some signs of using the {b_en} name.",
            f"تظهر في الصفحة مؤشرات على استخدام اسم {b_ar}.", "; ".join(brand.evidence[:2]))

    # ---------------- weighted signals
    if bl:
        add("blocklist", 60, f"Listed on threat-intelligence blocklists: {', '.join(bl)}.",
            f"مُدرج في قوائم حظر التهديدات: {', '.join(bl)}.", ", ".join(bl))

    if look and look.score >= 0.2 and not on_official and not brand_rule and not (big and look.score < 0.8):
        w = round(55 * look.score) if look.score >= 0.5 else round(20 * look.score)
        tech = ", ".join(look.techniques) or "similarity"
        add("lookalike_domain", w,
            f"The domain {dom} imitates {look.closest_official or b_en} ({tech}).",
            f"النطاق {dom} يقلّد {look.closest_official or b_ar} ({tech}).", f"score={look.score:.2f} distance={look.distance}")

    if age is not None:
        if age < 7:
            add("very_new_domain", 30, f"The domain was registered only {age} day(s) ago.",
                f"النطاق مسجّل منذ {age} أيام فقط.", f"age_days={age}")
        elif age < 30:
            add("new_domain", 18, f"The domain was registered {age} days ago (less than a month).",
                f"النطاق مسجّل منذ {age} يوماً (أقل من شهر).", f"age_days={age}")
        elif age < 180:
            add("recent_domain", 8, f"The domain is relatively new ({age} days).",
                f"النطاق حديث نسبياً ({age} يوماً).", f"age_days={age}")
        elif age > 5 * 365:
            add("old_domain", -15, f"The domain has existed for over {age // 365} years.",
                f"النطاق موجود منذ أكثر من {age // 365} سنوات.", f"age_days={age}")

    cfs = _days_since(intel.cert_first_seen) if intel and not shared else None
    if cfs is not None and cfs < 14 and (age is None or age >= 7):
        add("new_certificate", 10, f"The first TLS certificate for this domain appeared {cfs} day(s) ago.",
            f"ظهرت أول شهادة أمان لهذا النطاق منذ {cfs} أيام.", f"cert_first_seen={intel.cert_first_seen}")

    # registry takedown / hold
    rd_status = " ".join(str(x) for x in ((intel.raw_rdap or {}).get("status") or [])) if intel and not shared else ""
    if HOLD_STATUS.search(rd_status):
        add("registry_hold", 40, "The domain registry has put this domain on hold or deletion (typical after abuse reports).",
            "وضع سجل النطاقات هذا النطاق قيد التعليق أو الحذف (يحدث عادةً بعد بلاغات إساءة).", rd_status)

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

    # global brand names in the address / title
    label0 = dom.split(".")[0] if dom else ""
    sub = host[: -len(dom)] if dom and host.endswith(dom) else host
    scope = host if not shared else sub
    gm = _KW_RE.search(scope.replace("-", "").replace(".", "")) if not on_official and not established else None
    gb = None
    if gm and gm.group(0) not in label0.replace("-", "") or (gm and shared):
        gb = GLOBAL_BRANDS[gm.group(0)]
        add("brand_in_hostname", 25, f"The address contains the name \"{gb}\" but is not a {gb} website ({dom}).",
            f"يحتوي العنوان على اسم «{gb}» لكنه ليس موقعاً تابعاً لـ{gb} ({dom}).", host)
    elif gm and label0 != gm.group(0):  # combosquat in the registrable label itself, e.g. coinbase-secured.com
        gb = GLOBAL_BRANDS[gm.group(0)]
        add("brand_in_hostname", 25, f"The domain {dom} uses the name \"{gb}\" but is not an official {gb} domain.",
            f"النطاق {dom} يستخدم اسم «{gb}» لكنه ليس نطاقاً رسمياً لـ{gb}.", host)
    if not gb and not brand_rule and not established:
        tm = _KW_RE.search(" ".join(d.title.lower() for d in ok))
        if tm and (asks & SENSITIVE) and tm.group(0) not in label0:
            gb = GLOBAL_BRANDS[tm.group(0)]
            add("global_brand_login", 30, f"The page uses the {gb} name and asks for sensitive data, but is not on a {gb} domain.",
                f"تستخدم الصفحة اسم {gb} وتطلب بيانات حساسة، لكنها ليست على نطاق تابع لـ{gb}.", tm.group(0))
    bait = sorted(set(HOST_BAIT.findall(scope))) if not established and not on_official else []
    if bait:
        add("bait_words_in_hostname", min(15, 6 * len(bait)), f"The address uses bait words ({', '.join(bait)}).",
            f"يستخدم العنوان كلمات استدراج ({'، '.join(bait)}).", host)

    sens = sorted(asks & (SENSITIVE | {"personal_info"}))
    if sens and not brand_rule:
        w = 25 if asks & {"card", "otp", "emirates_id"} else 18 if "credentials" in asks else 8
        if big:
            w = 0
        if w:
            add("asks_sensitive", w, f"The page asks for {', '.join(ASK_EN[a] for a in sens)} on an unverified site.",
                f"تطلب الصفحة {('، '.join(ASK_AR[a] for a in sens))} على موقع غير موثّق.", ", ".join(sens))
        if shared and asks & SENSITIVE:
            add("sensitive_on_free_host", 15, "Sensitive data is requested on a free hosting page, which real "
                "organisations never do.", "تُطلب بيانات حساسة على صفحة استضافة مجانية، وهذا ما لا تفعله الجهات الرسمية أبداً.", host)
    elif sens and brand_rule:
        add("asks_sensitive", 10, f"It asks for {', '.join(ASK_EN[a] for a in sens)}.",
            f"وتطلب {('، '.join(ASK_AR[a] for a in sens))}.", ", ".join(sens))

    tls_err = next((d.tls.verify_error for d in ok if d.tls and d.tls.verify_error), "")
    if tls_err and asks & SENSITIVE:
        add("tls_error_sensitive", 15, f"The site's security certificate is invalid ({tls_err}) yet it asks for sensitive data.",
            f"شهادة الأمان للموقع غير صالحة ({tls_err}) ومع ذلك يطلب بيانات حساسة.", tls_err)

    sig.extend(extra)

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
    shortener = any(h.kind == "shortener" for h in chain) or registrable(url) in SHORTENERS
    hops = sum(1 for h in chain if h.kind not in ("start", "final"))
    if shortener or hops >= 3:
        add("redirects", 10 if shortener else 8,
            f"The link hides its destination behind {'a URL shortener' if shortener else f'{hops} redirects'}.",
            f"يُخفي الرابط وجهته الحقيقية عبر {'خدمة اختصار روابط' if shortener else f'{hops} عمليات تحويل'}.",
            " -> ".join(h.url for h in chain[:6]))

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

    # ---------------- page gone / dead
    if gone and not ok:
        g = gone[0]
        code = g.http_status or 0
        if shared:
            add("platform_takedown", 20, f"The hosting platform reports this page as removed (HTTP {code}); "
                "free-hosting pages are typically removed after abuse reports.",
                f"تُفيد منصة الاستضافة بأن هذه الصفحة أُزيلت (HTTP {code})؛ عادةً ما تُزال صفحات الاستضافة المجانية بعد بلاغات إساءة.",
                f"HTTP {code} {g.title[:60]}")
        else:
            add("page_gone", 5, f"The page returned HTTP {code} / 'not found' at scan time (it may already be taken down).",
                f"أعادت الصفحة الرمز HTTP {code} / «غير موجودة» وقت الفحص (ربما أُزيلت بالفعل).", f"HTTP {code} {g.title[:60]}")
    elif mode == "domain_only" and not any(x.id == "redirect_to_popular_site" for x in extra):
        nx = any(NXDOMAIN.search(d.error or "") for d in dets)
        registered = bool(intel and ((intel.raw_rdap or {}).get("found") or intel.created or intel.cert_count))
        unreg = bool(intel and (intel.sources or {}).get("rdap") == "not_found" and not shared)
        if unreg:
            add("domain_not_registered", 30, "The domain is not registered (any more): the link points to a site that "
                "was removed or never legitimately existed.",
                "النطاق غير مسجّل (حالياً): الرابط يشير إلى موقع أُزيل أو لم يكن موجوداً بشكل مشروع.", "RDAP not found")
        elif nx and shared:
            add("platform_takedown", 20, f"The free-hosting address {host} no longer exists (likely removed after abuse reports).",
                f"عنوان الاستضافة المجانية {host} لم يعد موجوداً (أُزيل غالباً بعد بلاغات إساءة).", "NXDOMAIN")
        elif nx and registered and not established:
            add("registered_not_resolving", 20, "The domain is registered but no longer resolves (often a pulled scam site).",
                "النطاق مسجّل لكنه لم يعد يعمل (غالباً موقع احتيال تم إيقافه).", "NXDOMAIN, RDAP registered")
        else:
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
