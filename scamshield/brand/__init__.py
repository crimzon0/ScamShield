"""Owner: brand. Which UAE brand does a page claim to be, and is it on that brand's official domain?

Signals: keywords (EN / AR / Arabizi) in title, text, form labels, URL path; favicon/screenshot pHash;
optional LLM. The official-domain check (core.domains.is_official) is never overridden by any signal.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

from scamshield.core.config import settings
from scamshield.core.domains import host_of, is_official, registrable
from scamshield.core.schemas import BrandMatch, Detonation, LookalikeResult

log = logging.getLogger(__name__)

_REG_CACHE: dict = {"mtime": None, "brands": []}


def load_registry() -> list[dict]:
    """Brands from data/registry.json: [{id, category, name_en, name_ar, official_domains, keywords_en, keywords_ar,
    arabizi, phones, short_codes, domain_keywords, sources, verified}]"""
    try:
        p = settings.registry_path
        m = p.stat().st_mtime
        if _REG_CACHE["mtime"] != m:
            _REG_CACHE["brands"] = json.loads(p.read_text(encoding="utf-8"))["brands"]
            _REG_CACHE["mtime"] = m
        return _REG_CACHE["brands"]
    except Exception:
        return []


def fictional_enabled() -> bool:
    """The fictional Sandbox Bank is only matched when SCAMSHIELD_FICTIONAL=1 (tests, local fixture servers)."""
    import os

    return os.environ.get("SCAMSHIELD_FICTIONAL", "").strip() == "1"


def active_brands() -> list[dict]:
    """Registry brands used for matching: fictional brands excluded unless SCAMSHIELD_FICTIONAL=1."""
    fx = fictional_enabled()
    return [b for b in load_registry() if fx or not b.get("fictional")]


def get_brand(brand_id: str) -> dict | None:
    return next((b for b in load_registry() if b.get("id") == brand_id), None)


def official_owner(url_or_host: str) -> dict | None:
    """The registry brand whose official domain covers this host (most specific domain wins), else None."""
    h = host_of(url_or_host)
    best, best_len = None, -1
    for b in active_brands():
        for d in b.get("official_domains", []):
            if is_official(h, [d]) and len(d) > best_len:
                best, best_len = b, len(d)
    return best


def lookalike(domain: str) -> LookalikeResult:
    """Domain-only: edit distance, homoglyphs, punycode/IDN, TLD swap, brand-keyword combosquat vs registry.
    An official domain (or subdomain) scores 0."""
    from .squat import lookalike as _l

    return _l(domain)


async def match_brand(det: Detonation) -> BrandMatch:
    """Never raises. Brand claimed by the page + asks_for + official-domain check + lookalike."""
    try:
        return await _match_brand(det)
    except Exception as e:  # pragma: no cover - defensive
        log.warning("match_brand failed: %s", e)
        try:
            look = lookalike(host_of(det.final_url or det.url))
        except Exception:
            look = None
        return BrandMatch(lookalike=look, evidence=[f"brand matcher error: {e}"])


def _llm_signal(det: Detonation, parts: dict, brands: list[dict]) -> dict | None:
    from scamshield.core.llm import llm_available, llm_json

    if not llm_available():
        return None
    ids = [b["id"] for b in brands if not b.get("fictional")] + ["sandbox_bank"]
    schema = {
        "type": "object",
        "properties": {
            "brand_claimed": {"type": ["string", "null"]},
            "brand_id": {"type": ["string", "null"], "enum": ids + [None]},
            "asks_for": {"type": "array", "items": {"type": "string", "enum": [
                "credentials", "card", "otp", "emirates_id", "payment", "personal_info"]}},
            "language": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        },
        "required": ["brand_claimed", "brand_id", "asks_for", "language", "confidence"],
    }
    forms = "; ".join(f"{f.label or f.placeholder or f.name} ({f.type})" for f in det.form_fields or [])[:1500]
    prompt = (
        "Which UAE organisation (bank, government entity, telecom, courier, airline...) does this web page present "
        "itself as? Pick brand_id from the allowed ids or null if none/unclear. List what sensitive data the page "
        "asks the visitor for. Judge only the page's claim, not whether it is genuine.\n"
        f"Allowed brand ids: {', '.join(ids)}\n"
        f"<page>\nTITLE: {det.title[:300]}\nFORM FIELDS: {forms}\nTEXT: {(det.visible_text or '')[:4000]}\n</page>"
    )
    out = llm_json(prompt, schema)
    if not isinstance(out, dict):
        return None
    if out.get("brand_id") not in ids:
        out["brand_id"] = None
    try:
        out["confidence"] = max(0.0, min(1.0, float(out.get("confidence") or 0)))
    except Exception:
        out["confidence"] = 0.0
    return out


CHALLENGE_HOSTS = {"perfdrive.com", "radwarebotmanager.com", "hcaptcha.com", "challenges.cloudflare.com"}


def _challenge_origin(det: Detonation, url: str) -> str | None:
    try:
        if not url or registrable(url) not in CHALLENGE_HOSTS and host_of(url) not in CHALLENGE_HOSTS:
            return None
        hops = [h.url for h in det.redirect_chain or []] or [det.url]
        for prev in reversed([h for h in hops if h and host_of(h) != host_of(url)]):
            return prev if official_owner(prev) else None
    except Exception:
        return None
    return None


async def _match_brand(det: Detonation) -> BrandMatch:
    from .text import detect_asks, page_parts, score_brands
    from . import visual

    brands = active_brands()
    url = det.final_url or det.url or ""
    host = host_of(url) if url else ""
    look = lookalike(host) if host else None  # full host: subdomain_brand needs the subdomain labels

    parts = page_parts(det)
    asks = detect_asks(" ".join([parts["title"], parts["text"], parts["form"]]), det.form_fields)
    scored = {r["id"]: r for r in score_brands(parts, brands)}

    # visual (favicon / screenshot pHash) - cheap, local, never raises
    for vm in visual.match(det):
        r = scored.setdefault(vm["id"], {"id": vm["id"], "confidence": 0.0, "methods": [], "evidence": [], "hits": 0})
        r["confidence"] = round(1 - (1 - r["confidence"]) * (1 - vm["weight"]), 3)
        r["methods"] = sorted(set(r["methods"]) | {vm["method"]})
        r["evidence"].append(vm["evidence"])
        r["hits"] += 1

    # LLM (optional; None without key)
    llm_used = False
    llm = await asyncio.to_thread(_llm_signal, det, parts, brands) if not settings.offline else None
    if llm:
        llm_used = True
        for a in llm.get("asks_for") or []:
            if a not in asks:
                asks.append(a)
        if llm.get("brand_id"):
            bid = llm["brand_id"]
            w = 0.45 * llm["confidence"]
            r = scored.setdefault(bid, {"id": bid, "confidence": 0.0, "methods": [], "evidence": [], "hits": 0})
            r["confidence"] = round(1 - (1 - r["confidence"]) * (1 - w), 3)
            r["methods"] = sorted(set(r["methods"]) | {"llm"})
            r["evidence"].append(f"LLM: page claims to be '{llm.get('brand_claimed')}' ({llm['confidence']:.2f})")
            r["hits"] += 1

    # domain keyword (from lookalike) as weak brand evidence
    if look and look.brand_id and look.score >= 0.6:
        bid = look.brand_id
        r = scored.setdefault(bid, {"id": bid, "confidence": 0.0, "methods": [], "evidence": [], "hits": 0})
        # an explicit brand claim in the hostname (subdomain/combosquat/homoglyph/IDN) is stronger than a fuzzy one
        w = (0.55 if ("subdomain_brand" in look.techniques or look.score >= 0.85) else 0.3) * look.score
        r["confidence"] = round(1 - (1 - r["confidence"]) * (1 - w), 3)
        r["methods"] = sorted(set(r["methods"]) | {"domain_keyword"})
        r["evidence"].append(f"domain '{look.domain}' resembles {look.closest_official} ({', '.join(look.techniques)})")
        r["hits"] += 1

    ranked = sorted(scored.values(), key=lambda r: (r["confidence"], r["hits"]), reverse=True)

    # Precision rule: if the page is on ANY registry brand's official domain, that owner is the answer
    # (an official site that mentions another brand - u.ae listing TAMM, ENBD mentioning Liv - is not impersonation).
    # Bot-challenge interstitials (WAF) reached by redirect from an official domain inherit that domain:
    # e.g. mashreqsecurities.com -> validate.perfdrive.com (Radware). Never applied for other hosts (open redirects).
    challenge_from = _challenge_origin(det, url)
    if challenge_from:
        url = challenge_from
    owner = official_owner(url) if url else None
    chosen = None
    if owner is not None:
        chosen = scored.get(owner["id"]) or {"id": owner["id"], "confidence": 0.5, "methods": ["official_domain"],
                                             "evidence": [], "hits": 0}
        others = [r["id"] for r in ranked if r["id"] != owner["id"]][:3]
        if others:
            chosen["evidence"] = chosen["evidence"] + [f"also mentions: {', '.join(others)} (on official {owner['id']} domain)"]
    elif ranked and ranked[0]["confidence"] >= 0.2:
        chosen = ranked[0]
        if len(ranked) > 1:
            chosen["evidence"] = chosen["evidence"] + [f"runner-up: {ranked[1]['id']} ({ranked[1]['confidence']:.2f})"]

    if chosen is None:
        return BrandMatch(asks_for=asks, lookalike=look, llm_used=llm_used,
                          evidence=[r["evidence"][0] for r in ranked[:2] if r["evidence"]])
    if challenge_from:
        chosen["evidence"] = list(chosen["evidence"]) + [f"final host is a bot-challenge page reached from official {host_of(url)}"]
    b = get_brand(chosen["id"]) or {}
    off = list(b.get("official_domains", []))
    return BrandMatch(
        brand_id=chosen["id"], name_en=b.get("name_en", ""), name_ar=b.get("name_ar", ""),
        confidence=float(chosen["confidence"]), methods=list(chosen["methods"]), evidence=list(chosen["evidence"]),
        official_domains=off, is_official_domain=bool(url) and is_official(url, off),
        asks_for=asks, lookalike=look, llm_used=llm_used,
    )
