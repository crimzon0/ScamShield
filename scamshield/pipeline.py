"""Owner: verdict. Orchestrates detonate -> enrich -> match_brand -> score -> save.

Concurrency: personas detonate in parallel; enrich(input domain) runs alongside detonation; if the final
domain differs it is re-enriched. A global timeout guard falls back to a domain-only verdict.
Every stage is wrapped: an error is never a verdict, and scan_url never raises.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone

from scamshield.core import db
from scamshield.core.domains import registrable
from scamshield.core.schemas import (BrandMatch, CloakDiff, Detonation, Intel, LookalikeResult, ScanResult, Signal,
                                     Verdict)

log = logging.getLogger("scamshield.pipeline")

DEFAULT_PERSONAS: tuple[str, ...] = ("uae_mobile_ad_click",)
SCAN_TIMEOUT = 40.0  # global guard (seconds)
ENRICH_TIMEOUT = 20.0
CACHE_TTL = 6 * 3600  # reuse a scan of the same URL within this window


def _normalize(url: str) -> str:
    u = (url or "").strip()
    if u and "://" not in u:
        u = "http://" + u
    return u


async def _guard(coro, timeout: float, default, stage: str):
    try:
        return await asyncio.wait_for(coro, timeout)
    except Exception as e:
        log.warning("stage %s failed: %s", stage, e)
        return default() if callable(default) else default


async def _detonate(url: str, persona: str, scan_id: str) -> Detonation:
    from scamshield.detonate import detonate

    try:
        return await detonate(url, persona, scan_id=scan_id)
    except Exception as e:
        return Detonation(url=url, persona=persona, status="error", final_url="", error=str(e)[:300])


async def _enrich(domain: str) -> Intel:
    from scamshield.intel import enrich

    if not domain:
        return Intel(domain="", sources={"enrich": "unavailable"})
    return await _guard(enrich(domain), ENRICH_TIMEOUT,
                        lambda: Intel(domain=domain, registrable_domain=domain, sources={"enrich": "unavailable"}),
                        "enrich")


def _blocklist(url: str) -> list[str]:
    try:
        from scamshield.intel import blocklist_hits

        return list(blocklist_hits(url) or [])
    except Exception:
        return []


_FP_DIRS = ("detonate", "intel", "brand", "score")


def pipeline_fingerprint() -> str:
    """Hash of source mtimes of the scoring-relevant modules + registry. Cached scans are reused only when
    the fingerprint matches (so results produced by stubs/older code are never served)."""
    import hashlib
    from pathlib import Path

    from scamshield.core.config import settings

    root = Path(__file__).resolve().parent
    files = [root / "pipeline.py", settings.registry_path]
    for d in _FP_DIRS:
        files += sorted((root / d).rglob("*.py"))
    h = hashlib.sha1()
    for f in files:
        try:
            h.update(f"{f.name}:{f.stat().st_mtime_ns}:{f.stat().st_size};".encode())
        except OSError:
            pass
    return h.hexdigest()[:16]


def _transient(res: ScanResult) -> bool:
    v = res.verdict
    if any(r.id in ("scan_error", "scoring_error") for r in v.reasons):
        return True
    if v.mode == "domain_only" and (not res.detonations or any(d.status in ("timeout", "error") for d in res.detonations)):
        return True
    if res.intel and any((res.intel.sources or {}).get(k) == "unavailable" for k in ("enrich", "rdap")):
        return True
    return False


def _recent(url: str, ttl: int):
    try:
        row = db.connect().execute(
            "SELECT result_json, created_at FROM scans WHERE url=? ORDER BY created_at DESC LIMIT 1", (url,)
        ).fetchone()
        if not row:
            return None
        created = datetime.fromisoformat(row["created_at"])
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - created).total_seconds() > ttl:
            return None
        res = ScanResult.model_validate_json(row["result_json"])
        if db.cache_get(f"scanfp:{res.scan_id}") != pipeline_fingerprint() or _transient(res):
            return None
        return res
    except Exception:
        return None


async def scan_url(url: str, personas: tuple[str, ...] = DEFAULT_PERSONAS, save: bool = True,
                   force: bool = False, timeout: float = SCAN_TIMEOUT, cache_ttl: int = CACHE_TTL) -> ScanResult:
    """Never raises. Always returns a ScanResult with a Verdict."""
    scan_id = uuid.uuid4().hex[:12]
    url_n = _normalize(url)
    try:
        if not force and save:
            hit = _recent(url_n, cache_ttl)
            if hit is not None:
                return hit
        state: dict = {"dets": [], "intel": None}
        try:
            res = await asyncio.wait_for(_full(scan_id, url_n, tuple(personas) or DEFAULT_PERSONAS, state), timeout)
        except Exception as e:  # timeout or unexpected -> domain-only fallback with whatever we have
            log.warning("scan %s fell back to domain-only: %s", url_n, e)
            res = await _domain_only(scan_id, url_n, state, reason=type(e).__name__)
    except Exception as e:
        res = _error_result(scan_id, url_n, e)
    if save:
        try:
            db.save_scan(res)
            db.cache_set(f"scanfp:{res.scan_id}", pipeline_fingerprint(), ttl=max(cache_ttl, 3600))
        except Exception as e:
            log.warning("save_scan failed: %s", e)
    return res


async def _full(scan_id: str, url: str, personas: tuple[str, ...], state: dict) -> ScanResult:
    from scamshield.brand import lookalike, match_brand
    from scamshield.detonate import cloak_diff
    from scamshield.score import score

    in_dom = registrable(url)
    det_task = asyncio.gather(*[_detonate(url, p, scan_id) for p in personas])
    enr_task = asyncio.ensure_future(_enrich(in_dom))
    bl_task = asyncio.ensure_future(asyncio.to_thread(_blocklist, url))
    dets = list(await det_task)
    state["dets"] = dets
    intel = await enr_task
    state["intel"] = intel

    ok = [d for d in dets if d.status == "ok"]
    final = next((d.final_url for d in ok if d.final_url), None) or next((d.final_url for d in dets if d.final_url), url)
    dom = registrable(final)
    bl = await _guard(bl_task, 5, list, "blocklist")
    if final != url:
        bl += await _guard(asyncio.to_thread(_blocklist, final), 5, list, "blocklist")
    in_intel, in_look = intel, None
    if dom and dom != in_dom:
        in_intel = intel.model_copy(deep=True)
        intel = await _enrich(dom)
        state["intel"] = intel
        in_look = await _guard(asyncio.to_thread(lookalike, in_dom), 10, None, "lookalike")
        in_intel.blocklist_hits = list(dict.fromkeys((in_intel.blocklist_hits or []) + bl))
    intel.blocklist_hits = list(dict.fromkeys((intel.blocklist_hits or []) + bl))

    brand = None
    if ok:
        best = max(ok, key=lambda d: len(d.visible_text or ""))
        brand = await _guard(match_brand(best), 20, None, "match_brand")
    look = await _guard(asyncio.to_thread(lookalike, dom), 10, None, "lookalike")
    if brand and look is None:
        look = brand.lookalike
    cloak = None
    if len(dets) > 1:
        try:
            cloak = cloak_diff(dets)
        except Exception:
            cloak = None
    extra = await _helpline_signals(ok, brand, final)
    v = score(scan_id, url, dets, intel, brand, look, cloak, extra=extra,
              input_intel=in_intel if in_intel is not intel else None, input_look=in_look)
    return ScanResult(scan_id=scan_id, url=url, detonations=dets, cloak=cloak, intel=intel, brand=brand,
                      lookalike=look, verdict=v)


async def _helpline_signals(ok: list[Detonation], brand, final: str) -> list[Signal]:
    """Fake helpline numbers on a page that claims a brand (helpline.phones_on_page)."""
    try:
        from scamshield.core.domains import is_official
        from scamshield.score import BRAND_THRESHOLD

        if not ok or not brand or not brand.brand_id or brand.confidence < BRAND_THRESHOLD:
            return []
        if is_official(final, brand.official_domains or []):
            return []
        from scamshield.helpline import phones_on_page

        best = max(ok, key=lambda d: len(d.visible_text or ""))
        found = await asyncio.wait_for(asyncio.to_thread(phones_on_page, best, brand.brand_id, None, True), 10)
        out = []
        for f in found or []:
            if f.status == "likely_scam":
                out.append(Signal(id="fake_helpline_on_page", weight=15,
                                  en=f.reasons_en or f"Unofficial phone number {f.number_e164} shown as a helpline.",
                                  ar=f.reasons_ar or f"رقم هاتف غير رسمي {f.number_e164} معروض كخط مساعدة.",
                                  evidence=f.number_e164))
        return out[:3]
    except Exception as e:
        log.warning("helpline check failed: %s", e)
        return []


async def _domain_only(scan_id: str, url: str, state: dict, reason: str) -> ScanResult:
    from scamshield.brand import lookalike
    from scamshield.score import score

    dets = state.get("dets") or [Detonation(url=url, status="timeout", error=f"scan guard: {reason}")]
    final = next((d.final_url for d in dets if d.final_url), url)
    dom = registrable(final)
    intel = state.get("intel") or await _enrich(dom)
    if not intel.blocklist_hits:
        intel.blocklist_hits = _blocklist(url)
    look = await _guard(asyncio.to_thread(lookalike, dom), 5, None, "lookalike")
    # force domain-only: ignore page content we may have partially collected
    dets_do = [d if d.status != "ok" else d.model_copy(update={"status": "timeout"}) for d in dets]
    v = score(scan_id, url, dets_do, intel, None, look, None)
    return ScanResult(scan_id=scan_id, url=url, detonations=dets, intel=intel, lookalike=look, verdict=v)


def _error_result(scan_id: str, url: str, e: Exception) -> ScanResult:
    try:
        dom = registrable(url)
    except Exception:
        dom = ""
    v = Verdict(scan_id=scan_id, url=url, final_url=url, registrable_domain=dom, score=50, label="suspicious",
                mode="domain_only",
                reasons=[Signal(id="scan_error", weight=0, en="The link could not be analysed; treat it with caution.",
                                ar="تعذّر تحليل الرابط؛ يرجى التعامل معه بحذر.", evidence=str(e)[:200])],
                summary_en="Suspicious (50/100): analysis failed, verify via official channels.",
                summary_ar="مشبوه (50/100): فشل التحليل، تحقّق عبر القنوات الرسمية.")
    return ScanResult(scan_id=scan_id, url=url, verdict=v)
