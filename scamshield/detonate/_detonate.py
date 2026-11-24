"""Owner: detonator. Passive headless-Chromium detonation of one URL as one persona.

Safety: downloads disabled, popups closed, dialogs dismissed, service workers blocked; we never
type into or submit forms. Page text is captured as data only.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from scamshield.core.config import settings
from scamshield.core.domains import host_of
from scamshield.core.schemas import Detonation, FormField, Persona, RedirectHop, TLSInfo, utcnow

from . import _browser, _stealth

MOBILE_UA = ("Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/131.0.0.0 Mobile Safari/537.36")
DESKTOP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/131.0.0.0 Safari/537.36")
GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

PERSONA_CONFIG: dict[str, dict[str, Any]] = {
    "uae_mobile_ad_click": {
        "context": dict(user_agent=MOBILE_UA, viewport={"width": 390, "height": 844}, device_scale_factor=2,
                        is_mobile=True, has_touch=True, locale="ar-AE", timezone_id="Asia/Dubai",
                        extra_http_headers={"Accept-Language": "ar-AE,ar;q=0.9,en;q=0.8"}),
        "referer": "https://www.google.com/",
    },
    "desktop": {
        "context": dict(user_agent=DESKTOP_UA, viewport={"width": 1366, "height": 900}, locale="en-US",
                        timezone_id="Asia/Dubai", extra_http_headers={"Accept-Language": "en-US,en;q=0.9"}),
        "referer": None,
    },
    "crawler": {
        "context": dict(user_agent=GOOGLEBOT_UA, viewport={"width": 1366, "height": 900}, locale="en-US",
                        timezone_id="UTC", extra_http_headers={"Accept-Language": "en-US,en;q=0.9"}),
        "referer": None,
    },
}
PERSONAS: tuple[str, ...] = tuple(PERSONA_CONFIG)

SHORTENERS = {
    "bit.ly", "bitly.com", "t.ly", "tinyurl.com", "goo.gl", "cutt.ly", "rb.gy", "is.gd", "ow.ly", "t.co",
    "rebrand.ly", "shorturl.at", "tiny.cc", "s.id", "lnkd.in", "buff.ly", "v.gd", "shorte.st", "bl.ink",
    "short.io", "tr.ee", "qrco.de", "urlz.fr", "linktr.ee", "surl.li", "u.to", "clck.ru", "did.li",
}

DEAD_ERRORS = (
    "ERR_NAME_NOT_RESOLVED", "ERR_NAME_RESOLUTION_FAILED", "ERR_CONNECTION_REFUSED", "ERR_CONNECTION_RESET",
    "ERR_CONNECTION_CLOSED", "ERR_CONNECTION_FAILED", "ERR_CONNECTION_TIMED_OUT", "ERR_ADDRESS_UNREACHABLE",
    "ERR_ADDRESS_INVALID", "ERR_INTERNET_DISCONNECTED", "ERR_EMPTY_RESPONSE", "ERR_TUNNEL_CONNECTION_FAILED",
    "ERR_NETWORK_CHANGED", "ERR_DNS_",
)
_BAD_SCHEMES = ("data:", "about:", "javascript:", "file:", "blob:", "chrome:", "view-source:", "mailto:",
                "tel:", "ftp:", "intent:", "ws:", "wss:", "vbscript:")

TEXT_CAP = 20_000
DOM_CAP = 5_000_000
FAVICON_CAP = 256 * 1024
SCREENSHOT_MAX_H = 10_000
SETTLE_QUIET_S = 1.5
_IN_USE: set[str] = set()
_CHALLENGE_RE = re.compile(r"^(Just a moment|Attention Required|لحظة|DDoS-Guard|Checking your browser)", re.I)  # wait this long without a new main-frame navigation before capturing


def is_shortener(url: str) -> bool:
    h = host_of(url)
    return h in SHORTENERS or (h.startswith("www.") and h[4:] in SHORTENERS)


def normalize_url(url: str) -> tuple[str, str]:
    """-> (normalized_url, error_reason). error_reason non-empty means do not load."""
    u = (url or "").strip()
    if not u:
        return u, "empty url"
    low = u.lower()
    if "://" in u:
        scheme = low.split("://", 1)[0]
        if scheme not in ("http", "https"):
            return u, f"unsupported scheme: {scheme}"
    elif low.startswith(_BAD_SCHEMES):
        return u, f"unsupported scheme: {low.split(':', 1)[0]}"
    else:
        u = "http://" + u.lstrip("/")
    try:
        if not urlsplit(u).hostname:
            return u, "no host in url"
    except Exception as e:  # malformed port etc.
        return u, f"malformed url: {e}"
    return u, ""


def _classify_error(msg: str) -> str:
    if any(e in msg for e in DEAD_ERRORS):
        return "dead"
    if "Timeout" in msg or "ERR_TIMED_OUT" in msg:
        return "timeout"
    return "error"


def _short_err(msg: str) -> str:
    m = re.search(r"net::ERR_[A-Z_]+", msg)
    if m:
        return m.group(0)
    return msg.strip().splitlines()[0][:300] if msg.strip() else "unknown error"


def _ts(v: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(v), tz=timezone.utc) if v else None
    except Exception:
        return None


def _san_sync(host: str, port: int, timeout: float) -> tuple[list[str], str, dict]:
    """Verified TLS handshake via stdlib -> (SAN list, verify_error, peercert)."""
    try:
        try:
            import certifi

            ctx = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert() or {}
                san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
                return san, "", cert
    except ssl.SSLCertVerificationError as e:
        return [], f"certificate verification failed: {e.verify_message or e}", {}
    except Exception:
        return [], "", {}


class _Run:
    """Mutable capture state, so a hard timeout can still return what was collected."""

    def __init__(self, det: Detonation, out_dir: Path):
        self.det = det
        self.out_dir = out_dir
        self.hops: list[dict[str, Any]] = []  # {url,status,kind(None until known),at}
        self.last_nav = time.monotonic()
        self.main_response = None
        self.notes: list[str] = []

    def add_hop(self, url: str, status: int | None, kind: str | None) -> None:
        self.hops.append({"url": url, "status": status, "kind": kind, "at": utcnow()})
        self.last_nav = time.monotonic()

    def chain(self, final_url: str, final_status: int | None) -> list[RedirectHop]:
        out: list[RedirectHop] = []
        hops = list(self.hops)
        for i, h in enumerate(hops):
            last = i == len(hops) - 1
            kind = h["kind"]
            if last:
                kind = "start" if (self.det.status == "dead" and len(hops) == 1) else "final"
            elif kind is None:
                kind = "js"  # a document that was replaced without a recognised mechanism
            if kind in ("http", "meta", "js") and is_shortener(h["url"]):
                kind = "shortener"
            out.append(RedirectHop(url=h["url"], status=h["status"], kind=kind, at=h["at"]))
        if not out:
            out.append(RedirectHop(url=final_url or self.det.url, status=final_status, kind="start",
                                   at=self.det.started_at))
        return out


async def _attach_listeners(run: _Run, context, page, ua_override: dict | None = None) -> None:
    def on_response(resp):
        try:
            req = resp.request
            if not req.is_navigation_request() or resp.frame != page.main_frame:
                return
            st = resp.status
            if 300 <= st < 400 and resp.headers.get("location"):
                run.add_hop(resp.url, st, "http")
            else:
                run.add_hop(resp.url, st, None)
                run.main_response = resp
        except Exception:
            pass

    def on_frame_nav(frame):
        try:
            if frame == page.main_frame:
                run.last_nav = time.monotonic()
        except Exception:
            pass

    page.on("response", on_response)
    page.on("framenavigated", on_frame_nav)
    page.on("dialog", lambda d: asyncio.ensure_future(_safe(d.dismiss())))
    page.on("download", lambda d: asyncio.ensure_future(_safe(d.cancel())))

    def on_new_page(p):
        if p != page:
            run.notes.append(f"popup blocked: {p.url}"[:300])
            asyncio.ensure_future(_safe(p.close()))

    context.on("page", on_new_page)

    # Chromium CDP tells us *why* the main frame navigates (meta refresh vs script).
    try:
        cdp = await context.new_cdp_session(page)
        if ua_override:  # consistent UA + client hints (hides "HeadlessChrome" brand)
            await _safe(cdp.send("Emulation.setUserAgentOverride", ua_override), 3)
        await cdp.send("Page.enable")
        tree = await cdp.send("Page.getFrameTree")
        main_id = tree["frameTree"]["frame"]["id"]

        def on_requested(params):
            try:
                if params.get("frameId") != main_id:
                    return
                reason = params.get("reason", "")
                kind = {"metaTagRefresh": "meta", "httpHeaderRefresh": "meta",
                        "scriptInitiated": "js"}.get(reason)
                if kind and run.hops and run.hops[-1]["kind"] is None:
                    run.hops[-1]["kind"] = kind
                run.last_nav = time.monotonic()
            except Exception:
                pass

        cdp.on("Page.frameRequestedNavigation", on_requested)
    except Exception:
        pass


async def _safe(coro, timeout: float | None = None, default=None):
    try:
        if timeout is not None:
            return await asyncio.wait_for(coro, timeout)
        return await coro
    except Exception:
        return default


_FORMS_JS = r"""
() => {
  const out = [];
  const els = document.querySelectorAll('input, select, textarea');
  for (const el of els) {
    const type = (el.getAttribute('type') || el.tagName).toLowerCase();
    if (['hidden','submit','button','image','reset'].includes(type)) continue;
    let label = '';
    try { if (el.labels && el.labels.length) label = el.labels[0].innerText; } catch (e) {}
    if (!label) label = el.getAttribute('aria-label') || '';
    if (!label) { const l = el.closest('label'); if (l) label = l.innerText; }
    out.push({name: el.getAttribute('name') || el.id || '', type: type,
              label: (label || '').trim().slice(0, 200),
              placeholder: (el.getAttribute('placeholder') || '').slice(0, 200),
              autocomplete: el.getAttribute('autocomplete') || '',
              inputmode: el.getAttribute('inputmode') || ''});
    if (out.length >= 100) break;
  }
  return out;
}
"""

_META_JS = r"""
() => {
  const icon = document.querySelector('link[rel~="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]');
  return {lang: (document.documentElement && document.documentElement.lang) || '',
          title: document.title || '',
          text: document.body ? document.body.innerText : '',
          icon: icon ? icon.href : '',
          height: Math.max(document.body ? document.body.scrollHeight : 0,
                           document.documentElement ? document.documentElement.scrollHeight : 0)};
}
"""

_FAVICON_EXT = {"image/png": "png", "image/x-icon": "ico", "image/vnd.microsoft.icon": "ico",
                "image/svg+xml": "svg", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp"}


async def _capture(run: _Run, context, page, deadline: float) -> None:
    det = run.det

    def left() -> float:
        return max(0.5, deadline - time.monotonic())

    final_url = page.url
    if not final_url or final_url.startswith(("about:", "chrome-error:")):
        final_url = run.hops[-1]["url"] if run.hops else det.url
    det.final_url = final_url
    resp = run.main_response
    det.http_status = resp.status if resp is not None else (run.hops[-1]["status"] if run.hops else None)

    # Screenshot first: it is the most important police evidence.
    shot = run.out_dir / "screenshot.png"
    meta = await _safe(page.evaluate(_META_JS), min(3, left()), {}) or {}
    height = int(meta.get("height") or 0)
    vp = page.viewport_size or {"width": 1366, "height": 900}
    if height > SCREENSHOT_MAX_H:
        ok = await _safe(page.screenshot(path=str(shot), full_page=True, timeout=min(5, left()) * 1000,
                                         clip={"x": 0, "y": 0, "width": vp["width"], "height": SCREENSHOT_MAX_H}),
                         min(6, left()))
    else:
        ok = await _safe(page.screenshot(path=str(shot), full_page=True, timeout=min(5, left()) * 1000),
                         min(6, left()))
    if ok is None:  # full page failed (e.g. huge/slow) -> viewport only
        ok = await _safe(page.screenshot(path=str(shot), timeout=min(3, left()) * 1000), min(4, left()))
    if shot.exists() and shot.stat().st_size > 0:
        det.screenshot_path = str(shot)

    det.title = str(meta.get("title") or "")[:500]
    det.lang = str(meta.get("lang") or "")[:20]
    det.visible_text = str(meta.get("text") or "")[:TEXT_CAP]

    html = await _safe(page.content(), min(3, left()), None)
    if html:
        dom = run.out_dir / "dom.html"
        try:
            dom.write_text(html[:DOM_CAP], encoding="utf-8", errors="replace")
            det.dom_path = str(dom)
        except Exception:
            pass

    fields: list[FormField] = []
    for fr in page.frames[:10]:
        rows = await _safe(fr.evaluate(_FORMS_JS), min(2, left()), []) or []
        for r in rows:
            t = str(r.get("type", ""))
            hint = (str(r.get("autocomplete", "")) + " " + str(r.get("inputmode", ""))).strip()
            if hint and t in ("text", "tel", "number", "input"):
                if "one-time-code" in hint:
                    t = "otp"
                elif "cc-number" in hint:
                    t = "card"
            fields.append(FormField(name=str(r.get("name", ""))[:100], type=t[:30],
                                    label=str(r.get("label", ""))[:200], placeholder=str(r.get("placeholder", ""))[:200]))
    det.form_fields = fields[:100]

    # Favicon (for the brand teammate's hashing). Small, size-capped, via the context's request API.
    icon = str(meta.get("icon") or "") or urljoin(det.final_url, "/favicon.ico")
    if icon.startswith(("http://", "https://")):
        det.favicon_url = icon
        r = await _safe(context.request.get(icon, timeout=min(3, left()) * 1000, max_redirects=3,
                                            fail_on_status_code=False), min(4, left()))
        if r is not None:
            try:
                ct = (r.headers.get("content-type") or "").split(";")[0].strip().lower()
                if r.ok and (ct.startswith("image/") or icon.lower().endswith(".ico")):
                    body = await _safe(r.body(), min(3, left()), b"") or b""
                    if 0 < len(body) <= FAVICON_CAP:
                        ext = _FAVICON_EXT.get(ct, "ico" if icon.lower().endswith(".ico") else "img")
                        fp = run.out_dir / f"favicon.{ext}"
                        fp.write_bytes(body)
                        det.favicon_path = str(fp)
            except Exception:
                pass
            await _safe(r.dispose(), 1)

    # TLS
    if resp is not None and det.final_url.startswith("https://"):
        sd = await _safe(resp.security_details(), min(2, left()), None)
        if sd:
            det.tls = TLSInfo(issuer=sd.get("issuer") or "", subject=sd.get("subjectName") or "",
                              valid_from=_ts(sd.get("validFrom")), valid_to=_ts(sd.get("validTo")),
                              protocol=sd.get("protocol") or "")
        if not settings.offline:
            sp = urlsplit(det.final_url)
            san, verr, _ = await _safe(asyncio.to_thread(_san_sync, sp.hostname or "", sp.port or 443,
                                                         min(3, left())), min(4, left()), ([], "", {}))
            if det.tls is None and (san or verr):
                det.tls = TLSInfo()
            if det.tls is not None:
                det.tls.san = san[:100]
            if verr and det.tls is not None:
                det.tls.verify_error = verr[:300]
                run.notes.append(f"tls certificate does not verify: {verr}"[:300])


async def _run(run: _Run, url: str, persona: str, referer: str | None, budget: float) -> None:
    det = run.det
    start = time.monotonic()
    deadline = start + budget
    capture_reserve = min(4.0, budget * 0.3)
    browser = await _browser.get_browser()
    cfg = PERSONA_CONFIG[persona]
    version = str(getattr(browser, "version", "") or "131.0.0.0")
    copts = dict(cfg["context"])
    copts["user_agent"] = _stealth.ua_for(persona, version.split(".")[0])
    copts["screen"] = dict(copts["viewport"])
    context = await browser.new_context(
        **copts, accept_downloads=False, ignore_https_errors=True, java_script_enabled=True,
        service_workers="block", record_har_path=str(run.out_dir / "page.har"), record_har_content="omit",
        permissions=[],
    )
    try:
        await context.add_init_script(_stealth.init_script(persona))
        page = await context.new_page()
        accept_lang = copts.get("extra_http_headers", {}).get("Accept-Language", "")
        await _attach_listeners(run, context, page, _stealth.ua_override(persona, version, accept_lang))
        nav_err = ""
        goto_timeout = max(1.0, budget - capture_reserve - 1.0)
        try:
            await page.goto(url, wait_until="load", timeout=goto_timeout * 1000, referer=referer)
        except Exception as e:  # noqa: BLE001
            nav_err = str(e)
            # "Download is starting" / aborted while a client redirect continues are not fatal
            if "ERR_ABORTED" in nav_err or "interrupted by another navigation" in nav_err:
                if run.main_response is not None:
                    nav_err = ""
        if nav_err:
            kind = _classify_error(nav_err)
            if kind == "dead" and run.main_response is None and len(run.hops) <= 1:
                det.status = "dead"
                det.error = _short_err(nav_err)
                if not run.hops:
                    run.add_hop(url, None, "start")
                det.final_url = url
                return
            if kind == "dead":  # died mid-chain: a hop worked, the last did not
                det.status = "dead"
            else:
                det.status = "timeout" if kind == "timeout" else "error"
            det.error = _short_err(nav_err)
        else:
            # Settle: follow meta/JS redirects until the main frame is quiet or budget runs low.
            await _safe(page.wait_for_load_state("networkidle",
                                                 timeout=max(100, (deadline - capture_reserve - time.monotonic()) * 1000)),
                        max(0.1, min(3.0, deadline - capture_reserve - time.monotonic())))
            # Also wait for short first-party timers / meta refresh (<= ~6 s after DOMContentLoaded).
            waited_timer = False
            while time.monotonic() < deadline - capture_reserve:
                if time.monotonic() - run.last_nav >= SETTLE_QUIET_S:
                    pending = await _safe(page.evaluate(f"() => window.{_stealth.PROBE} ? window.{_stealth.PROBE}() : 0"),
                                          0.5, 0)
                    if not pending or pending <= 0:
                        if not waited_timer:
                            break
                        # a timer just fired: give its navigation a short window to start/commit
                        waited_timer = False
                        run.last_nav = time.monotonic() - SETTLE_QUIET_S + 0.8
                        continue
                    waited_timer = True
                    await asyncio.sleep(min(0.5, max(0.1, pending / 1000)))
                    continue
                await asyncio.sleep(0.2)
            await _safe(page.wait_for_load_state("domcontentloaded", timeout=1000), 1.2)
        await _capture(run, context, page, deadline)
        if det.status == "ok":
            if len(det.visible_text.strip()) < 20 and not det.form_fields:
                det.status = "blank"
            if _CHALLENGE_RE.search(det.title or "") or "cf-chl" in (html_snip := (det.visible_text or "")[:2000])                     or "Verify you are human" in html_snip:
                run.notes.append("anti-bot challenge page (content hidden from scanner)")
    finally:
        await _safe(context.close(), 4)  # writes the HAR
        har = run.out_dir / "page.har"
        if har.exists():
            det.har_path = str(har)


async def detonate(url: str, persona: Persona = "uae_mobile_ad_click", scan_id: str | None = None) -> Detonation:
    """Load url in headless Chromium as persona. Never raises; hard cap settings.detonate_timeout.
    Artifacts under settings.artifacts_dir/<scan_id>/<persona>/. status in ok|dead|blank|timeout|error."""
    if persona not in PERSONA_CONFIG:
        persona = "uae_mobile_ad_click"
    det = Detonation(url=str(url or ""), persona=persona, status="ok")  # type: ignore[arg-type]
    t0 = time.monotonic()
    run: _Run | None = None
    in_use = ""
    try:
        norm, reason = normalize_url(str(url or ""))
        if reason:
            det.status, det.error, det.final_url = "error", reason, ""
            det.redirect_chain = [RedirectHop(url=det.url, kind="start", at=det.started_at)]
            return det
        sid = re.sub(r"[^A-Za-z0-9_.-]", "_", scan_id or ("det-" + uuid.uuid4().hex[:12]))[:80]
        out_dir = Path(settings.artifacts_dir) / sid / persona
        n = 2
        while str(out_dir) in _IN_USE:  # same scan_id+persona running concurrently: don't clobber
            out_dir = Path(settings.artifacts_dir) / sid / f"{persona}-{n}"
            n += 1
        _IN_USE.add(str(out_dir))
        in_use = str(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for old in out_dir.iterdir():  # never report stale artifacts from an earlier run
            try:
                if old.is_file():
                    old.unlink()
            except Exception:
                pass
        run = _Run(det, out_dir)
        budget = max(3.0, float(settings.detonate_timeout))
        async with _browser.semaphore():
            # the cap is per detonation; time queued for a slot is not counted
            t0 = time.monotonic()
            det.started_at = utcnow()
            try:
                await asyncio.wait_for(_run(run, norm, persona, PERSONA_CONFIG[persona]["referer"], budget),
                                       budget + 1.5)
            except asyncio.TimeoutError:
                det.status = "timeout"
                det.error = det.error or f"hard timeout after {budget:.0f}s"
    except Exception as e:  # noqa: BLE001
        if det.status == "ok":
            det.status = "error"
        det.error = det.error or f"{type(e).__name__}: {str(e)[:300]}"
    finally:
        try:
            if run is not None:
                if not det.final_url:
                    det.final_url = run.hops[-1]["url"] if run.hops else det.url
                det.redirect_chain = run.chain(det.final_url, det.http_status)
                det.notes = [n[:300] for n in run.notes][:20]
                if det.screenshot_path is None:
                    shot = run.out_dir / "screenshot.png"
                    if shot.exists() and shot.stat().st_size > 0:
                        det.screenshot_path = str(shot)
                har = run.out_dir / "page.har"
                if det.har_path is None and har.exists():
                    det.har_path = str(har)
        except Exception:
            pass
        _IN_USE.discard(in_use)
        det.finished_at = utcnow()
        det.duration_ms = int((time.monotonic() - t0) * 1000)
    return det
