"""Owner: detonator. Make personas look like real browsers (cloakers fingerprint scanners) and
track short first-party timers so delayed JS/meta redirects are waited for.

Passive only: we change what *we* report about ourselves, never what the page does.
"""
from __future__ import annotations

import json
from typing import Any

# Timers / meta refresh due within this many ms after DOMContentLoaded are waited for.
DELAYED_REDIRECT_MS = 6000


def ua_for(persona: str, major: str) -> str:
    if persona == "uae_mobile_ad_click":
        return (f"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/{major}.0.0.0 Mobile Safari/537.36")
    if persona == "desktop":
        return (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/{major}.0.0.0 Safari/537.36")
    return "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def ua_override(persona: str, version: str, accept_language: str) -> dict[str, Any] | None:
    """CDP Emulation.setUserAgentOverride params: consistent UA + client hints (no 'HeadlessChrome')."""
    major = version.split(".")[0] or "131"
    brands = [{"brand": "Chromium", "version": major}, {"brand": "Google Chrome", "version": major},
              {"brand": "Not/A)Brand", "version": "8"}]
    full = [{"brand": "Chromium", "version": version}, {"brand": "Google Chrome", "version": version},
            {"brand": "Not/A)Brand", "version": "8.0.0.0"}]
    if persona == "uae_mobile_ad_click":
        meta = dict(brands=brands, fullVersionList=full, fullVersion=version, platform="Android",
                    platformVersion="14.0.0", architecture="", model="SM-S918B", mobile=True, bitness="",
                    wow64=False, formFactors=["Mobile"])
        return {"userAgent": ua_for(persona, major), "acceptLanguage": accept_language,
                "platform": "Linux armv81", "userAgentMetadata": meta}
    if persona == "desktop":
        meta = dict(brands=brands, fullVersionList=full, fullVersion=version, platform="Windows",
                    platformVersion="15.0.0", architecture="x86", model="", mobile=False, bitness="64",
                    wow64=False, formFactors=["Desktop"])
        return {"userAgent": ua_for(persona, major), "acceptLanguage": accept_language,
                "platform": "Win32", "userAgentMetadata": meta}
    return None  # crawler: announce Googlebot honestly


_INIT = r"""
(() => {
  const CFG = __CFG__;
  const def = (obj, prop, val) => { try { Object.defineProperty(obj, prop, {get: () => val, configurable: true}); } catch (e) {} };
  def(Navigator.prototype, 'webdriver', false);
  if (CFG.languages) def(Navigator.prototype, 'languages', Object.freeze(CFG.languages.slice()));
  if (CFG.touch !== null) def(Navigator.prototype, 'maxTouchPoints', CFG.touch);
  if (CFG.hw) def(Navigator.prototype, 'hardwareConcurrency', CFG.hw);
  if (CFG.mem) def(Navigator.prototype, 'deviceMemory', CFG.mem);
  if (CFG.chrome && !window.chrome) {
    try { window.chrome = {runtime: {}, app: {isInstalled: false}, csi: function () {}, loadTimes: function () {}}; } catch (e) {}
  }
  if (window.top !== window) return;
  // Track short timers so the scanner waits for delayed first-party redirects.
  const pend = new Map();
  const oST = window.setTimeout, oCT = window.clearTimeout;
  window.setTimeout = new Proxy(oST, {apply(t, self, args) {
    const fn = args[0], d = Number(args[1]) || 0;
    let id;
    if (typeof fn === 'function') {
      args[0] = function () { pend.delete(id); return fn.apply(this, arguments); };
    }
    id = Reflect.apply(t, self, args);
    if (d >= 100 && d <= CFG.maxDelay) pend.set(id, Date.now() + d);
    return id;
  }});
  window.clearTimeout = new Proxy(oCT, {apply(t, self, args) { pend.delete(args[0]); return Reflect.apply(t, self, args); }});
  const dcl = () => {
    try { const n = performance.getEntriesByType('navigation')[0];
          if (n && n.domContentLoadedEventEnd) return performance.timeOrigin + n.domContentLoadedEventEnd; } catch (e) {}
    return Date.now();
  };
  Object.defineProperty(window, CFG.probe, {enumerable: false, configurable: false, value: () => {
    const now = Date.now(), cutoff = dcl() + CFG.maxDelay;
    let due = 0;
    for (const [, t] of pend) if (t > now - 50 && t <= cutoff) due = Math.max(due, t);
    try {
      const m = document.querySelector('meta[http-equiv="refresh" i]');
      if (m) { const s = parseFloat(m.getAttribute('content')); if (s >= 0 && s * 1000 <= CFG.maxDelay) {
        const t = dcl() + s * 1000 + 300; if (t > now) due = Math.max(due, t); } }
    } catch (e) {}
    return due ? due - now : 0;
  }});
})();
"""

PROBE = "__ssq_pending_ms"


def init_script(persona: str) -> str:
    if persona == "uae_mobile_ad_click":
        cfg = dict(languages=["ar-AE", "ar", "en-US", "en"], touch=5, hw=8, mem=8, chrome=True)
    elif persona == "desktop":
        cfg = dict(languages=["en-US", "en"], touch=0, hw=8, mem=8, chrome=True)
    else:
        cfg = dict(languages=None, touch=None, hw=None, mem=None, chrome=False)
    cfg.update(maxDelay=DELAYED_REDIRECT_MS, probe=PROBE)
    return _INIT.replace("__CFG__", json.dumps(cfg))
