"""Domain helpers shared by every module. Offline PSL (bundled snapshot), private suffixes ON,
so foo.vercel.app -> registrable 'foo.vercel.app' (shared hosts never inherit trust)."""
from __future__ import annotations

from urllib.parse import urlsplit

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_extract_icann = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)

# Hosting platforms where anyone can get a subdomain. Never trust by parent domain.
SHARED_HOSTS = {
    "vercel.app", "netlify.app", "webflow.io", "blogspot.com", "github.io", "pages.dev", "workers.dev",
    "web.app", "firebaseapp.com", "herokuapp.com", "glitch.me", "wixsite.com", "weebly.com",
    "000webhostapp.com", "azurewebsites.net", "cloudfront.net", "amazonaws.com", "appspot.com",
    "repl.co", "replit.app", "onrender.com", "surge.sh", "framer.app", "godaddysites.com",
    "sites.google.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "square.site", "carrd.co",
    "wordpress.com", "tilda.ws", "mystrikingly.com", "my.canva.site", "firebasestorage.googleapis.com",
    # free-subdomain providers (DigitalPlat FreeDomain etc.): parent age is meaningless
    "de5.net", "us.kg", "dpdns.org", "qzz.io", "eu.org", "duckdns.org", "freemyip.com", "no-ip.org", "ddns.net",
    "r2.dev", "fly.dev", "railway.app", "deno.dev", "bubbleapps.io", "typedream.app",
}


def host_of(url_or_host: str) -> str:
    s = url_or_host.strip()
    if "://" not in s:
        s = "http://" + s
    h = (urlsplit(s).hostname or "").lower().rstrip(".")
    try:
        h = h.encode("ascii").decode("idna") if h.startswith("xn--") or ".xn--" in h else h
    except Exception:
        pass
    return h


def registrable(url_or_host: str) -> str:
    """eTLD+1 with private suffixes (foo.vercel.app stays foo.vercel.app)."""
    h = host_of(url_or_host)
    ext = _extract(h)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return h


def registrable_icann(url_or_host: str) -> str:
    """eTLD+1 using ICANN suffixes only (foo.vercel.app -> vercel.app)."""
    ext = _extract_icann(host_of(url_or_host))
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host_of(url_or_host)


def is_shared_host(url_or_host: str) -> bool:
    h = host_of(url_or_host)
    return any(h == s or h.endswith("." + s) for s in SHARED_HOSTS)


def is_official(url_or_host: str, official_domains: list[str]) -> bool:
    """True if host equals or is a subdomain of an official domain, and is not on a shared host."""
    h = host_of(url_or_host)
    if is_shared_host(h):
        return any(h == d.lower() for d in official_domains)
    return any(h == d.lower() or h.endswith("." + d.lower()) for d in official_domains)
