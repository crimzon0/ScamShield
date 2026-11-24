"""DNS (A/NS/MX via dnspython) and IP -> ASN/org/country (Team Cymru DNS, fallback ip-api.com)."""
from __future__ import annotations

import ipaddress
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.resolver

from ._common import client, log

DNS_TIMEOUT = 3.0


def _resolver() -> dns.asyncresolver.Resolver:
    try:
        r = dns.asyncresolver.Resolver()
        if not r.nameservers:
            raise dns.resolver.NoResolverConfiguration
    except Exception:
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = ["1.1.1.1", "8.8.8.8"]
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    return r


async def _q(r, name: str, rtype: str) -> tuple[list[str], bool]:
    """Returns (records, nxdomain)."""
    try:
        ans = await r.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return [], True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return [], False
    out = []
    for rr in ans:
        if rtype == "MX":
            out.append(str(rr.exchange).lower().rstrip("."))
        elif rtype == "TXT":
            out.append(b"".join(rr.strings).decode("utf-8", "replace"))
        else:
            out.append(rr.to_text().lower().rstrip("."))
    return sorted(set(out)), False


async def fetch_dns(host: str, registrable_domain: str) -> dict:
    r = _resolver()
    a, nx = await _q(r, host, "A")
    if not a and not host.startswith("www."):
        a2, _ = await _q(r, "www." + host, "A")
        a = a2
    ns, nx2 = await _q(r, registrable_domain, "NS")
    mx, _ = await _q(r, registrable_domain, "MX")
    return {"a": a, "ns": ns, "mx": mx, "nxdomain": bool(nx and nx2 and not a)}


async def _cymru(ip: str) -> Optional[dict]:
    r = _resolver()
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        q = ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
    txt, _ = await _q(r, q, "TXT")
    if not txt:
        return None
    parts = [p.strip() for p in txt[0].split("|")]
    asn = parts[0].split()[0]
    country = parts[2] if len(parts) > 2 else ""
    org = ""
    txt2, _ = await _q(r, f"AS{asn}.asn.cymru.com", "TXT")
    if txt2:
        p2 = [p.strip() for p in txt2[0].split("|")]
        org = p2[-1] if len(p2) >= 5 else ""
    return {"asn": f"AS{asn}", "asn_org": org, "country": country, "prefix": parts[1] if len(parts) > 1 else "",
            "via": "cymru"}


async def _ipapi(ip: str) -> Optional[dict]:
    async with client(5) as c:
        r = await c.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode,as,org,isp")
        j = r.json()
    if j.get("status") != "success":
        return None
    asn = (j.get("as") or "").split(" ", 1)
    return {"asn": asn[0], "asn_org": (asn[1] if len(asn) > 1 else "") or j.get("org") or j.get("isp", ""),
            "country": j.get("countryCode", ""), "prefix": "", "via": "ip-api"}


async def fetch_asn(ip: str) -> Optional[dict]:
    try:
        if ipaddress.ip_address(ip).is_private:
            return {"asn": "", "asn_org": "private address", "country": "", "prefix": "", "via": "local"}
    except ValueError:
        return None
    try:
        v = await _cymru(ip)
        if v:
            return v
    except Exception as e:
        log.info("cymru failed for %s: %r", ip, e)
    return await _ipapi(ip)
