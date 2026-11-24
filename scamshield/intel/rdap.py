"""Registration data: RDAP (rdap.org -> IANA bootstrap) with WHOIS fallback (python-whois, then raw port 43)."""
from __future__ import annotations

import asyncio
import re
from typing import Any, Optional

import httpx

from ._common import DAY, client, log, parse_dt

RDAP_ORG = "https://rdap.org/domain/{}"
IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
WHOIS_SERVERS = {"ae": "whois.aeda.net", "abudhabi": "whois.nic.abudhabi", "dubai": "whois.nic.dubai"}
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

_bootstrap: Optional[dict] = None


# ------------------------------------------------------------------ RDAP parsing
def _vcard(ent: dict, field: str) -> list[str]:
    out = []
    try:
        for item in ent.get("vcardArray", [None, []])[1]:
            if item and item[0] == field and isinstance(item[3], str) and item[3]:
                out.append(item[3])
    except (IndexError, TypeError):
        pass
    return out


def parse_rdap(j: dict) -> dict:
    created = None
    for ev in j.get("events", []) or []:
        if ev.get("eventAction") == "registration":
            created = ev.get("eventDate")
    registrar, abuse = "", []

    def walk(ents, parent_registrar=False):
        nonlocal registrar
        for ent in ents or []:
            roles = ent.get("roles", []) or []
            if "registrar" in roles:
                fn = _vcard(ent, "fn")
                if fn and not registrar:
                    registrar = fn[0]
            if "abuse" in roles:
                abuse.extend(e.lower() for e in _vcard(ent, "email"))
            walk(ent.get("entities"), "registrar" in roles)

    walk(j.get("entities"))
    ns = sorted({(n.get("ldhName") or "").lower().rstrip(".") for n in j.get("nameservers", []) or []} - {""})
    slim = {k: j.get(k) for k in ("ldhName", "handle", "status", "events", "port43") if j.get(k) is not None}
    return {
        "found": True,
        "via": "rdap",
        "created": created,
        "registrar": registrar,
        "abuse_emails": sorted(set(abuse)),
        "nameservers": ns,
        "raw": slim,
    }


async def _bootstrap_base(c: httpx.AsyncClient, tld: str) -> Optional[str]:
    global _bootstrap
    from scamshield.core import db

    if _bootstrap is None:
        _bootstrap = db.cache_get("intel:iana_rdap_bootstrap")
        if _bootstrap is None:
            r = await c.get(IANA_BOOTSTRAP)
            r.raise_for_status()
            _bootstrap = r.json()
            db.cache_set("intel:iana_rdap_bootstrap", _bootstrap, 7 * DAY)
    for tlds, urls in _bootstrap.get("services", []):
        if tld in tlds and urls:
            https = [u for u in urls if u.startswith("https")]
            return (https or urls)[0]
    return None


async def fetch_rdap(domain: str) -> Optional[dict]:
    """Returns parsed dict, {"found": False} for not-registered, or None if no RDAP available."""
    tld = domain.rsplit(".", 1)[-1]
    async with client() as c:
        try:
            r = await c.get(RDAP_ORG.format(domain), headers={"Accept": "application/rdap+json"})
            if r.status_code == 200:
                return parse_rdap(r.json())
            # rdap.org answers 404 both for "no RDAP for this TLD" and (via redirect) "not found at registry"
            if r.status_code == 404 and str(r.url) != RDAP_ORG.format(domain):
                return {"found": False, "via": "rdap"}
        except Exception as e:
            log.info("rdap.org failed for %s: %r", domain, e)
        base = await _bootstrap_base(c, tld)
        if not base:
            return None  # TLD has no RDAP (e.g. .ae)
        r = await c.get(base.rstrip("/") + "/domain/" + domain, headers={"Accept": "application/rdap+json"})
        if r.status_code == 404:
            return {"found": False, "via": "rdap"}
        r.raise_for_status()
        return parse_rdap(r.json())


# ------------------------------------------------------------------ WHOIS
async def raw_whois(query: str, server: str, timeout: float = 6) -> str:
    async def go():
        reader, writer = await asyncio.open_connection(server, 43)
        writer.write((query + "\r\n").encode())
        await writer.drain()
        data = await reader.read(-1)
        writer.close()
        return data.decode("utf-8", "replace")

    return await asyncio.wait_for(go(), timeout)


NOT_FOUND_RE = re.compile(r"no match|not found|no data found|no entries found|status:\s*free|is available", re.I)
CREATED_KEYS = ("creation date", "created", "created on", "registered on", "registration time",
                "domain registration date", "registered", "create date")


def parse_whois_text(txt: str) -> dict:
    kv: dict[str, list[str]] = {}
    for line in txt.splitlines():
        if ":" not in line or line.lstrip().startswith(("%", "#", ">>>")):
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if v:
            kv.setdefault(k, []).append(v)
    if not kv and NOT_FOUND_RE.search(txt):
        return {"found": False, "via": "whois"}
    if NOT_FOUND_RE.search(txt[:300]) and not any(k in kv for k in ("domain name", "domain")):
        return {"found": False, "via": "whois"}
    created = next((kv[k][0] for k in CREATED_KEYS if k in kv), None)
    registrar = next((kv[k][0] for k in ("registrar", "registrar name", "sponsoring registrar") if k in kv), "")
    ns = sorted({v.split()[0].lower().rstrip(".") for k in ("name server", "nserver", "nameserver") for v in kv.get(k, [])})
    abuse = sorted({e.lower() for k, vs in kv.items() if "abuse" in k for v in vs for e in EMAIL_RE.findall(v)})
    return {"found": True, "via": "whois", "created": created, "registrar": registrar,
            "abuse_emails": abuse, "nameservers": ns, "raw": {"whois_excerpt": txt[:1500]}}


async def fetch_whois(domain: str) -> Optional[dict]:
    tld = domain.rsplit(".", 1)[-1]
    # 1) python-whois in a thread
    try:
        import whois  # python-whois

        w = await asyncio.wait_for(asyncio.to_thread(whois.whois, domain), 7)
        created = w.get("creation_date")
        if w and (created or w.get("registrar") or w.get("name_servers")):
            emails = w.get("emails") or []
            if isinstance(emails, str):
                emails = [emails]
            ns = w.get("name_servers") or []
            if isinstance(ns, str):
                ns = [ns]
            cd = parse_dt(created)
            return {"found": True, "via": "whois", "created": cd.isoformat() if cd else None,
                    "registrar": w.get("registrar") or "",
                    "abuse_emails": sorted({e.lower() for e in emails if "abuse" in e.lower()}),
                    "nameservers": sorted({n.lower().rstrip(".") for n in ns}),
                    "raw": {"whois_excerpt": (getattr(w, "text", "") or "")[:1500]}}
    except Exception as e:
        log.info("python-whois failed for %s: %r", domain, e)
    # 2) raw port-43 whois (known server, else IANA referral)
    server = WHOIS_SERVERS.get(tld)
    if not server:
        txt = await raw_whois(tld, "whois.iana.org")
        m = re.search(r"^whois:\s*(\S+)", txt, re.M)
        server = m.group(1) if m else None
    if not server:
        return None
    return parse_whois_text(await raw_whois(domain, server))


async def registration(domain: str) -> Optional[dict]:
    """RDAP first; WHOIS when RDAP is unavailable or lacks a creation date."""
    rd = None
    try:
        rd = await fetch_rdap(domain)
    except Exception as e:
        log.info("rdap failed for %s: %r", domain, e)
    if rd and (rd.get("found") is False or rd.get("created")):
        return rd
    try:
        wh = await fetch_whois(domain)
    except Exception as e:
        log.info("whois failed for %s: %r", domain, e)
        wh = None
    if rd and wh and wh.get("found"):
        merged = dict(rd)
        for k in ("created", "registrar", "abuse_emails", "nameservers"):
            if not merged.get(k):
                merged[k] = wh.get(k)
        merged["via"] = "rdap+whois"
        return merged
    return wh or rd
