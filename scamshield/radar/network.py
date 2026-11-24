"""Domain networks: which scanned / radar domains share infrastructure with `domain`?
Links: same IP (A records), same dedicated nameservers (big DNS providers ignored), same certificate
(crt.sh cert id, or same SAN list), same favicon (file hash of the detonator's favicon). Offline: reads the db only."""
from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from pathlib import Path

from scamshield.core import db

from scamshield.core.domains import is_shared_host

from .watchlist import registrable_of

MAX_SHARE = 25  # a feature value shared by more domains than this is infrastructure, not a network

log = logging.getLogger("scamshield.radar")

# nameserver providers shared by millions of unrelated domains -> not a meaningful link
COMMON_NS = ("cloudflare.com", "domaincontrol.com", "awsdns", "googledomains.com", "registrar-servers.com",
             "nsone.net", "azure-dns", "ultradns", "dnsmadeeasy", "name-services.com", "dns.com", "hostinger",
             "wixdns.net", "vercel-dns.com", "netlify", "digitalocean.com", "linode.com", "namecheaphosting",
             "bluehost.com", "hostgator.com", "dynect.net", "akam.net", "google.com", "parkingcrew", "sedoparking",
             "dan.com", "afternic.com", "abovedomains.com", "bodis.com", "parklogic", "above.com", "porkbun.com", "gname.net", "dnspod", "alidns.com", "hichina.com")
COMMON_IP_PREFIX = ("104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "172.64.", "172.65.",
                    "172.66.", "172.67.", "76.76.21.", "75.2.", "99.83.")  # big anycast/CDN fronts


def _fav_hash(path: str | None) -> str | None:
    try:
        if path and Path(path).exists():
            return hashlib.sha1(Path(path).read_bytes()).hexdigest()[:16]
    except Exception:
        pass
    return None


def _features() -> dict[str, dict[str, set]]:
    """registrable -> {ip, ns, cert, favicon} feature sets, from stored scans + radar hits."""
    feats: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    c = db.connect()
    for r in c.execute("SELECT result_json FROM scans ORDER BY created_at DESC LIMIT 3000"):
        try:
            res = json.loads(r["result_json"])
        except Exception:
            continue
        intel = res.get("intel") or {}
        dom = intel.get("registrable_domain") or registrable_of(res.get("url", ""))
        f = feats[dom]
        for ip in [intel.get("ip")] + list(intel.get("a_records") or []):
            if ip and not ip.startswith(COMMON_IP_PREFIX):
                f["ip"].add(ip)
        for ns in intel.get("nameservers") or []:
            ns = ns.lower().rstrip(".")
            if ns and not any(x in ns for x in COMMON_NS):
                f["ns"].add(ns)
        for d in res.get("detonations") or []:
            h = _fav_hash(d.get("favicon_path"))
            if h:
                f["favicon"].add(h)
            tls = d.get("tls") or {}
            san = sorted({s.lower().lstrip("*.") for s in tls.get("san") or []})
            if len(san) > 1:
                f["cert"].add("san:" + hashlib.sha1(",".join(san).encode()).hexdigest()[:12])
    for h in db.list_radar_hits(5000):
        f = feats[h.domain]
        for cid in h.extra.get("cert_ids") or []:
            f["cert"].add(f"crtsh:{cid}")
        if h.extra.get("fingerprint"):
            f["cert"].add("fp:" + str(h.extra["fingerprint"]))
    # drop values that are too common (CDN IPs, fixture IPs, provider NS) and IP links on shared hosts
    count: dict[tuple, int] = defaultdict(int)
    for d, f in feats.items():
        for k, vals in f.items():
            for v in vals:
                count[(k, v)] += 1
    for d, f in feats.items():
        for k in list(f):
            f[k] = {v for v in f[k] if count[(k, v)] <= MAX_SHARE}
        if is_shared_host(d):  # platform infra (blogspot/pages.dev IPs, NS, wildcard cert) is not a link
            f["ip"], f["ns"], f["favicon"] = set(), set(), set()
            f["cert"] = {v for v in f["cert"] if v.startswith(("crtsh:", "fp:"))}
        # stub/fixture data (documentation ranges, .example NS) must never form a network
        f["ip"] = {v for v in f["ip"] if not v.startswith(("203.0.113.", "192.0.2."))}
        f["ns"] = {v for v in f["ns"] if not v.endswith(".example")}
    return feats


def siblings(domain: str) -> list[dict]:
    """[{domain, shared: {ip: [...], ns: [...], cert: [...], favicon: [...]}, strength}] strongest first."""
    try:
        dom = registrable_of(domain)
        feats = _features()
        me = feats.get(dom)
        if not me:
            return []
        out = []
        weights = {"cert": 3, "favicon": 3, "ns": 2, "ip": 1}
        for other, f in feats.items():
            if other == dom:
                continue
            shared = {k: sorted(me[k] & f[k]) for k in weights if me.get(k) and f.get(k) and (me[k] & f[k])}
            if shared:
                out.append({"domain": other, "shared": shared,
                            "strength": sum(weights[k] * len(v) for k, v in shared.items())})
        out.sort(key=lambda x: -x["strength"])
        return out[:100]
    except Exception as e:
        log.debug("siblings failed: %s", e)
        return []


def clusters(min_size: int = 2) -> list[list[str]]:
    """Connected components over all shared links (for the dashboard 'domain networks' view)."""
    try:
        feats = _features()
        idx: dict[tuple, set] = defaultdict(set)
        for d, f in feats.items():
            for k, vals in f.items():
                for v in vals:
                    idx[(k, v)].add(d)
        parent = {d: d for d in feats}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for doms in idx.values():
            doms = list(doms)
            for o in doms[1:]:
                parent[find(o)] = find(doms[0])
        groups: dict[str, list] = defaultdict(list)
        try:
            from .watchlist import _is_official_fast, _wl

            off = _wl()["official_set"]
        except Exception:
            off = frozenset()
        for d in feats:
            if not (off and _is_official_fast(d, off)):  # official brand networks are not scam networks
                groups[find(d)].append(d)
        return sorted([sorted(g) for g in groups.values() if len(g) >= min_size], key=len, reverse=True)
    except Exception:
        return []
