"""Watchlist + matcher. Pure/offline: dnstwist is used only as a name generator (no DNS, no network)."""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

import tldextract

from scamshield.core.config import DATA_DIR, settings
from scamshield.core.domains import SHARED_HOSTS, is_official

log = logging.getLogger("scamshield.radar")

SEED_PATH = DATA_DIR / "radar" / "seed_terms.json"
_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

MIN_LEN = 5  # registry-derived terms shorter than this are too generic
MIN_LEN_AR = 4
# dnstwist fuzzers that create too much noise on their own
SKIP_FUZZERS = {"*original", "subdomain", "various"}
DEFAULT_STOP = {"bank", "login", "secure", "police", "dubai", "abudhabi", "emirates", "online", "service"}
# ASCII terms shorter than this (tamm, adcb, rta, icp, salik, ...) must be a whole host token, or a token
# made of the term plus a scam-typical affix (tamm-pay, adcbverify, uaesalik), never an arbitrary substring.
SUBSTRING_MIN = 7
AFFIXES = sorted({
    "pay", "payment", "payments", "fine", "fines", "login", "signin", "gov", "ae", "uae", "online", "verify",
    "verification", "portal", "service", "services", "secure", "security", "update", "bank", "app", "web", "my",
    "e", "id", "dubai", "abudhabi", "ad", "dxb", "auh", "card", "cards", "help", "support", "care", "customer",
    "track", "tracking", "delivery", "parcel", "post", "refund", "reward", "rewards", "points", "sms", "otp",
    "auth", "account", "accounts", "official", "smart", "digital", "net", "info", "center", "centre", "hub",
    "renew", "renewal", "visa", "toll", "tolls", "traffic", "police", "pass", "ebanking", "mobile", "unlock",
}, key=len, reverse=True)


def _token_hit(term: str, tokens: list[str]) -> bool:
    for tok in tokens:
        if tok == term:
            return True
        if tok.startswith(term) and tok[len(term):] in AFFIXES:
            return True
        if tok.endswith(term) and tok[: -len(term)] in AFFIXES:
            return True
    return False


# ------------------------------------------------------------------ helpers
def decode_host(domain: str) -> str:
    """Lower-case host, strip '*.' / trailing dot / scheme, decode each xn-- label to Unicode."""
    s = (domain or "").strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split(":", 1)[0].strip().rstrip(".")
    while s.startswith("*."):
        s = s[2:]
    labels = []
    for lab in s.split("."):
        if lab.startswith("xn--"):
            try:
                lab = lab.encode("ascii").decode("idna")
            except Exception:
                try:
                    lab = lab[4:].encode("ascii").decode("punycode")
                except Exception:
                    pass
        labels.append(lab)
    return ".".join(labels)


def registrable_of(host: str) -> str:
    ext = _extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host


def _squash(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch not in " -._")


def _load_registry() -> list[dict]:
    try:
        from scamshield.brand import load_registry

        return load_registry() or []
    except Exception:
        return []


def _load_seed() -> dict:
    try:
        return json.loads(SEED_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"terms": [], "stop": []}


def _mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime
    except Exception:
        return 0.0


# ------------------------------------------------------------------ build
@lru_cache(maxsize=4)
def _build(include_fictional: bool, _reg_mtime: float, _seed_mtime: float) -> dict:
    reg = [b for b in _load_registry() if include_fictional or not b.get("fictional")]
    seed = _load_seed()
    stop = {_squash(s) for s in seed.get("stop", [])} | DEFAULT_STOP
    ids = {b["id"] for b in reg}
    official: list[str] = sorted({d.lower() for b in reg for d in b.get("official_domains", []) if d})
    official_by_brand = {b["id"]: [d.lower() for d in b.get("official_domains", []) if d] for b in reg}

    entries: list[dict] = []
    seen: set[tuple] = set()

    def add(term, brand_id, kind, lang="en", query=False, **extra):
        key = (term, brand_id, kind)
        if term and key not in seen:
            seen.add(key)
            entries.append({"term": term, "brand_id": brand_id, "kind": kind, "lang": lang, "query": query, **extra})

    # curated radar tokens from the registry (domain_keywords), short ones are token-matched
    for b in reg:
        for k in b.get("domain_keywords", []):
            t = k.lower().strip().replace(" ", "")
            if len(t) >= 3 and _squash(t) not in stop:
                add(t, b["id"], "keyword", "en", query=len(_squash(t)) >= 5)
    # registry keywords (EN / Arabizi / Arabic)
    for b in reg:
        for k in b.get("keywords_en", []) + [b.get("name_en", "")]:
            t = _squash(k)
            if len(t) >= MIN_LEN and t not in stop and t.isascii():
                add(t, b["id"], "keyword", "en", query=len(t) >= 6)
        for k in b.get("arabizi", []):
            t = _squash(k)
            if len(t) >= MIN_LEN + 1 and t not in stop and t.isascii():
                add(t, b["id"], "keyword", "arabizi")
        for k in b.get("keywords_ar", []) + [b.get("name_ar", "")]:
            t = _squash(k)
            if len(t) >= MIN_LEN_AR and t not in stop and not t.isascii():
                add(t, b["id"], "keyword", "ar")

    # curated UAE scam-theme terms (may be shorter than MIN_LEN: they are hand-picked)
    for s in seed.get("terms", []):
        term = s["term"].lower().replace(" ", "")
        hint = s.get("brand_hint")
        bid = hint if hint in ids else None
        if bid is None:  # resolve by keyword overlap with the registry
            sq = _squash(term)
            for b in reg:
                kws = {_squash(k) for k in b.get("keywords_en", []) + b.get("arabizi", []) + b.get("keywords_ar", [])}
                kws |= {registrable_of(d).split(".")[0] for d in b.get("official_domains", [])}
                if sq and sq in kws:
                    bid = b["id"]
                    break
        add(term, bid, "keyword", "ar" if not term.isascii() else "en", query=bool(s.get("query")), theme=hint)

    # dnstwist permutations of official registrable domains
    perms: dict[str, tuple[str, str, str]] = {}  # label -> (brand_id, fuzzer, official)
    n_perm = 0
    try:
        import dnstwist
    except Exception:  # pragma: no cover
        dnstwist = None
    for b in reg:
        for d in official_by_brand.get(b["id"], []):
            r = registrable_of(d)
            if any(r == s or r.endswith("." + s) for s in SHARED_HOSTS):
                continue
            lab = r.split(".")[0]
            if len(lab) < MIN_LEN or dnstwist is None:
                continue
            try:
                f = dnstwist.Fuzzer(r)
                f.generate()
                for p in f.permutations():
                    if p["fuzzer"] in SKIP_FUZZERS:
                        continue
                    pl = decode_host(p["domain"]).split(".")[0]
                    if len(pl) >= MIN_LEN and pl != lab and pl not in stop:
                        perms.setdefault(pl, (b["id"], p["fuzzer"], r))
            except Exception as e:  # never raise
                log.debug("dnstwist failed for %s: %s", r, e)
            # same label on another TLD (tld swap / combo on official label)
            if lab not in stop:
                perms.setdefault(lab, (b["id"], "tld-swap", r))
    for pl, (bid, fz, off) in perms.items():
        n_perm += 1
        entries.append({"term": pl, "brand_id": bid, "kind": "permutation", "lang": "en", "query": False,
                        "fuzzer": fz, "official": off})
    kw = [e for e in entries if e["kind"] == "keyword"]
    # longest first so the most specific term wins
    kw.sort(key=lambda e: -len(e["term"]))
    return {"entries": entries, "keywords": kw, "perms": perms, "official": official,
            "official_by_brand": official_by_brand}


def _wl(include_fictional: bool = False) -> dict:
    return _build(include_fictional, _mtime(settings.registry_path), _mtime(SEED_PATH))


# ------------------------------------------------------------------ public
def watchlist(include_fictional: bool = False) -> list[dict]:
    """[{term, brand_id, kind: permutation|keyword, lang, query, ...}]"""
    try:
        return list(_wl(include_fictional)["entries"])
    except Exception as e:
        log.warning("watchlist failed: %s", e)
        return []


def query_terms(include_fictional: bool = False) -> list[dict]:
    """Strong keyword terms worth a crt.sh %term% query."""
    return [e for e in watchlist(include_fictional) if e["kind"] == "keyword" and e.get("query") and e["term"].isascii()]


def match_detail(domain: str, include_fictional: bool = False) -> Optional[dict]:
    """Match a host against the watchlist. Decodes punycode first. Official domains (and their
    subdomains) never match. Returns {term, brand_id, kind, host, registrable, ...} or None."""
    try:
        host = decode_host(domain)
        if not host or "." not in host:
            return None
        wl = _wl(include_fictional)
        if wl["official"] and is_official(host, wl["official"]):
            return None
        reg = registrable_of(host)
        label = reg.split(".")[0]
        # 1) permutation of an official registrable label (on the registrable part)
        p = wl["perms"].get(label)
        if p is not None and reg != p[2]:
            return {"term": label, "brand_id": p[0], "kind": "permutation", "fuzzer": p[1], "official": p[2],
                    "host": host, "registrable": reg}
        # 2) keyword anywhere in the host (hyphen-sensitive terms vs hyphen-insensitive)
        squashed = _squash(host)
        dotted = host.replace(".", "-")
        tokens = [t for t in dotted.split("-") if t]
        for e in wl["keywords"]:
            t = e["term"]
            if "-" in t:
                hit = t in dotted
            elif not t.isascii() or len(t) >= SUBSTRING_MIN:
                hit = t in squashed
            else:
                hit = _token_hit(t, tokens)
            if hit:
                return {"term": t, "brand_id": e["brand_id"], "kind": "keyword", "lang": e["lang"],
                        "theme": e.get("theme"), "host": host, "registrable": reg}
        return None
    except Exception as e:
        log.debug("match failed for %r: %s", domain, e)
        return None


def match(domain: str, include_fictional: bool = False) -> Optional[tuple[str, Optional[str]]]:
    m = match_detail(domain, include_fictional)
    return (m["term"], m["brand_id"]) if m else None
