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
PERM_MIN_LABEL = 7
AFFIXES = sorted({
    "pay", "payment", "payments", "fine", "fines", "login", "signin", "gov", "ae", "uae", "online", "verify",
    "verification", "portal", "service", "services", "secure", "security", "update", "bank", "app", "web", "my",
    "e", "id", "dubai", "abudhabi", "ad", "dxb", "auh", "card", "cards", "help", "support", "care", "customer",
    "track", "tracking", "delivery", "parcel", "post", "refund", "reward", "rewards", "points", "sms", "otp",
    "auth", "account", "accounts", "official", "smart", "digital", "net", "info", "center", "centre", "hub",
    "renew", "renewal", "visa", "toll", "tolls", "traffic", "police", "pass", "ebanking", "mobile", "unlock",
}, key=len, reverse=True)


def _token_hit(term: str, tokens: list[str]) -> bool:
    """Short ASCII term vs host tokens (public suffix excluded). 3-letter terms (rta, icp, moi, dib) also
    need a scam/UAE context token elsewhere in the host (rta-fines, icp-uae); 4+ letters may stand alone."""
    short = len(term) <= 3
    ctx = not short or any(t in AFFIXES for t in tokens if t != term)
    amin = 3 if short else 2  # 'pierre-emoi' must not read as e+moi
    for tok in tokens:
        if tok == term and ctx:
            return True
        rest = tok[len(term):]
        if tok.startswith(term) and len(rest) >= amin and rest in AFFIXES:
            return True
        rest = tok[: -len(term)]
        if tok.endswith(term) and len(rest) >= amin and rest in AFFIXES:
            return True
    return False


def hit_domain(m: dict) -> str:
    """The domain a hit is filed under: the registrable domain, unless the brand term only appears in the
    subdomain part (central-bank.sdm.network) - then the full host, so the feed shows what matched."""
    reg = m.get("registrable") or registrable_of(m.get("host", ""))
    if m.get("kind") == "keyword":
        core = _squash(m.get("term", ""))
        if core and core not in _squash(reg) and core not in _squash(skeleton(reg)):
            return m.get("host") or reg
    return reg


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


def _hyphen_hit(term: str, dotted: str) -> bool:
    """'tamm-' must start a token, '-tamm' must end one, 'rta-fine' must start a token."""
    d = "-" + dotted + "-"
    if term.startswith("-"):
        return (term + "-") in d
    return ("-" + term) in d


_CONFUSABLE: Optional[dict] = None
_MULTI = {"rn": "m", "vv": "w", "cl": "d", "nn": "m"}


def _confusables() -> dict:
    """single glyph -> ascii letter, inverted from dnstwist's homoglyph tables."""
    global _CONFUSABLE
    if _CONFUSABLE is None:
        m: dict[str, str] = {}
        try:
            import dnstwist

            tables = [dnstwist.Fuzzer.glyphs_unicode, dnstwist.Fuzzer.glyphs_ascii]
            tables += list(getattr(dnstwist.Fuzzer, "glyphs_idn_by_tld", {}).values())
            for tab in tables:
                for ascii_c, glyphs in tab.items():
                    if len(ascii_c) != 1 or not ascii_c.isalpha():
                        continue
                    for g in glyphs:
                        if len(g) == 1 and g != ascii_c and not g.isalpha() or (len(g) == 1 and not g.isascii()):
                            m.setdefault(g, ascii_c)
        except Exception:
            pass
        # Cyrillic / Greek look-alikes (dnstwist's unicode table is Latin-diacritics only)
        for a, gs in {"a": "аɑα", "b": "Ьβ", "c": "сϲ", "d": "ԁ", "e": "еєε", "h": "һ", "i": "іιӏ", "j": "ј",
                      "k": "кκ", "l": "ӏ", "m": "м", "n": "пη", "o": "оοσ", "p": "рρ", "q": "ԛ", "s": "ѕ",
                      "t": "т", "u": "υ", "v": "ν", "w": "ԝ", "x": "хχ", "y": "уγ"}.items():
            for g in gs:
                m.setdefault(g, a)
        m.update({"0": "o", "1": "l"})
        _CONFUSABLE = m
    return _CONFUSABLE


def skeleton(label: str) -> str:
    """Map confusable glyphs (Cyrillic а, Greek ο, 0->o, rn->m ...) to ASCII for homoglyph comparison."""
    c = _confusables()
    s = "".join(c.get(ch, ch) for ch in label.lower())
    for k, v in _MULTI.items():
        s = s.replace(k, v)
    return s


def _fuzz_labels(dnstwist, lab: str):
    """(fuzzer, label) pairs from dnstwist's cheap fuzzers on the bare label (no DNS, no network)."""
    if dnstwist is None:
        return
    try:
        f = dnstwist.Fuzzer(lab + ".com")
    except Exception:
        return
    for name in ("addition", "bitsquatting", "hyphenation", "insertion", "omission", "plural", "repetition",
                 "replacement", "transposition", "vowel_swap"):
        fn = getattr(f, "_" + name, None)
        if fn is None:
            continue
        try:
            for pl in fn():
                pl = decode_host(pl)
                if "." not in pl:
                    yield name.replace("_", "-"), pl
        except Exception:
            continue


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
                add(t, b["id"], "keyword", "en", query=len(_squash(t)) >= 4)
    # registry keywords (EN / Arabizi / Arabic)
    for b in reg:
        for k in b.get("keywords_en", []) + [b.get("name_en", "")]:
            t = _squash(k)
            if len(t) >= MIN_LEN and t not in stop and t.isascii():
                add(t, b["id"], "keyword", "en")
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
    skel: dict[str, tuple[str, str, str]] = {}  # confusable skeleton of official label -> (...)
    n_perm = 0
    try:
        import dnstwist
    except Exception:  # pragma: no cover
        dnstwist = None
    done_regs: set[str] = set()
    for b in reg:
        for d in official_by_brand.get(b["id"], []):
            r = registrable_of(d)
            if r in done_regs or any(r == s or r.endswith("." + s) for s in SHARED_HOSTS):
                continue
            done_regs.add(r)
            lab = r.split(".")[0]
            if len(lab) < MIN_LEN or lab in stop:
                continue
            # homoglyphs are matched via confusable skeleton (see skeleton()), not enumerated: dnstwist's
            # homoglyph fuzzer yields ~30k names per domain.
            # short labels (salik, mohre) explode into common words (salio, more); only long labels get
            # the cheap fuzzers. Short ones still get tld-swap + homoglyph skeleton below.
            for fz, pl in (_fuzz_labels(dnstwist, lab) if len(lab) >= PERM_MIN_LABEL else ()):
                if len(pl) >= MIN_LEN and pl != lab and pl not in stop:
                    perms.setdefault(pl, (b["id"], fz, r))
            # same label on another TLD (tld swap)
            perms.setdefault(lab, (b["id"], "tld-swap", r))
            skel.setdefault(skeleton(lab), (b["id"], "homoglyph", r))
    for pl, (bid, fz, off) in perms.items():
        n_perm += 1
        entries.append({"term": pl, "brand_id": bid, "kind": "permutation", "lang": "en", "query": False,
                        "fuzzer": fz, "official": off})
    kw = [e for e in entries if e["kind"] == "keyword"]
    # longest first so the most specific term wins
    kw.sort(key=lambda e: -len(e["term"]))
    import re as _re

    cores = sorted({_squash(e["term"]) for e in kw if _squash(e["term"])}, key=len, reverse=True)
    prefilter = _re.compile("|".join(_re.escape(c) for c in cores)) if cores else None
    return {"entries": entries, "keywords": kw, "perms": perms, "skel": skel, "official": official,
            "prefilter": prefilter, "official_set": frozenset(official),
            "official_by_brand": official_by_brand}


_mt = {"t": 0.0, "v": (0.0, 0.0)}


def _wl(include_fictional: bool = False) -> dict:
    import time as _t

    now = _t.monotonic()
    if now - _mt["t"] > 30:  # re-check registry/seed mtimes at most every 30 s (hot path)
        _mt["t"], _mt["v"] = now, (_mtime(settings.registry_path), _mtime(SEED_PATH))
    return _build(include_fictional, *_mt["v"])


def _is_official_fast(host: str, official: frozenset) -> bool:
    """Same semantics as core.domains.is_official, O(labels): host or any parent is official,
    except that on a shared host (vercel.app, ...) only an exact match counts."""
    if host in official:
        return True
    parts = host.split(".")
    parents = [".".join(parts[i:]) for i in range(1, len(parts))]
    if any(p in SHARED_HOSTS for p in parents) or host in SHARED_HOSTS:
        return False
    return any(p in official for p in parents)


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
        if wl["official"] and _is_official_fast(host, wl["official_set"]):
            return None
        squashed0 = _squash(host)
        if host.isascii() and wl["prefilter"] is not None and not wl["prefilter"].search(squashed0):
            # fast path (certstream/NRD volume): no keyword core anywhere -> only a permutation can match
            lab0 = registrable_of(host).split(".")[0]
            if lab0 not in wl["perms"]:
                return None
        reg = registrable_of(host)
        label = reg.split(".")[0]
        # 1) permutation of an official registrable label (on the registrable part)
        p = wl["perms"].get(label)
        if p is not None and reg != p[2]:
            return {"term": label, "brand_id": p[0], "kind": "permutation", "fuzzer": p[1], "official": p[2],
                    "host": host, "registrable": reg}
        sk = skeleton(label)
        q = wl["skel"].get(sk)
        if q is not None and sk != label and reg != q[2]:
            return {"term": label, "brand_id": q[0], "kind": "permutation", "fuzzer": "homoglyph", "official": q[2],
                    "host": host, "registrable": reg}
        # 2) keyword anywhere in the host (hyphen-sensitive terms vs hyphen-insensitive)
        squashed = _squash(host)
        if not host.isascii():  # homoglyph combosquat: еmiratesnbd-login.com
            squashed = squashed + "|" + _squash(skeleton(host))
        dotted = host.replace(".", "-")
        ext = _extract(host)
        tokens = [t for t in ".".join(x for x in (ext.subdomain, ext.domain) if x).replace(".", "-").split("-") if t]
        for e in wl["keywords"]:
            t = e["term"]
            if "-" in t:
                hit = _hyphen_hit(t, dotted)
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
