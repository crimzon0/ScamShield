"""Domain-only look-alike detection against the registry's official domains and domain keywords."""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

import tldextract
from rapidfuzz.distance import Levenshtein

from scamshield.core.domains import host_of, is_official, is_shared_host
from scamshield.core.schemas import LookalikeResult

_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

# Cyrillic / Greek / other confusables -> latin
_CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w", "в": "b", "к": "k", "м": "m", "н": "h",
    "т": "t", "ь": "b", "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "ρ": "p", "ε": "e",
    "υ": "u", "χ": "x", "β": "b", "η": "n", "ı": "i", "ł": "l", "ø": "o", "ß": "ss",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s", "@": "a",
})


def _decode_idn(label: str) -> str:
    if "xn--" not in label:
        return label
    out = []
    for part in label.split("."):
        if part.startswith("xn--"):
            try:
                part = part[4:].encode("ascii").decode("punycode")
            except Exception:
                pass
        out.append(part)
    return ".".join(out)


def skeleton(s: str) -> str:
    """Visual skeleton: confusables -> latin, strip accents, rn->m, vv->w, i->l."""
    s = s.lower().translate(_CONFUSABLE)
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    s = s.replace("rn", "m").replace("vv", "w").replace("cl", "d").replace("i", "l")
    return s


def _split(domain: str) -> tuple[str, str]:
    """(label-before-suffix, suffix). foo.vercel.app -> ('foo', 'vercel.app'); a.b.example.com -> ('example','com')."""
    ext = _extract(domain)
    if ext.domain and ext.suffix:
        return ext.domain, ext.suffix
    parts = domain.split(".")  # unknown TLD (e.g. .example): last label is the suffix
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return domain, ""


@lru_cache(maxsize=1)
def _index():
    from scamshield.brand import load_registry

    brands = load_registry()
    officials, entries = [], []  # entries: (brand_id, label, suffix, official_registrable)
    kws = []  # (brand_id, keyword)
    for b in brands:
        for d in b.get("official_domains", []):
            officials.append((b["id"], d.lower()))
            lab, suf = _split(d.lower())
            if len(lab) >= 3:
                entries.append((b["id"], lab, suf, f"{lab}.{suf}"))
        for k in b.get("domain_keywords", []):
            k = k.lower().replace(" ", "")
            if len(k) >= 3:
                kws.append((b["id"], k))
    first = {}
    for bid, d in officials:
        first.setdefault(bid, d)
    return officials, sorted(set(entries)), sorted(set(kws)), first


def _official_owner(host: str) -> tuple[str | None, str | None]:
    officials, *_ = _index()
    best = None
    for bid, d in officials:
        if is_official(host, [d]) and (best is None or len(d) > len(best[1])):
            best = (bid, d)
    return best if best else (None, None)


def _near_substring(k: str, s: str) -> bool:
    """k appears in s with at most one edit (window sizes len(k)-1..len(k)+1)."""
    n = len(k)
    for w in (n - 1, n, n + 1):
        for i in range(0, max(0, len(s) - w) + 1):
            if Levenshtein.distance(k, s[i:i + w], score_cutoff=1) <= 1:
                return True
    return False


def _tokens(label: str) -> list[str]:
    return [t for t in re.split(r"[-_.0-9]+", label) if t]


def lookalike(domain: str) -> LookalikeResult:
    try:
        return _lookalike(domain)
    except Exception:
        return LookalikeResult(domain=domain or "")


def _lookalike(domain: str) -> LookalikeResult:
    raw_host = (domain or "").strip().lower()
    if "://" in raw_host:
        raw_host = host_of(raw_host)
    raw_host = raw_host.rstrip(".")
    host = _decode_idn(raw_host)
    if not host:
        return LookalikeResult(domain=domain or "")
    owner, owner_dom = _official_owner(host)
    if owner is None and host != raw_host:
        owner, owner_dom = _official_owner(raw_host)
    if owner:
        return LookalikeResult(domain=domain, brand_id=owner, closest_official=owner_dom, distance=0, score=0.0)

    _, entries, kws, _ = _index()
    lab_raw, suf = _split(raw_host)
    lab = _decode_idn(lab_raw)
    idn = lab != lab_raw or any(ord(c) > 127 for c in lab)
    sk = skeleton(lab)
    shared = is_shared_host(host)

    best = LookalikeResult(domain=domain)

    def consider(score, bid, closest, dist, techs):
        nonlocal best
        if idn and "idn" not in techs:
            techs = techs + ["idn"]
        if score > best.score:
            best = LookalikeResult(domain=domain, brand_id=bid, closest_official=closest, distance=dist,
                                   techniques=techs, score=round(min(score, 1.0), 2))

    for bid, olab, osuf, oreg in entries:
        osk = skeleton(olab)
        dist = Levenshtein.distance(lab, olab)
        if lab == olab and suf != osuf:
            consider(0.85 if len(olab) >= 6 else 0.6 if len(olab) >= 4 else 0.35, bid, oreg, 0, ["tld_swap"])
            continue
        if lab != olab and sk == osk and len(olab) >= 3:
            consider(0.95, bid, oreg, dist, ["homoglyph"] + (["tld_swap"] if suf != osuf else []))
            continue
        if len(olab) >= 5:
            sd = Levenshtein.distance(sk, osk)
            if sd == 1 or (sd == 2 and len(olab) >= 8):
                consider(0.85 if sd == 1 else 0.7, bid, oreg, dist,
                         ["edit_distance"] + (["homoglyph"] if sd < dist else []))
    first = _index()[3]
    toks = _tokens(lab)
    tok_sk = [skeleton(t) for t in toks]
    for bid, k in kws:
        ksk = skeleton(k)
        closest = first.get(bid)
        if lab == k:  # keyword is the whole label but not an official domain (enbd.com, adcb.net)
            if len(k) >= 4:
                consider(0.75, bid, closest, 0, ["keyword"])
            continue
        if len(k) >= 5:
            if k in lab:
                consider(0.85 if not shared else 0.9, bid, closest, Levenshtein.distance(lab, k), ["keyword", "combosquat"])
            elif ksk in sk:
                consider(0.88, bid, closest, Levenshtein.distance(lab, k), ["keyword", "combosquat", "homoglyph"])
            elif len(k) >= 8 and _near_substring(ksk, sk):
                consider(0.75, bid, closest, Levenshtein.distance(lab, k), ["keyword", "combosquat", "edit_distance"])
        else:  # short keyword (adcb, tamm, rta, dib): need a whole token or label prefix
            if k in toks or ksk in tok_sk:
                consider(0.8 if len(k) >= 4 else 0.6, bid, closest, Levenshtein.distance(lab, k), ["keyword", "combosquat"])
            elif len(k) == 4 and (lab.startswith(k) or lab.endswith(k)) and len(lab) > len(k) + 2:
                consider(0.6, bid, closest, Levenshtein.distance(lab, k), ["keyword", "combosquat"])
    if idn and best.score == 0.0:
        best = LookalikeResult(domain=domain, techniques=["idn"], score=0.2)
    return best
