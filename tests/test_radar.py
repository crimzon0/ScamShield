"""Radar tests (offline). Uses a small in-test registry so results don't drift with data/registry.json."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scamshield.core.config import settings
from scamshield.core.schemas import RadarHit, ScanResult, Verdict

FIX = Path(__file__).parent / "fixtures" / "radar"
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)

REG = [
    {"id": "sandbox_bank", "fictional": True, "name_en": "Sandbox Bank", "name_ar": "بنك التجربة",
     "official_domains": ["sandboxbank.example"], "keywords_en": ["sandbox bank"], "keywords_ar": ["بنك التجربة"],
     "arabizi": [], "domain_keywords": ["sandboxbank"]},
    {"id": "uae_pass", "name_en": "UAE PASS", "name_ar": "الهوية الرقمية", "official_domains": ["uaepass.ae", "id.uaepass.ae"],
     "keywords_en": ["uae pass"], "keywords_ar": ["الهوية الرقمية"], "arabizi": [], "domain_keywords": ["uaepass"]},
    {"id": "emirates_nbd", "name_en": "Emirates NBD", "name_ar": "بنك الإمارات دبي الوطني",
     "official_domains": ["emiratesnbd.com", "online.emiratesnbd.com"], "keywords_en": ["emirates nbd"],
     "keywords_ar": [], "arabizi": [], "domain_keywords": ["emiratesnbd", "enbd"]},
    {"id": "tamm", "name_en": "TAMM", "name_ar": "تم", "official_domains": ["tamm.abudhabi"], "keywords_en": [],
     "keywords_ar": [], "arabizi": [], "domain_keywords": ["tamm"]},
    {"id": "salik", "name_en": "Salik", "name_ar": "سالك", "official_domains": ["salik.ae"], "keywords_en": [],
     "keywords_ar": ["سالك"], "arabizi": [], "domain_keywords": ["salik"]},
    {"id": "dubai_police", "name_en": "Dubai Police", "name_ar": "شرطة دبي", "official_domains": ["dubaipolice.gov.ae"],
     "keywords_en": ["dubai police"], "keywords_ar": ["شرطة دبي"], "arabizi": [], "domain_keywords": ["dubaipolice"]},
    {"id": "rta_dubai", "name_en": "RTA", "name_ar": "هيئة الطرق", "official_domains": ["rta.ae"], "keywords_en": [],
     "keywords_ar": [], "arabizi": [], "domain_keywords": ["rta"]},
]


@pytest.fixture(autouse=True)
def registry(monkeypatch, tmp_path):
    import importlib

    wl = importlib.import_module("scamshield.radar.watchlist")

    monkeypatch.setattr(wl, "_load_registry", lambda: [dict(b) for b in REG])
    wl._build.cache_clear()
    wl._mt["t"] = 0.0
    monkeypatch.setattr(settings, "db_path", tmp_path / "t.db")
    monkeypatch.setattr(settings, "offline", True)
    yield
    wl._build.cache_clear()


def test_watchlist_generation():
    from scamshield.radar import watchlist

    w = watchlist()
    kinds = {e["kind"] for e in w}
    assert {"keyword", "permutation"} <= kinds
    terms = {e["term"] for e in w}
    assert "uaepass" in terms and "emiratesnbd" in terms
    # dnstwist permutations of the official label (no DNS needed)
    perms = {e["term"] for e in w if e["kind"] == "permutation" and e["brand_id"] == "emirates_nbd"}
    assert "emiratesndb" in perms or "emiratsnbd" in perms
    # fictional brand skipped for live collection, available on request
    assert not any(e["brand_id"] == "sandbox_bank" for e in w)
    assert any(e["brand_id"] == "sandbox_bank" for e in watchlist(include_fictional=True))
    # Arabic keyword present
    assert any(not e["term"].isascii() for e in w)


def test_match_basic_and_official_excluded():
    from scamshield.radar import match

    assert match("uaepass-login.vercel.app") == ("uaepass", "uae_pass")
    assert match("emiratesnbd-secure.com")[1] == "emirates_nbd"
    assert match("emiratesnbd.co")[1] == "emirates_nbd"  # tld swap
    assert match("emiratesndb.com")[1] == "emirates_nbd"  # transposition
    # official domains and their subdomains never match
    for d in ("uaepass.ae", "id.uaepass.ae", "www.uaepass.ae", "online.emiratesnbd.com", "emiratesnbd.com",
              "*.salik.ae", "tamm.abudhabi", "x.tamm.abudhabi"):
        assert match(d) is None, d


def test_match_short_terms_need_context():
    from scamshield.radar import match

    assert match("tammy-bakery.com") is None
    assert match("tamm-pay.com")[1] == "tamm"
    assert match("rta-fines.com")[1] == "rta_dubai"
    assert match("trafficrta.xyz")[1] == "rta_dubai"
    assert match("marta.com") is None
    assert match("rta-kitchen.com") is None  # 3-letter token without UAE/scam context
    assert match("andre-tamm-001.workers.dev") is None  # surname, no context
    assert match("tamm.xyz")[1] == "tamm"
    assert match("pierre-emoi.com") is None
    assert match("saudi.moi") is None


def test_match_punycode_arabic_and_homoglyph():
    from scamshield.radar import match, match_detail

    ar = "شرطةدبي-مخالفات.com".encode("idna").decode()
    assert ar.startswith("xn--")
    m = match_detail(ar)
    assert m and m["brand_id"] == "dubai_police" and m["lang"] == "ar"
    assert match("سالك-دفع.com".encode("idna").decode())[1] == "salik"
    # Cyrillic 'а' in uаepass.ae
    hg = "uаepass.ae".encode("idna").decode()
    m = match_detail(hg)
    assert m and m["brand_id"] == "uae_pass" and m.get("fuzzer") == "homoglyph"
    assert match("еmiratesnbd-login.com".encode("idna").decode())[1] == "emirates_nbd"


def test_crtsh_parsing_from_fixture():
    from scamshield.radar.crtsh import parse_crtsh, split_names

    assert split_names("*.a.example.com\nb.example.com") == ["a.example.com", "b.example.com"]
    rows = json.loads((FIX / "crtsh_uaepass.json").read_text(encoding="utf-8"))
    out = parse_crtsh(rows, days=30, now=NOW)
    assert "uaepass-verify.com" in out
    e = out["uaepass-verify.com"]
    assert e["first_seen"] == datetime(2026, 11, 18, 8, 0, tzinfo=timezone.utc)  # earliest not_before
    assert set(e["cert_ids"]) == {101, 102}
    assert "docs.uaepass.ae" not in out and "uaepass.ae" not in out  # official
    assert "tamm-fines.top" not in out  # not_before older than 30 days
    assert "tammy-bakery.com" not in out
    assert "xn--uepass-3nf.com" not in out and any(k.startswith("u") and not k.isascii() for k in out)


def test_crtsh_patterns_trailing_wildcard_only():
    from scamshield.radar.crtsh import query_patterns

    pats = [p for _, p in query_patterns()]
    assert pats and all(not p.startswith("%") and p.endswith("%") for p in pats)
    assert "uaepass%" in pats and "rta-%" in pats


async def test_backfill_time_to_detection_and_scan(monkeypatch, tmp_path):
    from scamshield import pipeline
    from scamshield.core import db
    from scamshield.radar import crtsh, feed, time_to_detection_seconds

    raw = tmp_path / "raw"
    raw.mkdir()
    rows = json.loads((FIX / "crtsh_uaepass.json").read_text(encoding="utf-8"))
    now_nb = datetime.now(timezone.utc) - timedelta(hours=5)
    for r in rows:
        r["not_before"] = now_nb.strftime("%Y-%m-%dT%H:%M:%S") if r["id"] != 104 else r["not_before"]
    (raw / "uaepass.json").write_text(json.dumps({"term": "uaepass", "pattern": "uaepass%", "rows": rows}))
    monkeypatch.setattr(crtsh, "RAW_DIR", raw)
    scanned = []

    async def fake_scan(url, personas=("uae_mobile_ad_click",), save=True):
        scanned.append(url)
        v = Verdict(scan_id="s" + str(len(scanned)), url=url, score=88, label="scam")
        return ScanResult(scan_id=v.scan_id, url=url, verdict=v)

    monkeypatch.setattr(pipeline, "scan_url", fake_scan)
    hits = await crtsh.backfill_crtsh(days=30, scan=True, fetch=False)
    doms = {h.domain for h in hits}
    assert "uaepass-verify.com" in doms
    for h in hits:
        assert h.source == "crtsh" and h.first_seen and h.flagged_at
        assert h.flagged_at >= h.first_seen
        assert h.scan_id and h.label == "scam" and h.score == 88
        assert 4 * 3600 <= time_to_detection_seconds(h) <= 6 * 3600
    assert any(u.startswith("https://") for u in scanned)
    stored = db.list_radar_hits()
    assert {h.domain for h in stored} == doms
    f = feed()
    assert f and "time_to_detection_seconds" in f[0] and f[0]["time_to_detection_human"].endswith("m")
    # re-run keeps the original flagged_at (honest time-to-detection)
    first = {h.domain: h.flagged_at for h in stored}
    await crtsh.backfill_crtsh(days=30, scan=False, fetch=False)
    assert {h.domain: h.flagged_at for h in db.list_radar_hits()} == first


def test_certstream_message_parsing():
    from scamshield.radar.certstream import hits_from_message, parse_message

    msg = (FIX / "certstream_msg.json").read_text(encoding="utf-8")
    c = parse_message(msg)[0]
    assert c["domains"][0] == "salik-recharge.online"
    hits = hits_from_message(msg)
    assert len(hits) == 1
    h = hits[0]
    assert h.domain == "salik-recharge.online" and h.brand_id == "salik" and h.source == "certstream"
    assert h.first_seen == datetime.fromtimestamp(1795540000, tz=timezone.utc)
    assert parse_message("not json") == [] and parse_message('{"message_type":"heartbeat"}') == []


async def test_collectors_unavailable_offline():
    from scamshield.radar import run_certstream
    from scamshield.radar.search import collect_search

    st = await run_certstream(minutes=0.01, scan=False)
    assert st["state"] == "unavailable"
    assert await collect_search(scan=False) == []


def test_nrd_matching_and_url():
    import base64
    from datetime import date

    from scamshield.radar.nrd import match_domains, nrd_url

    u = nrd_url(date(2026, 11, 24))
    assert base64.b64encode(b"2026-11-24.zip").decode() in u
    hits = match_domains(["example.com", "uaepass-renew.top", "salik.ae", "trafficrta.xyz"], date(2026, 11, 23))
    assert {h.domain for h in hits} == {"uaepass-renew.top", "trafficrta.xyz"}
    assert all(h.first_seen == datetime(2026, 11, 23, tzinfo=timezone.utc) and h.source == "nrd" for h in hits)


def test_siblings_never_raises():
    from scamshield.radar import siblings

    assert siblings("nothing-here.example") == []
