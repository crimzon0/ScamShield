"""Intel tests: offline, network mocked via httpx.MockTransport / monkeypatched fetchers."""
import json
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

import scamshield.intel as intel_mod
from scamshield.core.config import settings
from scamshield.core.schemas import Intel
from scamshield.intel import _common, crtsh, feeds, keyed, rdap

FX = Path(__file__).parent / "fixtures" / "intel"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Fresh SQLite cache + feeds dir per test, offline by default."""
    monkeypatch.setattr(settings, "db_path", tmp_path / "t.db")
    monkeypatch.setattr(settings, "offline", True)
    monkeypatch.setattr(settings, "urlscan_key", "")
    monkeypatch.setattr(settings, "safe_browsing_key", "")
    fd = tmp_path / "feeds"
    fd.mkdir()
    monkeypatch.setattr(_common, "FEEDS_DIR", fd)
    feeds._index.clear()
    rdap._bootstrap = None
    return fd


def mock_client(monkeypatch, module, handler):
    """Replace module.client() with an AsyncClient on a MockTransport."""
    def factory(timeout=None):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)
    monkeypatch.setattr(module, "client", factory)


def install_feeds(fd: Path):
    shutil.copy(FX / "openphish.txt", fd / "openphish.txt")
    shutil.copy(FX / "phishunt.txt", fd / "phishunt.txt")


def install_tranco(fd: Path, rows):
    con = sqlite3.connect(fd / "tranco.sqlite")
    con.execute("CREATE TABLE tranco(domain TEXT PRIMARY KEY, rank INTEGER) WITHOUT ROWID")
    con.executemany("INSERT INTO tranco VALUES (?,?)", rows)
    con.commit()
    con.close()


# ------------------------------------------------------------------ parsing
def test_parse_rdap():
    p = rdap.parse_rdap(json.loads((FX / "rdap_domain.json").read_text()))
    assert p["created"] == "2026-11-21T09:15:00Z"
    assert p["registrar"] == "Example Registrar LLC"
    assert p["abuse_emails"] == ["abuse@registrar.example"]
    assert p["nameservers"] == ["ns1.host.example", "ns2.host.example"]
    assert p["found"] is True


def test_parse_whois_ae():
    p = rdap.parse_whois_text((FX / "whois_ae.txt").read_text())
    assert p["found"] and p["registrar"] == "Example AE Registrar"
    assert p["nameservers"] == ["ns1.host.example", "ns2.host.example"]
    assert p["raw"]["registrant"] == "SANDBOX TEST LLC"
    assert rdap.parse_whois_text("No Data Found\r\n") == {"found": False, "via": "whois"}
    with pytest.raises(rdap.WhoisRateLimited):
        rdap.parse_whois_text("BLACKLISTED: You have exceeded the query limit for your network")


def test_parse_dt_variants():
    assert _common.parse_dt("2026-11-21T09:15:00Z") == datetime(2026, 11, 21, 9, 15, tzinfo=timezone.utc)
    assert _common.parse_dt([datetime(2020, 1, 2), datetime(2019, 1, 1)]).year == 2019
    assert _common.parse_dt("garbage") is None and _common.parse_dt(None) is None


# ------------------------------------------------------------------ RDAP via mocked HTTP
async def test_fetch_rdap_ok_and_not_found(monkeypatch):
    body = json.loads((FX / "rdap_domain.json").read_text())

    def handler(req: httpx.Request):
        if req.url.path == "/domain/sandbox-bank-login.com":
            return httpx.Response(200, json=body)
        if req.url.host == "rdap.org" and req.url.path == "/domain/gone.com":
            return httpx.Response(302, headers={"Location": "https://rdap.registry.com/domain/gone.com"})
        return httpx.Response(404, json={"errorCode": 404})

    mock_client(monkeypatch, rdap, handler)
    ok = await rdap.fetch_rdap("sandbox-bank-login.com")
    assert ok["registrar"] == "Example Registrar LLC"
    nf = await rdap.fetch_rdap("gone.com")
    assert nf == {"found": False, "via": "rdap"}


async def test_fetch_rdap_bootstrap_fallback(monkeypatch):
    body = json.loads((FX / "rdap_domain.json").read_text())

    def handler(req: httpx.Request):
        if req.url.host == "rdap.org":
            return httpx.Response(503)
        if req.url.host == "data.iana.org":
            return httpx.Response(200, json={"services": [[["com"], ["https://rdap.nic.com/"]]]})
        if req.url.host == "rdap.nic.com":
            return httpx.Response(200, json=body)
        return httpx.Response(404)

    mock_client(monkeypatch, rdap, handler)
    ok = await rdap.fetch_rdap("sandbox-bank-login.com")
    assert ok["created"] == "2026-11-21T09:15:00Z"


async def test_fetch_ip_rdap(monkeypatch):
    body = json.loads((FX / "rdap_ip.json").read_text())
    mock_client(monkeypatch, rdap, lambda req: httpx.Response(200, json=body))
    v = await rdap.fetch_ip_rdap("203.0.113.7")
    assert v["abuse_emails"] == ["abuse@hosting.example"]
    assert v["country"] == "NL"


# ------------------------------------------------------------------ crt.sh
async def test_crtsh_search_and_cooldown(monkeypatch):
    monkeypatch.setattr(settings, "offline", False)
    rows = json.loads((FX / "crtsh.json").read_text())
    calls = []
    real = httpx.AsyncClient

    def factory(status):
        def handler(req):
            calls.append(str(req.url))
            return httpx.Response(status, json=rows if status == 200 else None)
        return lambda **kw: real(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(crtsh.httpx, "AsyncClient", factory(200))
    monkeypatch.setattr(crtsh, "datetime", type("D", (), {"now": staticmethod(
        lambda tz=None: datetime(2026, 11, 24, tzinfo=timezone.utc))}))
    out = await crtsh.crtsh_search("%sandbox-bank%", days=30)
    assert [r["id"] for r in out] == [3, 2]  # 2024 cert filtered, newest first
    assert set(out[0]) == {"name_value", "not_before", "issuer_name", "id"}
    assert await crtsh.crtsh_search("%sandbox-bank%", days=30) == out and len(calls) == 1  # cached

    monkeypatch.setattr(crtsh.httpx, "AsyncClient", factory(429))
    assert await crtsh.crtsh_search("%other%", days=30) == []
    n = len(calls)
    assert await crtsh.crtsh_search("%third%", days=30) == []  # cooldown: no request made
    assert len(calls) == n


# ------------------------------------------------------------------ feeds / blocklists / tranco
def test_blocklist_hits(isolated):
    install_feeds(isolated)
    install_tranco(isolated, [("popular.com", 50)])
    bh = intel_mod.blocklist_hits
    assert bh("https://sandbox-bank-login.com/verify") == ["openphish"]  # exact URL
    assert bh("https://sandbox-bank-login.com/other") == ["openphish"]  # host
    assert bh("https://www.sandbox-bank-login.com/") == ["openphish"]  # www variant
    assert bh("https://sandboxbank-otp.com/") == ["phishunt"]
    assert bh("https://pay.sandboxbank-secure.com/") == ["openphish"]  # sibling subdomain, unpopular reg
    assert bh("https://other-app.vercel.app/") == []  # shared host: never by parent
    assert bh("https://sandbox-phish.vercel.app/x") == ["openphish"]
    assert bh("https://www.popular.com/") == []  # popular registrable domain not tainted by docs.popular
    assert bh("https://docs.popular.com/forms/x") == ["openphish"]
    assert bh("https://sandboxbank.com/") == []
    assert bh("not a url") == []


def test_feed_urls_and_tranco(isolated):
    install_feeds(isolated)
    install_tranco(isolated, [("popular.com", 50)])
    f = intel_mod.feed_urls(limit=2)
    assert f["openphish"] == ["https://sandbox-bank-login.com/verify", "http://login.sandboxbank-secure.com/a/b"]
    assert f["phishunt"] == ["https://sandboxbank-otp.com"]
    assert feeds.tranco_rank("popular.com") == 50
    assert feeds.tranco_rank("www.popular.com") == 50
    assert feeds.tranco_rank("nope.com") is None


def test_feed_urls_without_files():
    assert intel_mod.feed_urls() == {"openphish": [], "phishunt": []}
    assert intel_mod.blocklist_hits("https://x.com/") == []


def test_refresh_feed_mocked(isolated, monkeypatch):
    monkeypatch.setattr(settings, "offline", False)

    def fake_get(url, **kw):
        return httpx.Response(200, text="junk line\nhttps://a.com/x\nhttp://b.com/\n",
                              request=httpx.Request("GET", url))

    monkeypatch.setattr(feeds.httpx, "get", fake_get)
    st = feeds.refresh_feeds(force=True)
    assert st == {"openphish": "ok", "phishunt": "ok"}
    assert (isolated / "openphish.txt").read_text().split() == ["https://a.com/x", "http://b.com/"]
    assert feeds.refresh_feeds() == {"openphish": "cached", "phishunt": "cached"}  # fresh: no refetch


# ------------------------------------------------------------------ enrich
async def test_enrich_offline_never_raises():
    i = await intel_mod.enrich("https://Login.Sandbox-Bank-Login.com/verify")
    assert isinstance(i, Intel)
    assert i.domain == "login.sandbox-bank-login.com"
    assert i.registrable_domain == "sandbox-bank-login.com"
    for s in ("rdap", "dns", "crtsh"):
        assert i.sources[s] == "offline"
    assert i.sources["urlscan"] == "no_key" and i.sources["safe_browsing"] == "no_key"


def _patch_sources(monkeypatch, calls):
    created = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()

    async def reg(d):
        calls.append(("reg", d))
        return {"found": True, "via": "rdap", "created": created, "registrar": "Example Registrar LLC",
                "abuse_emails": ["abuse@registrar.example"], "nameservers": ["ns1.host.example"], "raw": {}}

    async def dns_(h, r):
        calls.append(("dns", h))
        return {"a": ["203.0.113.7"], "ns": ["ns1.host.example"], "mx": [], "nxdomain": False}

    async def asn(ip):
        return {"asn": "AS64500", "asn_org": "Example Hosting", "country": "NL", "prefix": "", "via": "cymru"}

    async def iprdap(ip):
        return {"abuse_emails": ["abuse@hosting.example"], "country": "NL"}

    def crt(reg_):
        from scamshield.core import db

        calls.append(("crt", reg_))
        v = {"first_seen": "2026-11-21T10:00:00+00:00", "count": 2, "via": "crtsh"}
        db.cache_set(f"intel:crtsh:{reg_}", v, 3600)  # the real worker caches its own answer
        return v

    monkeypatch.setattr(intel_mod, "registration", reg)
    monkeypatch.setattr(intel_mod, "fetch_dns", dns_)
    monkeypatch.setattr(intel_mod, "fetch_asn", asn)
    monkeypatch.setattr(intel_mod, "fetch_ip_rdap", iprdap)
    monkeypatch.setattr(intel_mod, "_crtsh_bg", crt)
    monkeypatch.setattr(feeds, "refresh_feeds", lambda force=False: {"openphish": "cached", "phishunt": "cached"})
    monkeypatch.setattr(feeds, "ensure_tranco_background", lambda: None)


async def test_enrich_full_mocked(isolated, monkeypatch):
    monkeypatch.setattr(settings, "offline", False)
    install_feeds(isolated)
    install_tranco(isolated, [("popular.com", 50)])
    calls = []
    _patch_sources(monkeypatch, calls)
    i = await intel_mod.enrich("sandbox-bank-login.com")
    assert i.age_days == 3 and i.registrar == "Example Registrar LLC"
    assert i.abuse_emails == ["abuse@registrar.example"]
    assert i.ip == "203.0.113.7" and i.asn == "AS64500" and i.asn_org == "Example Hosting"
    assert i.hosting_country == "NL" and i.hosting_abuse_emails == ["abuse@hosting.example"]
    assert i.cert_first_seen == datetime(2026, 11, 21, 10, tzinfo=timezone.utc) and i.cert_count == 2
    assert i.blocklist_hits == ["openphish"]
    assert i.tranco_rank is None and i.sources["tranco"] == "cached"
    assert i.sources["rdap"] == "ok" and i.sources["dns"] == "ok" and i.sources["asn"] == "ok"
    assert i.sources["crtsh"] == "ok"
    # second call is served from the SQLite cache
    n = len(calls)
    i2 = await intel_mod.enrich("sandbox-bank-login.com")
    assert i2.sources["rdap"] == "cached" and i2.sources["dns"] == "cached" and i2.sources["crtsh"] == "cached"
    assert i2.age_days == 3 and len(calls) == n


async def test_enrich_not_found_and_failures(monkeypatch):
    monkeypatch.setattr(settings, "offline", False)
    calls = []
    _patch_sources(monkeypatch, calls)

    async def nf(d):
        return {"found": False, "via": "rdap"}

    async def boom(*a):
        raise RuntimeError("network down")

    async def nothing(*a, **k):
        return None

    monkeypatch.setattr(intel_mod, "registration", nf)
    monkeypatch.setattr(intel_mod, "fetch_dns", boom)
    monkeypatch.setattr(intel_mod, "_crtsh_bg", lambda r: None)
    monkeypatch.setattr(crtsh, "_certspotter", nothing)
    i = await intel_mod.enrich("never-registered-sandbox.com")
    assert i.sources["rdap"] == "not_found" and i.raw_rdap["found"] is False
    assert i.sources["dns"] == "unavailable" and i.sources["asn"] == "unavailable"
    assert i.sources["crtsh"] == "unavailable" and i.sources["certspotter"] == "unavailable"
    assert i.age_days is None


async def test_enrich_time_cap(monkeypatch):
    import asyncio

    monkeypatch.setattr(settings, "offline", False)
    _patch_sources(monkeypatch, [])
    monkeypatch.setattr(intel_mod, "TOTAL_CAP", 0.3)

    async def slow(*a):
        await asyncio.sleep(5)

    monkeypatch.setattr(intel_mod, "registration", slow)
    i = await intel_mod.enrich("slow-sandbox.com")
    assert i.sources["rdap"] == "unavailable" and i.sources["dns"] == "ok"


async def test_keyed_sources(monkeypatch):
    monkeypatch.setattr(settings, "offline", False)
    monkeypatch.setattr(settings, "urlscan_key", "test-key")
    monkeypatch.setattr(settings, "safe_browsing_key", "test-key")

    def handler(req: httpx.Request):
        if req.url.host == "urlscan.io":
            assert req.headers["API-Key"] == "test-key"
            return httpx.Response(200, json={"total": 1, "results": [
                {"page": {"url": "https://sandbox-bank-login.com/"}, "task": {"time": "2026-11-23T00:00:00Z"},
                 "result": "https://urlscan.io/api/v1/result/x/"}]})
        return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})

    mock_client(monkeypatch, keyed, handler)
    u = await keyed.fetch_urlscan("sandbox-bank-login.com")
    assert u["total"] == 1 and u["results"][0]["url"].startswith("https://sandbox")
    assert await keyed.fetch_safe_browsing("sandbox-bank-login.com") == ["SOCIAL_ENGINEERING"]


# ------------------------------------------------------------------ live (skipped offline)
@pytest.mark.network
@pytest.mark.skipif(settings.offline, reason="SCAMSHIELD_OFFLINE=1")
async def test_live_enrich(monkeypatch, tmp_path):
    from scamshield.core.config import DATA_DIR

    monkeypatch.setattr(settings, "offline", False)
    monkeypatch.setattr(_common, "FEEDS_DIR", DATA_DIR / "feeds")
    i = await intel_mod.enrich("emiratesnbd.com")
    assert i.registrable_domain == "emiratesnbd.com"
    assert i.age_days and i.age_days > 5000
