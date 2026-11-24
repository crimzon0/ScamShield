import asyncio

import pytest

from scamshield import pipeline
from scamshield.core.schemas import Detonation, ScanResult


@pytest.fixture(autouse=True)
def _tmp_db(tmp_path, monkeypatch):
    from scamshield.core import db
    from scamshield.core.config import settings

    monkeypatch.setattr(settings, "db_path", tmp_path / "t.db")
    yield


def test_scan_url_returns_verdict():
    res = asyncio.run(pipeline.scan_url("https://sandbox-bank-login.example/verify", save=False))
    assert isinstance(res, ScanResult) and 0 <= res.verdict.score <= 100


def test_scan_url_never_raises_when_detonate_breaks(monkeypatch):
    import scamshield.detonate as det

    async def boom(*a, **k):
        raise RuntimeError("browser crashed")

    monkeypatch.setattr(det, "detonate", boom)
    res = asyncio.run(pipeline.scan_url("https://x.example/", save=False))
    assert res.verdict.mode == "domain_only"


def test_timeout_guard_falls_back(monkeypatch):
    import scamshield.detonate as det

    async def slow(url, persona="uae_mobile_ad_click", scan_id=None):
        await asyncio.sleep(10)
        return Detonation(url=url)

    monkeypatch.setattr(det, "detonate", slow)
    res = asyncio.run(pipeline.scan_url("https://slow.example/", save=False, timeout=0.5))
    assert res.verdict.mode == "domain_only"
    assert res.verdict.reasons


def test_cache_reuse_and_force(monkeypatch):
    monkeypatch.setattr(pipeline, "_transient", lambda r: False)  # offline scans are transient
    a = asyncio.run(pipeline.scan_url("https://cache.example/", save=True))
    b = asyncio.run(pipeline.scan_url("https://cache.example/", save=True))
    c = asyncio.run(pipeline.scan_url("https://cache.example/", save=True, force=True))
    assert a.scan_id == b.scan_id
    assert c.scan_id != a.scan_id


def test_garbage_input():
    res = asyncio.run(pipeline.scan_url("", save=False))
    assert isinstance(res, ScanResult)


def test_transient_not_reused():
    a = asyncio.run(pipeline.scan_url("https://dead-offline.example/", save=True))
    if pipeline._transient(a):
        b = asyncio.run(pipeline.scan_url("https://dead-offline.example/", save=True))
        assert b.scan_id != a.scan_id
