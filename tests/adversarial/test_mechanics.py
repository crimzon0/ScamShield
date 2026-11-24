"""Breaker: delivery mechanics against the local fixture server (fictional Sandbox Bank only, no internet).

Runs the real pipeline (real headless Chromium detonation) against tests/adversarial/fixtures/advserver.py.
Host is `adv-fixture.localhost` (Chromium maps *.localhost to loopback; not 127.0.0.1) so the ip_host signal does not do the work for us.
Intel is forced offline. SCAMSHIELD_FICTIONAL=1 so Sandbox Bank is a known brand (official: sandboxbank.example).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import advserver  # noqa: E402

from scamshield.detonate import close_browser, detonate  # noqa: E402

pytestmark = pytest.mark.asyncio(loop_scope="module")
BAD = ("scam", "likely_scam")


@pytest.fixture(scope="module")
def base():
    srv, port = advserver.start()
    yield f"http://adv-fixture.localhost:{port}"
    srv.shutdown()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    from scamshield.core.config import settings

    monkeypatch.setenv("SCAMSHIELD_FICTIONAL", "1")
    monkeypatch.setattr(settings, "offline", True, raising=False)


@pytest_asyncio.fixture(scope="module", loop_scope="module", autouse=True)
async def _browser_cleanup():
    yield
    await close_browser()


async def _scan(url, personas=("uae_mobile_ad_click",)):
    from scamshield import pipeline

    res = await pipeline.scan_url(url, personas=personas, save=False, force=True)
    return res


def _why(res):
    v = res.verdict
    return (v.url, v.final_url, v.label, v.score, v.mode, [s.id for s in v.reasons],
            [(d.persona, d.status, d.error[:120]) for d in res.detonations])


async def test_control_benign_page(base):
    res = await _scan(base + "/benign")
    assert res.verdict.label in ("legitimate", "suspicious"), _why(res)


async def test_direct_phish(base):
    res = await _scan(base + "/phish")
    assert res.verdict.label in BAD, _why(res)


async def test_long_mixed_redirect_chain(base):
    res = await _scan(base + "/chain/0")
    d = res.detonations[0]
    assert d.final_url.endswith("/phish"), (d.final_url, [(h.kind, h.url) for h in d.redirect_chain])
    assert res.verdict.label in BAD, _why(res)
    assert any(s.id == "redirects" for s in res.verdict.reasons), _why(res)


async def test_redirect_loop_gives_verdict(base):
    t0 = time.monotonic()
    res = await _scan(base + "/loop/a")
    assert res.verdict.label in ("scam", "likely_scam", "suspicious", "legitimate")
    assert time.monotonic() - t0 < 45
    assert res.verdict.summary_en and res.verdict.summary_ar


async def test_cloaking_mobile_ar_vs_crawler(base):
    res = await _scan(base + "/cloak", personas=("uae_mobile_ad_click", "crawler"))
    by = {d.persona: d for d in res.detonations}
    assert "Sandbox Bank" in by["uae_mobile_ad_click"].title, _why(res)
    assert "Gardening" in by["crawler"].title, _why(res)
    assert res.cloak is not None and res.cloak.cloaked, (res.cloak, _why(res))
    assert res.verdict.label in BAD, _why(res)


async def test_cloaking_default_persona_sees_payload(base):
    """Default scan (one persona) must still see the ar-AE mobile payload."""
    res = await _scan(base + "/cloak")
    assert res.verdict.label in BAD, _why(res)


async def test_referrer_gated(base):
    res = await _scan(base + "/refgate")
    assert res.verdict.label in BAD, _why(res)


async def test_js_only_render(base):
    res = await _scan(base + "/jsonly")
    assert res.verdict.label in BAD, _why(res)


async def test_delayed_form_3s(base):
    res = await _scan(base + "/delayed")
    d = res.detonations[0]
    assert any(f.type == "password" for f in d.form_fields), (d.form_fields, _why(res))
    assert res.verdict.label in BAD, _why(res)


async def test_blank_page(base):
    res = await _scan(base + "/blank")
    assert res.verdict.summary_en and res.verdict.mode == "domain_only", _why(res)


async def test_huge_page(base):
    t0 = time.monotonic()
    res = await _scan(base + "/huge")
    assert time.monotonic() - t0 < 45
    assert res.verdict.label in BAD, _why(res)


async def test_slow_page_times_out_to_verdict(base):
    t0 = time.monotonic()
    res = await _scan(base + "/slow")
    assert time.monotonic() - t0 < 45, time.monotonic() - t0
    assert res.verdict.mode == "domain_only", _why(res)


async def test_dead_url():
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    res = await _scan(f"http://adv-fixture.localhost:{port}/login")
    assert res.verdict.mode == "domain_only", _why(res)
    assert res.verdict.summary_en


async def test_phish_on_path_of_shared_like_host(base):
    res = await _scan(base + "/shared/sandboxbank-login/")
    assert res.verdict.label in BAD, _why(res)


async def test_detonator_chain_records_hops(base):
    d = await detonate(base + "/chain/0", scan_id="adv-chain")
    kinds = [h.kind for h in d.redirect_chain]
    assert d.status == "ok", d.error
    assert {"meta", "js"} <= set(kinds) and ("http" in kinds), kinds
    assert len(d.redirect_chain) >= 10, kinds
