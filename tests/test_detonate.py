"""Detonator tests: local fixture server only (fictional Sandbox Bank). Offline-safe."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).parent / "fixtures" / "detonate"))
import server as fixture_server  # noqa: E402

from scamshield.core.schemas import Detonation, FormField  # noqa: E402
from scamshield.detonate import PERSONAS, cloak_diff, close_browser, detonate, normalize_url  # noqa: E402

pytestmark = pytest.mark.asyncio(loop_scope="module")


@pytest.fixture(scope="module")
def base():
    srv, url = fixture_server.start()
    yield url
    srv.shutdown()


@pytest_asyncio.fixture(scope="module", loop_scope="module", autouse=True)
async def _browser_cleanup():
    yield
    await close_browser()


def kinds(d: Detonation) -> list[str]:
    return [h.kind for h in d.redirect_chain]


async def test_http_redirect_chain(base):
    d = await detonate(base + "/r1", scan_id="t-r1")
    assert d.status == "ok", d.error
    assert d.final_url == base + "/final"
    assert kinds(d) == ["http"] * 5 + ["final"]
    assert [h.status for h in d.redirect_chain] == [302, 302, 301, 302, 302, 200]
    assert d.http_status == 200
    assert d.screenshot_path and Path(d.screenshot_path).stat().st_size > 0
    assert d.dom_path and Path(d.dom_path).exists()
    assert d.har_path and Path(d.har_path).exists()
    assert d.favicon_path and Path(d.favicon_path).exists()
    assert d.lang == "ar"
    assert "Sandbox Bank" in d.title
    types = {f.type for f in d.form_fields}
    assert "password" in types and "otp" in types
    assert any("كلمة المرور" in f.label for f in d.form_fields)
    assert d.finished_at and d.duration_ms > 0


async def test_meta_refresh(base):
    d = await detonate(base + "/meta", scan_id="t-meta")
    assert d.status == "ok", d.error
    assert d.final_url == base + "/final"
    assert kinds(d) == ["meta", "final"]


async def test_js_redirect(base):
    d = await detonate(base + "/js", scan_id="t-js")
    assert d.status == "ok", d.error
    assert d.final_url == base + "/final"
    assert kinds(d) == ["js", "final"]


async def test_blank(base):
    d = await detonate(base + "/blank", scan_id="t-blank")
    assert d.status == "blank"


async def test_dead():
    # grab a free port and release it: nothing listens there -> connection refused
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    d = await detonate(f"http://127.0.0.1:{port}/", scan_id="t-dead")
    assert d.status == "dead"
    assert d.error.startswith("net::ERR_")
    assert kinds(d) == ["start"]


async def test_slow_times_out(base):
    t0 = time.monotonic()
    d = await detonate(base + "/slow", scan_id="t-slow")
    assert time.monotonic() - t0 < 17.5
    assert d.status == "timeout"
    assert d.redirect_chain


async def test_cloak_detected(base):
    dets = [await detonate(base + "/cloak", persona=p, scan_id="t-cloak") for p in PERSONAS]
    by = {d.persona: d for d in dets}
    assert by["crawler"].title.startswith("Gardening")
    assert "Sandbox Bank" in by["uae_mobile_ad_click"].title
    cd = cloak_diff(dets)
    assert cd.cloaked
    assert cd.similarity < 0.5
    assert any("credential" in x for x in cd.differences)


async def test_not_cloaked_same_page(base):
    dets = [await detonate(base + "/final", persona=p, scan_id="t-same") for p in ("uae_mobile_ad_click", "desktop")]
    cd = cloak_diff(dets)
    assert not cd.cloaked, cd.differences


async def test_bad_inputs_never_raise():
    for u in ["data:text/html,hi", "about:blank", "javascript:alert(1)", "", "ftp://x.example/", "http://"]:
        d = await detonate(u)
        assert d.status == "error" and d.error


async def test_normalize_url():
    assert normalize_url("example.ae/x") == ("http://example.ae/x", "")
    assert normalize_url("https://a.ae")[1] == ""
    assert normalize_url("file:///etc/passwd")[1]


async def test_cloak_diff_unit():
    a = Detonation(url="u", persona="uae_mobile_ad_click", final_url="https://evil.example/x", visible_text="login now",
                   form_fields=[FormField(type="password")])
    b = Detonation(url="u", persona="crawler", final_url="https://other.example/", visible_text="login now")
    cd = cloak_diff([a, b])
    assert cd.cloaked and any("final domain" in x for x in cd.differences)
    assert cloak_diff([a]).cloaked is False
    assert cloak_diff([]).cloaked is False


async def test_tall_page_screenshot_capped(base):
    from PIL import Image

    d = await detonate(base + "/tall", persona="desktop", scan_id="t-tall")
    assert d.status == "ok", d.error
    with Image.open(d.screenshot_path) as im:
        assert im.height <= 10_000 * 2  # css px * device scale


async def test_concurrent_five(base):
    import asyncio

    t0 = time.monotonic()
    dets = await asyncio.gather(*[detonate(base + "/r1", scan_id="t-conc") for _ in range(5)])
    assert all(d.status == "ok" and d.final_url == base + "/final" for d in dets)
    assert len({d.screenshot_path for d in dets}) == 5  # no artifact clobbering
    assert time.monotonic() - t0 < 30
