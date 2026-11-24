import asyncio

from scamshield.core.domains import is_official, is_shared_host, registrable
from scamshield.core.schemas import ScanResult


def test_registrable_private_suffix():
    assert registrable("https://foo.vercel.app/x") == "foo.vercel.app"
    assert registrable("https://online.emiratesnbd.com/a") == "emiratesnbd.com"
    assert registrable("https://www.tamm.abudhabi/en") == "tamm.abudhabi"
    assert is_shared_host("evil.netlify.app")


def test_is_official():
    assert is_official("https://secure.sandboxbank.example/login", ["sandboxbank.example"])
    assert not is_official("https://sandboxbank.example.evil.com", ["sandboxbank.example"])


def test_pipeline_runs_on_stubs(tmp_path, monkeypatch):
    from scamshield.pipeline import scan_url

    res = asyncio.run(scan_url("https://sandbox-bank-login.example/verify", save=False))
    assert isinstance(res, ScanResult)
    assert 0 <= res.verdict.score <= 100
