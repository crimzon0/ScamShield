"""Breaker: domain-level adversarial cases (no network, no browser).

Every input must produce a Verdict (never an exception) pointing in the right direction.
Detonation is replaced by a dead page => these are the domain-only verdicts a cloaked/taken-down scam gets.
"""
from __future__ import annotations

import pytest

from scamshield import pipeline
from scamshield.core.schemas import Detonation, FormField, RedirectHop
from scamshield.score import score

LABELS = {"scam", "likely_scam", "suspicious", "legitimate"}


async def _scan(url):
    res = await pipeline.scan_url(url, save=False, force=True, timeout=20)
    assert res.verdict.label in LABELS
    return res.verdict


def _why(v):
    return (v.url[:120], v.label, v.score, [s.id for s in v.reasons])


# ---- look-alikes that must NOT be legitimate even when the page is dead/cloaked (domain-only)
NOT_LEGIT = [
    ("idn_homoglyph_adcb_cyrillic_a", "https://xn--dcb-5cd.com/"),
    ("idn_homoglyph_enbd_cyrillic_e", "https://xn--emiratsnbd-psi.com/login"),
    ("idn_enbd_variant", "https://xn--emiratesnd-f7h.com/"),
    ("combosquat_adcb", "https://adcb-secure-login.com/"),
    ("combosquat_tamm", "https://tamm-pay.net/"),
    ("combosquat_enbd", "https://emiratesnbd-secure.com/login"),
    ("combosquat_rta_fines", "https://rta-fines-pay.com/"),
    ("combosquat_uaepass", "https://uaepass-login.online/"),
    ("combosquat_icp", "https://icp-gov-ae.com/"),
    ("tld_swap_enbd_co", "https://emiratesnbd.co/"),
    ("tld_swap_enbd_ae", "https://emiratesnbd.ae/"),
    ("tld_swap_fab_co", "https://bankfab.co/"),
    ("typo_digit_enbd", "https://e1iratesnbd.com/"),
    ("shared_host_enbd_vercel", "https://emiratesnbd-login.vercel.app/"),
    ("shared_host_adcb_netlify", "https://adcb-secure.netlify.app/"),
    ("shared_host_adcb_github", "https://adcb.github.io/login"),
    ("ip_literal", "http://203.0.113.7/adcb/login"),
    ("ipv6_literal", "http://[2001:db8::1]/adcb/login"),
]

# deceptive hosts: brand name outside the registrable domain (subdomain / userinfo) and obfuscated IPs
DECEPTIVE = [
    ("subdomain_trick_enbd", "https://emiratesnbd.com.verify-login.xyz/"),
    ("subdomain_trick_dubaipolice", "https://dubaipolice.gov.ae.secure-pay.top/fines"),
    ("subdomain_trick_tamm", "https://www.tamm.abudhabi.pay-fines.com/"),
    ("subdomain_trick_adcb_com_ae", "https://adcb.com.ae/"),
    ("userinfo_adcb_at_evil", "https://www.adcb.com@evil.example/"),
    ("userinfo_tamm_at_ip", "https://tamm.abudhabi:pay@203.0.113.9/"),
    ("ip_hex", "http://0x7f000001/adcb"),
    ("ip_decimal", "http://3232235777/adcb"),
]

LEGIT = [
    ("official_plain", "https://www.emiratesnbd.com/en/"),
    ("official_upper_trailing_dot", "HTTPS://ONLINE.EMIRATESNBD.COM./"),
    ("official_no_scheme", "emiratesnbd.com"),
    ("official_no_scheme_path", "www.tamm.abudhabi/services"),
    ("official_whitespace", "  https://www.adcb.com  "),
    ("official_port", "https://adcb.com:443/"),
    ("official_uppercase_host", "https://WWW.ADCB.COM/personal/"),
    ("official_long_path", "https://www.emiratesnbd.com/" + "a" * 5000),
    ("official_unicode_path", "https://u.ae/ar/خدمات?q=مخالفات"),
    ("official_at_in_path", "https://adcb.com/@evil.example/"),
    ("official_fragment_at", "https://www.rta.ae/#@evil.example"),
    ("official_query_with_other_url", "https://www.rta.ae/?next=https://evil.example/"),
]

GARBAGE = ["", " ", "not a url", "://", "http://", "https://", "javascript:alert(1)",
           "data:text/html,<h1>Sandbox Bank</h1>", "http://[::1", "http://exa mple.com/", "\x00\x01",
           "https://" + "a" * 300 + ".com/", "https://evil.example/" + "x" * 100_000, "http://-.com",
           "ftp://adcb.com/", "mailto:x@adcb.com", "http://.", "http://..../", "https://xn--/", "https://xn--zz.com/",
           "http://adcb.com:99999/", "http://user:pa@ss@adcb.com/"]


@pytest.mark.parametrize("case,url", NOT_LEGIT, ids=[c for c, _ in NOT_LEGIT])
async def test_lookalike_not_legit(dead_detonate, case, url):
    v = await _scan(url)
    assert v.label != "legitimate", _why(v)


@pytest.mark.parametrize("case,url", DECEPTIVE, ids=[c for c, _ in DECEPTIVE])
async def test_deceptive_host_not_legit(dead_detonate, case, url):
    v = await _scan(url)
    assert v.label != "legitimate", _why(v)


@pytest.mark.parametrize("case,url", LEGIT, ids=[c for c, _ in LEGIT])
async def test_official_variants_legit(dead_detonate, case, url):
    v = await _scan(url)
    assert v.label == "legitimate", _why(v)


@pytest.mark.parametrize("url", GARBAGE, ids=[f"g{i}" for i in range(len(GARBAGE))])
async def test_garbage_never_raises(dead_detonate, url):
    v = await _scan(url)
    assert v.summary_en and v.summary_ar


@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,<h1>x</h1>", "", "not a url"])
async def test_garbage_not_called_legitimate(dead_detonate, url):
    """A non-URL must not get a 'Looks legitimate' badge: it was never analysed."""
    v = await _scan(url)
    assert v.label != "legitimate", _why(v)


# ---- same deceptive hosts, but the page loaded and shows a brand login (synthetic Detonation, no real page)
def _phish_det(final_url: str, brand_words: str) -> Detonation:
    return Detonation(url=final_url, status="ok", final_url=final_url, http_status=200,
                      redirect_chain=[RedirectHop(url=final_url, status=200, kind="final")],
                      title=f"{brand_words} - Online Banking Login",
                      visible_text=f"{brand_words}. Your account is suspended. Verify your account: enter username, "
                                   "password and the OTP sent to your mobile.",
                      form_fields=[FormField(name="username", type="text", label="Username"),
                                   FormField(name="password", type="password", label="Password"),
                                   FormField(name="otp", type="text", label="OTP")])


PHISH_HOSTS = [
    ("subdomain_trick", "https://emiratesnbd.com.verify-login.xyz/login", "Emirates NBD"),
    ("userinfo", "https://www.adcb.com@evil.example/login", "ADCB"),
    ("ip_literal", "http://203.0.113.7/login", "ADCB"),
    ("shared_host", "https://sandboxbank-login.vercel.app/", "Sandbox Bank بنك التجربة"),
]


@pytest.mark.parametrize("case,final,words", PHISH_HOSTS, ids=[c for c, *_ in PHISH_HOSTS])
async def test_brand_login_on_deceptive_host_is_scam(monkeypatch, offline, case, final, words):
    monkeypatch.setenv("SCAMSHIELD_FICTIONAL", "1")
    import scamshield.detonate as dmod

    async def _det(url, persona="uae_mobile_ad_click", scan_id=None):
        return _phish_det(final, words)

    monkeypatch.setattr(dmod, "detonate", _det)
    v = await _scan(final)
    assert v.label in ("scam", "likely_scam"), _why(v)


# ---- score() unit tests: shared-host trust is never inherited
@pytest.mark.parametrize("final", ["https://sandboxbank-login.vercel.app/", "https://sandboxbank.example.vercel.app/",
                                   "https://adcb.github.io/login", "https://tamm-abudhabi.web.app/"])
def test_score_shared_host_never_official(final):
    d = Detonation(url=final, status="dead", final_url=final)
    v = score("t", final, [d], None, None, None, None)
    assert not any(s.id == "official_domain" for s in v.reasons), _why(v)


def test_score_sandbox_official_is_legit():
    d = _phish_det("https://login.sandboxbank.example/", "Sandbox Bank")
    v = score("t", d.final_url, [d], None, None, None, None)
    assert v.label == "legitimate", _why(v)
