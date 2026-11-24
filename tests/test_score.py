from datetime import timedelta

from scamshield.core import fixtures
from scamshield.core.schemas import BrandMatch, CloakDiff, Detonation, FormField, Intel, LookalikeResult
from scamshield.score import score

NOW = fixtures.NOW


def _det(url, status="ok", **kw):
    return Detonation(url=url, final_url=url if status == "ok" else kw.pop("final_url", ""), status=status, **kw)


def test_official_domain_is_legitimate():
    url = "https://www.emiratesnbd.com/en/personal-banking"
    d = _det(url, title="Emirates NBD", visible_text="Log in to online banking",
             form_fields=[FormField(name="password", type="password")])
    b = BrandMatch(brand_id="emirates_nbd", name_en="Emirates NBD", confidence=0.95,
                   official_domains=["emiratesnbd.com"], is_official_domain=True, asks_for=["credentials"])
    v = score("t1", url, [d], Intel(domain="emiratesnbd.com", age_days=9000), b, None)
    assert v.label == "legitimate" and v.score <= 10
    assert v.reasons and all(r.ar for r in v.reasons)


def test_official_of_other_brand_is_legitimate():
    # page on fixture official domain mentions a different brand -> still legitimate
    url = "https://secure.sandboxbank.example/login"
    b = BrandMatch(brand_id="other", name_en="Other", confidence=0.9, official_domains=["other.example"])
    v = score("t2", url, [_det(url)], None, b, None)
    assert v.label == "legitimate"


def test_brand_on_shared_host_is_scam():
    url = "https://sandbox-bank-verify.vercel.app/login"
    b = fixtures.brand_match()
    v = score("t3", url, [_det(url)], Intel(domain="sandbox-bank-verify.vercel.app"), b, None)
    assert v.label == "scam" and v.score >= 85
    ids = {r.id for r in v.reasons}
    assert "brand_on_unofficial_domain" in ids and "shared_host" in ids
    assert v.summary_ar and v.summary_en


def test_shared_host_does_not_inherit_tranco():
    url = "https://x.vercel.app/"
    v = score("t4", url, [_det(url)], Intel(domain="x.vercel.app", tranco_rank=500), None, None)
    assert "popular_site" not in {r.id for r in v.reasons}


def test_dead_page_young_lookalike_domain_only():
    url = "https://sandbox-bank-login.example/verify"
    d = _det(url, status="dead", error="NXDOMAIN")
    v = score("t5", url, [d], fixtures.intel(), None, fixtures.lookalike())
    assert v.mode == "domain_only"
    assert v.label in ("scam", "likely_scam")
    assert all(r.ar.strip() for r in v.reasons)
    assert any("أيام" in r.ar for r in v.reasons)


def test_no_detonations_domain_only_and_never_raises():
    v = score("t6", "not a url", [], None, None, None)
    assert v.mode == "domain_only" and 0 <= v.score <= 100


def test_popular_site_is_legitimate():
    url = "https://www.google.com/"
    v = score("t7", url, [_det(url, title="Google")], Intel(domain="google.com", tranco_rank=1, age_days=10000),
              None, LookalikeResult(domain="google.com"))
    assert v.label == "legitimate"


def test_blocklist_forces_scam_even_if_unknown():
    url = "https://random-thing.example/"
    v = score("t8", url, [_det(url)], Intel(domain="random-thing.example", blocklist_hits=["openphish"]), None, None)
    assert v.label == "scam"


def test_blocklist_overrides_official():
    url = "https://www.sandboxbank.example/"
    v = score("t9", url, [_det(url)], Intel(domain="sandboxbank.example", blocklist_hits=["openphish"]), None, None)
    assert v.label != "legitimate"


def test_news_site_mentioning_brand_not_scam():
    url = "https://www.bignews.example/article"
    b = BrandMatch(brand_id="sandbox_bank", name_en="Sandbox Bank", confidence=0.8,
                   official_domains=["sandboxbank.example"])
    v = score("t10", url, [_det(url)], Intel(domain="bignews.example", tranco_rank=3000, age_days=8000), b, None)
    assert v.label == "legitimate"


def test_generic_phish_signals_without_brand():
    url = "http://198.51.100.7/secure/login.php"
    d = _det(url, visible_text="Your account has been suspended. Verify your account now.",
             form_fields=[FormField(name="pass", type="password")])
    v = score("t11", url, [d], None, None, None, CloakDiff(cloaked=True, differences=["crawler saw blank page"]))
    assert v.label in ("scam", "likely_scam")
    ids = {r.id for r in v.reasons}
    assert {"ip_host", "password_no_https", "cloaking", "phishing_language"} <= ids


def test_new_risky_tld_with_card_form():
    url = "https://pay-fine-now.top/"
    d = _det(url, form_fields=[FormField(name="cardnumber", label="Card number")])
    i = Intel(domain="pay-fine-now.top", age_days=2, cert_first_seen=NOW - timedelta(days=1))
    v = score("t12", url, [d], i, None, None)
    assert v.label in ("scam", "likely_scam")
