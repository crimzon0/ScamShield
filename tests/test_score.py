import os

os.environ.setdefault("SCAMSHIELD_FICTIONAL", "1")

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


def test_platform_404_ignores_brand_content():
    url = "https://ephemeral-squirrel-f84ee4.netlify.app/"
    d = _det(url, http_status=404, title="Site not found", visible_text="Site not found. Looks like you followed a broken link")
    v = score("t13", url, [d], Intel(domain="ephemeral-squirrel-f84ee4.netlify.app"), fixtures.brand_match(), None)
    assert v.mode == "domain_only"
    ids = {r.id for r in v.reasons}
    assert "brand_on_unofficial_domain" not in ids and "platform_takedown" in ids


def test_bounce_to_popular_site_judges_link_domain():
    url = "https://login-secure-verify.example/"
    d = Detonation(url=url, final_url="https://www.google.com/", status="ok", title="Google")
    final_intel = Intel(domain="google.com", tranco_rank=1, age_days=9000)
    in_intel = Intel(domain="login-secure-verify.example", age_days=2)
    v = score("t14", url, [d], final_intel, None, None, input_intel=in_intel)
    ids = {r.id for r in v.reasons}
    assert "redirect_to_popular_site" in ids and "popular_site" not in ids
    assert v.label in ("scam", "likely_scam")


def test_legit_redirect_between_official_domains():
    url = "https://www.etisalat.ae/en/"
    d = Detonation(url=url, final_url="https://www.eand.ae/en/index.html", status="ok", title="e&")
    v = score("t15", url, [d], Intel(domain="eand.ae", tranco_rank=60000), None, None,
              input_intel=Intel(domain="etisalat.ae", tranco_rank=20000))
    assert v.label == "legitimate"


def test_global_brand_combosquat_domain_only():
    url = "https://user.coinbase-secured.com"
    d = _det(url, status="dead", error="net::ERR_NAME_NOT_RESOLVED")
    v = score("t16", url, [d], Intel(domain="coinbase-secured.com", age_days=20, raw_rdap={"found": True}), None, None)
    assert "brand_in_hostname" in {r.id for r in v.reasons}
    assert v.label in ("scam", "likely_scam")


def _dom(tmp_path, html):
    p = tmp_path / "dom.html"
    p.write_text(html, encoding="utf-8")
    return str(p)


def test_sso_integration_is_not_impersonation(tmp_path):
    url = "https://sandbox-bank-connect.dev.integrator.example/"
    html = '<a href="https://id.sandboxbank.example/oauth/authorize?client_id=x&redirect_uri=y">Sign in with Sandbox Bank</a>'
    d = _det(url, title="Sign in with Sandbox Bank", dom_path=_dom(tmp_path, html))
    b = BrandMatch(brand_id="sandbox_bank", name_en="Sandbox Bank", confidence=0.9, methods=["text"],
                   official_domains=["sandboxbank.example"], asks_for=[])
    v = score("t20", url, [d], Intel(domain="integrator.example"), b, fixtures.lookalike())
    ids = {r.id for r in v.reasons}
    assert "sso_integration" in ids and "brand_on_unofficial_domain" not in ids
    assert v.label in ("legitimate", "suspicious")


def test_phish_posting_credentials_locally_still_scam(tmp_path):
    url = "https://sandbox-bank-login.example/verify"
    html = ('<form action="/post.php"><input type="password" name="pw"></form>'
            '<a href="https://id.sandboxbank.example/login">real site</a>')
    d = _det(url, title="Sandbox Bank", dom_path=_dom(tmp_path, html),
             form_fields=[FormField(name="pw", type="password")])
    b = BrandMatch(brand_id="sandbox_bank", name_en="Sandbox Bank", confidence=0.9, methods=["text"],
                   official_domains=["sandboxbank.example"], asks_for=["credentials"])
    v = score("t21", url, [d], Intel(domain="sandbox-bank-login.example", age_days=3), b, fixtures.lookalike())
    assert v.label == "scam"
    assert "sso_integration" not in {r.id for r in v.reasons}


def test_footer_link_to_official_homepage_is_not_sso(tmp_path):
    url = "https://sandbox-bank-rewards.example/"
    html = '<a href="https://www.sandboxbank.example/">Sandbox Bank</a>'
    d = _det(url, title="Sandbox Bank rewards", dom_path=_dom(tmp_path, html))
    b = BrandMatch(brand_id="sandbox_bank", name_en="Sandbox Bank", confidence=0.9, methods=["text"],
                   official_domains=["sandboxbank.example"], asks_for=[])
    v = score("t22", url, [d], Intel(domain="sandbox-bank-rewards.example", age_days=3), b, None)
    assert v.label == "scam"


def test_registry_brand_on_sslip_with_ip_is_scam():
    url = "https://adcbupdate.6983254321app.ovinramavol.tkdev.35-204-139-184.sslip.io/"
    d = _det(url, status="timeout")
    v = score("t30", url, [d], Intel(domain="sslip.io", age_days=4000), None, None)
    ids = {r.id for r in v.reasons}
    assert {"brand_in_hostname", "ip_in_hostname"} <= ids
    assert v.label in ("scam", "likely_scam")


def test_brand_token_buried_in_word_is_weak():
    url = "https://almashreqmedical.example/"
    look = LookalikeResult(domain="almashreqmedical.example", brand_id="mashreq", closest_official="mashreq.com",
                           techniques=["keyword", "combosquat"], score=0.85)
    v = score("t31", url, [_det(url)], Intel(domain="almashreqmedical.example", age_days=4000), None, look)
    lw = next(r.weight for r in v.reasons if r.id == "lookalike_domain")
    assert lw <= 20 and v.label in ("legitimate", "suspicious")


def _sub_look(host):
    return LookalikeResult(domain=host, brand_id="sandbox_bank", closest_official="sandboxbank.example",
                           techniques=["subdomain_brand"], score=0.9)


def test_integrator_subdomain_on_established_parent_capped():
    url = "https://sandboxbank.partnerpay.io/"
    b = BrandMatch(brand_id="sandbox_bank", name_en="Sandbox Bank", confidence=0.8, methods=["text"],
                   official_domains=["sandboxbank.example"], asks_for=[])
    v = score("t40", url, [_det(url)], Intel(domain="partnerpay.io", age_days=900), b, _sub_look(url))
    assert v.score <= 59 and v.label != "scam" and v.label != "likely_scam"


def test_integrator_rule_keeps_young_parent_and_secret_forms():
    url = "https://sandboxbank.partnerpay.io/"
    v = score("t41", url, [_det(url)], Intel(domain="partnerpay.io", age_days=10), None, _sub_look(url))
    assert v.label in ("scam", "likely_scam")
    d = _det(url, form_fields=[FormField(name="otp", label="OTP")])
    v2 = score("t42", url, [d], Intel(domain="partnerpay.io", age_days=900), None, _sub_look(url))
    assert v2.label in ("scam", "likely_scam")


def _uaepass(conf=0.5, ev=("body-text mention only",), asks=()):
    return BrandMatch(brand_id="uae_pass", name_en="UAE PASS", confidence=conf, methods=["text"],
                      evidence=list(ev), official_domains=["uaepass.ae"], asks_for=list(asks))


def test_gov_ae_login_with_uaepass_button_is_legitimate():
    url = "https://eservice.sewa.gov.ae/portal/"
    d = _det(url, title="SEWA eServices", form_fields=[FormField(name="password", type="password")])
    v = score("t50", url, [d], Intel(domain="sewa.gov.ae"), _uaepass(0.7, ev=["'UAE PASS' in title"]), None)
    assert v.label == "legitimate", [(r.id, r.weight) for r in v.reasons]


def test_ac_ae_portal_with_mention_is_legitimate():
    url = "https://my.uaeu.ac.ae/"
    d = _det(url, form_fields=[FormField(name="pwd", type="password")])
    v = score("t51", url, [d], Intel(domain="uaeu.ac.ae"), _uaepass(), None)
    assert v.label == "legitimate"


def test_uaepass_sso_button_on_unknown_site_not_scam():
    url = "https://portal.someauthority.example.com/login"
    v = score("t52", url, [_det(url)], Intel(domain="example.com"), _uaepass(0.8, ev=["'UAE PASS' in title"]), None)
    assert "brand_on_unofficial_domain" not in {r.id for r in v.reasons}


def test_regulator_footer_is_not_claim():
    url = "https://www.exchange-house.example.com/"
    b = BrandMatch(brand_id="central_bank_uae", name_en="Central Bank of the UAE", confidence=0.7, methods=["text"],
                   official_domains=["centralbank.ae"])
    v = score("t53", url, [_det(url)], Intel(domain="example.com", tranco_rank=400000), b, None)
    assert v.label == "legitimate"


def test_mention_only_is_not_claim():
    url = "https://shop.example.com/"
    b = BrandMatch(brand_id="adcb", name_en="ADCB", confidence=0.5, methods=["text"],
                   evidence=["body-text mention only"], official_domains=["adcb.com"])
    v = score("t54", url, [_det(url)], Intel(domain="example.com", age_days=2000), b, None)
    assert "brand_on_unofficial_domain" not in {r.id for r in v.reasons}


# ------------------------------------------------------------------ LLM gate (fake llm_json; offline)
def _fake_llm(monkeypatch, brand_id, asks=("card", "otp"), conf=1.0):
    from scamshield.core import llm as llm_mod
    from scamshield.core.config import settings

    seen = []

    def fake(prompt, schema):
        seen.append(prompt)
        return {"brand_claimed": brand_id, "brand_id": brand_id, "asks_for": list(asks), "language": "en",
                "confidence": conf}

    monkeypatch.setattr(settings, "offline", False)
    monkeypatch.setattr(llm_mod, "llm_available", lambda: True)
    monkeypatch.setattr(llm_mod, "llm_json", fake)
    return seen


async def _llm_scan(monkeypatch, url, bid, intel, look=None, asks=("card", "otp"), **kw):
    from scamshield.brand import match_brand

    seen = _fake_llm(monkeypatch, bid, asks)
    d = _det(url, **kw)
    b = await match_brand(d)
    return b, score("tl", url, [d], intel, b, look), seen


async def test_llm_only_evidence_cannot_flag(monkeypatch):
    # unknown site, no brand text, no forms; the (fake) LLM claims Sandbox Bank and card+OTP requests
    url = "https://www.small-merchant.example/checkout"
    b, v, seen = await _llm_scan(monkeypatch, url, "sandbox_bank", None,
                                 title="Checkout", visible_text="Thank you for shopping with us.")
    assert seen and all("<page>" in p and "</page>" in p for p in seen)
    assert b.llm_used and "llm" in b.methods and b.brand_id == "sandbox_bank"  # LLM evidence is recorded ...
    assert v.label == "legitimate", [(r.id, r.weight) for r in v.reasons]  # ... but cannot flag on its own
    assert "llm_uncorroborated" in {r.id for r in v.reasons}
    assert "brand_on_unofficial_domain" not in {r.id for r in v.reasons}
    # the same with an LLM-only claim but an established domain
    _, v2, _ = await _llm_scan(monkeypatch, url, "sandbox_bank", Intel(domain="small-merchant.example", age_days=3000),
                               title="Checkout", visible_text="Thank you for shopping with us.")
    assert v2.label == "legitimate"


async def test_llm_brand_on_login_page_of_legit_site_not_likely_scam(monkeypatch):
    # legit established non-registry login page (password form); LLM wrongly says it is Sandbox Bank
    url = "https://portal.some-company.example/login"
    _, v, _ = await _llm_scan(monkeypatch, url, "sandbox_bank", Intel(domain="some-company.example", age_days=3000),
                              asks=("credentials", "otp"), title="Employee portal", visible_text="Sign in",
                              form_fields=[FormField(name="username"), FormField(name="password", type="password")])
    assert v.label not in ("scam", "likely_scam"), [(r.id, r.weight) for r in v.reasons]


async def test_official_domain_stays_legitimate_whatever_llm_says(monkeypatch):
    url = "https://secure.sandboxbank.example/login"
    b, v, _ = await _llm_scan(monkeypatch, url, "sandbox_bank", None, asks=("credentials", "otp", "card"),
                              title="Login", form_fields=[FormField(name="password", type="password")])
    assert v.label == "legitimate" and v.score <= 10
    # LLM claims a *different* brand on the official domain: still legitimate
    from scamshield.brand import load_registry

    other = next((x["id"] for x in load_registry() if x["id"] != "sandbox_bank" and not x.get("fictional")), None)
    if other:
        _, v2, _ = await _llm_scan(monkeypatch, url, other, None, asks=("card",), title="Login")
        assert v2.label == "legitimate"


async def test_llm_still_corroborates_independent_signals(monkeypatch):
    # young look-alike domain with a card form: non-LLM evidence already flags it; LLM agreeing keeps it a scam
    url = "https://sandbox-bank-login.example/verify"
    b, v, _ = await _llm_scan(monkeypatch, url, "sandbox_bank", fixtures.intel(), fixtures.lookalike(),
                              title="Verify your card", form_fields=[FormField(name="card", label="Card number"),
                                                                     FormField(name="cvv", label="CVV")])
    assert v.label == "scam" and "llm_uncorroborated" not in {r.id for r in v.reasons}


def test_strip_llm_recovers_non_llm_brand():
    from scamshield.score import strip_llm

    b = BrandMatch(brand_id="sandbox_bank", name_en="Sandbox Bank", confidence=round(1 - 0.8 * 0.55, 3),
                   methods=["llm", "text"], llm_used=True, asks_for=["credentials", "card"],
                   evidence=["'Sandbox Bank' in title", "LLM: page claims to be 'Sandbox (Bank)' (1.00)",
                             "LLM: page asks for card"])
    s = strip_llm(b)
    assert s.methods == ["text"] and abs(s.confidence - 0.2) < 0.01 and s.asks_for == ["credentials"]
    assert not any(e.startswith("LLM:") for e in s.evidence) and b.methods == ["llm", "text"]  # original untouched
    only = strip_llm(BrandMatch(brand_id="adcb", confidence=0.4, methods=["llm"], llm_used=True,
                                evidence=["LLM: page claims to be 'ADCB' (0.90)"]))
    assert only.brand_id is None and only.confidence == 0.0
    plain = BrandMatch(brand_id="adcb", confidence=0.9, methods=["text"])
    assert strip_llm(plain) is plain


async def test_llm_cannot_raise_legit_score(monkeypatch):
    # LLM-only brand claim on an unknown page with no other signal: no weak_brand_claim points either
    url = "https://www.rewards-portal.example/"
    _, v, _ = await _llm_scan(monkeypatch, url, "sandbox_bank", Intel(domain="rewards-portal.example", age_days=3000),
                              asks=(), title="Rewards", visible_text="Earn points")
    ids = {r.id for r in v.reasons}
    assert v.label == "legitimate" and "weak_brand_claim" not in ids and "llm_uncorroborated" in ids
