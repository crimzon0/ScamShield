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


# ---------------------------------------------------------------- radar false-positive classes (2026-11-25)
def _bm(bid="sandbox_bank", name="Sandbox Bank", conf=0.9, methods=("text",), evidence=("'Sandbox Bank' in title",),
        asks=(), official=("sandboxbank.example",)):
    return BrandMatch(brand_id=bid, name_en=name, name_ar="بنك التجربة", confidence=conf, methods=list(methods),
                      evidence=list(evidence), official_domains=list(official), asks_for=list(asks))


def _flagged(v):
    return v.label in ("scam", "likely_scam")


def _look(domain, score, techniques, distance=None):
    return LookalikeResult(domain=domain, brand_id="sandbox_bank", closest_official="sandboxbank.example",
                           techniques=list(techniques), distance=distance, score=score)


def test_gov_site_with_own_login_and_uae_pass_button_is_not_scam():
    # gcaa.ae pattern: real authority, not in registry, no intel (.ae has no RDAP), own username/password/OTP login
    # next to a 'Login with UAE PASS' button. The fields are the site's own, not UAE PASS's.
    url = "https://sandboxauthority.ae/en/pages/login.aspx"
    d = _det(url, title="Login with UAE PASS", visible_text="Login with UAE PASS\nSandbox Authority (SandboxAuthority) "
             "e-services. Do not have a UAE PASS account? Enter the OTP code sent to your phone.",
             form_fields=[FormField(name="txtUserName", type="text", placeholder="Enter your username"),
                          FormField(name="txtPwd", type="password", placeholder="Enter your password"),
                          FormField(name="txtphoneOTP", type="text", label="OTP")])
    b = _bm("uae_pass", "UAE PASS", 0.9, ("text", "llm"), ("'uae pass' in title",), ("credentials", "otp"),
            ("uaepass.ae", "id.uaepass.ae"))
    v = score("fp1", url, [d], Intel(domain="sandboxauthority.ae"), b, None)
    assert not _flagged(v), (v.score, [r.id for r in v.reasons])
    assert "sso_integration" in {r.id for r in v.reasons}


def test_fake_uae_pass_login_collecting_its_password_still_scam():
    url = "https://secure-gov-portal.example/login"
    d = _det(url, title="Login with UAE PASS", visible_text="Login with UAE PASS",
             form_fields=[FormField(name="u", label="UAE PASS username"),
                          FormField(name="p", type="password", label="UAE PASS password")])
    b = _bm("uae_pass", "UAE PASS", 0.9, ("text",), ("'uae pass' in title",), ("credentials",), ("uaepass.ae",))
    v = score("fp2", url, [d], Intel(domain="secure-gov-portal.example", age_days=5), b, None)
    assert v.label == "scam"


def test_established_guide_mentioning_brand_is_not_scam():
    # whatson.ae / pitstoparabia.com pattern: old site, brand in the title of a guide, 'OTP' / 'card' in prose only
    url = "https://www.cityguide.example/2026/06/how-to-pay-sandbox-bank-card-bill/"
    d = _det(url, title="How to pay your Sandbox Bank card bill", visible_text="Enter the OTP sent to your phone and "
             "your card number in the Sandbox Bank app.", form_fields=[FormField(name="s", type="text", placeholder="Search")])
    v = score("fp3", url, [d], Intel(domain="cityguide.example", age_days=4000, tranco_rank=160_000),
              _bm(asks=("card", "otp", "payment")), None)
    assert not _flagged(v) and "brand_on_unofficial_domain" not in {r.id for r in v.reasons}


def test_guide_on_site_naming_itself_is_not_scam_without_intel():
    # hertz.ae pattern: no RDAP / Tranco, but the page names its own organisation (its domain label)
    url = "https://www.carhire.ae/en/blog/sandbox-bank-card-recharge"
    d = _det(url, title="Sandbox Bank Recharge: different ways", visible_text="Carhire Car Rental Blog\nRecharge your "
             "Sandbox Bank card: enter the card number and OTP in the app.")
    v = score("fp4", url, [d], Intel(domain="carhire.ae"), _bm(asks=("card", "otp", "payment")), None)
    assert not _flagged(v)
    assert "brand_mention_other_site" in {r.id for r in v.reasons}


def test_cobrand_partner_page_on_established_site_is_not_scam():
    # airarabia.com RAKBANK card page: old high-rank site, brand only in the text, its own login modal has a password
    url = "https://www.airline.example/en/rewards/sandbox-bank-platinum-credit-card"
    d = _det(url, title="Airline Platinum Credit Card - Your ticket to more travel",
             visible_text="Rewarding journeys with the Sandbox Bank Airline Platinum Credit Card. Apply now.",
             form_fields=[FormField(name="emailaddress", type="email"), FormField(name="password", type="password")])
    b = _bm(evidence=("'Sandbox Bank' in text",), methods=("text", "llm"), asks=("credentials", "card"))
    v = score("fp5", url, [d], Intel(domain="airline.example", age_days=8781, tranco_rank=12769), b, None)
    assert not _flagged(v)


def test_compromised_old_site_with_branded_password_form_still_scam():
    url = "https://old-shop.example/wp-content/x/sandbox/login.php"
    d = _det(url, title="Sandbox Bank - Online Banking", visible_text="Sign in to Sandbox Bank",
             form_fields=[FormField(name="user", label="Username"), FormField(name="pw", type="password")])
    v = score("fp6", url, [d], Intel(domain="old-shop.example", age_days=4000), _bm(asks=("credentials",)), None)
    assert v.label == "scam"


def test_parking_page_is_domain_only_and_capped():
    # .ph wildcard parking: 'Redirecting...' + 'This domain is available to be registered'
    url = "https://sandbox-bank-app.example.ph/"
    d = _det(url, title="Redirecting...", visible_text="This domain is available to be registered. Click here to register.\n"
             "sandbox-bank-app.example.ph\nFinance\nTravel")
    look = _look("sandbox-bank-app.example.ph", 0.85, ["keyword", "combosquat"])
    v = score("fp7", url, [d], Intel(domain="sandbox-bank-app.example.ph"),
              _bm(conf=0.65, methods=("text", "domain_keyword")), look)
    ids = {r.id for r in v.reasons}
    assert v.mode == "domain_only" and "parked_page" in ids and "brand_on_unofficial_domain" not in ids
    assert not _flagged(v)


def test_brand_protection_registrar_placeholder_is_defensive():
    url = "https://sandboxbankpay.example/"
    d = _det(url, title="Domain Registered at Safenames", visible_text="This domain is registered with Safenames\n\nThere is "
             "no website configured for this address yet.")
    look = _look("sandboxbankpay.example", 0.85, ["keyword", "combosquat"])
    v = score("fp8", url, [d], Intel(domain="sandboxbankpay.example", age_days=4000, registrar="SafeNames Ltd."), None, look)
    assert v.label == "legitimate" and "defensive_registration" in {r.id for r in v.reasons}


def test_single_word_free_host_404_is_at_most_suspicious():
    url = "https://sandboxbank.vercel.app/"
    d = _det(url, http_status=404, title="404: NOT_FOUND", visible_text="404 DEPLOYMENT_NOT_FOUND")
    look = _look("sandboxbank.vercel.app", 0.85, ["tld_swap"], 0)
    v = score("fp9", url, [d], Intel(domain="sandboxbank.vercel.app"), None, look)
    assert v.label == "suspicious" and "platform_takedown" in {r.id for r in v.reasons}
    nx = _det(url, status="dead", error="net::ERR_NAME_NOT_RESOLVED")
    assert score("fp9b", url, [nx], Intel(domain="sandboxbank.vercel.app"), None, look).label == "suspicious"


def test_throwaway_free_host_404_still_flagged():
    url = "https://secure-login-update-7781.vercel.app/"
    d = _det(url, http_status=404, title="404: NOT_FOUND", visible_text="404 DEPLOYMENT_NOT_FOUND")
    assert _flagged(score("fp10", url, [d], Intel(domain="secure-login-update-7781.vercel.app"), None, None))


def test_unrelated_business_with_brand_word_is_at_most_suspicious():
    # mashreqpress.com pattern: printing press named like the bank, contact form whose honeypot fields carry
    # autocomplete=one-time-code (type 'otp'); asks for nothing sensitive
    url = "https://sandboxbankpress.example/"
    d = _det(url, title="Sandbox Bank - Printing Press Company", visible_text="Contact Us Now. We are a full-service printing press.",
             form_fields=[FormField(name="First Name", type="text"), FormField(name="Email", type="email"),
                          FormField(name="website", type="otp"), FormField(name="notes", type="otp")])
    look = _look("sandboxbankpress.example", 0.4, ["keyword", "combosquat"])
    v = score("fp11", url, [d], Intel(domain="sandboxbankpress.example", age_days=259), _bm(asks=("personal_info",)), look)
    assert not _flagged(v) and "no_sensitive_request" in {r.id for r in v.reasons}


def test_foreign_namesake_cctld_is_at_most_suspicious():
    # adcb.com.eg / emiratesnbd.com.eg: exact brand label on another country's ccTLD, Tranco-ranked
    url = "https://online.sandboxbank.com.eg/login"
    d = _det(url, title="Sandbox Bank", visible_text="Sandbox Bank Egypt online banking",
             form_fields=[FormField(name="user", label="Username"), FormField(name="pw", type="password")])
    look = _look("online.sandboxbank.com.eg", 0.85, ["tld_swap"], 0)
    v = score("fp12", url, [d], Intel(domain="sandboxbank.com.eg", tranco_rank=623_020), _bm(asks=("credentials",)), look)
    assert v.label == "suspicious" and "foreign_namesake" in {r.id for r in v.reasons}


def test_new_lookalike_brand_page_without_form_still_scam():
    # fabbankinternational.com pattern: young combosquat, brand in title, only a contact form
    url = "https://sandboxbankinternational.example/"
    d = _det(url, title="SANDBOX BANK INTERNATIONAL", visible_text="+234 816 000 0000 Your next logistics solution",
             form_fields=[FormField(name="your-name"), FormField(name="phone", type="tel")])
    look = _look("sandboxbankinternational.example", 0.85, ["keyword", "combosquat"])
    v = score("fp13", url, [d], Intel(domain="sandboxbankinternational.example", age_days=208),
              _bm(asks=("personal_info",)), look)
    assert v.label == "scam"


def test_prize_scam_with_payment_still_scam():
    # mashreq.watch pattern: young domain, brand in title, prize / pay-now page, no form
    url = "https://sandboxbank.watch/"
    d = _det(url, title="بنك التجربة - احصل على ساعتك", visible_text="اطلب ساعتك الآن ادفع اربح جوائز")
    look = _look("sandboxbank.watch", 0.4, ["tld_swap"], 0)
    v = score("fp14", url, [d], Intel(domain="sandboxbank.watch", age_days=108), _bm(asks=("payment",)), look)
    assert v.label == "scam"


def test_cloud_api_endpoint_with_brand_name_is_at_most_suspicious():
    # rakbank-*-apim.azure-api.net from CT logs: no page, RDAP lookup of the full host fails
    url = "https://sandboxbank-tst-apim.developer.azure-api.net/"
    d = _det(url, status="dead", error="net::ERR_NAME_NOT_RESOLVED")
    look = _look("sandboxbank-tst-apim.developer.azure-api.net", 0.9, ["subdomain_brand", "keyword"])
    i = Intel(domain="azure-api.net", sources={"rdap": "not_found"})
    v = score("fp15", url, [d], i, None, look)
    assert not _flagged(v) and "cloud_service_endpoint" in {r.id for r in v.reasons}


def test_brand_protection_registrar_of_parent_domain_is_not_defensive():
    url = "https://sandboxbank-dev.postgres.database.azure.com/"
    d = _det(url, status="dead", error="timeout")
    look = _look("sandboxbank-dev.postgres.database.azure.com", 0.9, ["subdomain_brand", "keyword"])
    v = score("fp16", url, [d], Intel(domain="azure.com", registrar="MarkMonitor Inc.", age_days=9000), None, look)
    assert "defensive_registration" not in {r.id for r in v.reasons}


def test_established_site_own_login_on_page_naming_brand_is_not_scam():
    # expatwoman.com: 20-year-old site, brand in a guide title, the password field is the site's own login
    url = "https://www.expatguide.com/dubai/finance/how-to-pay-sandbox-bank-bills"
    d = _det(url, title="How to Pay Bills Online: Sandbox Bank, Phone, Parking | Expatguide",
             visible_text="Here's everything you need to know about paying Sandbox Bank bills.",
             form_fields=[FormField(name="name", label="Username or email *"), FormField(name="pass", type="password")])
    v = score("fp17", url, [d], Intel(domain="expatguide.com", age_days=8210, tranco_rank=424_105),
              _bm(asks=("credentials", "card")), None)
    assert not _flagged(v)
