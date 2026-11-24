"""Helpline tests. Offline only (synthetic data, no network)."""
import pytest

from scamshield.core import db
from scamshield.core.config import settings
from scamshield.helpline import check_all, check_brand, last_sources, normalize
from scamshield.helpline.classify import classify, claims_brand, findings_from_listing, official_numbers
from scamshield.helpline.phones import extract, is_mobile, number_kind, whatsapp_numbers

BANK = {"id": "sandbox_bank", "category": "bank", "name_en": "Sandbox Bank", "name_ar": "بنك التجربة",
        "keywords_en": ["sandbox bank", "sandboxbank"], "keywords_ar": ["بنك التجربة"],
        "official_domains": ["sandboxbank.example"], "phones": ["+97180000000", "800 00001"]}


@pytest.fixture(autouse=True)
def _offline_tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "offline", True)
    monkeypatch.setattr(settings, "google_places_key", "")
    monkeypatch.setattr(settings, "serpapi_key", "")
    monkeypatch.setattr(settings, "db_path", tmp_path / "t.db")


# ---------------------------------------------------------------- normalisation
@pytest.mark.parametrize("raw,e164", [
    ("800 4444", "+9718004444"),
    ("600 54 0000", "+971600540000"),
    ("04-345 6789", "+97143456789"),
    ("050 123 4567", "+971501234567"),
    ("0501234567", "+971501234567"),
    ("+971 50 000 0123", "+971500000123"),
    ("00971 50 000 0123", "+971500000123"),
    ("٨٠٠ ٤٤٤٤", "+9718004444"),            # Arabic-Indic digits
    ("۰۵۰ ۱۲۳ ۴۵۶۷", "+971501234567"),      # Eastern Arabic-Indic digits
    ("‎+٩٧١ ٥٠ ١٢٣ ٤٥٦٧", "+971501234567"),  # LRM mark
    ("not a number", ""),
    ("", ""),
    ("12", ""),
])
def test_normalize(raw, e164):
    assert normalize(raw) == e164


def test_number_kind():
    assert is_mobile("+971501234567")
    assert number_kind("+9718004444") == "tollfree"
    assert number_kind("+97143456789") == "landline"
    assert not is_mobile("+9718004444")


def test_extract_mixed_text_keeps_original_raw():
    text = "اتصل على ۰۵۰ ۰۰۰ ۰۱۰۳ أو 800 4444 أو wa.me/971500000555 ‎04-3456789"
    got = dict((e, raw) for raw, e in extract(text))
    assert set(got) == {"+971500000103", "+9718004444", "+971500000555", "+97143456789"}
    assert got["+971500000103"] == "۰۵۰ ۰۰۰ ۰۱۰۳"
    assert whatsapp_numbers("https://wa.me/971500000555") == ["+971500000555"]


def test_claims_brand_arabic_normalisation():
    assert claims_brand("بنك التجربة - خدمة العملاء", BANK)
    assert claims_brand("SANDBOX-BANK Care", BANK)
    assert not claims_brand("Al Noor Cafeteria", BANK)


def test_official_numbers_normalised():
    assert official_numbers(BANK) == ["+97180000000", "+97180000001"]


# ---------------------------------------------------------------- status logic
def _l(**kw):
    base = {"source": "places", "query": "q", "name": "Sandbox Bank Customer Care", "rating_count": 100}
    base.update(kw)
    return base


def test_official_match_even_with_arabic_digits():
    fs = findings_from_listing(_l(phone="٨٠٠ ٠٠٠٠٠", url="https://sandboxbank.example"), BANK)
    assert [f.status for f in fs] == ["official"]
    assert fs[0].number_e164 == "+97180000000" and fs[0].reasons_ar


def test_not_in_list_without_second_signal_is_only_unverified():
    # 600 number, official website, many reviews: no second signal
    f = classify(_l(url="https://www.sandboxbank.example/branch"), BANK, "600 50 0105", "+971600500105")
    assert f.status == "unverified" and f.second_signals == []
    # no website at all, landline: still only unverified
    f = classify(_l(), BANK, "04 345 6789", "+97143456789")
    assert f.status == "unverified"


@pytest.mark.parametrize("listing,number,signal", [
    (_l(url="https://sandboxbank-support.example"), "+971600500104", "brand_name_unofficial_website"),
    (_l(), "+971500000101", "mobile_number_for_institution"),
    (_l(rating_count=1), "+971600500104", "new_listing_few_reviews"),
    (_l(landing_label="scam"), "+971600500104", "landing_page_scam"),
    (_l(whatsapp_only=True), "+971600500104", "whatsapp_only"),
    (_l(url="https://wa.me/971500000102"), "+971600500104", "whatsapp_only"),
])
def test_each_second_signal_makes_likely_scam(listing, number, signal):
    f = classify(listing, BANK, number, number)
    assert f.status == "likely_scam"
    assert signal in f.second_signals
    assert f.reasons_en and f.reasons_ar


def test_official_number_never_flagged_even_with_signals():
    f = classify(_l(url="https://sandboxbank-support.example", rating_count=0, whatsapp_only=True),
                 BANK, "800 00000", "+97180000000")
    assert f.status == "official" and f.second_signals == []


def test_shared_host_site_is_not_official():
    f = classify(_l(url="https://sandboxbank.vercel.app"), BANK, "x", "+971600500104")
    assert "brand_name_unofficial_website" in f.second_signals


def test_mobile_for_non_institution_is_not_a_signal():
    shop = dict(BANK, category="retail")
    f = classify(_l(), shop, "x", "+971500000101")
    assert f.status == "unverified"


def test_few_reviews_only_counts_for_brand_named_listing():
    l = _l(name="Generic Phone Repair", rating_count=0, text="")
    assert findings_from_listing(dict(l, phone="600 50 0104"), BANK) == []  # unrelated listing skipped


def test_unrelated_listing_skipped():
    assert findings_from_listing({"name": "Al Noor Cafeteria", "phone": "04 345 6789"}, BANK) == []


# ---------------------------------------------------------------- end to end (synthetic)
async def test_check_brand_synthetic_covers_all_cases_and_saves():
    fs = await check_brand("sandbox_bank")  # live=None, no key -> synthetic
    assert fs and all(f.synthetic and f.listing_name.startswith("[SYNTHETIC]") for f in fs)
    statuses = {f.status for f in fs}
    assert statuses == {"official", "unverified", "likely_scam"}
    assert any(f.status == "official" and any("٠" <= c <= "٩" for c in f.raw_number) for f in fs)
    assert {f.source for f in fs} == {"places", "snippet", "landing"}
    assert all(f.second_signals for f in fs if f.status == "likely_scam")
    assert all(not f.second_signals for f in fs if f.status != "likely_scam")
    saved = db.list_phone_findings()
    assert len(saved) == len(fs)
    # idempotent: second run does not duplicate
    await check_brand("sandbox_bank")
    assert len(db.list_phone_findings()) == len(fs)


async def test_live_without_key_falls_back_with_no_key_status():
    fs = await check_brand("sandbox_bank", live=True, save=False)
    assert fs and all(f.synthetic for f in fs)
    assert last_sources["places"] in ("no_key", "offline")


async def test_unknown_brand_and_check_all():
    assert await check_brand("does_not_exist", save=False) == []
    fs = await check_all(save=False)
    assert {"sandbox_bank", "emirates_nbd", "tamm"} <= {f.brand_id for f in fs}
    # real brands only appear with fake synthetic numbers, never as official
    assert all(f.status != "official" for f in fs if f.brand_id != "sandbox_bank")


def test_place_queries_bilingual_all_cities():
    from scamshield.helpline.sources import CITIES, place_queries

    qs = place_queries(BANK)
    texts = [q["text"] for q in qs]
    assert any("خدمة العملاء" in t for t in texts) and any(t.startswith("رقم ") for t in texts)
    assert any("call center Dubai" in t for t in texts)
    assert {q["city"] for q in qs if q["city"]} == {c[0] for c in CITIES}
    assert {q["lang"] for q in qs} == {"en", "ar"}


async def test_live_sources_return_none_offline():
    from scamshield.helpline.sources import places_search, serp_snippets

    assert await places_search({"text": "x", "lang": "en", "lat": 0, "lng": 0}) is None
    assert await serp_snippets(BANK) is None


async def test_live_path_with_mocked_places_and_landing(monkeypatch):
    import scamshield.helpline as hl
    from scamshield.helpline import sources

    monkeypatch.setattr(settings, "google_places_key", "test-key")
    monkeypatch.setattr(settings, "offline", False)
    monkeypatch.setattr(hl, "_brand", lambda bid, synthetic_ok: BANK)

    async def fake_places(q):
        return [
            {"source": "places", "query": q["text"], "place_id": "p1", "name": "Sandbox Bank Head Office",
             "phone": "800 00000", "url": "https://sandboxbank.example", "rating_count": 300},
            {"source": "places", "query": q["text"], "place_id": "p2", "name": "Sandbox Bank Help 24/7",
             "phone": "04 345 6789", "url": "https://sandbox-help.example", "rating_count": 40},
            {"source": "places", "query": q["text"], "place_id": "p3", "name": "Cafe", "phone": "04 345 6780"},
        ]

    scanned = []

    async def fake_scan(url):
        scanned.append(url)
        return "scam", "Sandbox Bank support call 050 000 0999"

    monkeypatch.setattr(sources, "places_search", fake_places)
    monkeypatch.setattr(hl, "_scan_landing", fake_scan)
    fs = await check_brand("sandbox_bank", save=False)
    by = {(f.source, f.number_e164): f for f in fs}
    assert by[("places", "+97180000000")].status == "official"
    help_ = by[("places", "+97143456789")]
    assert help_.status == "likely_scam"
    assert {"brand_name_unofficial_website", "landing_page_scam"} <= set(help_.second_signals)
    assert by[("landing", "+971500000999")].status == "likely_scam"
    assert scanned == ["https://sandbox-help.example"]  # official site + unrelated cafe not scanned
    assert not any(f.synthetic for f in fs)
    assert last_sources["places"] == "ok" and last_sources["serpapi"] == "no_key"
