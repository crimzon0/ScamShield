"""Offline tests for scamshield.evidence (fictional Sandbox Bank fixtures only)."""
import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from PIL import Image

from scamshield.core import db, fixtures
from scamshield.core.config import settings
from scamshield.core.schemas import ScanResult
from scamshield.evidence import build_case
from scamshield.evidence.rdap import parse_rdap

RDAP = {
    "ldhName": "SANDBOX-BANK-LOGIN.EXAMPLE", "status": ["active"],
    "events": [{"eventAction": "registration", "eventDate": "2026-11-21T10:00:00Z"}],
    "nameservers": [{"ldhName": "NS1.HOST.EXAMPLE"}],
    "entities": [{"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}],
                  "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]],
                  "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                      ["fn", {}, "text", "Abuse"], ["email", {}, "text", "rdap-abuse@registrar.example"],
                      ["tel", {}, "uri", "tel:+1.5555550100"]]]}]}],
}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "db_path", tmp_path / "t.db")
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir()
    return tmp_path


def _scan(tmp_path: Path, scan_id="evtest0001", with_dom_relative=False) -> ScanResult:
    shot = tmp_path / "shot.png"
    Image.new("RGB", (64, 48), (200, 30, 30)).save(shot)
    d1 = fixtures.detonation()
    d1.screenshot_path = str(shot)
    if with_dom_relative:
        dom = Path(settings.artifacts_dir) / "dom1.html"
        dom.write_text("<html><body>Sandbox Bank بنك التجربة</body></html>", encoding="utf-8")
        d1.dom_path = "dom1.html"  # relative -> resolved against artifacts_dir
    d2 = fixtures.detonation(persona="desktop")
    d2.screenshot_path = "does/not/exist.png"
    intel = fixtures.intel()
    intel.raw_rdap = RDAP
    return ScanResult(scan_id=scan_id, url=d1.url, detonations=[d1, d2], intel=intel,
                      brand=fixtures.brand_match(), lookalike=fixtures.lookalike(),
                      verdict=fixtures.verdict(scan_id=scan_id))


def test_parse_rdap():
    p = parse_rdap(RDAP)
    assert p["registrar"] == "Example Registrar"
    assert p["registrar_iana_id"] == "9999"
    assert p["registrar_abuse_emails"] == ["rdap-abuse@registrar.example"]
    assert p["events"]["registration"].startswith("2026-11-21")
    assert parse_rdap(None)["registrar"] == ""


async def test_build_case_full(env):
    scan = _scan(env, with_dom_relative=True)
    db.save_scan(scan)
    case = await build_case(scan.scan_id)

    zp, pp = Path(case.zip_path), Path(case.pdf_path)
    assert zp.is_file() and zp.name == "evtest0001.zip"
    assert zp.parent == Path(settings.artifacts_dir) / "cases" / "evtest0001"
    assert pp.is_file() and pp.read_bytes()[:4] == b"%PDF"

    with zipfile.ZipFile(zp) as z:
        names = set(z.namelist())
        for n in ["manifest.json", "manifest.sha256", "redirect_chain.json", "intel/rdap_whois.json",
                  "intel/dns_hosting.json", "brand_match.json", "verdict.json", "scan_result.json",
                  "report.pdf", "report.html", "takedown_en.txt", "takedown_ar.txt",
                  "screenshots/01_uae_mobile_ad_click.png", "dom/01_uae_mobile_ad_click.html"]:
            assert n in names, n
        raw_manifest = z.read("manifest.json")
        manifest = json.loads(raw_manifest)
        assert z.read("manifest.sha256").decode().split()[0] == hashlib.sha256(raw_manifest).hexdigest()
        for f in manifest["files"]:
            data = z.read(f["path"])
            assert hashlib.sha256(data).hexdigest() == f["sha256"], f["path"]
            assert len(data) == f["size"]
            assert f["created_utc"].endswith("Z")
        assert {f["path"] for f in manifest["files"]} | {"manifest.json", "manifest.sha256"} == names
        missing = {m["path"] for m in manifest["missing"]}
        assert "screenshots/02_desktop.png" in missing
        assert manifest["tool"] == {"name": "ScamShield", "version": "0.1.0"}
        for k in ("case_id", "scan_id", "url", "final_url", "generated_at", "timestamps"):
            assert manifest[k]

        html = z.read("report.html").decode("utf-8")
        assert 'dir="rtl"' in html and 'lang="ar"' in html
        assert "بنك التجربة" in html and "سلسلة حفظ الأدلة" in html
        assert "data:image/png;base64," in html
        rdap = json.loads(z.read("intel/rdap_whois.json"))
        assert rdap["parsed_rdap"]["registrar_abuse_emails"] == ["rdap-abuse@registrar.example"]
        assert rdap["raw_rdap"]["ldhName"] == "SANDBOX-BANK-LOGIN.EXAMPLE"

    # notices
    assert "rdap-abuse@registrar.example" in case.notice_en and "abuse@registrar.example" in case.notice_en
    assert "Example Hosting" in case.notice_en and "sandboxbank.example" in case.notice_en
    assert "requires officer review" in case.notice_en
    assert "بنك التجربة" in case.notice_ar and "مسودة" in case.notice_ar
    shot_sha = next(f["sha256"] for f in manifest["files"] if f["path"].startswith("screenshots/"))
    assert shot_sha in case.notice_en and shot_sha in case.notice_ar

    # saved to db
    row = db.connect().execute("SELECT case_json FROM cases WHERE scan_id=?", (scan.scan_id,)).fetchone()
    assert row and json.loads(row["case_json"])["zip_path"] == case.zip_path


async def test_build_case_unknown_scan(env):
    case = await build_case("nope")
    assert case.zip_path == "" and case.pdf_path == ""
    assert "not found" in case.manifest["error"]


async def test_build_case_domain_only(env):
    """Dead page: no detonation artifacts, no intel — must still build."""
    v = fixtures.verdict(scan_id="evdead01")
    v.mode = "domain_only"
    scan = ScanResult(scan_id="evdead01", url="https://dead.example/", detonations=[], verdict=v)
    db.save_scan(scan)
    case = await build_case("evdead01")
    assert Path(case.zip_path).is_file()
    with zipfile.ZipFile(case.zip_path) as z:
        assert "verdict.json" in z.namelist()
