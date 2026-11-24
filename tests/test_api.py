"""Dashboard API tests (offline). Owner: dashboard."""
import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from scamshield.core import db, fixtures
from scamshield.core.config import settings
from scamshield.core.schemas import CaseFile, ScanResult


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "db_path", tmp_path / "t.db")
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir()

    async def fake_scan(url, personas=("uae_mobile_ad_click",), save=True):
        shot = tmp_path / "artifacts" / "shot.png"
        shot.write_bytes(b"\x89PNG\r\n\x1a\nfake")
        det = fixtures.detonation(url)
        det.screenshot_path = str(shot)
        res = ScanResult(scan_id="t" + str(abs(hash(url)) % 10**8), url=url, detonations=[det],
                         intel=fixtures.intel(), brand=fixtures.brand_match(), lookalike=fixtures.lookalike(),
                         verdict=fixtures.verdict("x", url))
        res.verdict.scan_id = res.scan_id
        if save:
            db.save_scan(res)
        return res

    async def fake_case(scan_id):
        d = tmp_path / "artifacts" / "cases" / scan_id
        d.mkdir(parents=True, exist_ok=True)
        z = d / f"{scan_id}.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("manifest.json", "{}")
        p = d / f"{scan_id}.pdf"
        p.write_bytes(b"%PDF-1.4 fake")
        return CaseFile(scan_id=scan_id, zip_path=str(z), pdf_path=str(p), notice_en="n", notice_ar="ن")

    import scamshield.evidence
    import scamshield.pipeline

    monkeypatch.setattr(scamshield.pipeline, "scan_url", fake_scan)
    monkeypatch.setattr(scamshield.evidence, "build_case", fake_case)
    return TestClient(app_())


def app_():
    from scamshield.api.app import app

    return app


def test_scan_detail_screenshot_and_list(client):
    r = client.post("/api/scan", json={"url": "sandbox-bank-login.example/verify"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"]["label"] == "scam"
    assert body["url"].startswith("https://")
    sid = body["scan_id"]
    assert any(s["scan_id"] == sid for s in client.get("/api/scans").json())
    d = client.get(f"/api/scans/{sid}").json()
    assert d["screenshots"]["uae_mobile_ad_click"].endswith("/uae_mobile_ad_click")
    s = client.get(f"/api/scans/{sid}/screenshot/uae_mobile_ad_click")
    assert s.status_code == 200 and s.content.startswith(b"\x89PNG")
    assert client.get(f"/api/scans/{sid}/screenshot/desktop").status_code == 404
    assert client.get("/api/scans/nope").status_code == 404


def test_screenshot_path_traversal_blocked(client, tmp_path):
    outside = tmp_path / "secret.png"
    outside.write_bytes(b"secret")
    det = fixtures.detonation()
    det.screenshot_path = str(tmp_path / "artifacts" / ".." / "secret.png")
    res = ScanResult(scan_id="trav1", url=det.url, detonations=[det], verdict=fixtures.verdict("trav1"))
    db.save_scan(res)
    assert client.get("/api/scans/trav1/screenshot/uae_mobile_ad_click").status_code == 404


def test_case_build_and_download(client):
    sid = client.post("/api/scan", json={"url": "https://a.example/"}).json()["scan_id"]
    out = client.post(f"/api/scans/{sid}/case").json()
    assert out["zip_url"] == f"/api/cases/{sid}/zip" and out["pdf_url"] == f"/api/cases/{sid}/pdf"
    z = client.get(out["zip_url"])
    assert z.status_code == 200 and z.headers["content-type"] == "application/zip"
    assert "manifest.json" in zipfile.ZipFile(io.BytesIO(z.content)).namelist()
    p = client.get(out["pdf_url"])
    assert p.status_code == 200 and p.content.startswith(b"%PDF")
    assert client.get("/api/cases/unknown/zip").status_code == 404
    assert client.post("/api/scans/unknown/case").status_code == 404


def test_case_fallback_zip_when_evidence_has_no_file(client, monkeypatch):
    import scamshield.evidence

    async def stub_case(scan_id):
        return fixtures.case_file(scan_id)  # paths that do not exist

    monkeypatch.setattr(scamshield.evidence, "build_case", stub_case)
    sid = client.post("/api/scan", json={"url": "https://b.example/"}).json()["scan_id"]
    out = client.post(f"/api/scans/{sid}/case").json()
    assert out["zip_url"] and out["pdf_url"] is None
    z = client.get(out["zip_url"])
    assert "scan.json" in zipfile.ZipFile(io.BytesIO(z.content)).namelist()


def test_radar_ttd_and_backfill(client, monkeypatch):
    import scamshield.radar

    async def fake_backfill(days=30, scan=True):
        return [fixtures.radar_hit()]

    monkeypatch.setattr(scamshield.radar, "backfill_crtsh", fake_backfill)
    assert client.get("/api/radar").json() == []
    assert client.post("/api/radar/backfill").json()["started"] is True
    rows = client.get("/api/radar").json()
    assert rows[0]["domain"] == "sandboxbank-verify.example"
    assert rows[0]["time_to_detection_seconds"] == 5 * 3600
    assert client.get("/api/radar/status").json()["last_count"] == 1


def test_helpline_run_and_list(client, monkeypatch):
    import scamshield.helpline

    async def fake_check(brand_id, live=None):
        return [fixtures.phone_finding()]

    monkeypatch.setattr(scamshield.helpline, "check_brand", fake_check)
    out = client.post("/api/helpline/run", json={}).json()
    assert out["findings"] >= 1
    rows = client.get("/api/helpline").json()
    assert rows[0]["synthetic"] is True and rows[0]["number_e164"] == "+971501234567"
    assert rows[0]["brand_name_en"] == "Sandbox Bank"


def test_batch_json_and_csv(client):
    j = client.post("/api/batch", json={"urls": ["a.example", "b.example"]}).json()
    st = client.get(f"/api/batch/{j['job_id']}").json()
    assert st["status"] == "done" and st["done"] == 2
    assert all(r["label"] == "scam" for r in st["results"])
    j2 = client.post("/api/batch", files={"file": ("u.csv", b"id,url\n1,c.example\n2,d.example\n")}).json()
    assert j2["total"] == 2
    assert client.post("/api/batch", json={"urls": []}).status_code == 400
    assert client.get("/api/batch/nope").status_code == 404


def test_health_and_spa(client):
    assert client.get("/api/health").json()["ok"] is True
    assert client.get("/").status_code == 200
    assert client.get("/api/nonexistent").status_code == 404


def test_bundle(client, monkeypatch, tmp_path):
    import scamshield.evidence

    async def fake_bundle(scan_ids, concurrency=3):
        p = tmp_path / "artifacts" / "cases" / "bundles" / "bundle_x.zip"
        p.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("index.csv", ",".join(scan_ids))
        return str(p)

    monkeypatch.setattr(scamshield.evidence, "build_bundle", fake_bundle, raising=False)
    r = client.post("/api/bundle", json={"scan_ids": ["a", "b"]})
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert zipfile.ZipFile(io.BytesIO(r.content)).read("index.csv") == b"a,b"
    assert client.post("/api/bundle", json={"scan_ids": []}).status_code == 400


def test_fixture_flags(client):
    from scamshield.api.app import is_fixture

    assert is_fixture("https://sandbox-bank-login.example/verify")
    assert is_fixture("www.tamm.abudhabi", "sandbox_bank")
    assert not is_fixture("https://www.tamm.abudhabi/")
    sid = client.post("/api/scan", json={"url": "https://x.example/"}).json()["scan_id"]
    assert client.get(f"/api/scans/{sid}").json()["is_fixture"] is True
    assert client.get("/api/scans").json()[0]["is_fixture"] is True
    db.save_radar_hit(fixtures.radar_hit())
    assert client.get("/api/radar").json()[0]["is_fixture"] is True


def test_eval_endpoint(client, monkeypatch, tmp_path):
    import scamshield.api.app as appmod

    monkeypatch.setattr(appmod, "EVAL_PATH", tmp_path / "last_eval.json")
    assert client.get("/api/eval").json() is None
    (tmp_path / "last_eval.json").write_text('{"n": 10, "precision": 1.0, "recall": 0.8}', encoding="utf-8")
    out = client.get("/api/eval").json()
    assert out["precision"] == 1.0 and out["generated_at"]


def test_radar_collectors_and_feed_extra(client):
    c = client.get("/api/radar/collectors").json()
    assert "certstream" in c and "state" in c["certstream"] and "backfill" in c
    db.save_radar_hit(fixtures.radar_hit())
    rows = client.get("/api/radar").json()
    assert rows and rows[0]["time_to_detection_seconds"] is not None and "extra" in rows[0]
