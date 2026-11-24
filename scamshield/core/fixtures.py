"""Fixture objects used by stubs and tests. Fictional brand only: Sandbox Bank / بنك التجربة."""
from datetime import datetime, timedelta, timezone

from .schemas import (BrandMatch, CaseFile, Detonation, FormField, Intel, LookalikeResult, PhoneFinding,
                      RadarHit, RedirectHop, Signal, TLSInfo, Verdict)

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)


def detonation(url="https://sandbox-bank-login.example/verify", persona="uae_mobile_ad_click"):
    return Detonation(
        url=url, persona=persona, status="ok", final_url=url, http_status=200,
        redirect_chain=[RedirectHop(url="https://bit.ly/x", status=301, kind="shortener", at=NOW),
                        RedirectHop(url=url, status=200, kind="final", at=NOW)],
        title="Sandbox Bank | بنك التجربة - Verify your account",
        visible_text="Sandbox Bank بنك التجربة. Your account is suspended. Enter your card number and OTP.",
        lang="ar", form_fields=[FormField(name="card", type="text", label="Card number"),
                                FormField(name="otp", type="password", label="OTP")],
        tls=TLSInfo(issuer="R11", subject=url.split("/")[2], valid_from=NOW - timedelta(days=2)),
        started_at=NOW, finished_at=NOW + timedelta(seconds=3), duration_ms=3000,
    )


def intel(domain="sandbox-bank-login.example"):
    return Intel(domain=domain, registrable_domain=domain, created=NOW - timedelta(days=3), age_days=3,
                 registrar="Example Registrar", abuse_emails=["abuse@registrar.example"],
                 nameservers=["ns1.host.example"], a_records=["203.0.113.7"], ip="203.0.113.7",
                 asn="AS64500", asn_org="Example Hosting", hosting_country="NL",
                 cert_first_seen=NOW - timedelta(days=2), sources={"stub": "ok"})


def lookalike(domain="sandbox-bank-login.example"):
    return LookalikeResult(domain=domain, brand_id="sandbox_bank", closest_official="sandboxbank.example",
                           distance=6, techniques=["keyword"], score=0.7)


def brand_match():
    return BrandMatch(brand_id="sandbox_bank", name_en="Sandbox Bank", name_ar="بنك التجربة", confidence=0.9,
                      methods=["text", "arabic"], evidence=["'Sandbox Bank' in title"],
                      official_domains=["sandboxbank.example"], is_official_domain=False,
                      asks_for=["card", "otp"], lookalike=lookalike())


def verdict(scan_id="fixture0001", url="https://sandbox-bank-login.example/verify"):
    return Verdict(scan_id=scan_id, url=url, final_url=url, registrable_domain="sandbox-bank-login.example",
                   score=92, label="scam", reasons=[
                       Signal(id="brand_on_unofficial_domain", weight=60,
                              en="Page claims to be Sandbox Bank but is not on an official Sandbox Bank domain.",
                              ar="تدّعي الصفحة أنها بنك التجربة لكنها ليست على نطاق رسمي للبنك."),
                       Signal(id="young_domain", weight=20, en="Domain registered 3 days ago.",
                              ar="تم تسجيل النطاق قبل 3 أيام.")],
                   summary_en="Scam: impersonates Sandbox Bank.", summary_ar="احتيال: انتحال صفة بنك التجربة.",
                   brand_id="sandbox_bank")


def radar_hit():
    return RadarHit(domain="sandboxbank-verify.example", source="crtsh", matched_term="sandboxbank",
                    brand_id="sandbox_bank", first_seen=NOW - timedelta(hours=5), flagged_at=NOW)


def phone_finding():
    return PhoneFinding(brand_id="sandbox_bank", query="Sandbox Bank customer service Dubai", source="places",
                        listing_name="Sandbox Bank Helpline 24/7", raw_number="+971 50 123 4567",
                        number_e164="+971501234567", official_numbers=["+97180000000"], status="unverified",
                        reasons_en="Number not in official registry.", reasons_ar="الرقم غير موجود في السجل الرسمي.",
                        synthetic=True)


def case_file(scan_id="fixture0001"):
    return CaseFile(scan_id=scan_id, zip_path=f"var/cases/{scan_id}.zip", pdf_path=f"var/cases/{scan_id}.pdf",
                    notice_en="Takedown request (stub)", notice_ar="طلب إزالة (نموذج)", manifest={"files": []})
