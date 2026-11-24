"""Pre-drafted takedown notices (EN + AR). Text only — nothing is ever sent."""
from __future__ import annotations

from typing import Any

SIGNATURE_EN = "Abu Dhabi Police – Cyber Crime (draft, requires officer review)"
SIGNATURE_AR = "شرطة أبوظبي – مكافحة الجرائم الإلكترونية (مسودة، تتطلب مراجعة الضابط)"


def _lines(items, empty="-"):
    items = [i for i in items if i]
    return "\n".join(f"  - {i}" for i in items) if items else f"  {empty}"


def notice_en(ctx: dict[str, Any]) -> str:
    to = ", ".join(ctx["registrar_contacts"]) or "(registrar abuse contact not found — look up via RDAP/ICANN)"
    host = ctx["hosting_contact"]
    hashes = _lines([f"{h['path']}  sha256={h['sha256']}" for h in ctx["key_hashes"]])
    return f"""DRAFT — NOT SENT — REQUIRES OFFICER REVIEW BEFORE USE

Subject: Urgent abuse report — phishing / brand impersonation — {ctx['domain']} — Case {ctx['case_id']}

To (registrar abuse): {to}
Registrar: {ctx['registrar'] or 'unknown'}
Cc (hosting abuse): {host}

Dear Abuse Team,

Abu Dhabi Police (Cyber Crime) requests the urgent suspension of the domain and/or hosted content below,
which is being used for a phishing / fraud campaign targeting residents of the United Arab Emirates.

Reported URL(s):
{_lines(ctx['urls'])}
Final URL after redirects: {ctx['final_url'] or '-'}
Registrable domain: {ctx['domain']}
Hosting: IP {ctx['ip'] or '-'}, {ctx['asn'] or '-'} {ctx['asn_org'] or ''}, country {ctx['hosting_country'] or '-'}

Brand impersonated: {ctx['brand_en'] or 'not determined'}
Official domain(s) of that brand: {', '.join(ctx['official_domains']) or 'not on file'}
The reported domain is NOT an official domain of this brand.

Assessment: {ctx['label_en']} (risk score {ctx['score']}/100)
Reasons:
{_lines(ctx['reasons_en'])}

Timeline (UTC):
  - Domain registered: {ctx['domain_created'] or 'unknown'}
  - Certificate first seen: {ctx['cert_first_seen'] or 'unknown'}
  - Page captured (detonation): {ctx['captured_at'] or 'unknown'}
  - Case generated: {ctx['generated_at']}

Evidence (case package {ctx['case_id']}, SHA-256 of key files):
{hashes}
Manifest SHA-256 is provided in manifest.sha256 inside the case package.

Requested action:
  1. Suspend / disable the domain {ctx['domain']} (registrar) and remove the hosted content (hosting provider).
  2. Preserve all logs, account and payment details related to this domain and its registrant.
  3. Confirm the action taken and its UTC time by reply.

Regards,
{SIGNATURE_EN}
Reference: {ctx['case_id']}
"""


def notice_ar(ctx: dict[str, Any]) -> str:
    to = "، ".join(ctx["registrar_contacts"]) or "(لم يُعثر على جهة الإبلاغ عن إساءة الاستخدام لدى المسجّل — يُرجى البحث عبر RDAP/ICANN)"
    hashes = _lines([f"{h['path']}  sha256={h['sha256']}" for h in ctx["key_hashes"]])
    return f"""مسودة — لم تُرسل — تتطلب مراجعة الضابط قبل الاستخدام

الموضوع: بلاغ عاجل عن إساءة استخدام — تصيّد احتيالي / انتحال علامة تجارية — {ctx['domain']} — القضية {ctx['case_id']}

إلى (قسم إساءة الاستخدام لدى المسجّل): {to}
المسجّل: {ctx['registrar'] or 'غير معروف'}
نسخة إلى (قسم إساءة الاستخدام لدى مزوّد الاستضافة): {ctx['hosting_contact']}

فريق مكافحة إساءة الاستخدام المحترم،

تطلب شرطة أبوظبي (مكافحة الجرائم الإلكترونية) الإيقاف العاجل للنطاق و/أو المحتوى المستضاف أدناه،
والذي يُستخدم في حملة تصيّد واحتيال تستهدف المقيمين في دولة الإمارات العربية المتحدة.

الرابط/الروابط المُبلّغ عنها:
{_lines(ctx['urls'])}
الرابط النهائي بعد إعادة التوجيه: {ctx['final_url'] or '-'}
النطاق المسجّل: {ctx['domain']}
الاستضافة: عنوان IP {ctx['ip'] or '-'}، {ctx['asn'] or '-'} {ctx['asn_org'] or ''}، الدولة {ctx['hosting_country'] or '-'}

العلامة التجارية المنتحَلة: {ctx['brand_ar'] or ctx['brand_en'] or 'غير محددة'}
النطاقات الرسمية لهذه العلامة: {'، '.join(ctx['official_domains']) or 'غير مسجّلة لدينا'}
النطاق المُبلّغ عنه ليس نطاقاً رسمياً لهذه العلامة.

التقييم: {ctx['label_ar']} (درجة الخطورة {ctx['score']}/100)
الأسباب:
{_lines(ctx['reasons_ar'])}

التسلسل الزمني (بالتوقيت العالمي UTC):
  - تاريخ تسجيل النطاق: {ctx['domain_created'] or 'غير معروف'}
  - أول ظهور للشهادة الرقمية: {ctx['cert_first_seen'] or 'غير معروف'}
  - وقت التقاط الصفحة: {ctx['captured_at'] or 'غير معروف'}
  - وقت إنشاء القضية: {ctx['generated_at']}

الأدلة (حزمة القضية {ctx['case_id']}، بصمات SHA-256 للملفات الرئيسية):
{hashes}
بصمة SHA-256 لملف البيان (manifest) موجودة في الملف manifest.sha256 داخل حزمة القضية.

الإجراء المطلوب:
  1. إيقاف/تعطيل النطاق {ctx['domain']} (المسجّل) وإزالة المحتوى المستضاف (مزوّد الاستضافة).
  2. الاحتفاظ بجميع السجلات وبيانات الحساب والدفع المتعلقة بهذا النطاق ومسجّله.
  3. تأكيد الإجراء المتخذ ووقته بالتوقيت العالمي UTC بالرد على هذا البلاغ.

مع التحية،
{SIGNATURE_AR}
المرجع: {ctx['case_id']}
"""
