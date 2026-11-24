"""Shared contract. Owned by the lead. Changes go through the lead only."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


Persona = Literal["uae_mobile_ad_click", "desktop", "crawler"]
Label = Literal["scam", "likely_scam", "suspicious", "legitimate"]


# ---------------------------------------------------------------- detonate
class RedirectHop(BaseModel):
    url: str
    status: Optional[int] = None
    kind: Literal["start", "http", "meta", "js", "shortener", "final"] = "http"
    at: datetime = Field(default_factory=utcnow)


class FormField(BaseModel):
    name: str = ""
    type: str = ""
    label: str = ""
    placeholder: str = ""


class TLSInfo(BaseModel):
    issuer: str = ""
    subject: str = ""
    san: list[str] = []
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    protocol: str = ""


class Detonation(BaseModel):
    url: str
    persona: Persona = "uae_mobile_ad_click"
    status: Literal["ok", "dead", "blank", "timeout", "error"] = "ok"
    final_url: str = ""
    http_status: Optional[int] = None
    redirect_chain: list[RedirectHop] = []
    title: str = ""
    visible_text: str = ""
    lang: str = ""
    dom_path: Optional[str] = None
    screenshot_path: Optional[str] = None
    har_path: Optional[str] = None
    favicon_url: Optional[str] = None
    favicon_path: Optional[str] = None
    form_fields: list[FormField] = []
    tls: Optional[TLSInfo] = None
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None
    duration_ms: int = 0
    error: str = ""


class CloakDiff(BaseModel):
    cloaked: bool = False
    personas: list[str] = []
    differences: list[str] = []
    similarity: float = 1.0  # 0..1 text similarity between personas


# ---------------------------------------------------------------- intel
class Intel(BaseModel):
    domain: str
    registrable_domain: str = ""
    created: Optional[datetime] = None
    age_days: Optional[int] = None
    registrar: str = ""
    abuse_emails: list[str] = []
    nameservers: list[str] = []
    a_records: list[str] = []
    mx_records: list[str] = []
    ip: str = ""
    asn: str = ""
    asn_org: str = ""
    hosting_country: str = ""
    cert_first_seen: Optional[datetime] = None
    cert_count: Optional[int] = None
    blocklist_hits: list[str] = []  # feed names that list this domain/url
    tranco_rank: Optional[int] = None
    urlscan: dict[str, Any] = {}
    safe_browsing: list[str] = []  # threat types
    raw_rdap: dict[str, Any] = {}
    sources: dict[str, str] = {}  # source -> "ok" | "unavailable" | "cached" | "no_key"
    fetched_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------- brand
class LookalikeResult(BaseModel):
    domain: str
    brand_id: Optional[str] = None
    closest_official: Optional[str] = None
    distance: Optional[int] = None
    techniques: list[str] = []  # "edit_distance","homoglyph","idn","keyword","tld_swap","combosquat"
    score: float = 0.0  # 0..1


class BrandMatch(BaseModel):
    brand_id: Optional[str] = None
    name_en: str = ""
    name_ar: str = ""
    confidence: float = 0.0  # 0..1
    methods: list[str] = []  # "text","arabic","arabizi","logo_hash","screenshot_hash","llm","domain_keyword"
    evidence: list[str] = []
    official_domains: list[str] = []
    is_official_domain: bool = False
    asks_for: list[str] = []  # "credentials","card","otp","emirates_id","payment","personal_info"
    lookalike: Optional[LookalikeResult] = None
    llm_used: bool = False


# ---------------------------------------------------------------- verdict
class Signal(BaseModel):
    id: str  # stable machine id e.g. "brand_on_unofficial_domain"
    weight: int  # contribution to score, may be negative
    en: str
    ar: str
    evidence: str = ""


class Verdict(BaseModel):
    scan_id: str
    url: str
    final_url: str = ""
    registrable_domain: str = ""
    score: int = Field(ge=0, le=100)
    label: Label
    mode: Literal["full", "domain_only"] = "full"
    reasons: list[Signal] = []
    summary_en: str = ""
    summary_ar: str = ""
    brand_id: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)


class ScanResult(BaseModel):
    scan_id: str
    url: str
    detonations: list[Detonation] = []
    cloak: Optional[CloakDiff] = None
    intel: Optional[Intel] = None
    brand: Optional[BrandMatch] = None
    lookalike: Optional[LookalikeResult] = None
    verdict: Verdict
    created_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------- evidence
class CaseFile(BaseModel):
    scan_id: str
    zip_path: str
    pdf_path: str
    notice_en: str = ""
    notice_ar: str = ""
    manifest: dict[str, Any] = {}
    created_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------- radar
class RadarHit(BaseModel):
    id: Optional[int] = None
    domain: str
    source: Literal["certstream", "crtsh", "nrd", "search_ads", "search_organic", "manual"]
    matched_term: str = ""
    brand_id: Optional[str] = None
    first_seen: datetime  # when the source says it appeared (cert notBefore, NRD date, ...)
    flagged_at: datetime = Field(default_factory=utcnow)  # when we flagged it
    scan_id: Optional[str] = None
    score: Optional[int] = None
    label: Optional[Label] = None
    extra: dict[str, Any] = {}


# ---------------------------------------------------------------- helpline
class PhoneFinding(BaseModel):
    id: Optional[int] = None
    brand_id: str
    query: str
    source: Literal["places", "snippet", "landing"]
    listing_name: str = ""
    listing_url: str = ""
    address: str = ""
    raw_number: str = ""
    number_e164: str = ""
    official_numbers: list[str] = []
    status: Literal["official", "unverified", "likely_scam"] = "unverified"
    second_signals: list[str] = []
    reasons_en: str = ""
    reasons_ar: str = ""
    synthetic: bool = False
    found_at: datetime = Field(default_factory=utcnow)
