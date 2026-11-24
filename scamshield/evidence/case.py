"""Case-file builder: police evidence ZIP + bilingual PDF + EN/AR takedown notices."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scamshield.core import db
from scamshield.core.config import ROOT, VERSION, settings
from scamshield.core.schemas import CaseFile, ScanResult

from .notices import notice_ar, notice_en
from .rdap import parse_rdap

log = logging.getLogger(__name__)
TOOL = f"ScamShield {VERSION}"
TEMPLATES = Path(__file__).parent / "templates"
LABEL_EN = {"scam": "SCAM", "likely_scam": "LIKELY SCAM", "suspicious": "SUSPICIOUS", "legitimate": "LEGITIMATE"}
LABEL_AR = {"scam": "احتيال", "likely_scam": "احتيال مرجّح", "suspicious": "مشبوه", "legitimate": "موقع سليم"}


def iso(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def now_iso() -> str:
    return iso(datetime.now(timezone.utc))


def safe_id(scan_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", scan_id or "")[:80] or "unknown"


def resolve(p: Optional[str]) -> Optional[Path]:
    """Artifact paths are absolute, relative to repo root, or relative to artifacts_dir."""
    if not p:
        return None
    path = Path(p)
    cands = [path] if path.is_absolute() else [ROOT / path, Path(settings.artifacts_dir) / path, Path.cwd() / path]
    for c in cands:
        if c.is_file():
            return c
    return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)


class _Staging:
    def __init__(self, root: Path):
        self.root = root
        self.files: list[dict[str, Any]] = []
        self.missing: list[dict[str, str]] = []

    def _record(self, rel: str, extra: dict | None = None) -> dict:
        p = self.root / rel
        entry = {"path": rel, "sha256": sha256_file(p), "size": p.stat().st_size, "created_utc": now_iso()}
        if extra:
            entry.update(extra)
        self.files = [f for f in self.files if f["path"] != rel] + [entry]
        return entry

    def write_text(self, rel: str, text: str, **extra) -> dict:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode("utf-8"))
        return self._record(rel, extra)

    def write_json(self, rel: str, obj: Any, **extra) -> dict:
        return self.write_text(rel, _dump(obj), **extra)

    def copy(self, rel: str, src: Optional[str], **extra) -> Optional[dict]:
        found = resolve(src)
        if not found:
            self.missing.append({"path": rel, "source": src or "", "reason": "not captured" if not src else "file not found"})
            return None
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(found, p)
        return self._record(rel, {"source": str(found), **extra})


def _context(scan: ScanResult, case_id: str, generated_at: str) -> dict[str, Any]:
    v, intel, brand = scan.verdict, scan.intel, scan.brand
    rd = parse_rdap(intel.raw_rdap if intel else None)
    reg_contacts: list[str] = []
    for m in (rd["registrar_abuse_emails"] + (intel.abuse_emails if intel else [])):
        if m and m not in reg_contacts:
            reg_contacts.append(m)
    final = v.final_url or next((d.final_url for d in scan.detonations if d.final_url), "")
    asn_org = intel.asn_org if intel else ""
    asn = intel.asn if intel else ""
    hosting_contact = (f"abuse desk of {asn_org} ({asn})" if (asn_org or asn) else "hosting provider unknown")
    tls = next((d.tls for d in scan.detonations if d.tls), None)
    captured = next((iso(d.finished_at or d.started_at) for d in scan.detonations), "")
    urls = [scan.url] + [u for u in dict.fromkeys(d.url for d in scan.detonations) if u != scan.url]
    brand_en = brand.name_en if brand and brand.brand_id else ""
    if not brand_en and scan.lookalike and scan.lookalike.brand_id:
        brand_en = scan.lookalike.brand_id
    return {
        "case_id": case_id, "scan_id": scan.scan_id, "url": scan.url, "urls": urls, "final_url": final,
        "domain": v.registrable_domain or (intel.registrable_domain if intel else "") or (intel.domain if intel else ""),
        "generated_at": generated_at, "scan_created": iso(scan.created_at), "tool": TOOL,
        "label": v.label, "label_en": LABEL_EN.get(v.label, v.label), "label_ar": LABEL_AR.get(v.label, v.label),
        "score": v.score, "mode": v.mode, "summary_en": v.summary_en, "summary_ar": v.summary_ar,
        "reasons": [r.model_dump() for r in v.reasons],
        "reasons_en": [f"{r.en} ({r.weight:+d})" for r in v.reasons if r.weight > 0] or [r.en for r in v.reasons],
        "reasons_ar": [f"{r.ar} ({r.weight:+d})" for r in v.reasons if r.weight > 0] or [r.ar for r in v.reasons],
        "brand_en": brand_en, "brand_ar": brand.name_ar if brand else "",
        "official_domains": list(brand.official_domains) if brand else [],
        "asks_for": list(brand.asks_for) if brand else [],
        "registrar": (intel.registrar if intel else "") or rd["registrar"], "registrar_contacts": reg_contacts,
        "hosting_contact": hosting_contact, "rdap": rd,
        "domain_created": iso(intel.created) if intel else "", "age_days": intel.age_days if intel else None,
        "nameservers": (intel.nameservers if intel else []) or rd["nameservers"],
        "ip": intel.ip if intel else "", "a_records": intel.a_records if intel else [],
        "mx_records": intel.mx_records if intel else [], "asn": asn, "asn_org": asn_org,
        "hosting_country": intel.hosting_country if intel else "",
        "cert_first_seen": iso(intel.cert_first_seen) if intel else "", "cert_count": intel.cert_count if intel else None,
        "blocklists": (intel.blocklist_hits + intel.safe_browsing) if intel else [],
        "sources": intel.sources if intel else {},
        "tls": ({"issuer": tls.issuer, "subject": tls.subject, "valid_from": iso(tls.valid_from),
                 "valid_to": iso(tls.valid_to)} if tls else None),
        "captured_at": captured,
        "hop_count": max((len(d.redirect_chain) for d in scan.detonations), default=0),
        "detonations": [{"persona": d.persona, "status": d.status, "http_status": d.http_status,
                         "started_at": iso(d.started_at), "finished_at": iso(d.finished_at), "error": d.error,
                         "chain": [{"url": h.url, "status": h.status, "kind": h.kind, "at": iso(h.at)}
                                   for h in d.redirect_chain]} for d in scan.detonations],
    }


def render_html(ctx: dict[str, Any]) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html"]))
    return env.get_template("report.html").render(c=ctx)


async def html_to_pdf(html: str, out: Path) -> Optional[str]:
    """Print trusted local HTML with our own Chromium. Returns error string or None."""
    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                ctx = await browser.new_context(java_script_enabled=False, offline=True)
                page = await ctx.new_page()
                await page.set_content(html, wait_until="load", timeout=30000)
                await page.pdf(path=str(out), format="A4", print_background=True,
                               margin={"top": "14mm", "bottom": "16mm", "left": "12mm", "right": "12mm"})
            finally:
                await browser.close()
        return None
    except Exception as exc:
        log.warning("PDF render failed: %s", exc)
        return f"{type(exc).__name__}: {exc}"


def _error_case(scan_id: str, error: str) -> CaseFile:
    return CaseFile(scan_id=scan_id, zip_path="", pdf_path="", manifest={"scan_id": scan_id, "error": error})


async def build_case(scan_id: str) -> CaseFile:
    """Build the evidence package for a saved scan. Never raises.

    Unknown scan_id -> CaseFile with zip_path="" and pdf_path="" and manifest["error"] set (not saved to db).
    Output: <artifacts_dir>/cases/<scan_id>/<scan_id>.zip and <scan_id>.pdf (+ notices and manifest alongside).
    """
    try:
        scan = db.get_scan(scan_id)
    except Exception as exc:
        return _error_case(scan_id, f"db error: {exc}")
    if scan is None:
        return _error_case(scan_id, f"scan not found: {scan_id}")
    try:
        return await _build(scan)
    except Exception as exc:  # last resort — never raise
        log.exception("build_case failed")
        return _error_case(scan_id, f"build failed: {type(exc).__name__}: {exc}")


async def _build(scan: ScanResult) -> CaseFile:
    sid = safe_id(scan.scan_id)
    generated_at = now_iso()
    case_id = f"SS-{generated_at[:10].replace('-', '')}-{sid}"
    case_dir = Path(settings.artifacts_dir) / "cases" / sid
    stage_dir = case_dir / "package"
    if stage_dir.exists():
        shutil.rmtree(stage_dir, ignore_errors=True)
    stage_dir.mkdir(parents=True, exist_ok=True)
    st = _Staging(stage_dir)

    # ---- raw captured artifacts per persona
    for i, d in enumerate(scan.detonations):
        tag = f"{i + 1:02d}_{d.persona}"
        st.copy(f"screenshots/{tag}.png", d.screenshot_path, persona=d.persona, kind="screenshot")
        st.copy(f"dom/{tag}.html", d.dom_path, persona=d.persona, kind="dom")
        if d.har_path:
            st.copy(f"har/{tag}.har", d.har_path, persona=d.persona, kind="har")
        if d.favicon_path:
            st.copy(f"favicon/{tag}{Path(d.favicon_path).suffix or '.ico'}", d.favicon_path, persona=d.persona,
                    kind="favicon")

    # ---- structured evidence
    st.write_json("redirect_chain.json", [{
        "persona": d.persona, "url": d.url, "final_url": d.final_url, "status": d.status,
        "http_status": d.http_status, "started_at": iso(d.started_at), "finished_at": iso(d.finished_at),
        "hops": [{"url": h.url, "status": h.status, "kind": h.kind, "at": iso(h.at)} for h in d.redirect_chain],
    } for d in scan.detonations], kind="redirect_chain")
    intel = scan.intel
    parsed = parse_rdap(intel.raw_rdap if intel else None)
    st.write_json("intel/rdap_whois.json", {
        "domain": intel.domain if intel else "", "registrable_domain": intel.registrable_domain if intel else "",
        "registrar": intel.registrar if intel else "", "created": iso(intel.created) if intel else "",
        "age_days": intel.age_days if intel else None, "abuse_emails": intel.abuse_emails if intel else [],
        "nameservers": intel.nameservers if intel else [], "fetched_at": iso(intel.fetched_at) if intel else "",
        "parsed_rdap": parsed, "raw_rdap": intel.raw_rdap if intel else {},
    }, kind="whois")
    st.write_json("intel/dns_hosting.json", {k: (iso(v) if isinstance(v, datetime) else v) for k, v in {
        "domain": intel.domain, "a_records": intel.a_records, "mx_records": intel.mx_records,
        "nameservers": intel.nameservers, "ip": intel.ip, "asn": intel.asn, "asn_org": intel.asn_org,
        "hosting_country": intel.hosting_country, "cert_first_seen": intel.cert_first_seen,
        "cert_count": intel.cert_count, "blocklist_hits": intel.blocklist_hits, "safe_browsing": intel.safe_browsing,
        "tranco_rank": intel.tranco_rank, "urlscan": intel.urlscan, "sources": intel.sources,
        "fetched_at": intel.fetched_at,
    }.items()} if intel else {"error": "no intel recorded"}, kind="hosting")
    st.write_json("brand_match.json", {
        "brand": scan.brand.model_dump(mode="json") if scan.brand else None,
        "lookalike": scan.lookalike.model_dump(mode="json") if scan.lookalike else None,
        "cloak": scan.cloak.model_dump(mode="json") if scan.cloak else None,
    }, kind="brand")
    st.write_json("verdict.json", scan.verdict.model_dump(mode="json"), kind="verdict")
    st.write_text("scan_result.json", scan.model_dump_json(indent=2), kind="scan_result")

    # ---- notices (reference hashes of everything captured so far)
    ctx = _context(scan, case_id, generated_at)
    ctx["key_hashes"] = [{"path": f["path"], "sha256": f["sha256"], "size": f["size"]} for f in st.files]
    ctx["missing"] = st.missing
    en, ar = notice_en(ctx), notice_ar(ctx)
    st.write_text("takedown_en.txt", en, kind="notice", lang="en")
    st.write_text("takedown_ar.txt", ar, kind="notice", lang="ar")

    # ---- report (HTML always, PDF via Chromium)
    ctx["screenshots"] = []
    for f in st.files:
        if f.get("kind") == "screenshot":
            data = (stage_dir / f["path"]).read_bytes()
            ctx["screenshots"].append({
                "persona": f.get("persona", ""), "sha256": f["sha256"],
                "captured_at": next((iso(d.finished_at or d.started_at) for d in scan.detonations
                                     if d.persona == f.get("persona")), ""),
                "data_uri": "data:image/png;base64," + base64.b64encode(data).decode()})
    html = render_html(ctx)
    st.write_text("report.html", html, kind="report_html")
    pdf_err = await html_to_pdf(html, stage_dir / "report.pdf")
    if pdf_err is None and (stage_dir / "report.pdf").is_file():
        st._record("report.pdf", {"kind": "report_pdf"})
    else:
        st.missing.append({"path": "report.pdf", "source": "", "reason": f"pdf render failed: {pdf_err}"})

    # ---- manifest
    manifest = {
        "case_id": case_id, "scan_id": scan.scan_id, "url": scan.url, "final_url": ctx["final_url"],
        "registrable_domain": ctx["domain"], "label": scan.verdict.label, "score": scan.verdict.score,
        "tool": {"name": "ScamShield", "version": VERSION}, "generated_at": generated_at,
        "hash_algorithm": "sha256",
        "timestamps": {
            "scan_created": iso(scan.created_at), "verdict_created": iso(scan.verdict.created_at),
            "intel_fetched": iso(intel.fetched_at) if intel else "",
            "domain_created": ctx["domain_created"], "cert_first_seen": ctx["cert_first_seen"],
            "detonations": [{"persona": d.persona, "started_at": iso(d.started_at),
                             "finished_at": iso(d.finished_at)} for d in scan.detonations],
        },
        "files": [{k: f[k] for k in ("path", "sha256", "size", "created_utc")} |
                  {k: f[k] for k in ("kind", "persona", "lang") if k in f} for f in st.files],
        "missing": st.missing,
        "note": "manifest.sha256 holds the SHA-256 of this manifest.json file exactly as stored in the ZIP.",
    }
    manifest_bytes = _dump(manifest).encode("utf-8")
    (stage_dir / "manifest.json").write_bytes(manifest_bytes)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    (stage_dir / "manifest.sha256").write_text(f"{manifest_sha}  manifest.json\n", encoding="utf-8")

    # ---- ZIP + loose copies next to it
    zip_path = case_dir / f"{sid}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(st.files, key=lambda x: x["path"]):
            z.write(stage_dir / f["path"], f["path"])
        z.write(stage_dir / "manifest.json", "manifest.json")
        z.write(stage_dir / "manifest.sha256", "manifest.sha256")
    pdf_path = case_dir / f"{sid}.pdf"
    if (stage_dir / "report.pdf").is_file():
        shutil.copyfile(stage_dir / "report.pdf", pdf_path)
    (case_dir / "takedown_en.txt").write_bytes(en.encode("utf-8"))
    (case_dir / "takedown_ar.txt").write_bytes(ar.encode("utf-8"))

    manifest_out = dict(manifest, manifest_sha256=manifest_sha, zip_sha256=sha256_file(zip_path),
                        zip_size=zip_path.stat().st_size)
    if pdf_err:
        manifest_out["error"] = f"pdf: {pdf_err}"
    case = CaseFile(scan_id=scan.scan_id, zip_path=str(zip_path),
                    pdf_path=str(pdf_path) if pdf_path.is_file() else "",
                    notice_en=en, notice_ar=ar, manifest=manifest_out)
    try:
        db.save_case(case)
    except Exception as exc:
        log.warning("save_case failed: %s", exc)
    return case
