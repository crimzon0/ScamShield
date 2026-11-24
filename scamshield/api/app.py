"""Owner: dashboard. FastAPI app: `uvicorn scamshield.api.app:app`.

All heavy lifting is delegated to the other packages through their public functions, looked up at call time
(`pipeline.scan_url`, `evidence.build_case`, `radar.backfill_crtsh`, `helpline.check_brand`) so the API works
against stubs today and real modules later, and tests can monkeypatch them.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import mimetypes
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from scamshield.core import db
from scamshield.core.config import ROOT, VERSION, settings

log = logging.getLogger("scamshield.api")

WEB_DIST = ROOT / "web" / "dist"
MAX_BATCH = 200

app = FastAPI(title="ScamShield", version=VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:4173",
                   "http://127.0.0.1:4173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------ helpers
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dump(obj: Any) -> Any:
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, list):
        return [_dump(o) for o in obj]
    return obj


def _parse_dt(v: Any) -> Optional[datetime]:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, str) and v:
        try:
            d = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _resolve(p: str | Path) -> Path:
    path = Path(p)
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def _safe_file(p: str | Path | None, roots: list[Path]) -> Optional[Path]:
    """Return the resolved path only if it is an existing file inside one of `roots` (path-traversal safe)."""
    if not p:
        return None
    try:
        path = _resolve(p)
    except (OSError, ValueError):
        return None
    for r in roots:
        try:
            path.relative_to(Path(r).resolve())
        except ValueError:
            continue
        return path if path.is_file() else None
    return None


def _artifact_roots() -> list[Path]:
    return [Path(settings.artifacts_dir).resolve()]


def _case_roots() -> list[Path]:
    return [Path(settings.artifacts_dir).resolve(), (ROOT / "var").resolve()]


FIXTURE_BRANDS = {"sandbox_bank"}


def is_fixture(domain_or_url: str = "", brand_id: Optional[str] = None) -> bool:
    """Fictional test data (Sandbox Bank, reserved .example/.test/.invalid TLDs): badge it, never a live detection."""
    if brand_id in FIXTURE_BRANDS:
        return True
    host = (domain_or_url or "").lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    return host.endswith((".example", ".test", ".invalid")) or host in ("example", "localhost")


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if url and "://" not in url:
        url = "https://" + url
    return url


async def _scan(url: str):
    from scamshield import pipeline  # looked up at call time (monkeypatch-friendly)

    return await pipeline.scan_url(url)


# ------------------------------------------------------------------ health
@app.get("/api/health")
def health():
    return {"ok": True, "version": VERSION, "offline": settings.offline, "time": _now().isoformat()}


# ------------------------------------------------------------------ scan
class ScanIn(BaseModel):
    url: str


@app.post("/api/scan")
async def scan(body: ScanIn):
    url = _normalize_url(body.url)
    if not url:
        raise HTTPException(400, "url required")
    try:
        res = await _scan(url)
    except Exception as e:  # pipeline promises never to raise; be defensive anyway
        log.exception("scan failed")
        raise HTTPException(502, f"scan failed: {e}")
    return _dump(res)


# ------------------------------------------------------------------ batch
_jobs: dict[str, dict] = {}


async def _run_batch(job_id: str) -> None:
    job = _jobs[job_id]
    job["status"] = "running"
    for i, url in enumerate(job["urls"]):
        item = job["results"][i]
        item["status"] = "running"
        try:
            res = await _scan(url)
            v = res.verdict
            item.update(status="done", scan_id=res.scan_id, score=v.score, label=v.label, mode=v.mode,
                        registrable_domain=v.registrable_domain)
        except Exception as e:
            item.update(status="error", error=str(e))
        job["done"] += 1
    job["status"] = "done"
    job["finished_at"] = _now().isoformat()


def _urls_from_csv(text: str) -> list[str]:
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return []
    header = [h.strip().lower() for h in rows[0]]
    col, start = 0, 0
    if "url" in header:
        col, start = header.index("url"), 1
    out = []
    for r in rows[start:]:
        if len(r) > col and r[col].strip() and not r[col].strip().startswith("#"):
            out.append(r[col].strip())
    return out


@app.post("/api/batch")
async def batch(request: Request, background: BackgroundTasks):
    """JSON {urls:[...]} or multipart CSV upload (field `file`, column `url` or first column)."""
    ctype = request.headers.get("content-type", "")
    urls: list[str] = []
    if ctype.startswith("multipart/"):
        form = await request.form()
        f = form.get("file")
        if f is None or not hasattr(f, "read"):
            raise HTTPException(400, "multipart upload needs a `file` field")
        raw = await f.read()
        urls = _urls_from_csv(raw.decode("utf-8-sig", errors="replace"))
    elif ctype.startswith("text/csv"):
        urls = _urls_from_csv((await request.body()).decode("utf-8-sig", errors="replace"))
    else:
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(400, "expected JSON {urls:[...]} or CSV upload")
        urls = [str(u) for u in (data.get("urls") or [])] if isinstance(data, dict) else []
    urls = [u for u in (_normalize_url(u) for u in urls) if u][:MAX_BATCH]
    if not urls:
        raise HTTPException(400, "no urls")
    job_id = uuid.uuid4().hex[:10]
    _jobs[job_id] = {"job_id": job_id, "status": "queued", "total": len(urls), "done": 0, "urls": urls,
                     "created_at": _now().isoformat(), "finished_at": None,
                     "results": [{"url": u, "status": "queued"} for u in urls]}
    background.add_task(_run_batch, job_id)
    return {"job_id": job_id, "total": len(urls), "poll": f"/api/batch/{job_id}"}


@app.get("/api/batch/{job_id}")
def batch_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")
    return job


# ------------------------------------------------------------------ scans
@app.get("/api/scans")
def scans(limit: int = 50):
    rows = db.list_scans(limit=max(1, min(limit, 500)))
    for r in rows:
        try:
            from scamshield.core.domains import registrable

            r["domain"] = registrable(r["url"])
        except Exception:
            r["domain"] = ""
        r["is_fixture"] = is_fixture(r["url"])
    return rows


def _get_scan_or_404(scan_id: str):
    res = db.get_scan(scan_id)
    if res is None:
        raise HTTPException(404, "scan not found")
    return res


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: str):
    res = _get_scan_or_404(scan_id)
    out = _dump(res)
    # tell the UI which personas have a servable screenshot
    out["screenshots"] = {
        d.persona: f"/api/scans/{scan_id}/screenshot/{d.persona}"
        for d in res.detonations
        if _safe_file(d.screenshot_path, _artifact_roots())
    }
    out["case"] = _case_info(scan_id)
    out["is_fixture"] = is_fixture(res.verdict.final_url or res.url, res.verdict.brand_id) or is_fixture(
        res.url, res.brand.brand_id if res.brand else None)
    return out


@app.get("/api/scans/{scan_id}/screenshot/{persona}")
def screenshot(scan_id: str, persona: str):
    res = _get_scan_or_404(scan_id)
    det = next((d for d in res.detonations if d.persona == persona), None)
    path = _safe_file(det.screenshot_path if det else None, _artifact_roots())
    if not path:
        raise HTTPException(404, "screenshot not available")
    return FileResponse(path, media_type=mimetypes.guess_type(path.name)[0] or "image/png")


# ------------------------------------------------------------------ radar
_radar_state: dict[str, Any] = {"running": False, "last_started": None, "last_finished": None, "last_count": None,
                                "error": ""}


def _radar_row(h) -> dict:
    d = _dump(h)
    fs, fa = _parse_dt(h.first_seen), _parse_dt(h.flagged_at)
    d["time_to_detection_seconds"] = int((fa - fs).total_seconds()) if fs and fa else None
    d["is_fixture"] = is_fixture(h.domain, h.brand_id)
    return d


@app.get("/api/radar")
def radar_hits(limit: int = 200, source: Optional[str] = None):
    """radar.feed() (richer: extra.official / extra.fuzzer, human TTD) with a db fallback."""
    limit = max(1, min(limit, 1000))
    try:
        from scamshield.radar import feed

        rows = feed(limit=limit, source=source)
        if isinstance(rows, list):
            out = []
            for r in rows:
                d = _dump(r) if isinstance(r, BaseModel) else dict(r)
                if d.get("time_to_detection_seconds") is None:
                    fs, fa = _parse_dt(d.get("first_seen")), _parse_dt(d.get("flagged_at"))
                    d["time_to_detection_seconds"] = int((fa - fs).total_seconds()) if fs and fa else None
                d["is_fixture"] = is_fixture(d.get("domain", ""), d.get("brand_id"))
                out.append(d)
            return out
    except Exception:
        log.exception("radar.feed failed; falling back to db")
    hits = db.list_radar_hits(limit=limit)
    return [_radar_row(h) for h in hits if not source or h.source == source]


@app.get("/api/radar/collectors")
def radar_collectors():
    """Collector health for the Radar page: live CT stream, search collector, API-triggered backfill."""
    out: dict[str, Any] = {"backfill": _radar_state}
    try:
        from scamshield.radar import certstream

        out["certstream"] = certstream.status()
    except Exception as e:
        out["certstream"] = {"state": "unavailable", "reason": str(e)}
    try:
        out["search"] = json.loads((ROOT / "data" / "radar" / "search_status.json").read_text(encoding="utf-8"))
    except Exception:
        out["search"] = {"state": "unavailable", "reason": "never ran"}
    return out


@app.get("/api/radar/status")
def radar_status():
    return _radar_state


async def _run_backfill(days: int) -> None:
    from scamshield import radar

    _radar_state.update(running=True, last_started=_now().isoformat(), error="")
    try:
        hits = await radar.backfill_crtsh(days=days, scan=True)
        for h in hits or []:
            try:
                db.save_radar_hit(h)  # idempotent upsert; radar may already have saved it
            except Exception:
                pass
        _radar_state["last_count"] = len(hits or [])
    except Exception as e:
        log.exception("backfill failed")
        _radar_state["error"] = str(e)
    finally:
        _radar_state.update(running=False, last_finished=_now().isoformat())


@app.post("/api/radar/backfill")
async def radar_backfill(background: BackgroundTasks, days: int = 30):
    if _radar_state["running"]:
        return {"started": False, "running": True}
    background.add_task(_run_backfill, max(1, min(days, 90)))
    return {"started": True}


# ------------------------------------------------------------------ helpline
def _registry() -> list[dict]:
    try:
        from scamshield.brand import load_registry

        return load_registry() or []
    except Exception:
        return []


@app.get("/api/helpline")
def helpline(limit: int = 500):
    names = {b["id"]: {"name_en": b.get("name_en", ""), "name_ar": b.get("name_ar", "")} for b in _registry()}
    out = []
    for f in db.list_phone_findings(limit=max(1, min(limit, 2000))):
        if isinstance(f.found_at, str):  # db.list_phone_findings assigns the raw ISO string
            f.found_at = _parse_dt(f.found_at) or _now()
        d = _dump(f)
        d.update({"brand_" + k: v for k, v in names.get(f.brand_id, {}).items()})
        out.append(d)
    return out


class HelplineIn(BaseModel):
    brand_id: Optional[str] = None
    live: Optional[bool] = None


@app.post("/api/helpline/run")
async def helpline_run(body: Optional[HelplineIn] = None):
    from scamshield import helpline as hl

    body = body or HelplineIn()
    ids = [body.brand_id] if body.brand_id else [b["id"] for b in _registry()] or ["sandbox_bank"]
    total, errors = 0, []
    for bid in ids:
        try:
            found = await asyncio.wait_for(hl.check_brand(bid, live=body.live), timeout=120)
        except Exception as e:
            errors.append(f"{bid}: {e}")
            continue
        for f in found or []:
            try:
                db.save_phone_finding(f)  # INSERT OR IGNORE: safe if helpline already saved it
            except Exception:
                pass
        total += len(found or [])
    return {"brands": ids, "findings": total, "errors": errors}


# ------------------------------------------------------------------ cases
def _load_case(scan_id: str):
    from scamshield.core.schemas import CaseFile

    row = db.connect().execute("SELECT case_json FROM cases WHERE scan_id=?", (scan_id,)).fetchone()
    return CaseFile.model_validate_json(row["case_json"]) if row else None


def _case_info(scan_id: str) -> Optional[dict]:
    try:
        case = _load_case(scan_id)
    except Exception:
        return None
    if not case:
        return None
    return {
        "zip_url": f"/api/cases/{scan_id}/zip" if _case_file(case, "zip") else None,
        "pdf_url": f"/api/cases/{scan_id}/pdf" if _case_file(case, "pdf") else None,
        "created_at": case.created_at.isoformat(),
    }


def _case_file(case, kind: str) -> Optional[Path]:
    return _safe_file(case.zip_path if kind == "zip" else case.pdf_path, _case_roots())


def _fallback_zip(res) -> Path:
    """Minimal evidence ZIP built by the dashboard if the evidence module produced no file (stub phase)."""
    out_dir = Path(settings.artifacts_dir) / "cases"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{res.scan_id}_basic.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("scan.json", res.model_dump_json(indent=2))
        z.writestr("verdict.json", res.verdict.model_dump_json(indent=2))
        for d in res.detonations:
            p = _safe_file(d.screenshot_path, _artifact_roots())
            if p:
                z.write(p, f"screenshots/{d.persona}{p.suffix}")
        z.writestr("README.txt", "Basic export generated by ScamShield dashboard (evidence module output missing).\n")
    return out


@app.post("/api/scans/{scan_id}/case")
async def build_case(scan_id: str):
    from scamshield import evidence

    res = _get_scan_or_404(scan_id)
    try:
        case = await evidence.build_case(scan_id)
    except Exception as e:
        log.exception("build_case failed")
        raise HTTPException(502, f"case build failed: {e}")
    if not _case_file(case, "zip"):
        try:
            case.zip_path = str(_fallback_zip(res))
            case.manifest = {**(case.manifest or {}), "fallback_zip": True}
        except Exception:
            log.exception("fallback zip failed")
    try:
        db.save_case(case)
    except Exception:
        log.exception("save_case failed")
    return {
        "scan_id": scan_id,
        "zip_url": f"/api/cases/{scan_id}/zip" if _case_file(case, "zip") else None,
        "pdf_url": f"/api/cases/{scan_id}/pdf" if _case_file(case, "pdf") else None,
        "notice_en": case.notice_en,
        "notice_ar": case.notice_ar,
        "manifest": case.manifest,
    }


@app.get("/api/cases/{scan_id}/{kind}")
def case_download(scan_id: str, kind: str):
    if kind not in ("zip", "pdf"):
        raise HTTPException(404, "unknown kind")
    case = _load_case(scan_id)
    path = _case_file(case, kind) if case else None
    if not path:
        raise HTTPException(404, f"{kind} not available; POST /api/scans/{scan_id}/case first")
    media = "application/zip" if kind == "zip" else "application/pdf"
    return FileResponse(path, media_type=media, filename=f"scamshield_case_{scan_id}.{kind}")


class BundleIn(BaseModel):
    scan_ids: list[str]


@app.post("/api/bundle")
async def bundle(body: BundleIn):
    """ZIP of several case files (evidence.build_bundle). Returns the file directly."""
    ids = [s for s in dict.fromkeys(body.scan_ids) if s][:100]
    if not ids:
        raise HTTPException(400, "no scan_ids")
    try:
        from scamshield import evidence

        build = getattr(evidence, "build_bundle", None)
        if build is None:
            from scamshield.evidence.bundle import build_bundle as build
        path = await build(ids)
    except Exception as e:
        log.exception("bundle failed")
        raise HTTPException(502, f"bundle failed: {e}")
    f = _safe_file(path, _case_roots())
    if not f:
        raise HTTPException(404, "bundle not produced")
    return FileResponse(f, media_type="application/zip", filename=f.name)


EVAL_PATH = ROOT / "data" / "eval" / "last_eval.json"


@app.get("/api/eval")
def eval_results():
    """Latest offline accuracy run written by `python -m scamshield.cli.eval` (owner: verdict). null if none."""
    try:
        data = json.loads(EVAL_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception as e:
        return {"error": f"unreadable last_eval.json: {e}"}
    if isinstance(data, dict) and "generated_at" not in data:
        data["generated_at"] = datetime.fromtimestamp(EVAL_PATH.stat().st_mtime, timezone.utc).isoformat()
    return data


@app.get("/api/brands")
def brands():
    return [{k: b.get(k) for k in ("id", "name_en", "name_ar", "category", "official_domains", "phones",
                                   "fictional")} for b in _registry()]


# ------------------------------------------------------------------ static UI (web/dist)
@app.get("/{path:path}", include_in_schema=False)
def spa(path: str):
    if path.startswith("api/"):
        raise HTTPException(404, "not found")
    index = WEB_DIST / "index.html"
    if not index.is_file():
        return JSONResponse({"ok": True, "ui": "web/dist not built; run `npm run build` in web/ or `make demo`"})
    if path:
        f = _safe_file(WEB_DIST / path, [WEB_DIST])
        if f:
            return FileResponse(f)
    return FileResponse(index)
