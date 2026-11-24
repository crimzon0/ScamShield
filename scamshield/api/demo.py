"""Owner: dashboard. `make demo` -> seed the db, build the web UI if needed, serve API + UI on :8000.

    python -m scamshield.api.demo [--no-seed] [--with-fixtures] [--rebuild] [--port 8000] [--host 127.0.0.1]

Fictional Sandbox Bank fixture data is only seeded with --with-fixtures; the UI badges it FIXTURE / تجريبي.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import subprocess
import sys
import time

from scamshield.core import db, fixtures
from scamshield.core.config import ROOT, settings
from scamshield.core.schemas import ScanResult

WEB = ROOT / "web"
DEMO_URLS = [
    "https://www.tamm.abudhabi/",  # real official UAE gov site -> must be legitimate
    "https://sandboxbank-verify-account-ae.example/login",  # dead domain -> domain-only verdict
]


def _p(msg: str) -> None:
    print(f"[demo] {msg}", flush=True)


async def _seed_scans(with_fixtures: bool) -> None:
    if with_fixtures:  # fictional Sandbox Bank scan, available offline
        fx = ScanResult(scan_id="fixture0001", url="https://sandbox-bank-login.example/verify",
                        detonations=[fixtures.detonation()], intel=fixtures.intel(), brand=fixtures.brand_match(),
                        lookalike=fixtures.lookalike(), verdict=fixtures.verdict(), created_at=fixtures.NOW)
        if not db.get_scan(fx.scan_id):
            db.save_scan(fx)
        _p(f"fixture scan {fx.scan_id}: {fx.verdict.label} {fx.verdict.score}")
    from scamshield import pipeline

    for url in DEMO_URLS:
        t0 = time.time()
        try:
            res = await asyncio.wait_for(pipeline.scan_url(url), timeout=120)
            _p(f"scan {url} -> {res.verdict.label} {res.verdict.score} mode={res.verdict.mode} "
               f"id={res.scan_id} ({time.time() - t0:.1f}s)")
        except Exception as e:
            _p(f"scan {url} failed: {e!r}")


async def _seed_radar(with_fixtures: bool) -> None:
    hits = []
    if not settings.offline:
        try:
            from scamshield import radar

            _p("radar: crt.sh backfill (7 days, max 180 s)...")
            hits = await asyncio.wait_for(radar.backfill_crtsh(days=7, scan=True), timeout=180) or []
            for h in hits:
                db.save_radar_hit(h)
        except Exception as e:
            _p(f"radar backfill unavailable: {e!r}")
    if not hits and with_fixtures:
        db.save_radar_hit(fixtures.radar_hit())
        _p("radar: no live hits; saved fixture hit (badged FIXTURE)")
    elif not hits:
        _p("radar: no live hits (use --with-fixtures for a sample row)")
    else:
        _p(f"radar: {len(hits)} hits")


async def _seed_helpline() -> None:
    from scamshield import helpline
    from scamshield.brand import load_registry

    ids = [b["id"] for b in (load_registry() or [])][:12] or ["sandbox_bank"]
    n = 0
    for bid in ids:
        try:
            found = await asyncio.wait_for(helpline.check_brand(bid), timeout=90) or []
        except Exception as e:
            _p(f"helpline {bid}: {e!r}")
            continue
        for f in found:
            db.save_phone_finding(f)
        n += len(found)
    _p(f"helpline: {n} findings across {len(ids)} brands")


def _build_web(force: bool = False) -> None:
    if (WEB / "dist" / "index.html").is_file() and not force:
        _p("web/dist present (use --rebuild to rebuild)")
        return
    if not shutil.which("npm"):
        _p("npm not found: UI not built; API still served")
        return
    shell = os.name == "nt"
    if not (WEB / "node_modules").is_dir():
        _p("npm install ...")
        subprocess.run("npm install --no-audit --no-fund", cwd=WEB, shell=shell, check=False)
    _p("npm run build ...")
    subprocess.run("npm run build", cwd=WEB, shell=shell, check=False)


async def seed(with_fixtures: bool = False) -> None:
    await _seed_scans(with_fixtures)
    await _seed_radar(with_fixtures)
    await _seed_helpline()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="ScamShield demo server")
    ap.add_argument("--no-seed", action="store_true")
    ap.add_argument("--rebuild", action="store_true")
    ap.add_argument("--with-fixtures", action="store_true", help="also seed fictional Sandbox Bank sample data")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args(argv)
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    if not a.no_seed:
        asyncio.run(seed(a.with_fixtures))
    _build_web(a.rebuild)
    import uvicorn

    url = f"http://{a.host}:{a.port}"
    _p(f"ScamShield running at {url}  (API docs: {url}/docs)")
    uvicorn.run("scamshield.api.app:app", host=a.host, port=a.port, log_level="info")


if __name__ == "__main__":
    main()
