"""Combined multi-scan export (e.g. a radar batch): one ZIP holding each case ZIP + an index."""
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import logging
import zipfile
from pathlib import Path

from scamshield.core.config import VERSION, settings

from .case import build_case, now_iso, safe_id, sha256_file

log = logging.getLogger(__name__)


async def build_bundle(scan_ids: list[str], concurrency: int = 3) -> str:
    """Build (or rebuild) every case, then pack them into
    <artifacts_dir>/cases/bundles/bundle_<UTC>_<n>.zip containing:
      cases/<scan_id>.zip, cases/<scan_id>.pdf, index.csv, bundle_manifest.json, bundle_manifest.sha256.
    Unknown scan ids are listed in the manifest under "failed". Never raises; returns "" only if nothing could be written."""
    try:
        ids = list(dict.fromkeys(s for s in scan_ids if s))
        sem = asyncio.Semaphore(max(1, concurrency))

        async def one(sid):
            async with sem:
                return await build_case(sid)

        cases = await asyncio.gather(*(one(s) for s in ids))
        generated = now_iso()
        out_dir = Path(settings.artifacts_dir) / "cases" / "bundles"
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"bundle_{generated[:19].replace(':', '').replace('-', '')}_{len(ids)}.zip"

        entries, failed = [], []
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for c in cases:
                if not c.zip_path or not Path(c.zip_path).is_file():
                    failed.append({"scan_id": c.scan_id, "error": c.manifest.get("error", "no zip")})
                    continue
                sid = safe_id(c.scan_id)
                files = []
                for src, arc in ((c.zip_path, f"cases/{sid}.zip"), (c.pdf_path, f"cases/{sid}.pdf")):
                    if src and Path(src).is_file():
                        z.write(src, arc)
                        files.append({"path": arc, "sha256": sha256_file(Path(src)), "size": Path(src).stat().st_size})
                m = c.manifest
                entries.append({"scan_id": c.scan_id, "case_id": m.get("case_id", ""), "url": m.get("url", ""),
                                "final_url": m.get("final_url", ""), "domain": m.get("registrable_domain", ""),
                                "label": m.get("label", ""), "score": m.get("score", ""),
                                "case_manifest_sha256": m.get("manifest_sha256", ""), "files": files})
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["scan_id", "case_id", "label", "score", "domain", "url", "final_url", "case_zip_sha256"])
            for e in entries:
                w.writerow([e["scan_id"], e["case_id"], e["label"], e["score"], e["domain"], e["url"], e["final_url"],
                            next((f["sha256"] for f in e["files"] if f["path"].endswith(".zip")), "")])
            index = buf.getvalue().encode("utf-8-sig")  # BOM so Excel opens Arabic/UTF-8 correctly
            z.writestr("index.csv", index)
            manifest = {"bundle": out.name, "tool": {"name": "ScamShield", "version": VERSION},
                        "generated_at": generated, "count": len(entries), "cases": entries, "failed": failed,
                        "index_csv_sha256": hashlib.sha256(index).hexdigest()}
            mb = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
            z.writestr("bundle_manifest.json", mb)
            z.writestr("bundle_manifest.sha256", f"{hashlib.sha256(mb).hexdigest()}  bundle_manifest.json\n")
        return str(out)
    except Exception:
        log.exception("build_bundle failed")
        return ""
