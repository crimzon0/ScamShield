"""Owner: evidence. Police evidence package: ZIP + bilingual PDF + EN/AR takedown notices.

Public API:
    async build_case(scan_id) -> CaseFile   (never raises)
      - found:     ZIP at <artifacts_dir>/cases/<scan_id>/<scan_id>.zip, PDF at .../<scan_id>.pdf, saved via db.save_case
      - not found: CaseFile(zip_path="", pdf_path="", manifest={"scan_id":..., "error": "scan not found: ..."})
    async build_bundle(scan_ids) -> str   path of <artifacts_dir>/cases/bundles/bundle_<UTC>_<n>.zip ("" on failure)
CLI: python -m scamshield.evidence <scan_id> | --scan <url> | --bundle <id> <id> ...
"""
from .bundle import build_bundle
from .case import build_case

__all__ = ["build_case", "build_bundle"]
