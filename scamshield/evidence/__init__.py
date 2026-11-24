"""Owner: evidence. STUB."""
from scamshield.core import fixtures
from scamshield.core.schemas import CaseFile


async def build_case(scan_id: str) -> CaseFile:
    """ZIP (screenshots, DOM, HAR, chain, RDAP/WHOIS, DNS/hosting, verdict, manifest.json with SHA-256) +
    bilingual PDF (HTML template printed by Chromium) + EN/AR takedown notice. Under artifacts_dir/cases/."""
    return fixtures.case_file(scan_id)
