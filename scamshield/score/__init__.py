"""Owner: verdict. STUB."""
from scamshield.core import fixtures
from scamshield.core.schemas import BrandMatch, CloakDiff, Detonation, Intel, LookalikeResult, Verdict


def score(scan_id: str, url: str, dets: list[Detonation], intel: Intel | None, brand: BrandMatch | None,
          look: LookalikeResult | None, cloak: CloakDiff | None = None) -> Verdict:
    """Combine signals into a 0-100 Verdict with bilingual reasons. Works with dets empty/dead (domain-only)."""
    return fixtures.verdict(scan_id, url)
