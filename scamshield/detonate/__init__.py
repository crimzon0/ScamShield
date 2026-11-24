"""Owner: detonator. STUB — replace with real Playwright implementation."""
from scamshield.core import fixtures
from scamshield.core.schemas import CloakDiff, Detonation, Persona

PERSONAS: tuple[str, ...] = ("uae_mobile_ad_click", "desktop", "crawler")


async def detonate(url: str, persona: Persona = "uae_mobile_ad_click", scan_id: str | None = None) -> Detonation:
    """Load url in headless Chromium as persona. Never raises; 15 s cap. Artifacts under
    settings.artifacts_dir/<scan_id>/. status in ok|dead|blank|timeout|error."""
    return fixtures.detonation(url, persona)


def cloak_diff(dets: list[Detonation]) -> CloakDiff:
    """Compare detonations of the same URL across personas."""
    return CloakDiff(cloaked=False, personas=[d.persona for d in dets])
