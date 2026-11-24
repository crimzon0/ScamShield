"""Owner: detonator. Passive headless-Chromium detonation + cross-persona cloaking diff.

Public API: detonate(url, persona, scan_id) -> Detonation (never raises), cloak_diff(dets) -> CloakDiff,
PERSONAS, close_browser().
"""
from scamshield.core.schemas import CloakDiff, Detonation, Persona  # noqa: F401

from ._browser import close_browser
from ._cloak import cloak_diff
from ._detonate import PERSONAS, SHORTENERS, detonate, is_shortener, normalize_url

__all__ = ["PERSONAS", "SHORTENERS", "detonate", "cloak_diff", "close_browser", "is_shortener", "normalize_url"]
