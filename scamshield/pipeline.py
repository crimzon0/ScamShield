"""Owner: verdict. Orchestrates detonate -> enrich -> match_brand -> score -> save. Minimal wiring stub."""
import uuid

from scamshield.brand import lookalike, match_brand
from scamshield.core import db
from scamshield.core.domains import registrable
from scamshield.core.schemas import ScanResult
from scamshield.detonate import cloak_diff, detonate
from scamshield.intel import enrich
from scamshield.score import score


async def scan_url(url: str, personas: tuple[str, ...] = ("uae_mobile_ad_click",), save: bool = True) -> ScanResult:
    """Never raises. Always returns a ScanResult with a Verdict."""
    scan_id = uuid.uuid4().hex[:12]
    dets = [await detonate(url, p, scan_id=scan_id) for p in personas]
    final = next((d.final_url for d in dets if d.final_url), url)
    dom = registrable(final)
    intel = await enrich(dom)
    brand = await match_brand(dets[0]) if dets else None
    look = lookalike(dom)
    cloak = cloak_diff(dets) if len(dets) > 1 else None
    v = score(scan_id, url, dets, intel, brand, look, cloak)
    res = ScanResult(scan_id=scan_id, url=url, detonations=dets, cloak=cloak, intel=intel, brand=brand,
                     lookalike=look, verdict=v)
    if save:
        db.save_scan(res)
    return res
