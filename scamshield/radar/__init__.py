"""Owner: radar. STUB."""
from scamshield.core import fixtures
from scamshield.core.schemas import RadarHit


def watchlist() -> list[dict]:
    """[{term, brand_id, kind: permutation|keyword}] from dnstwist + registry keywords (incl. Arabic/punycode)."""
    return [{"term": "sandboxbank", "brand_id": "sandbox_bank", "kind": "keyword"}]


async def backfill_crtsh(days: int = 30, scan: bool = True) -> list[RadarHit]:
    """Query crt.sh for watchlist terms, save hits (first_seen = cert not_before), push each through pipeline."""
    return [fixtures.radar_hit()]


def siblings(domain: str) -> list[dict]:
    """Domains sharing IP / nameserver / cert / favicon hash with domain."""
    return []
