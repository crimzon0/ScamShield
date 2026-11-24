"""Owner: intel. STUB."""
from scamshield.core import fixtures
from scamshield.core.schemas import Intel


async def enrich(domain: str) -> Intel:
    """RDAP/WHOIS, DNS, ASN, crt.sh, blocklists, Tranco, optional urlscan/Safe Browsing. Never raises;
    each unavailable source is recorded in Intel.sources. Cached in SQLite."""
    return fixtures.intel(domain)


def blocklist_hits(url: str) -> list[str]:
    """Feed names (openphish, phishunt, ...) listing this URL or its host. Offline-safe."""
    return []
