"""Owner: helpline. STUB."""
from scamshield.core import fixtures
from scamshield.core.schemas import PhoneFinding


async def check_brand(brand_id: str, live: bool | None = None) -> list[PhoneFinding]:
    """Places text search (EN+AR, UAE cities) + snippets + landing pages; compare to registry phones.
    live=None -> live if key present else labelled synthetic samples."""
    return [fixtures.phone_finding()]


def normalize(raw: str, region: str = "AE") -> str:
    """Return E.164 or '' using phonenumbers."""
    return ""
