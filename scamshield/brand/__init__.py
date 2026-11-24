"""Owner: brand. STUB."""
import json

from scamshield.core import fixtures
from scamshield.core.config import settings
from scamshield.core.schemas import BrandMatch, Detonation, LookalikeResult


def load_registry() -> list[dict]:
    """Brands from data/registry.json: [{id, name_en, name_ar, official_domains, keywords_en, keywords_ar,
    arabizi, phones, category, sources, verified}]"""
    try:
        return json.loads(settings.registry_path.read_text(encoding="utf-8"))["brands"]
    except Exception:
        return []


def get_brand(brand_id: str) -> dict | None:
    return next((b for b in load_registry() if b["id"] == brand_id), None)


async def match_brand(det: Detonation) -> BrandMatch:
    """Which brand does this page claim to be? Text (EN/AR/Arabizi), logo+screenshot pHash, llm_json.
    Sets is_official_domain by comparing registrable(final_url) to the brand's official_domains."""
    return fixtures.brand_match()


def lookalike(domain: str) -> LookalikeResult:
    """Domain-only: edit distance, homoglyphs, punycode/IDN, brand keywords vs registry."""
    return fixtures.lookalike(domain)
