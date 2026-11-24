"""Settings read from environment / .env. A missing key is never an error."""
from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
except Exception:  # pragma: no cover
    pass

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
VERSION = "0.1.0"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


class Settings:
    db_path: Path = Path(_env("SCAMSHIELD_DB", str(ROOT / "var" / "scamshield.db")))
    artifacts_dir: Path = Path(_env("SCAMSHIELD_ARTIFACTS", str(ROOT / "var" / "artifacts")))
    registry_path: Path = DATA_DIR / "registry.json"

    # LLM (llm_json). provider: anthropic | openai | none
    llm_provider: str = _env("LLM_PROVIDER", "anthropic")
    llm_api_key: str = _env("LLM_API_KEY") or _env("ANTHROPIC_API_KEY") or _env("OPENAI_API_KEY")
    llm_model: str = _env("LLM_MODEL", "claude-sonnet-5-5")
    llm_base_url: str = _env("LLM_BASE_URL")

    google_places_key: str = _env("GOOGLE_PLACES_API_KEY")
    serpapi_key: str = _env("SERPAPI_KEY")
    urlscan_key: str = _env("URLSCAN_API_KEY")
    safe_browsing_key: str = _env("SAFE_BROWSING_API_KEY")
    certstream_url: str = _env("CERTSTREAM_URL", "ws://localhost:8080/")

    http_timeout: float = float(_env("HTTP_TIMEOUT", "8"))
    detonate_timeout: float = float(_env("DETONATE_TIMEOUT", "15"))
    cache_ttl: int = int(_env("CACHE_TTL", str(24 * 3600)))
    offline: bool = _env("SCAMSHIELD_OFFLINE") == "1"  # tests: no network calls


settings = Settings()
settings.db_path.parent.mkdir(parents=True, exist_ok=True)
settings.artifacts_dir.mkdir(parents=True, exist_ok=True)


def has(key_attr: str) -> bool:
    return bool(getattr(settings, key_attr, ""))
