"""Adversarial (breaker) test helpers.

- Tests marked @pytest.mark.network run only when selected explicitly (`-m network`) or SCAMSHIELD_NETWORK=1,
  and never when SCAMSHIELD_OFFLINE=1. Everything else here is offline: intel is forced offline.
- `dead_detonate` replaces the detonator with a dead page (domain-only verdicts): no browser, no network.
"""
from __future__ import annotations

import os

import pytest

from scamshield.core.schemas import Detonation


def pytest_collection_modifyitems(config, items):
    sel = config.getoption("-m") or ""
    want_net = os.environ.get("SCAMSHIELD_NETWORK") == "1" or ("network" in sel and "not network" not in sel)
    off = os.environ.get("SCAMSHIELD_OFFLINE") == "1"
    for it in items:
        if "adversarial" not in str(it.fspath):
            continue
        if "network" in it.keywords and (off or not want_net):
            it.add_marker(pytest.mark.skip(reason="network test: run with -m network (and without SCAMSHIELD_OFFLINE=1)"))


@pytest.fixture
def offline(monkeypatch):
    from scamshield.core.config import settings

    monkeypatch.setattr(settings, "offline", True, raising=False)
    return settings


@pytest.fixture
def dead_detonate(monkeypatch, offline):
    import scamshield.detonate as dmod

    async def _dead(url, persona="uae_mobile_ad_click", scan_id=None):
        return Detonation(url=str(url), persona=persona, status="dead", final_url=str(url),
                          error="net::ERR_NAME_NOT_RESOLVED")

    monkeypatch.setattr(dmod, "detonate", _dead)
    return _dead
