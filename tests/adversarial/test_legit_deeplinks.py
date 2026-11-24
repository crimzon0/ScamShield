"""Breaker: real deep links on official UAE bank/government domains must come back `legitimate`.

URLs in legit_deeplinks.csv were collected from links on the official sites themselves (see `note`).
Network test: run with `.venv/Scripts/python -m pytest -q -m network tests/adversarial`.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

ROWS = list(csv.DictReader((Path(__file__).parent / "legit_deeplinks.csv").open(encoding="utf-8")))


@pytest.mark.network
@pytest.mark.parametrize("row", ROWS, ids=[f"{r['brand_id']}-{r['category']}-{i}" for i, r in enumerate(ROWS)])
async def test_official_deeplink_is_legitimate(row):
    from scamshield import pipeline

    res = await pipeline.scan_url(row["url"], save=False, force=True)
    v = res.verdict
    assert v.label == "legitimate", (row["url"], v.final_url, v.score, [s.id for s in v.reasons])
