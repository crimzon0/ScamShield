"""Breaker: real legitimate pages that LOOK risky (login/payment forms, not in the registry, global-brand titles).

Must come back `legitimate` (hard requirement: never scam/likely_scam). URLs taken from the organisations' own sites.
Network test: `.venv/Scripts/python -m pytest -q -m network tests/adversarial/test_hard_legit.py`.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

ROWS = list(csv.DictReader((Path(__file__).parent / "hard_legit.csv").open(encoding="utf-8")))


@pytest.mark.network
@pytest.mark.parametrize("row", ROWS, ids=[f"{r['category']}-{i}" for i, r in enumerate(ROWS)])
async def test_risky_looking_legit_page(row):
    from scamshield import pipeline

    res = await pipeline.scan_url(row["url"], save=False, force=True)
    v = res.verdict
    why = (row["url"], v.final_url, v.label, v.score, v.mode, [(s.id, s.weight) for s in v.reasons])
    print("HARDLEGIT", why)
    assert v.label not in ("scam", "likely_scam"), why
    assert v.label == "legitimate", why
