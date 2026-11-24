"""Perceptual-hash visual matching: favicon and screenshot top band vs data/brand_assets/hashes.json.

hashes.json: {"<brand_id>": {"favicon": ["<phash hex>", ...], "screenshot_top": ["<phash hex>", ...],
              "source": ["https://official/favicon.ico", ...]}}
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

from scamshield.core.config import DATA_DIR

log = logging.getLogger(__name__)
HASHES_PATH = DATA_DIR / "brand_assets" / "hashes.json"
FAVICON_MAX = 6      # Hamming distance (64-bit phash)
SCREEN_MAX = 8


@lru_cache(maxsize=1)
def _refs() -> dict:
    try:
        import imagehash

        raw = json.loads(HASHES_PATH.read_text(encoding="utf-8"))
        out = {}
        for bid, v in raw.items():
            if bid.startswith("_"):
                continue
            out[bid] = {k: [imagehash.hex_to_hash(h) for h in v.get(k, [])] for k in ("favicon", "screenshot_top")}
        return out
    except Exception:
        return {}


def _informative(h) -> bool:
    """Reject near-blank images (solid colour favicons hash to almost all-0/all-1)."""
    bits = int(h.hash.sum())
    return 6 <= bits <= 58


def phash_image(path: str | Path, top_fraction: float | None = None):
    import imagehash
    from PIL import Image

    with Image.open(path) as im:
        im.load()
        if getattr(im, "n_frames", 1) > 1:
            im.seek(0)
        im = im.convert("RGBA")
        bg = Image.new("RGBA", im.size, (255, 255, 255, 255))
        im = Image.alpha_composite(bg, im).convert("RGB")
        if top_fraction:
            w, h = im.size
            im = im.crop((0, 0, w, max(1, int(min(h, w * 1.2) * top_fraction))))
        return imagehash.phash(im)


def match(det) -> list[dict]:
    """[{id, method, weight, evidence}] for brands whose reference hashes are close. Never raises."""
    refs = _refs()
    if not refs:
        return []
    out = []
    try:
        if det.favicon_path and Path(det.favicon_path).exists():
            h = phash_image(det.favicon_path)
            if _informative(h):
                for bid, r in refs.items():
                    ds = [h - x for x in r["favicon"]]
                    if ds and min(ds) <= FAVICON_MAX:
                        d = min(ds)
                        out.append({"id": bid, "method": "logo_hash", "weight": 0.55 if d <= 3 else 0.4,
                                    "evidence": f"favicon pHash distance {d} to {bid} reference"})
    except Exception as e:
        log.debug("favicon hash failed: %s", e)
    try:
        if det.screenshot_path and Path(det.screenshot_path).exists():
            h = phash_image(det.screenshot_path, top_fraction=0.25)
            if _informative(h):
                for bid, r in refs.items():
                    ds = [h - x for x in r["screenshot_top"]]
                    if ds and min(ds) <= SCREEN_MAX:
                        out.append({"id": bid, "method": "screenshot_hash", "weight": 0.35,
                                    "evidence": f"screenshot header pHash distance {min(ds)} to {bid} reference"})
    except Exception as e:
        log.debug("screenshot hash failed: %s", e)
    return out
