"""Build reference favicon hashes from OFFICIAL domains only (passive: homepage + icon, one request each).

    python -m scamshield.brand.build_assets            # all brands
    python -m scamshield.brand.build_assets tamm adcb  # some brands
Also: add_reference(brand_id, favicon_path=..., screenshot_path=...) to register a detonator capture
of an official site (e.g. the screenshot of https://www.tamm.abudhabi/).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

import httpx

from scamshield.brand import get_brand, load_registry
from scamshield.brand.visual import HASHES_PATH, _informative, phash_image
from scamshield.core.domains import is_official

ASSETS = HASHES_PATH.parent
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
_ICON_RE = re.compile(r"<link[^>]+rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*>", re.I)
_HREF_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)


def _load() -> dict:
    try:
        return json.loads(HASHES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(d: dict) -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    HASHES_PATH.write_text(json.dumps(d, indent=1, ensure_ascii=False), encoding="utf-8")


def add_reference(brand_id: str, favicon_path: str | None = None, screenshot_path: str | None = None,
                  source: str = "") -> dict:
    d = _load()
    e = d.setdefault(brand_id, {"favicon": [], "screenshot_top": [], "source": []})
    if favicon_path:
        h = phash_image(favicon_path)
        if _informative(h) and str(h) not in e["favicon"]:
            e["favicon"].append(str(h))
    if screenshot_path:
        h = phash_image(screenshot_path, top_fraction=0.25)
        if _informative(h) and str(h) not in e["screenshot_top"]:
            e["screenshot_top"].append(str(h))
    if source and source not in e["source"]:
        e["source"].append(source)
    _save(d)
    return e


def _icon_urls(client: httpx.Client, home: str) -> list[str]:
    urls = []
    try:
        r = client.get(home)
        if r.status_code < 400 and is_official(str(r.url), _official):
            for tag in _ICON_RE.findall(r.text[:300000]):
                m = _HREF_RE.search(tag)
                if m:
                    urls.append(urljoin(str(r.url), m.group(1)))
    except Exception as e:
        print("  homepage failed:", e)
    urls.append(urljoin(home, "/favicon.ico"))
    seen, out = set(), []
    for u in urls:
        if u not in seen and not u.startswith("data:"):
            seen.add(u)
            out.append(u)
    return out[:4]


_official: list[str] = []


def build(brand_ids: list[str] | None = None) -> None:
    global _official
    with httpx.Client(timeout=10, follow_redirects=True, headers={"User-Agent": UA}) as client:
        for b in load_registry():
            if b.get("fictional") or (brand_ids and b["id"] not in brand_ids) or not b["official_domains"]:
                continue
            _official = b["official_domains"]
            home = f"https://www.{b['official_domains'][0]}/"
            print(b["id"], home)
            outdir = ASSETS / b["id"]
            got = 0
            for u in _icon_urls(client, home):
                if not is_official(u, _official):  # only ever take icons served by the official domain
                    continue
                try:
                    r = client.get(u)
                    if r.status_code >= 400 or not r.content or len(r.content) > 2_000_000:
                        continue
                    if not is_official(str(r.url), _official):
                        continue
                    outdir.mkdir(parents=True, exist_ok=True)
                    ext = (Path(u.split("?")[0]).suffix or ".ico")[:5]
                    if ext.lower() == ".svg":
                        continue  # PIL cannot rasterise SVG
                    f = outdir / f"favicon{got}{ext}"
                    f.write_bytes(r.content)
                    e = add_reference(b["id"], favicon_path=str(f), source=u)
                    got += 1
                    print("  ok", u, e["favicon"][-1:] if e["favicon"] else "(uninformative)")
                except Exception as ex:
                    print("  fail", u, type(ex).__name__)
            if not got:
                print("  no favicon")


if __name__ == "__main__":
    build(sys.argv[1:] or None)
