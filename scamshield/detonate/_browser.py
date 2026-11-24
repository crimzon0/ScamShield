"""Owner: detonator. Lazy per-event-loop Chromium singleton + concurrency limit."""
from __future__ import annotations

import asyncio
import weakref
from typing import Any

_MAX_CONCURRENT = 5

# loop -> {"lock", "sem", "pw", "browser"}
_state: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, Any]]" = weakref.WeakKeyDictionary()


def _loop_state() -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    st = _state.get(loop)
    if st is None:
        st = {"lock": asyncio.Lock(), "sem": asyncio.Semaphore(_MAX_CONCURRENT), "pw": None, "browser": None}
        _state[loop] = st
    return st


def semaphore() -> asyncio.Semaphore:
    return _loop_state()["sem"]


async def get_browser():
    st = _loop_state()
    async with st["lock"]:
        b = st["browser"]
        if b is not None and b.is_connected():
            return b
        from playwright.async_api import async_playwright

        if st["pw"] is None:
            st["pw"] = await async_playwright().start()
        st["browser"] = await st["pw"].chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--no-first-run",
                "--mute-audio",
                "--disable-features=DownloadBubble,DownloadBubbleV2",
            ],
        )
        return st["browser"]


async def close_browser() -> None:
    """Close this event loop's browser + playwright driver. Never raises."""
    try:
        st = _loop_state()
    except RuntimeError:
        return
    async with st["lock"]:
        b, pw = st["browser"], st["pw"]
        st["browser"], st["pw"] = None, None
        try:
            if b is not None:
                await asyncio.wait_for(b.close(), 10)
        except Exception:
            pass
        try:
            if pw is not None:
                await asyncio.wait_for(pw.stop(), 10)
        except Exception:
            pass
