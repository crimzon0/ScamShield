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
        st = {"lock": asyncio.Lock(), "sem": asyncio.Semaphore(_MAX_CONCURRENT), "sem_n": _MAX_CONCURRENT, "pw": None, "browser": None}
        _state[loop] = st
    return st


def set_concurrency(n: int) -> None:
    """Max simultaneous detonations per process (default 5). Applies to loops created later and,
    if called inside a running loop with no detonation in flight, to the current loop too."""
    global _MAX_CONCURRENT
    _MAX_CONCURRENT = max(1, min(16, int(n)))
    try:
        st = _loop_state()
        sem = st["sem"]
        if not sem.locked() and getattr(sem, "_value", 0) == st.get("sem_n", _MAX_CONCURRENT):
            st["sem"] = asyncio.Semaphore(_MAX_CONCURRENT)
            st["sem_n"] = _MAX_CONCURRENT
    except RuntimeError:  # no running loop
        pass


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
                "--disable-blink-features=AutomationControlled",
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
