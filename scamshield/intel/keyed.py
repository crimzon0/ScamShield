"""Optional keyed sources: urlscan.io search and Google Safe Browsing v4. 'no_key' when absent."""
from __future__ import annotations

from typing import Optional

from scamshield.core.config import settings

from ._common import client


async def fetch_urlscan(domain: str) -> Optional[dict]:
    async with client() as c:
        r = await c.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": 10},
                        headers={"API-Key": settings.urlscan_key})
        if r.status_code != 200:
            return None
        j = r.json()
    res = []
    for it in j.get("results", [])[:10]:
        page, task = it.get("page", {}) or {}, it.get("task", {}) or {}
        res.append({"url": page.get("url") or task.get("url", ""), "time": task.get("time", ""),
                    "ip": page.get("ip", ""), "asnname": page.get("asnname", ""),
                    "result": it.get("result", ""), "screenshot": it.get("screenshot", ""),
                    "verdict_malicious": (it.get("verdicts", {}) or {}).get("overall", {}).get("malicious")})
    return {"total": j.get("total", len(res)), "results": res}


async def fetch_safe_browsing(domain: str, urls: Optional[list[str]] = None) -> Optional[list]:
    urls = urls or [f"http://{domain}/", f"https://{domain}/"]
    body = {
        "client": {"clientId": "scamshield", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    async with client() as c:
        r = await c.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                         params={"key": settings.safe_browsing_key}, json=body)
        if r.status_code != 200:
            return None
        j = r.json()
    return sorted({m.get("threatType", "") for m in j.get("matches", [])} - {""})
