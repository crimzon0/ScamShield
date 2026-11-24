"""Lead's integration check: real pipeline on a few URLs, print compact results."""
import asyncio, json, sys, time
from scamshield.pipeline import scan_url

URLS = sys.argv[1:] or ["https://www.tamm.abudhabi/", "https://this-domain-does-not-exist-sc4m.ae/", "https://bit.ly/3x"]

async def main():
    for u in URLS:
        t = time.time()
        try:
            r = await scan_url(u, force=True)
            v = r.verdict
            d = r.detonations[0] if r.detonations else None
            print(json.dumps({"url": u, "secs": round(time.time()-t,1), "score": v.score, "label": v.label, "mode": v.mode,
                              "det": d and d.status, "final": d and d.final_url, "hops": d and len(d.redirect_chain),
                              "brand": v.brand_id, "reasons": [s.id for s in v.reasons],
                              "intel_sources": r.intel and r.intel.sources}, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({"url": u, "CRASH": repr(e)}))

asyncio.run(main())
