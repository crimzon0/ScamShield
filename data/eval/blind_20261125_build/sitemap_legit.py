import json, re, sys, asyncio, httpx
from urllib.parse import urlsplit
sys.path.insert(0, r"C:\scamshiled"); sys.path.insert(0, sys.argv[2])
from scamshield.core.domains import registrable
import importlib.util
spec = importlib.util.spec_from_file_location("bl", sys.argv[2] + "/build_legit.py")
src = open(sys.argv[2] + "/build_legit.py", encoding="utf-8").read().split("async def get")[0]
ns = {}; exec(src, ns)
KW, BAD, UA, ex, norm = ns["KW"], ns["BAD"], ns["UA"], ns["ex"], ns["norm"]
SITES = ["https://www.rakbank.ae","https://tamm.abudhabi","https://www.uaepass.ae","https://www.dubaipolice.gov.ae","https://www.rta.ae",
 "https://www.moi.gov.ae","https://www.mohre.gov.ae","https://www.etisalat.ae","https://www.du.ae","https://www.dha.gov.ae","https://www.emirates.com",
 "https://www.etihad.com","https://www.flydubai.com","https://www.salik.ae","https://www.dewa.gov.ae","https://www.aramex.com","https://www.adcb.com",
 "https://www.centralbank.ae","https://www.adnoc.ae","https://www.carrefouruae.com","https://adpolice.gov.ae","https://www.cbd.ae","https://www.abudhabi.gov.ae"]
LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
async def get(c, u):
    try: return await c.get(u)
    except Exception: return None
async def one(c, sem, site):
    async with sem:
        sms = []
        r = await get(c, site + "/robots.txt")
        if r is not None and r.status_code == 200:
            sms = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", r.text)
        if not sms: sms = [site + "/sitemap.xml"]
        locs = []
        for sm in sms[:3]:
            r = await get(c, sm)
            if r is None or r.status_code != 200: continue
            l = LOC.findall(r.text[:3000000])
            if l and all(x.endswith(".xml") or ".xml" in x for x in l[:5]):
                for child in [x for x in l if "en" in x.lower() or True][:3]:
                    r2 = await get(c, child)
                    if r2 is not None and r2.status_code == 200: locs += LOC.findall(r2.text[:3000000])
            else: locs += l
        sreg = registrable(site)
        kw = [u.replace("&amp;", "&") for u in dict.fromkeys(locs) if u.startswith("https://") and registrable(u) == sreg and not BAD.search(u)
              and norm(u) not in ex and KW.search(urlsplit(u).path) and "/ar/" not in u.lower() and "/ar-" not in u.lower()]
        got, used = [], set()
        for u in kw:
            k = KW.search(urlsplit(u).path).group(1).lower()
            if k in used: continue
            used.add(k); got.append(u)
            if len(got) >= 3: break
        print(f"{site:35s} sitemaps={len(sms)} locs={len(locs)} kw={len(kw)} picked={len(got)}", file=sys.stderr)
        return [(site, u) for u in got]
async def main():
    sem = asyncio.Semaphore(4)
    async with httpx.AsyncClient(timeout=25, follow_redirects=True, headers=UA) as c:
        res = await asyncio.gather(*[one(c, sem, s) for s in SITES])
        picks = [p for r in res for p in r]
        async def ver(u):
            async with sem:
                r = await get(c, u); return (r.status_code if r is not None else 0), (str(r.url) if r is not None else "")
        vs = await asyncio.gather(*[ver(u) for _, u in picks])
    out = [dict(url=u, org=s, status=st, final=f) for (s, u), (st, f) in zip(picks, vs)]
    json.dump(out, open(sys.argv[1], "w", encoding="utf-8"), indent=1)
    for o in out: print(o["status"], o["url"][:110], "->", o["final"][:60] if o["final"] != o["url"] else "")
asyncio.run(main())
