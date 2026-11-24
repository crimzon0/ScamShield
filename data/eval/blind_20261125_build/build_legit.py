import csv, json, re, sys, collections, asyncio, httpx
from urllib.parse import urljoin, urlsplit
sys.path.insert(0, r"C:\scamshiled")
from scamshield.core.domains import registrable
ROOT = r"C:\scamshiled"
def norm(u): return u.strip().rstrip("/").lower().replace("://www.", "://").split("#")[0]
ex = set()
for f, col in [("data/eval/sample.csv","url"),("data/eval/holdout.csv","url"),("tests/adversarial/hard_legit.csv","url"),("tests/adversarial/legit_deeplinks.csv","url")]:
    for r in csv.DictReader(open(f"{ROOT}/{f}", encoding="utf-8")): ex.add(norm(r[col]))
reg = json.load(open(f"{ROOT}/data/registry.json", encoding="utf-8"))["brands"]
starts = []  # (brand/org, category, start url)
for b in reg:
    if b["id"] == "sandbox_bank": continue
    d = b["official_domains"][0]
    starts.append((b["id"], b.get("category",""), f"https://www.{d}/" if d.count(".") == 1 and not d.endswith(".abudhabi") and d not in ("u.ae",) else f"https://{d}/"))
WELL_KNOWN = [("flydubai","airline","https://www.flydubai.com/en/"),("air_arabia","airline","https://www.airarabia.com/en"),
  ("noon","retail","https://www.noon.com/uae-en/"),("carrefour_uae","retail","https://www.carrefouruae.com/mafuae/en/"),
  ("dha","government","https://www.dha.gov.ae/en"),("abu_dhabi_gov","government","https://www.abudhabi.gov.ae/en"),
  ("github","global","https://github.com/"),("wikipedia","global","https://en.wikipedia.org/wiki/Main_Page"),
  ("bbc","global","https://www.bbc.com/"),("stackoverflow","global","https://stackoverflow.com/"),("mozilla","global","https://www.mozilla.org/en-US/")]
starts += WELL_KNOWN
KW = re.compile(r"(log-?in|sign-?in|online-banking|internet-banking|pay|fine|bill|contact|card|account|track|recharge|e-?services|apply|loan|support|help|customer|traffic|violation|renew|visa|booking|manage)", re.I)
BAD = re.compile(r"\.(pdf|jpg|jpeg|png|gif|svg|zip|docx?|xlsx?|mp4|webp|ico|css|js)(\?|$)|^mailto:|^tel:|^javascript:|/(ar|ar-ae)(/|$)", re.I)
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36", "Accept-Language": "en-US,en;q=0.9"}
HREF = re.compile(r'href\s*=\s*["\']([^"\'#]+)', re.I)
async def get(c, u):
    try:
        r = await c.get(u); return r
    except Exception as e: return None
async def one(c, sem, org, cat, start):
    async with sem:
        r = await get(c, start)
        if r is None: return org, cat, start, None, []
        base = str(r.url); sreg = registrable(start)
        links = []
        for h in HREF.findall(r.text[:800000]):
            u = urljoin(base, h.strip())
            if not u.startswith("https://") or BAD.search(u) or BAD.search(h): continue
            if registrable(u) != sreg: continue
            p = urlsplit(u)
            if p.path in ("", "/") and not p.query: continue
            if norm(u) in ex or norm(u) == norm(start) or norm(u) == norm(base): continue
            links.append(u.split("#")[0])
        links = list(dict.fromkeys(links))
        kw = [u for u in links if KW.search(urlsplit(u).path + urlsplit(u).netloc)]
        return org, cat, start, r.status_code, kw
async def verify(c, sem, u):
    async with sem:
        r = await get(c, u)
        return u, (r.status_code if r is not None else 0), (str(r.url) if r is not None else "")
async def main():
    sem = asyncio.Semaphore(4)
    async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers=UA, http2=False) as c:
        res = await asyncio.gather(*[one(c, sem, *s) for s in starts])
        picks = []
        for org, cat, start, st, kw in res:
            # up to 3 per site: pick distinct keywords, deterministic order of appearance
            got, used = [], set()
            for u in kw:
                k = KW.search(urlsplit(u).path + urlsplit(u).netloc).group(1).lower()
                if k in used: continue
                used.add(k); got.append(u)
                if len(got) >= (2 if cat == "global" else 3): break
            print(f"{org:22s} {st} links={len(kw)} picked={len(got)} {start}", file=sys.stderr)
            picks += [(org, cat, u) for u in got]
        ver = await asyncio.gather(*[verify(c, sem, u) for _, _, u in picks])
    out = []
    for (org, cat, u), (_, st, final) in zip(picks, ver):
        out.append(dict(url=u, org=org, category=cat, status=st, final=final, final_reg_same=registrable(final) == registrable(u) if final else None))
    json.dump(out, open(sys.argv[1], "w", encoding="utf-8"), indent=1)
    for o in out: print(o["status"], o["org"], o["url"][:100], "->", o["final"][:60] if o["final"] != o["url"] else "")
asyncio.run(main())
