import httpx, json, time, sys
out = sys.argv[1]
start = '2026-11-24T20:57:00.000Z'
allr = {}; end = '*'
for i in range(20):
    q = f'task.tags:phishing AND date:[{start} TO {end}]'
    r = httpx.get("https://urlscan.io/api/v1/search/", params={"q": q, "size": 100}, timeout=60, headers={"User-Agent": "Mozilla/5.0 scamshield-eval"})
    if r.status_code != 200: print(i, r.status_code, r.text[:200], file=sys.stderr); break
    res = r.json().get("results", [])
    new = [x for x in res if x["_id"] not in allr]
    for x in res: allr[x["_id"]] = x
    print(i, len(res), len(new), res[-1]["task"]["time"] if res else None, file=sys.stderr)
    if len(res) < 100 or not new: break
    end = res[-1]["task"]["time"]
    time.sleep(3)
json.dump({"query": "task.tags:phishing AND date:[2026-11-24T20:57:00.000Z TO *] (paged by date window)", "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": list(allr.values())}, open(out, "w", encoding="utf-8"))
print(len(allr))
