import json, csv, collections, sys
sys.path.insert(0, r"C:\scamshiled")
from scamshield.core.domains import registrable
S=sys.argv[1]
sc=json.load(open(S+"/scams.json",encoding="utf-8"))
a=json.load(open(S+"/legit.json",encoding="utf-8")); b=json.load(open(S+"/legit_sm.json",encoding="utf-8"))
drop=lambda u,st: st not in (200,403) or u.endswith(".xml") or "&amp;" in u or u=="https://adpolice.gov.ae/ContactUs"
rows=[[c["url"],"scam",c["source"],c["first_published"],c["basis"]] for c in sc]
L=[]
for o in a:
    if not drop(o["url"],o["status"]): L.append([o["url"],"legit",f"official site link ({o['org']}; home page; HTTP {o['status']} on 2026-11-24)","","discovered_on_official_homepage"])
for o in b:
    if not drop(o["url"],o["status"]): L.append([o["url"],"legit",f"official site link ({registrable(o['org'])}; sitemap; HTTP {o['status']} on 2026-11-24)","","discovered_in_official_sitemap"])
seen=set(); L2=[]
for r in L:
    k=r[0].lower().rstrip('/')
    if k in seen: continue
    seen.add(k); L2.append(r)
rows+=L2
with open("data/eval/blind_20261125.csv","w",newline="",encoding="utf-8") as f:
    w=csv.writer(f); w.writerow(["url","label","source","first_published","basis"]); w.writerows(rows)
print(collections.Counter(r[1] for r in rows), collections.Counter(r[4] for r in rows), collections.Counter(r[2] for r in rows if r[1]=="scam"))
print(collections.Counter(registrable(r[0]) for r in L2).most_common(40))
