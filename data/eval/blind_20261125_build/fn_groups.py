import csv, sys, collections, re
truth = {r["url"]: r for r in csv.DictReader(open(sys.argv[1], encoding="utf-8"))}
P = {r["url"]: r for r in csv.DictReader(open(sys.argv[2], encoding="utf-8"))}
RANK = {"legitimate": 0, "suspicious": 1, "likely_scam": 2, "scam": 3}
thr = RANK[sys.argv[3] if len(sys.argv) > 3 else "likely_scam"]
src = collections.defaultdict(lambda: [0, 0])
groups = collections.defaultdict(list)
for u, t in truth.items():
    if t["label"] != "scam": continue
    p = P[u]; hit = RANK.get(p["label"], 0) >= thr
    s = src[t["source"]]; s[1] += 1; s[0] += hit
    if hit: continue
    r = p["reasons_en"]
    if p["mode"] == "domain_only":
        m = re.search(r"could not be analysed \((\w+)\)|HTTP (\d+)", r)
        why = "domain-only: " + ((m.group(1) or "HTTP " + m.group(2)) if m else "other")
        if re.search(r"registered only \d+ day|registered \d+ days ago", r): why += " (new domain flagged, not enough alone)"
    elif "well-known site" in r and "immediately sends" in r: why = "redirect to well-known site"
    elif re.search(r"Well-known website|global top-1M|existed for over", r): why = "full page, scored on established final domain (redirect to real brand / old domain)"
    elif p.get("brand_id"): why = f"full page, brand {p['brand_id']} matched but below threshold"
    elif "registered only" in r: why = "full page, new domain but no brand claim"
    else: why = "full page, no brand claim / no bait (e.g. crypto drainer, spam redirector, gated kit)"
    groups[why].append(f"{p['label']} {p['score']} {u[:90]}")
print("per-source recall:", {k: f"{v[0]}/{v[1]}" for k, v in src.items()})
for k, v in sorted(groups.items(), key=lambda x: -len(x[1])):
    print(f"\n## {k} ({len(v)})"); [print("  ", x) for x in v]
