"""Build scam candidates for the blind set from frozen raw feed snapshots (no scam URL is fetched)."""
import csv, json, re, sqlite3, sys, glob, collections
from pathlib import Path
sys.path.insert(0, r"C:\scamshiled")
from scamshield.core.domains import registrable, registrable_icann, host_of
from scamshield.intel import feeds

ROOT = Path(r"C:\scamshiled"); RAW = ROOT / "data/eval/raw/blind_20261125"
CUT = "2026-11-24T20:57:00"

def norm(u): return u.strip().rstrip("/").lower().replace("://www.", "://")
# exclusion sets
ex_urls, ex_regs = set(), set()
for f in list((ROOT/"data/eval/raw").glob("*.txt")) + list((ROOT/"data/feeds").glob("*.txt")):
    for ln in f.read_text(encoding="utf-8", errors="replace").splitlines():
        if ln.strip().startswith("http"): ex_urls.add(norm(ln))
snap_urls = set(ex_urls)
for f in ["data/eval/sample.csv", "data/eval/holdout.csv"]:
    for r in csv.DictReader(open(ROOT/f, encoding="utf-8")):
        ex_urls.add(norm(r["url"])); ex_regs.add(registrable(r["url"]))
db = sqlite3.connect(ROOT/"var/scamshield.db")
radar_regs = {registrable("https://"+d) for (d,) in db.execute("select domain from radar_hits")}
radar_hosts = {d.lower() for (d,) in db.execute("select domain from radar_hits")}

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+(@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
UAE = re.compile(r"(uae|dubai|abudhabi|abu-dhabi|emirates|\baed\b|\.ae(/|$|:)|\brta\b|salik|adcb|bankfab|enbd|etisalat|aramex|\btamm\b|uaepass|adnoc|dewa|mashreq|rakbank|emiratespost|etihad|careem|talabat|empost)", re.I)
BRANDISH = re.compile(r"(paypal|apple|icloud|microsoft|office|outlook|netflix|amazon|meta|facebook|instagram|whatsapp|google|dhl|fedex|ups|usps|post|bank|allegro|olx|inpost|binance|coinbase|metamask|trezor|ledger|trust|zoom|docu|adobe|steam|roblox|chase|wells|santander|bbva|itau|caixa|correos|evri|royal|telegram|tiktok|linkedin|att|verizon|orange|swisscom|ing|kbc|crelan|delivery|toll|ezpass|fines?|parking)", re.I)

cands = []
def add(url, source, ts, basis, target=""):
    cands.append(dict(url=url.strip(), source=source, first_published=ts, basis=basis, target=target or ""))

for r in csv.DictReader(open(RAW/"phishtank.csv", encoding="utf-8", errors="replace")):
    if r["submission_time"] > CUT and r["verified"] == "yes":
        add(r["url"], "phishtank", r["submission_time"], "feed_timestamp:submission_time", r["target"])
for f in sorted(RAW.glob("ps_*.json")):
    for x in json.load(open(f, encoding="utf-8")):
        if x["date"] > CUT: add(x["url"], "phishstats", x["date"], "feed_timestamp:date", x.get("title") or "")
for x in json.load(open(RAW/"certpl.json", encoding="utf-8")):
    if x["InsertDate"] > CUT and not x["DeleteDate"]:
        add("https://" + x["DomainAddress"] + "/", "cert.pl", x["InsertDate"], "feed_timestamp:InsertDate")
urlscan_own_brand = []
us = json.load(open(RAW/"urlscan_phishing.json", encoding="utf-8"))["results"]
for x in sorted(us, key=lambda x: x["task"]["time"]):
    t = x["task"]; tags = t.get("tags", [])
    if t["time"] <= CUT or "phishing" not in tags or "possiblethreat" in tags: continue
    if t["url"].lower().split("?")[0].endswith("favicon.ico"): continue
    reg0 = registrable(t["url"]); lab = reg0.split(".")[0]; flat = reg0.replace(".", "")
    btags = [g[6:] if g.startswith("brand-") else g for g in tags if g not in ("phishing","malicious","threat","scam","credential-theft","fake-login","crypto-scam","wallet-drainer","gv","@ecarlesi","meta","google")]
    if any(lab == b or lab == b + "bank" or flat == b for b in btags): urlscan_own_brand.append(t["url"]); continue
    rk = feeds.tranco_rank(reg0)
    if rk and rk <= 100000: continue
    add(t["url"], "urlscan", t["time"], "feed_timestamp:task.time", ",".join(g for g in tags if g.startswith("brand-") or g in ("google","meta","usaa","zoom")))
for ln in (RAW/"phishunt_feed.txt").read_text(encoding="utf-8").splitlines():
    if ln.startswith("http") and norm(ln) not in snap_urls:
        add(ln, "phishunt", "", "absent_from_20261124_snapshot")
for ln in (RAW/"openphish_feed.txt").read_text(encoding="utf-8").splitlines():
    if ln.startswith("http") and norm(ln) not in snap_urls:
        add(ln, "openphish", "", "absent_from_20261124_snapshot")

print("urlscan dropped (brand tag == own domain):", urlscan_own_brand)
print("raw candidates", collections.Counter(c["source"] for c in cands))
drop = collections.Counter(); keep = []; seen = set()
for c in cands:
    u = c["url"]; reg = registrable(u); h = host_of(u)
    if not u.startswith(("http://", "https://")) or not h: drop["bad_url"] += 1; continue
    if norm(u) in seen: drop["dup_url"] += 1; continue
    seen.add(norm(u))
    if c["basis"].startswith("feed") and norm(u) in snap_urls: drop["in_earlier_snapshot"] += 1; continue
    if norm(u) in ex_urls or reg in ex_regs: drop["in_sample_or_holdout"] += 1; continue
    if reg in radar_regs or h in radar_hosts: drop["in_radar_db"] += 1; continue
    if EMAIL.search(u): drop["embeds_email"] += 1; continue
    blob = u + " " + c["target"]
    c["prio"] = 0 if UAE.search(blob) else (1 if (BRANDISH.search(blob) or (c["target"] and c["target"] != "Other")) else 2)
    keep.append(c)
print("dropped", dict(drop)); print("eligible", len(keep), collections.Counter(c["source"] for c in keep), collections.Counter(c["prio"] for c in keep))
# deterministic selection: priority, then round-robin across sources (oldest first), cap 2 per registrable, 4 per ICANN registrable
bysrc = collections.defaultdict(list)
for c in sorted(keep, key=lambda c: (c["prio"], c["first_published"] or "9", c["url"])): bysrc[(c["prio"], c["source"])].append(c)
per_reg = collections.Counter(); per_icann = collections.Counter(); out = []
TARGET = int(sys.argv[1]) if len(sys.argv) > 1 else 110
for prio in (0, 1, 2):
    qs = [bysrc[k] for k in sorted(bysrc) if k[0] == prio]
    while any(qs) and len(out) < TARGET:
        for q in qs:
            while q:
                c = q.pop(0); r = registrable(c["url"]); ri = registrable_icann(c["url"])
                if per_reg[r] >= 2 or per_icann[ri] >= 4: drop["domain_cap"] += 1; continue
                per_reg[r] += 1; per_icann[ri] += 1; out.append(c); break
            if len(out) >= TARGET: break
print("selected", len(out), collections.Counter(c["source"] for c in out), "prio", collections.Counter(c["prio"] for c in out), "domain_cap drops", drop["domain_cap"])
json.dump(out, open(sys.argv[2] if len(sys.argv) > 2 else "scams.json", "w", encoding="utf-8"), indent=1)
for c in out: print(c["prio"], c["source"], c["first_published"][:19], c["url"][:110], "|", c["target"][:30])
