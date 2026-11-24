"""Re-score stored scans of a predictions CSV (no network) and write a new predictions CSV. Env decides blocklist on/off."""
import csv, sys
sys.path.insert(0, r"C:\scamshiled")
from scamshield.cli.eval import rescore
src, dst = sys.argv[1], sys.argv[2]
rows = list(csv.DictReader(open(src, encoding="utf-8")))
out = [rescore(p, "likely_scam") for p in rows]
with open(dst, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), extrasaction="ignore"); w.writeheader(); w.writerows(out)
print("rescored", len(out), "->", dst)
