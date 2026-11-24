"""Like rescore_dump.py but re-runs match_brand + lookalike on stored detonations first (env SCAMSHIELD_NO_LLM=1 => keyword rules only)."""
import csv, sys
sys.path.insert(0, r"C:\scamshiled")
import scamshield.cli.eval as ev
ev.REBRAND = True
rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8")))
out = [ev.rescore(p, "likely_scam") for p in rows]
with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), extrasaction="ignore"); w.writeheader(); w.writerows(out)
print("rescored+rebranded", len(out), "->", sys.argv[2])
