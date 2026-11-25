"""Re-score stored radar scans with the current engine (no network, no re-detonation) and persist
the new verdicts to the scan and the radar hit. Usage: python -m scamshield.radar.rescore"""
from __future__ import annotations

import os
from collections import Counter

os.environ.setdefault("SCAMSHIELD_OFFLINE", "1")


def main() -> None:
    from scamshield.brand import lookalike
    from scamshield.core import db
    from scamshield.core.domains import host_of
    from scamshield.core.schemas import Intel, LookalikeResult
    from scamshield.score import score

    before, after = Counter(), Counter()
    for h in db.list_radar_hits(limit=100000):
        if not h.scan_id:
            continue
        try:
            r = db.get_scan(h.scan_id)
            if r is None:
                continue
            extra = [s for s in r.verdict.reasons if s.id == "fake_helpline_on_page"]
            st = db.cache_get(f"scaninput:{r.scan_id}") or {}
            ii = Intel.model_validate(st["intel"]) if st.get("intel") else None
            il = LookalikeResult.model_validate(st["look"]) if st.get("look") else None
            look = lookalike(host_of(r.verdict.final_url or r.url))
            v = score(r.scan_id, r.url, r.detonations, r.intel, r.brand, look, r.cloak,
                      extra=extra, input_intel=ii, input_look=il)
            before[r.verdict.label] += 1
            after[v.label] += 1
            r.verdict, r.lookalike = v, look
            db.save_scan(r)
            h.score, h.label = v.score, v.label
            db.save_radar_hit(h)
        except Exception as e:  # never stop the batch
            print("skip", h.domain, e)
    print("before", dict(before))
    print("after ", dict(after))


if __name__ == "__main__":
    main()
