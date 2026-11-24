"""Owner: detonator. Cross-persona cloaking comparison."""
from __future__ import annotations

from itertools import combinations

from rapidfuzz import fuzz

from scamshield.core.domains import registrable
from scamshield.core.schemas import CloakDiff, Detonation

_SENSITIVE = ("password", "otp", "card")
_SENSITIVE_WORDS = ("password", "otp", "card", "cvv", "pin", "كلمة", "رمز", "بطاقة")


def _sensitive(d: Detonation) -> bool:
    for f in d.form_fields:
        blob = f"{f.type} {f.name} {f.label} {f.placeholder}".lower()
        if f.type in _SENSITIVE or any(w in blob for w in _SENSITIVE_WORDS):
            return True
    return False


def _norm_text(t: str) -> str:
    return " ".join((t or "").split())[:5000]


def cloak_diff(dets: list[Detonation]) -> CloakDiff:
    """Compare detonations of the same URL across personas. Never raises."""
    try:
        dets = [d for d in (dets or []) if d is not None]
        out = CloakDiff(cloaked=False, personas=[d.persona for d in dets])
        if len(dets) < 2:
            return out
        diffs: list[str] = []
        cloaked = False
        min_sim = 1.0
        for a, b in combinations(dets, 2):
            pa, pb = a.persona, b.persona
            loaded_a, loaded_b = a.status in ("ok", "blank"), b.status in ("ok", "blank")
            if a.status != b.status:
                diffs.append(f"status differs: {pa}={a.status}, {pb}={b.status}")
                # one persona gets a working page, another a dead/error one -> selective serving
                if loaded_a != loaded_b and "timeout" not in (a.status, b.status):
                    cloaked = True
            if not (loaded_a and loaded_b):
                continue
            da, db = registrable(a.final_url or a.url), registrable(b.final_url or b.url)
            if da != db:
                diffs.append(f"final domain differs: {pa}={da}, {pb}={db}")
                cloaked = True
            if (a.title or "").strip() != (b.title or "").strip():
                diffs.append(f"title differs: {pa}='{a.title[:60]}', {pb}='{b.title[:60]}'")
            ta, tb = _norm_text(a.visible_text), _norm_text(b.visible_text)
            sim = 1.0 if not ta and not tb else fuzz.ratio(ta, tb) / 100.0
            min_sim = min(min_sim, sim)
            if sim < 0.5:
                diffs.append(f"page text differs ({sim:.0%} similar): {pa} vs {pb}")
                cloaked = True
            sa, sb = _sensitive(a), _sensitive(b)
            if sa != sb:
                who, other = (pa, pb) if sa else (pb, pa)
                diffs.append(f"credential/card/OTP form shown to {who} but not to {other}")
                cloaked = True
            elif bool(a.form_fields) != bool(b.form_fields):
                who, other = (pa, pb) if a.form_fields else (pb, pa)
                diffs.append(f"form shown to {who} but not to {other}")
                cloaked = True
        out.cloaked = cloaked
        out.differences = diffs
        out.similarity = round(min_sim, 3)
        return out
    except Exception as e:  # noqa: BLE001
        return CloakDiff(cloaked=False, personas=[getattr(d, "persona", "") for d in (dets or [])],
                         differences=[f"cloak_diff error: {type(e).__name__}"])
