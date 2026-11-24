"""Parse an RDAP JSON blob (Intel.raw_rdap) into police-friendly fields. Pure, never raises."""
from __future__ import annotations

from typing import Any


def _vcard(entity: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"fn": [], "email": [], "tel": [], "org": []}
    try:
        arr = entity.get("vcardArray") or []
        props = arr[1] if len(arr) > 1 else []
        for p in props:
            if not isinstance(p, list) or len(p) < 4:
                continue
            name, val = str(p[0]).lower(), p[3]
            if isinstance(val, list):
                val = " ".join(str(v) for v in val if v)
            val = str(val).strip()
            if val.startswith("mailto:"):
                val = val[7:]
            if val.startswith("tel:"):
                val = val[4:]
            if name in out and val and val not in out[name]:
                out[name].append(val)
    except Exception:
        pass
    return out


def _walk(entities: Any, parent_roles: list[str] | None = None):
    for e in entities or []:
        if not isinstance(e, dict):
            continue
        roles = [str(r) for r in e.get("roles", [])]
        yield e, roles, parent_roles or []
        yield from _walk(e.get("entities"), roles)


def parse_rdap(raw: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "handle": "", "ldh_name": "", "status": [], "events": {}, "nameservers": [],
        "registrar": "", "registrar_iana_id": "", "registrar_abuse_emails": [], "registrar_abuse_phones": [],
        "entities": [],
    }
    if not raw or not isinstance(raw, dict):
        return out
    try:
        out["handle"] = str(raw.get("handle", ""))
        out["ldh_name"] = str(raw.get("ldhName", ""))
        out["status"] = [str(s) for s in raw.get("status", []) or []]
        for ev in raw.get("events", []) or []:
            if isinstance(ev, dict) and ev.get("eventAction"):
                out["events"][str(ev["eventAction"])] = str(ev.get("eventDate", ""))
        out["nameservers"] = [str(n.get("ldhName", "")).lower() for n in raw.get("nameservers", []) or []
                              if isinstance(n, dict)]
        for e, roles, parent in _walk(raw.get("entities")):
            vc = _vcard(e)
            out["entities"].append({"roles": roles, "parent_roles": parent, "handle": str(e.get("handle", "")),
                                    "name": (vc["fn"] or vc["org"] or [""])[0], "emails": vc["email"],
                                    "phones": vc["tel"]})
            if "registrar" in roles:
                out["registrar"] = out["registrar"] or (vc["fn"] or vc["org"] or [""])[0]
                for pid in e.get("publicIds", []) or []:
                    if isinstance(pid, dict) and "IANA" in str(pid.get("type", "")):
                        out["registrar_iana_id"] = str(pid.get("identifier", ""))
            if "abuse" in roles:
                for m in vc["email"]:
                    if m not in out["registrar_abuse_emails"]:
                        out["registrar_abuse_emails"].append(m)
                for t in vc["tel"]:
                    if t not in out["registrar_abuse_phones"]:
                        out["registrar_abuse_phones"].append(t)
    except Exception as exc:  # pragma: no cover
        out["parse_error"] = str(exc)
    return out
