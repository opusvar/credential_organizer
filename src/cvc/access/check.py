"""Lint a loaded registry for hygiene problems (expiry, unused roles, unenforced kinds)."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from cvc.access.model import Registry

SOON_DAYS = 30


@dataclass(frozen=True)
class Finding:
    level: str   # "error" | "warning" | "info"
    path: str
    message: str


def check_registry(registry: Registry, today: dt.date | None = None) -> list[Finding]:
    today = today or dt.date.today()
    out: list[Finding] = []
    used: set[str] = set()
    for p in registry.principals():
        path = f"{p.section}.{p.id}"
        used.update(p.roles)
        if p.expires is not None:
            if p.expires < today:
                out.append(Finding("warning", path, f"expired on {p.expires}; has no access"))
            elif (p.expires - today).days < SOON_DAYS:
                out.append(Finding("warning", path, f"expires soon ({p.expires})"))
        if not p.roles:
            out.append(Finding("warning", path, "has no roles"))
    for rid in sorted(registry.roles):
        if rid not in used:
            out.append(Finding("warning", f"roles.{rid}", "role is not used by any principal"))
        for g in registry.roles[rid].grants:
            s = registry.system_of(g)
            if not s.enforced:
                out.append(Finding("info", g.path,
                                   f"grant to system '{s.id}' (kind {s.kind}) is unenforced "
                                   "(documented only)"))
    return out
