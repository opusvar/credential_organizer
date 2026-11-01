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
    today = today or dt.datetime.now().astimezone().date()
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
    out += _check_devices(registry, today)
    return out


def _check_devices(registry: Registry, today: dt.date) -> list[Finding]:
    """D13/D11 hygiene: cert expiry, missing certs, recovery-key redundancy."""
    out: list[Finding] = []
    for did in sorted(registry.devices):
        c = registry.devices[did].cert
        path = f"devices.{did}"
        if c is None or (c.status == "pending" and not c.serial):
            out.append(Finding("warning", path, "has no cert (issue one via step-ca, then "
                                                "`cvc-access device set-cert`)"))
        elif c.status == "active" and c.not_after is not None:
            if c.not_after < today:
                out.append(Finding("warning", path, f"cert expired on {c.not_after}"))
            elif (c.not_after - today).days < SOON_DAYS:
                out.append(Finding("warning", path, f"cert expires soon ({c.not_after})"))
    if not (registry.hardware_keys or registry.devices):
        return out
    active = [k for k in registry.hardware_keys.values() if k.usable]
    recovery = [k for k in active if "recovery" in k.uses]
    if len(recovery) < 2:
        out.append(Finding("warning", "hardware_keys",
                           f"only {len(recovery)} active hardware key(s) with the recovery use; "
                           "D11 requires at least 2"))
    if len(active) >= 2 and len({k.location for k in active}) == 1:
        out.append(Finding("warning", "hardware_keys",
                           f"all active hardware keys are in the same location "
                           f"({active[0].location}); keep one elsewhere"))
    return out
