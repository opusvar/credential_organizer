"""Lint a loaded registry for hygiene problems (expiry, unused roles, unenforced kinds)."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from cvc.access.model import GUEST_TIERS, PERSON_TIERS, Agent, Registry

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
    out += check_tiers(registry)
    return out


# ── tiers ───────────────────────────────────────────────────────────────────
# Agent tiers sit on the person scale; `assistant` is resolved via its bound person.
_RANK = {t: i for i, t in enumerate(PERSON_TIERS)}
_AGENT_RANK = {"scoped": _RANK["low"], "low": _RANK["low"], "medium": _RANK["medium"],
               "high": _RANK["high"]}
_OWNER_ONLY = frozenset({"high", "admin", "owner"})
_EXPECTED_TAILNET = {"guest-short": "short-guests", "guest-long": "long-guests",
                     "owner": "owner"}
SCOPED_MAX_SYSTEMS = 2


def agent_rank(registry: Registry, agent: Agent) -> int | None:
    """Effective tier rank on the person scale (assistant = min(person, medium))."""
    if agent.tier == "assistant":
        person = registry.people.get(agent.owner or "")
        if person is None or person.tier is None:
            return None
        return min(_RANK[person.tier], _RANK["medium"])
    return _AGENT_RANK.get(agent.tier or "")


def _grant_ok(grantor_tier: str, granted_rank: int, granted_name: str) -> str | None:
    """Return an error message if grantor_tier may not grant granted_rank."""
    if grantor_tier == "owner":
        return None
    if granted_name in _OWNER_ONLY:
        return f"only an owner may grant tier {granted_name} (grantor is {grantor_tier})"
    if _RANK[grantor_tier] - granted_rank < 2:
        return (f"grantor tier {grantor_tier} must be at least 2 tiers above "
                f"granted tier {granted_name}")
    return None


def _check_grantor(registry: Registry, path: str, granted_by: str | None, rank: int | None,
                   name: str | None) -> list[Finding]:
    if granted_by is None or rank is None or name is None:
        return []
    grantor = registry.people.get(granted_by)
    if grantor is None:
        return [Finding("error", path, f"granted_by: unknown person {granted_by!r}")]
    if grantor.tier is None:
        return [Finding("error", path, f"granted_by {granted_by!r} has no tier")]
    msg = _grant_ok(grantor.tier, rank, name)
    return [Finding("error", path, msg)] if msg else []


def check_tiers(registry: Registry) -> list[Finding]:
    out: list[Finding] = []
    for pid in sorted(registry.people):
        u = registry.people[pid]
        path = f"people.{pid}"
        guest = u.tier in GUEST_TIERS
        if guest and u.expires is None:
            out.append(Finding("error", path, f"tier {u.tier} requires an expires date"))
        if u.ha != "none" and not guest:
            out.append(Finding("error", path, "ha access is only valid for guest tiers"))
        want = _EXPECTED_TAILNET.get(u.tier or "")
        if want and u.tailnet and u.tailnet != want:
            out.append(Finding("error", path, f"tier {u.tier} belongs on tailnet {want}, "
                                              f"not {u.tailnet}"))
        if u.tailnet in ("agents", "machines"):
            out.append(Finding("error", path, f"people may not be on tailnet {u.tailnet}"))
        if u.tier is not None:
            out += _check_grantor(registry, path, u.granted_by, _RANK[u.tier], u.tier)
    for aid in sorted(registry.agents):
        a = registry.agents[aid]
        path = f"agents.{aid}"
        if a.tailnet is not None and a.tailnet != "agents":
            out.append(Finding("error", path, f"agents must be on tailnet agents, "
                                              f"not {a.tailnet}"))
        if a.tier == "assistant":
            person = registry.people.get(a.owner or "")
            if person is None:
                out.append(Finding("error", path, "assistant agents must bind to one person "
                                                  f"via owner (got {a.owner!r})"))
            elif person.tier is None:
                out.append(Finding("error", path, f"assistant owner {a.owner!r} has no tier"))
        if a.tier == "scoped":
            systems = {g.system for _, g in registry.grants_for(a)}
            if len(systems) > SCOPED_MAX_SYSTEMS:
                out.append(Finding("error", path,
                                   f"scoped agents may reach at most {SCOPED_MAX_SYSTEMS} "
                                   f"systems; has {len(systems)} ({', '.join(sorted(systems))})"))
        rank = agent_rank(registry, a)
        name = None if rank is None else PERSON_TIERS[rank]
        out += _check_grantor(registry, path, a.granted_by, rank, name)
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
    owner_keys = [k for k in active
                  if (p := registry.people.get(k.owner)) is not None and p.tier == "owner"]
    if not owner_keys:
        out.append(Finding("error", "hardware_keys",
                           "no active hardware key belongs to an owner-tier person; the owner "
                           "YubiKey is the root of recovery (D11/D14)"))
    elif len(owner_keys) == 1:
        out.append(Finding("warning", "hardware_keys",
                           f"only one active owner hardware key ({owner_keys[0].id}); "
                           "enroll a second (D11)"))
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
