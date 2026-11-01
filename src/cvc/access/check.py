"""Lint a loaded registry for hygiene problems (expiry, unused roles, unenforced kinds)."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from cvc.access.classify import APPROVAL, DENIED, classify_grant, effective, grant_labels
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
    out += check_classification(registry, today)
    out += check_resources(registry)
    return out


# ── D16 classification ──────────────────────────────────────────────────────
_ACTION_RANK = {"read": 0, "relay": 1, "write": 2, "act": 3}


def _exceeds(granted: str, exposed: str) -> bool:
    if "delegate" in (granted, exposed):
        return granted != exposed
    return _ACTION_RANK[granted] > _ACTION_RANK[exposed]


def check_classification(registry: Registry, today: dt.date | None = None) -> list[Finding]:
    """Data/action labels vs tier ceilings (docs/ACCESS-CLASSIFICATION.md)."""
    today = today or dt.datetime.now().astimezone().date()
    out: list[Finding] = []
    for rid in sorted(registry.roles):
        for g in registry.roles[rid].grants:
            s = registry.system_of(g)
            if g.action and s.action and _exceeds(g.action, s.action):
                out.append(Finding("error", g.path, f"action {g.action} exceeds what system "
                                                    f"{s.id} exposes ({s.action})"))
            if g.via and grant_labels(registry, g)[0] != "secret":
                out.append(Finding("warning", g.path, f"via: {g.via} is only meaningful for "
                                                      "secret data"))
    for aid in sorted(registry.agents):
        a = registry.agents[aid]
        path = f"agents.{aid}"
        sp = registry.people.get(a.sponsor_id or "")
        if sp is not None and sp.tier in GUEST_TIERS and a.active(today) is False \
                and a.roles:
            out.append(Finding("warning", path, f"sponsor {sp.id} (guest) access ended; agent "
                                                "is revoked with them"))
        if sp is not None and not sp.active(today) and sp.tier not in GUEST_TIERS:
            out.append(Finding("warning", path, f"sponsor {sp.id} is not active"))
        eff = effective(registry, a)
        if eff.row is not None and eff.row != a.tier and a.tier is not None:
            out.append(Finding("info", path, f"effective ceiling {eff.row} ({eff.reason})"))
        for rid in a.roles:
            for g in registry.roles[rid].grants:
                res = classify_grant(registry, a, g)
                if res is None:
                    continue
                verdict, why = res
                if verdict == DENIED:
                    out.append(Finding("error", path, f"role {rid} ({g.path}) exceeds tier "
                                                      f"ceiling: {why}"))
                elif verdict == APPROVAL:
                    out.append(Finding("warning", path, f"role {rid} ({g.path}) needs "
                                                        f"per-action approval: {why}"))
    return out


def check_resources(registry: Registry) -> list[Finding]:
    """Resource catalog: min_tier must be on the person ladder; hosts must be unique."""
    out: list[Finding] = []
    hosts: dict[str, str] = {}
    for rid in sorted(registry.resources):
        r = registry.resources[rid]
        path = f"resources.{rid}"
        if r.min_tier not in PERSON_TIERS:
            out.append(Finding("error", path, f"unknown min_tier {r.min_tier!r} "
                                              f"(one of {', '.join(PERSON_TIERS)})"))
        if r.host in hosts:
            out.append(Finding("error", path, f"duplicate host {r.host!r} "
                                              f"(also resources.{hosts[r.host]})"))
        else:
            hosts[r.host] = rid
    return out


# ── tiers ───────────────────────────────────────────────────────────────────
# Agent tiers sit on the person scale; `assistant` is resolved via its bound person.
_RANK = {t: i for i, t in enumerate(PERSON_TIERS)}
_AGENT_RANK = {"scoped": _RANK["low"], "low": _RANK["low"], "medium": _RANK["medium"],
               "high": _RANK["high"]}
_OWNER_ONLY = frozenset({"high", "admin", "owner"})
_EXPECTED_TAILNET = {"guest-short": "guests", "guest-long": "guests", "owner": "owner"}
SCOPED_MAX_SYSTEMS = 2


def agent_rank(registry: Registry, agent: Agent) -> int | None:
    """Effective tier rank on the person scale (assistant = min(person, medium))."""
    if agent.tier == "assistant":
        person = registry.people.get(agent.sponsor_id or "")
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
            person = registry.people.get(a.sponsor_id or "")
            if person is None:
                out.append(Finding("error", path, "assistant agents must bind to one person "
                                                  f"via sponsor/owner (got {a.sponsor_id!r})"))
            elif person.tier is None:
                out.append(Finding("error", path, f"assistant sponsor {a.sponsor_id!r} has "
                                                  "no tier"))
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
                  if (p := registry.people.get(k.owner)) is not None and p.tier == "owner"
                  and p.status == "active"]
    if not owner_keys:
        out.append(Finding("error", "hardware_keys",
                           "no active hardware key belongs to an owner-tier person; the owner "
                           "YubiKey is the root of recovery (D11/D14)"))
    elif len(owner_keys) == 1:
        out.append(Finding("warning", "hardware_keys",
                           f"only one active owner hardware key ({owner_keys[0].id}); "
                           "enroll a second (D11)"))
    for pid in sorted({k.owner for k in owner_keys}):
        prim = [k.id for k in owner_keys if k.owner == pid and k.role == "primary"]
        if len(prim) != 1:
            out.append(Finding("error", f"people.{pid}",
                               f"owner must have exactly one active primary hardware key "
                               f"(role: primary); has {len(prim)}"
                               + (f" ({', '.join(sorted(prim))})" if prim else "")))
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
