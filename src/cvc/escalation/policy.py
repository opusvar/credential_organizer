"""D27 agent escalation policy: validate one request, classify it, pick the approver tier.

An escalation asks a human to let an agent do ONE named action above its effective D16
tier. This module is pure (no I/O): `evaluate()` turns a raw request into an `Assessment`
or raises `EscalationRefused` (hard ceiling / invalid) / returns `already_permitted`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from cvc.access.classify import ALLOWED, APPROVAL, DENIED, ceiling
from cvc.approvals.model import ACTIONS, AGENT_TIERS, DATA_LEVELS, PERSON_RANK, PERSON_TIERS

from .text import TextError, normalize

DEFAULT_TTL_S = 15 * 60
MAX_TTL_S = 24 * 3600
MIN_TTL_S = 60

LADDER = ("scoped", "low", "medium", "high")
# Agent tier -> rank on the person scale (same mapping as cvc.access.check).
_AGENT_PERSON = {"scoped": "low", "low": "low", "medium": "medium", "high": "high"}
_OWNER_ONLY_GRANTS = frozenset({"high", "admin", "owner"})

# Resource kinds an escalation may name, with the exact-identifier pattern each must match.
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HA_ENTITY = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
RESOURCE_KINDS = {"credential": _UUID, "ha": _HA_ENTITY, "system": _NAME, "task": _NAME}
# Kinds that are hard ceilings: never escalatable, whatever the approver.
HARD_CEILINGS = {
    "owner-key": "owner key changes need the owner's YubiKey, never an escalation",
    "takeover": "takeover (D15) is an owner/YubiKey flow, never an escalation",
    "delegation": "estate delegation (D17) is an owner/YubiKey flow, never an escalation",
    "tier": "an agent's tier is changed only in the registry by its grantor, never by escalation",
    "role": "role grants are changed only in the registry, never by escalation",
    "grant": "granting access to other agents is never escalatable",
    "agent": "granting access to other agents is never escalatable",
}
_WILDCARD = re.compile(r"[*?%#+\[\]{}]|\.\.")
_WILD_WORDS = frozenset({"all", "any", "every", "everything", "*", "none"})
_PERSON = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_AGENT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_FIELDS = {"action", "data", "resource", "purpose", "justification", "on_behalf_of",
           "ttl_s", "physical"}


class EscalationRefused(Exception):
    """Invalid request (code 'invalid') or hard ceiling (code 'hard_ceiling')."""

    def __init__(self, code: str, reason: str, status: int = 422):
        super().__init__(reason)
        self.code, self.reason, self.status = code, reason, status


@dataclass(frozen=True)
class Assessment:
    agent: str
    agent_tier: str            # the agent's own tier (ACL / registry)
    current_tier: str          # the effective D16 row applied
    required_tier: str         # lowest tier whose cell allows it ("owner" for secret)
    cell: str                  # the agent's current D16 cell (A/P/D)
    action: str
    data: str
    resource: str
    purpose: str
    justification: str
    on_behalf_of: str | None
    physical: bool
    approver_min_tier: str     # human person tier
    owner_only: bool
    ttl_s: int
    already_permitted: bool = False


def _invalid(msg: str) -> EscalationRefused:
    return EscalationRefused("invalid", msg)


def parse_resource(resource: object) -> tuple[str, str]:
    """`kind:identifier` -> (kind, id). Rejects wildcards and unknown kinds."""
    if not isinstance(resource, str) or ":" not in resource:
        raise _invalid("resource: must be kind:identifier (credential:<uuid>, ha:<entity>, "
                       "system:<name>, task:<id>)")
    kind, ident = resource.split(":", 1)
    kind = kind.strip().lower()
    if kind in HARD_CEILINGS:
        raise EscalationRefused("hard_ceiling", HARD_CEILINGS[kind], 403)
    if not ident or ident.strip().lower() in _WILD_WORDS or _WILDCARD.search(ident) \
            or ident.endswith("/") or " " in ident:
        raise _invalid("resource: wildcards are not allowed; name exactly one resource")
    pat = RESOURCE_KINDS.get(kind)
    if pat is None:
        raise _invalid(f"resource: unknown kind {kind!r}")
    if not pat.match(ident):
        raise _invalid(f"resource: {kind} identifier {ident!r} is not exact/valid")
    return kind, ident


def required_tier(data: str, action: str) -> str:
    """Lowest agent tier whose D16 cell allows (A) or else approves (P) the action."""
    if data == "secret":
        return "owner"
    for verdict in (ALLOWED, APPROVAL):
        for t in LADDER:
            if ceiling(t, data, action) == verdict:
                return t
    return "owner"


def approver_min_tier(required: str, data: str, action: str) -> tuple[str, bool]:
    """(person tier, owner_only). Grant rule: approver >= 2 tiers above the required tier;
    owner-only for secret data, any delegate action, and required tiers high and above."""
    if data == "secret" or action == "delegate" or required == "owner":
        return "owner", True
    person = _AGENT_PERSON[required]
    if person in _OWNER_ONLY_GRANTS:
        return "owner", True
    idx = PERSON_RANK[person] + 2
    tier = PERSON_TIERS[min(idx, len(PERSON_TIERS) - 1)]
    return tier, tier == "owner"


def row_for(agent_tier: str) -> str:
    if agent_tier not in AGENT_TIERS:
        raise _invalid(f"agent tier {agent_tier!r} unknown")
    return agent_tier


def evaluate(agent: str, agent_tier: str, raw: object, *, effective_row: str | None = None,
             on_behalf_of_default: str | None = None) -> Assessment:
    """Validate + classify. `effective_row` = min(agent, sponsor) row when known."""
    if not isinstance(raw, dict):
        raise _invalid("request must be an object")
    unknown = set(raw) - _FIELDS
    if unknown:
        raise _invalid(f"unknown fields: {sorted(unknown)}")
    if not isinstance(agent, str) or not _AGENT.match(agent):
        raise _invalid("agent: invalid id")
    action, data = raw.get("action"), raw.get("data")
    if action not in ACTIONS:
        raise _invalid(f"action: must be exactly one of {list(ACTIONS)}")
    if data not in DATA_LEVELS:
        raise _invalid(f"data: must be exactly one of {list(DATA_LEVELS)}")
    kind, ident = parse_resource(raw.get("resource"))
    if action == "delegate" and kind == "system":
        raise EscalationRefused("hard_ceiling", "delegating a whole system is delegation of "
                                "everything on it; never escalatable", 403)
    try:
        purpose = normalize(raw.get("purpose"), "purpose", 256)
        justification = normalize(raw.get("justification"), "justification", 512)
    except TextError as e:
        raise _invalid(f"{e.field}: {e.code}") from None
    obo = raw.get("on_behalf_of", None)
    if obo is None:
        obo = on_behalf_of_default
    if obo is not None and (not isinstance(obo, str) or not _PERSON.match(obo)):
        raise _invalid("on_behalf_of: must be a person id")
    if agent_tier == "assistant" and not obo:
        raise _invalid("on_behalf_of: required for assistant tier")
    ttl = raw.get("ttl_s", DEFAULT_TTL_S)
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not MIN_TTL_S <= ttl <= MAX_TTL_S:
        raise _invalid(f"ttl_s: integer between {MIN_TTL_S} and {MAX_TTL_S}")
    physical = raw.get("physical", False)
    if not isinstance(physical, bool):
        raise _invalid("physical: must be a boolean")
    physical = physical or (kind == "ha" and action == "act")

    row = row_for(effective_row or agent_tier)
    cell = ceiling(row, data, action)
    req = required_tier(data, action)
    appr, owner_only = approver_min_tier(req, data, action)
    resource = f"{kind}:{ident}"
    permitted = cell == ALLOWED and not physical
    return Assessment(agent=agent, agent_tier=agent_tier, current_tier=row, required_tier=req,
                      cell=cell, action=action, data=data, resource=resource, purpose=purpose,
                      justification=justification, on_behalf_of=obo, physical=physical,
                      approver_min_tier=appr, owner_only=owner_only, ttl_s=ttl,
                      already_permitted=permitted)


def describe_cell(cell: str) -> str:
    return {ALLOWED: "allowed", APPROVAL: "approval-required", DENIED: "denied"}[cell]
