"""D16 access classification: tier ceilings over (data level x action).

Source of truth: docs/ACCESS-CLASSIFICATION.md section 2 (matrix) and section 6 (sponsors).

    effective(agent, data, action) = min(tier ceiling(agent), sponsor ceiling) ∩ role grants

`ceiling(row, data, action)` returns "A" (allowed), "P" (approval required) or "D" (denied).
"""
from __future__ import annotations

from dataclasses import dataclass

from cvc.access.model import GUEST_TIERS, Agent, Grant, Registry

ALLOWED, APPROVAL, DENIED = "A", "P", "D"
_RW = ("read", "relay", "write", "act")


def _row(public: str, internal: str, private: str, delegate: str) -> dict:
    cells: dict[tuple[str, str], str] = {}
    for level, spec in (("public", public), ("internal", internal), ("private", private)):
        for action, v in zip(_RW, spec.split("/"), strict=True):
            cells[(level, action)] = v
        cells[(level, "delegate")] = delegate
    for action in (*_RW, "delegate"):
        cells[("secret", action)] = DENIED
    return cells


# Rows exactly as in the matrix doc (R / Rl / W / Act per data level; delegate column).
MATRIX: dict[str, dict[tuple[str, str], str]] = {
    "scoped":    _row("A/A/D/D", "A/A/D/D", "D/D/D/D", DENIED),
    "low":       _row("A/A/D/D", "A/A/D/D", "D/D/D/D", DENIED),
    "medium":    _row("A/A/A/P", "A/A/A/P", "A/A/P/P", DENIED),
    "high":      _row("A/A/A/P", "A/A/A/P", "A/A/A/P", ALLOWED),
    "assistant": _row("A/A/A/P", "A/A/A/P", "A/A/P/P", DENIED),
}
_LADDER = ("scoped", "low", "medium", "high")      # assistant ~ medium, minus delegate
_RANK = {t: i for i, t in enumerate(_LADDER)}

# Human tier -> highest agent ceiling that person may sponsor.
SPONSOR_CEILING = {"guest-short": "low", "guest-long": "low", "media-only": "low",
                   "low": "low", "medium": "medium", "high": "high", "admin": "high",
                   "owner": "high"}


def ceiling(row: str, data: str, action: str) -> str:
    return MATRIX[row][(data, action)]


@dataclass(frozen=True)
class Effective:
    row: str | None            # MATRIX row to apply, None = unknown (no tier)
    reason: str                # why it is capped (for messages)


def sponsor_cap(registry: Registry, agent: Agent) -> tuple[str | None, str]:
    """Ceiling imposed by the sponsor (or owner): (ladder tier or None, explanation)."""
    sid = agent.sponsor_id
    if sid is None:
        return None, "no sponsor"
    p = registry.people.get(sid)
    if p is None or p.tier is None:
        return None, f"sponsor {sid!r} unknown or has no tier"
    cap = SPONSOR_CEILING[p.tier]
    if p.tier in GUEST_TIERS:
        return "low", f"guest-sponsored by {sid} (capped at low)"
    if p.tier != "owner" and _RANK[cap] > _RANK["medium"]:
        return "medium", f"sponsored by non-owner {sid} (capped at medium)"
    return cap, f"sponsor {sid} ({p.tier})"


def effective(registry: Registry, agent: Agent) -> Effective:
    if agent.tier is None:
        return Effective(None, "agent has no tier")
    cap, why = sponsor_cap(registry, agent)
    if agent.tier == "assistant" and cap is None and agent.sponsor_id is None:
        return Effective(None, "assistant has no sponsor/owner")
    base = "medium" if agent.tier == "assistant" else agent.tier
    if cap is not None and _RANK[cap] < _RANK[base]:
        return Effective(cap, why)
    return Effective(agent.tier, f"tier {agent.tier}" + (f", {why}" if cap else ""))


def grant_labels(registry: Registry, grant: Grant) -> tuple[str | None, str | None]:
    """(data, action) of a grant: grant labels override the system's."""
    s = registry.system_of(grant)
    return grant.data or s.data, grant.action or s.action


def classify_grant(registry: Registry, agent: Agent, grant: Grant) -> tuple[str, str] | None:
    """(verdict, explanation) for one grant held by an agent, or None if unlabeled/no tier."""
    eff = effective(registry, agent)
    data, action = grant_labels(registry, grant)
    if eff.row is None or data is None or action is None:
        return None
    if data == "secret":
        if grant.via == "broker-approved" and eff.row == "high":
            return APPROVAL, ("secret via broker-approved single-use fetch "
                              "(per-use owner approval, never a standing grant)")
        if grant.via == "broker-approved":
            return DENIED, (f"secret via broker is only for an effective high tier "
                            f"({eff.reason})")
        return DENIED, "secret is never a standing grant (use via: broker-approved)"
    v = ceiling(eff.row, data, action)
    return v, f"{data}/{action} is {_WORD[v]} for {eff.row} ({eff.reason})"


_WORD = {ALLOWED: "allowed", APPROVAL: "approval-required", DENIED: "denied"}
