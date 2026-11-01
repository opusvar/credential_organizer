"""Delegation records, the 48-hour window and the hash-chained store (D17).

Lifecycle, counted from ``started_at``:
  hour 0-48  ``revocable``  nothing has moved; the delegator may revoke, the recipient decline
  hour 48+   ``pending``    ``cvc delegate complete`` may execute; revoke is refused
Terminal: ``executed``, ``revoked`` (delegator, inside the window), ``declined`` (recipient,
before execution), ``refused`` (execution re-check failed, e.g. the D14 owner-key guard).

The store reuses the takeover store (same JSON + hash-chained ``history.jsonl`` scheme) under
its own state directory. No secret is ever stored.
"""
from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timedelta

from cvc.takeover.model import TakeoverError, TakeoverStore

WINDOW_HOURS = 48
DEFAULT_STATE_DIR = "~/.local/state/cvc/delegate"
SECTIONS = ("vault", "orgs", "hwkeys", "devices", "grants", "agents", "roles")
SECTION_TITLES = {"vault": "vault items/folders", "orgs": "organization memberships",
                  "hwkeys": "hardware keys", "devices": "devices", "grants": "grants given",
                  "agents": "agents and sponsored agents", "roles": "roles (tier)"}
ICONS = {"revocable": "[~]", "pending": "[..]", "executed": "[ok]", "revoked": "[x]",
         "declined": "[x]", "refused": "[!]"}


class DelegationError(TakeoverError):
    """A delegation step was refused. The message says why."""


def new_id(now: datetime) -> str:
    return f"dg-{now:%Y%m%d}-{secrets.token_hex(3)}"


@dataclass
class DelegationRecord:
    id: str
    delegator: str
    recipient: str
    started_at: str                      # ISO-8601 UTC
    delegator_cert_fingerprint: str
    factor: str                          # "yubikey:<key id>" | "passkey"
    elevation_method: str
    sections: list[str]
    preview: list[dict]                  # snapshot shown to the delegator
    status: str = "pending"              # pending | executed | revoked | declined | refused
    revoked_at: str | None = None
    declined_at: str | None = None
    executed_at: str | None = None
    refused_reason: str | None = None
    executed_actions: list[dict] = field(default_factory=list)

    @property
    def started(self) -> datetime:
        return datetime.fromisoformat(self.started_at)

    @property
    def window_ends(self) -> datetime:
        return self.started + timedelta(hours=WINDOW_HOURS)

    def in_window(self, now: datetime) -> bool:
        return now < self.window_ends

    def phase(self, now: datetime) -> str:
        if self.status != "pending":
            return self.status
        return "revocable" if self.in_window(now) else "pending"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> DelegationRecord:
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in names})


def status_line(rec: DelegationRecord, now: datetime) -> str:
    ph = rec.phase(now)
    base = f"{ICONS[ph]} {ph}: delegation {rec.id} {rec.delegator} -> {rec.recipient}"
    if ph == "revocable":
        left = rec.window_ends - now
        hours = int(left.total_seconds() // 3600)
        return (f"{base}; nothing has moved; {hours}h left to revoke "
                f"(cvc delegate revoke {rec.id}) or decline (cvc delegate decline {rec.id})")
    if ph == "pending":
        return f"{base}; window closed; ready to execute (cvc delegate complete {rec.id})"
    if ph == "refused":
        return f"{base}; {rec.refused_reason}"
    return base


class DelegationStore(TakeoverStore):
    record_cls = DelegationRecord
    key = "delegations"
    ref = "delegation"
    error = DelegationError

    def _parties(self, r) -> tuple[str, ...]:
        return (r.delegator, r.recipient)
