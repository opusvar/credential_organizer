"""Bridge (temporary-device) records, limits and the cert URI SAN format (D27).

A bridge is a short-lived step-ca device cert for a person who is between permanent devices
(new or borrowed phone, loaner laptop, replacing a lost or broken device, travel). Its SANs:

    urn:cvc:person:<person>
    urn:cvc:device:<person>-temp-<n>
    urn:cvc:tier:<min(person tier, medium)>
    urn:cvc:temp:<expires_at, ISO-8601 UTC>      <- the temp flag

Only public metadata is stored: ids, tiers, timestamps, who approved. Never a key or a .p12.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

PERSON_TIERS = ("guest-short", "guest-long", "media-only", "low", "medium", "high", "admin",
                "owner")
RANK = {t: i for i, t in enumerate(PERSON_TIERS)}
TIER_CAP = "medium"
GUEST_TIERS = frozenset({"guest-short", "guest-long"})
SELF_ISSUE_TIERS = frozenset({"admin", "owner"})

DEFAULT_LIFETIME = timedelta(hours=72)
MAX_TOTAL = timedelta(days=14)
APPROVAL_WINDOW = timedelta(hours=24)       # pending requests/extensions expire (deny) after
LOST_BLOCK = timedelta(days=7)              # D23 passwordless block
AUDIT_MAX_AGE = timedelta(days=7)           # audit flags bridges older than this
REPEAT_WINDOW = timedelta(days=90)
REPEAT_THRESHOLD = 3                        # bridges per person within REPEAT_WINDOW

STATUSES = ("pending", "active", "denied", "expired", "revoked")
OPEN = frozenset({"pending", "active"})

URN_TEMP = "urn:cvc:temp:"
TEMP_DEVICE_RE = re.compile(r"^(?P<person>.+)-temp-(?P<n>[0-9]+)$")


def now_utc() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


def capped_tier(tier: str) -> str:
    """Effective tier on a temp device: min(person tier, medium)."""
    if tier not in RANK:
        raise ValueError(f"unknown tier {tier!r}")
    return tier if RANK[tier] <= RANK[TIER_CAP] else TIER_CAP


def device_id(person: str, n: int) -> str:
    return f"{person}-temp-{n}"


def is_temp_device(device: str | None) -> bool:
    return bool(device and TEMP_DEVICE_RE.match(device))


def bridge_sans(person: str, device: str, tier: str, expires_at: str) -> list[str]:
    return [f"urn:cvc:person:{person}", f"urn:cvc:device:{device}",
            f"urn:cvc:tier:{capped_tier(tier)}", f"{URN_TEMP}{expires_at}"]


def required_approver_rank(person_tier: str) -> int:
    """Grant rule (D12/D13): approver >= 2 tiers above the tier being granted (the capped
    tier). Owners can always approve, so the requirement never exceeds owner."""
    return min(RANK[capped_tier(person_tier)] + 2, RANK["owner"])


def approver_ok(approver_tier: str | None, person_tier: str) -> bool:
    if approver_tier not in RANK:
        return False
    return approver_tier == "owner" or RANK[approver_tier] >= required_approver_rank(person_tier)


@dataclass
class Bridge:
    id: str                       # == device id, e.g. alex-temp-2
    person: str
    person_tier: str
    tier: str                     # capped tier carried in the cert
    reason: str                   # free text: "borrowed phone", "travel" ...
    requested_at: str
    status: str = "pending"
    requested_hours: int = 72
    lost_report: bool = False     # requested during a D23 7-day passwordless block
    self_issued: bool = False
    approval_id: str | None = None
    approved_by: str | None = None
    issued_at: str | None = None
    expires_at: str | None = None
    ended_at: str | None = None
    ended_by: str | None = None
    end_reason: str | None = None
    promoted_to: str | None = None
    pending_extension: dict[str, Any] | None = None   # {hours, requested_at, approval_id}
    extensions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.status in OPEN

    def hours_left(self, now: datetime) -> int | None:
        if self.status != "active" or not self.expires_at:
            return None
        return max(0, int((parse_ts(self.expires_at) - now).total_seconds() // 3600))

    def sans(self) -> list[str]:
        if not self.expires_at:
            raise ValueError("bridge has no expiry yet")
        return bridge_sans(self.person, self.id, self.tier, self.expires_at)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Bridge:
        b = cls(**d)
        if b.status not in STATUSES:
            raise ValueError(f"bridge {b.id}: bad status {b.status!r}")
        return b
