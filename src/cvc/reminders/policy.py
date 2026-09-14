"""Rotation / reuse / weakness policy. Pure and testable; the breach check lives in hibp.py.

Operates on lightweight records so it never holds full vault objects longer than needed.
Reason strings never include the password itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class CredRecord:
    item_id: str
    name: str
    username: str
    password: str          # held only for in-memory evaluation; never logged
    last_rotated: datetime | None = None


@dataclass
class Finding:
    item_id: str
    name: str
    reasons: list[str] = field(default_factory=list)


def _age_days(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    ref = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return (now - ref).days


def _is_weak(pw: str) -> bool:
    return len(pw) < 12 or pw.isalpha() or pw.isdigit()


def evaluate(records: list[CredRecord], *, max_age_days: int = 180) -> list[Finding]:
    """Flag stale (by age), reused (same password across items), and weak credentials."""
    # Records with no password (URI-only logins, passkey-only entries) are not credentials
    # this policy can judge: there is nothing to rotate, and counting "" as a shared value
    # would report every one of them as reused.
    scored = [r for r in records if r.password]

    # Reuse: group by password value (kept in memory only).
    counts: dict[str, int] = {}
    for r in scored:
        counts[r.password] = counts.get(r.password, 0) + 1

    findings: list[Finding] = []
    for r in scored:
        reasons: list[str] = []
        age = _age_days(r.last_rotated)
        if age is not None and age > max_age_days:
            reasons.append(f"stale: {age}d since rotation (> {max_age_days})")
        if counts.get(r.password, 0) > 1:
            reasons.append("reused across multiple items")
        if _is_weak(r.password):
            reasons.append("weak: short or single character class")
        if reasons:
            findings.append(Finding(item_id=r.item_id, name=r.name, reasons=reasons))
    return findings
