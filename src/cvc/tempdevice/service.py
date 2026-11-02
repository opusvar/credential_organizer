"""Bridge lifecycle: request, approve/deny, extend, promote, revoke, expire (D27).

Pure policy over (registry, bridge store, clock). Nothing here contacts step-ca: issuing and
revoking print `step` commands (see `cvc.tempdevice.certs`) that an operator runs. Every state
change is written to the hash-chained audit log (`cvc.broker.audit.AuditLog`) before the
store is saved, so a change can never land without a record.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from cvc.access.model import Registry
from cvc.broker.audit import AuditEvent, AuditLog

from .model import (
    APPROVAL_WINDOW,
    DEFAULT_LIFETIME,
    GUEST_TIERS,
    LOST_BLOCK,
    MAX_TOTAL,
    RANK,
    SELF_ISSUE_TIERS,
    Bridge,
    approver_ok,
    capped_tier,
    device_id,
    is_temp_device,
    iso,
    now_utc,
    parse_ts,
    required_approver_rank,
)

DEFAULT_DIR = "~/.local/state/cvc/tempdevice"
STATE_ENV = "CVC_TEMPDEVICE_STATE"
LOST_EVENTS = ("passwordless-block", "passwordless_block")
LIFT_EVENTS = ("passwordless-unblock", "passwordless_unblock")


class BridgeError(Exception):
    """A refused operation. The message says why (shown to the user)."""


@dataclass(frozen=True)
class AuthProof:
    """Factors the caller proved (asserted by Authentik / the CLI operator)."""
    password: bool = False
    passkey: bool = False
    yubikey: bool = False

    @property
    def strong(self) -> bool:
        """password + passkey, or a physical YubiKey."""
        return (self.password and self.passkey) or self.yubikey


def state_dir(path: str | os.PathLike | None = None) -> Path:
    return Path(os.path.expanduser(str(path or os.environ.get(STATE_ENV) or DEFAULT_DIR)))


def lost_report_active(registry: Registry, person: str, now: datetime) -> bool:
    """True while a D23 lost-device report's 7-day passwordless block is running (and no
    later owner lift is recorded)."""
    p = registry.people.get(person)
    if p is None:
        return False
    start: dt.date | None = None
    for h in p.history:
        try:
            day = dt.date.fromisoformat(str(h.get("date")))
        except ValueError:
            continue
        if h.get("event") in LOST_EVENTS:
            start = day if start is None or day > start else start
        elif h.get("event") in LIFT_EVENTS and start is not None and day >= start:
            start = None
    if start is None:
        return False
    return now.date() < start + dt.timedelta(days=LOST_BLOCK.days)


class BridgeStore:
    """JSON state file (0600, atomic replace, flock'd) + hash-chained audit log."""

    def __init__(self, directory: str | os.PathLike | None = None):
        self.dir = state_dir(directory)
        self.path = self.dir / "bridges.json"
        self.audit_path = self.dir / "audit.jsonl"     # AuditLog made on first write only

    @contextmanager
    def locked(self) -> Iterator[dict[str, Bridge]]:
        self.dir.mkdir(parents=True, exist_ok=True)
        with open(self.dir / ".lock", "a") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            items = self.load()
            yield items
            self._save(items)

    def load(self) -> dict[str, Bridge]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        return {k: Bridge.from_dict(v) for k, v in raw.get("bridges", {}).items()}

    def _save(self, items: dict[str, Bridge]) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".bridges.")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"bridges": {k: v.to_dict() for k, v in items.items()}}, fh, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def record(self, actor: str, bridge: Bridge, event: str, outcome: str = "ok") -> None:
        AuditLog(str(self.audit_path)).record(AuditEvent(agent=actor, credential=f"bridge:{bridge.id}",
                                     purpose=f"tempdevice:{event}", outcome=outcome,
                                     on_behalf_of=bridge.person))


class ApprovalsLink:
    """Optional mirror into the approvals pipeline (card on the dashboard + ntfy)."""

    def __init__(self, service):
        self.svc = service

    def submit(self, b: Bridge, hours: int, approver_rank: int, what: str, now: datetime) -> str:
        from cvc.approvals.model import PERSON_TIERS, new_request
        req = new_request(
            agent=f"tempdevice:{b.person}", agent_tier="scoped", on_behalf_of=b.person,
            intent=f"temporary device {what}",
            summary=(f"{b.person} asks for a temporary device ({b.id}) for {hours} h, tier "
                     f"{b.tier}" + (" (lost-device report active)" if b.lost_report else "")
                     + f". Reason: {b.reason}"),
            if_approved=f"{b.id} gets a short-lived device cert capped at {b.tier}",
            if_denied="no temporary device; password + passkey still work",
            action="act", deadline_s=int(APPROVAL_WINDOW.total_seconds()), now=now)
        req.approver_min_tier = PERSON_TIERS[approver_rank]
        return self.svc.submit(req).id

    def resolve(self, approval_id: str | None, status: str, by: str) -> None:
        if approval_id:
            self.svc.record_external(approval_id, status, by)

    def decision(self, approval_id: str | None) -> tuple[str, str | None] | None:
        if not approval_id:
            return None
        req = self.svc.get(approval_id)
        return (req.status, req.decided_by) if req else None


class BridgeService:
    def __init__(self, registry: Registry, store: BridgeStore,
                 clock: Callable[[], datetime] = now_utc,
                 approvals: ApprovalsLink | None = None):
        self.reg, self.store, self.clock, self.approvals = registry, store, clock, approvals

    # -- helpers -----------------------------------------------------------------------
    def _person_tier(self, person: str) -> str:
        if person in self.reg.agents or person in self.reg.machines:
            raise BridgeError("agents and machines never get a temporary device")
        p = self.reg.people.get(person)
        if p is None:
            raise BridgeError(f"unknown person {person!r}")
        if not p.active(self.clock().date()):
            raise BridgeError(f"{person} is not active")
        if p.tier is None:
            raise BridgeError(f"{person} has no tier")
        if p.tier in GUEST_TIERS:
            raise BridgeError("guests cannot get a temporary device")
        return p.tier

    def _tier_of(self, who: str) -> str | None:
        p = self.reg.people.get(who)
        return p.tier if p is not None and p.active(self.clock().date()) else None

    @staticmethod
    def _get(items: dict[str, Bridge], bid: str) -> Bridge:
        if bid not in items:
            raise BridgeError(f"unknown bridge {bid!r}")
        return items[bid]

    @staticmethod
    def _hours(hours: int | None, default: timedelta = DEFAULT_LIFETIME) -> int:
        h = int(default.total_seconds() // 3600) if hours is None else int(hours)
        if h <= 0:
            raise BridgeError("hours must be positive")
        return h

    def _check_approver(self, b: Bridge, approver: str, passkey: bool) -> None:
        if approver == b.person:
            raise BridgeError("self-approval is not allowed; another person must approve")
        if approver in self.reg.agents:
            raise BridgeError("agents cannot approve temporary devices")
        tier = self._tier_of(approver)
        if not approver_ok(tier, b.person_tier):
            raise BridgeError(f"approver {approver} (tier {tier}) must be at least 2 tiers "
                              f"above {b.tier}, or an owner")
        if not passkey:
            raise BridgeError("approver must confirm with a passkey")

    # -- operations --------------------------------------------------------------------
    def request(self, person: str, reason: str, proof: AuthProof, *, hours: int | None = None,
                self_issue: bool = False) -> Bridge:
        now = self.clock()
        tier = self._person_tier(person)
        if not proof.strong:
            raise BridgeError("requesting needs password + passkey, or a YubiKey")
        h = self._hours(hours)
        if timedelta(hours=h) > MAX_TOTAL:
            raise BridgeError("a bridge can last at most 14 days in total")
        lost = lost_report_active(self.reg, person, now)
        if self_issue:
            if tier not in SELF_ISSUE_TIERS:
                raise BridgeError("only owners and admins can self-issue")
            if not proof.yubikey:
                raise BridgeError("self-issue needs a physical YubiKey")
            if lost:
                raise BridgeError("lost-device report active: someone else must approve")
        with self.store.locked() as items:
            if any(b.person == person and b.is_open for b in items.values()):
                raise BridgeError(f"{person} already has an active or pending bridge")
            n = 1 + sum(1 for b in items.values() if b.person == person)
            b = Bridge(id=device_id(person, n), person=person, person_tier=tier,
                       tier=capped_tier(tier), reason=reason.strip() or "unspecified",
                       requested_at=iso(now), requested_hours=h, lost_report=lost)
            if self_issue:
                b.self_issued = True
                self._activate(b, person, now)
                self.store.record(person, b, "self-issue", f"active:until:{b.expires_at}")
            else:
                if self.approvals is not None:
                    b.approval_id = self.approvals.submit(
                        b, h, required_approver_rank(tier), "request", now)
                self.store.record(person, b, "request", f"pending:{h}h")
            items[b.id] = b
        return b

    def _activate(self, b: Bridge, by: str, now: datetime) -> None:
        b.status, b.approved_by, b.issued_at = "active", by, iso(now)
        b.expires_at = iso(now + timedelta(hours=b.requested_hours))

    def approve(self, bid: str, approver: str, *, passkey: bool) -> Bridge:
        now = self.clock()
        with self.store.locked() as items:
            b = self._get(items, bid)
            if b.status != "pending":
                raise BridgeError(f"{bid} is {b.status}, not pending")
            try:
                self._check_approver(b, approver, passkey)
            except BridgeError as e:
                self.store.record(approver, b, "approve", f"deny:{e}")
                raise
            self._activate(b, approver, now)
            self.store.record(approver, b, "approve", f"active:until:{b.expires_at}")
        if self.approvals is not None:
            self.approvals.resolve(b.approval_id, "approved", approver)
        return b

    def deny(self, bid: str, approver: str) -> Bridge:
        with self.store.locked() as items:
            b = self._get(items, bid)
            if b.status == "pending":
                self._end(b, "denied", approver, "denied")
            elif b.pending_extension:
                b.pending_extension = None
                self.store.record(approver, b, "extend-deny")
                return b
            else:
                raise BridgeError(f"{bid} has nothing pending")
            self.store.record(approver, b, "deny")
        if self.approvals is not None:
            self.approvals.resolve(b.approval_id, "denied", approver)
        return b

    def extend(self, bid: str, requester: str, proof: AuthProof, hours: int | None = None
               ) -> Bridge:
        """Ask for more time. Needs approval again (same rules as the first request)."""
        now = self.clock()
        h = self._hours(hours, DEFAULT_LIFETIME)
        with self.store.locked() as items:
            b = self._get(items, bid)
            if requester != b.person:
                raise BridgeError("only the bridge's person can ask to extend it")
            if not proof.strong:
                raise BridgeError("extending needs password + passkey, or a YubiKey")
            if b.status != "active":
                raise BridgeError(f"{bid} is {b.status}; only an active bridge can be extended")
            if b.pending_extension:
                raise BridgeError(f"{bid} already has an extension waiting for approval")
            new_end = parse_ts(b.expires_at) + timedelta(hours=h)
            if new_end - parse_ts(b.issued_at) > MAX_TOTAL:
                raise BridgeError("a bridge can last at most 14 days in total; enroll a "
                                  "permanent device instead")
            b.pending_extension = {"hours": h, "requested_at": iso(now), "approval_id": None}
            if self.approvals is not None:
                b.pending_extension["approval_id"] = self.approvals.submit(
                    b, h, required_approver_rank(b.person_tier), "extension", now)
            self.store.record(requester, b, "extend-request", f"pending:{h}h")
        return b

    def approve_extension(self, bid: str, approver: str, *, passkey: bool) -> Bridge:
        now = self.clock()
        with self.store.locked() as items:
            b = self._get(items, bid)
            ext = b.pending_extension
            if b.status != "active" or not ext:
                raise BridgeError(f"{bid} has no extension waiting")
            try:
                self._check_approver(b, approver, passkey)
            except BridgeError as e:
                self.store.record(approver, b, "extend-approve", f"deny:{e}")
                raise
            new_end = parse_ts(b.expires_at) + timedelta(hours=int(ext["hours"]))
            if new_end - parse_ts(b.issued_at) > MAX_TOTAL:   # re-check at decision time
                raise BridgeError("extension would pass the 14-day total")
            b.expires_at = iso(new_end)
            b.extensions.append({"hours": ext["hours"], "approved_by": approver,
                                 "approved_at": iso(now)})
            b.pending_extension = None
            self.store.record(approver, b, "extend-approve", f"active:until:{b.expires_at}")
        if self.approvals is not None:
            self.approvals.resolve(ext.get("approval_id"), "approved", approver)
        return b

    def _end(self, b: Bridge, status: str, by: str, reason: str) -> None:
        b.status, b.ended_at, b.ended_by, b.end_reason = status, iso(self.clock()), by, reason
        b.pending_extension = None

    def revoke(self, bid: str, by: str, reason: str = "revoked", *, system: bool = False
               ) -> Bridge:
        """The person or an owner may revoke at any time. `system` is for offboarding/promote."""
        with self.store.locked() as items:
            b = self._get(items, bid)
            if not system and by != b.person and self._tier_of(by) != "owner":
                self.store.record(by, b, "revoke", "deny:not person or owner")
                raise BridgeError("only the person or an owner can revoke a bridge")
            if not b.is_open:
                raise BridgeError(f"{bid} is already {b.status}")
            was_pending = b.status == "pending"
            self._end(b, "revoked", by, reason)
            self.store.record(by, b, "revoke", reason)
        if was_pending and self.approvals is not None:
            self.approvals.resolve(b.approval_id, "cancelled", by)
        return b

    def revoke_all(self, person: str, by: str, reason: str = "offboard") -> list[Bridge]:
        out = []
        for b in self.list(person=person):
            if b.is_open:
                out.append(self.revoke(b.id, by, reason, system=True))
        return out

    def promote(self, person: str, device: str, by: str) -> Bridge | None:
        """A permanent device was enrolled: end the person's bridge. Returns it (or None)."""
        if is_temp_device(device):
            raise BridgeError("a temporary device cannot be promoted to permanent")
        d = self.reg.devices.get(device)
        if d is None or d.owner != person:
            raise BridgeError(f"{device} is not a registered device of {person}")
        if d.cert is None or d.cert.status != "active":
            raise BridgeError(f"{device} has no active cert yet; record it with "
                              "`cvc-access device set-cert` first")
        open_ = [b for b in self.list(person=person) if b.is_open]
        if not open_:
            return None
        b = self.revoke(open_[0].id, by, f"promoted:{device}", system=True)
        with self.store.locked() as items:
            items[b.id].promoted_to = device
            b = items[b.id]
        return b

    def sweep(self) -> list[Bridge]:
        """Expire active bridges past their end, and pending asks past 24 h (deny)."""
        now = self.clock()
        changed: list[Bridge] = []
        with self.store.locked() as items:
            for b in items.values():
                if b.status == "active" and parse_ts(b.expires_at) <= now:
                    self._end(b, "expired", "system", "expired")
                    self.store.record("system", b, "expire")
                    changed.append(b)
                elif b.status == "pending" and \
                        now - parse_ts(b.requested_at) >= APPROVAL_WINDOW:
                    self._end(b, "denied", "system", "approval timed out")
                    self.store.record("system", b, "timeout")
                    changed.append(b)
                elif b.pending_extension and now - parse_ts(
                        b.pending_extension["requested_at"]) >= APPROVAL_WINDOW:
                    b.pending_extension = None
                    self.store.record("system", b, "extend-timeout")
                    changed.append(b)
        return changed

    def sync_approvals(self, passkey_verified: bool = True) -> list[Bridge]:
        """Apply decisions made on the dashboard card. Our own rules are re-checked (the
        card alone does not know about self-approval or the grant rule)."""
        if self.approvals is None:
            return []
        out = []
        for b in self.list():
            pend = b.approval_id if b.status == "pending" else (
                (b.pending_extension or {}).get("approval_id"))
            dec = self.approvals.decision(pend)
            if not dec or dec[0] == "pending" or not dec[1]:
                continue
            status, by = dec
            try:
                if status == "approved" and b.status == "pending":
                    out.append(self.approve(b.id, by, passkey=passkey_verified))
                elif status == "approved":
                    out.append(self.approve_extension(b.id, by, passkey=passkey_verified))
                elif status in ("denied", "expired", "cancelled"):
                    out.append(self.deny(b.id, by))
            except BridgeError:
                out.append(self.deny(b.id, "system"))
        return out

    def list(self, person: str | None = None, open_only: bool = False) -> list[Bridge]:
        items = self.store.load()
        return sorted((b for b in items.values()
                       if (person is None or b.person == person)
                       and (not open_only or b.is_open)), key=lambda b: b.requested_at)

    def active_for(self, person: str) -> Bridge | None:
        return next((b for b in self.list(person=person) if b.status == "active"), None)


__all__ = ["RANK", "ApprovalsLink", "AuthProof", "BridgeError", "BridgeService", "BridgeStore",
           "lost_report_active", "state_dir"]
