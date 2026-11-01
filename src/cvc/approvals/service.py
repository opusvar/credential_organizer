"""ApprovalService: holds requests, enforces decide rules, expires, publishes.

Decide rules (D18):
- Only a pending, unexpired request can change state; repeating the same decision on an
  already-decided request is an idempotent no-op; a conflicting decision is rejected (409).
- The approver needs a known person tier >= `approver_min_tier`.
- `requires_passkey` -> the Authentik (passkey) username must be present and match the person.
- Assistant-tier requests (acting on behalf of a person) are decidable only by that person or
  by an owner; the on_behalf_of person is exempt from `approver_min_tier` (it is their own
  errand) but not from the passkey requirement.
- Timeout is always deny: past-deadline pending requests become `expired`.

State is in memory, optionally mirrored to a JSON file (`state_path`) so the owner CLI and
the broker see the same requests. Resolved requests stay retained (updated) on MQTT for 24h,
then their retained message is cleared; the record itself stays in the state file as
history for `history_days` (default 90, env CVC_APPROVALS_HISTORY_DAYS) and is then dropped.

Every state change bumps `version`; callers may pass `expected_version` (HTTP If-Match)
so a decision is only applied to the exact record the human looked at (else 412).
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from .model import PERSON_RANK, ApprovalRequest, iso, now_utc, parse_ts
from .publisher import SUMMARY_TOPIC, NullPublisher, Publisher, discovery_config, request_topic

RETAIN_RESOLVED = timedelta(hours=24)       # retained MQTT message lifetime after resolve
DEFAULT_HISTORY_DAYS = 90                   # resolved records kept in the state file
DECISIONS = {"approve": "approved", "deny": "denied"}


class DecideError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code, self.detail = status_code, detail


def check_authority(req: ApprovalRequest, person: str | None, tier: str | None,
                    passkey_user: str | None) -> None:
    """Raise DecideError unless `person` (at `tier`) may decide `req`."""
    if not person or tier not in PERSON_RANK:
        raise DecideError(403, "approver identity/tier unknown")
    is_owner = tier == "owner"
    obo = req.requester.on_behalf_of
    if req.requester.tier == "assistant" and not (is_owner or (obo and person == obo)):
        raise DecideError(403, "assistant requests are decided by the on_behalf_of "
                               "person or an owner")
    if not (req.requester.tier == "assistant" and person == obo) and \
            PERSON_RANK[tier] < PERSON_RANK[req.approver_min_tier]:
        raise DecideError(403, f"approver tier below {req.approver_min_tier}")
    if req.requires_passkey and (not passkey_user or passkey_user != person):
        raise DecideError(403, "passkey (Authentik) login required for this approval")


class ApprovalService:
    def __init__(self, publisher: Publisher | None = None, state_path: str | None = None,
                 clock: Callable[[], datetime] = now_utc, discovery_prefix: str = "homeassistant",
                 history_days: int | None = None):
        if history_days is None:
            history_days = int(os.environ.get("CVC_APPROVALS_HISTORY_DAYS",
                                              DEFAULT_HISTORY_DAYS))
        self.history = timedelta(days=history_days)
        self._cleared: set[str] = set()
        self.publisher = publisher or NullPublisher()
        self.state_path = Path(state_path) if state_path else None
        self.clock = clock
        self.discovery_prefix = discovery_prefix
        self._items: dict[str, ApprovalRequest] = {}
        self._lock = threading.RLock()
        self._announced = False
        self.on_resolved: list[Callable[[ApprovalRequest], None]] = []

    # -- persistence ------------------------------------------------------------------
    def _load(self) -> None:
        if self.state_path and self.state_path.exists():
            raw = json.loads(self.state_path.read_text(encoding="utf-8") or "{}")
            items = raw.get("approvals", {}) if "approvals" in raw else raw
            self._items = {k: ApprovalRequest.from_dict(v) for k, v in items.items()}
            self._cleared = set(raw.get("cleared", [])) & set(self._items)

    def _save(self) -> None:
        if not self.state_path:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.state_path.parent, prefix=".approvals.")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"approvals": {k: v.to_dict() for k, v in self._items.items()},
                       "cleared": sorted(self._cleared & set(self._items))}, fh, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.state_path)

    # -- publishing -------------------------------------------------------------------
    def _publish_one(self, req: ApprovalRequest) -> None:
        self.publisher.publish(request_topic(req.id), json.dumps(req.to_dict()), retain=True)

    def _publish_summary(self) -> None:
        if not self._announced:
            self.publisher.publish(*discovery_config(self.discovery_prefix), retain=True)
            self._announced = True
        pending = sorted((r for r in self._items.values() if r.status == "pending"),
                         key=lambda r: r.deadline)
        self.publisher.publish(SUMMARY_TOPIC, json.dumps({
            "pending": len(pending),
            "most_urgent_deadline": pending[0].deadline if pending else None,
            "most_urgent_id": pending[0].id if pending else None,
            "urgent": sum(1 for r in pending if r.urgency == "urgent"),
            "updated_at": iso(self.clock()),
        }), retain=True)

    # -- operations -------------------------------------------------------------------
    def submit(self, req: ApprovalRequest) -> ApprovalRequest:
        with self._lock:
            self._load()
            self._items[req.id] = req
            self._save()
            self._publish_one(req)
            self._publish_summary()
        return req

    def _transition(self, req: ApprovalRequest, status: str, by: str | None) -> None:
        req.status, req.decided_by, req.decided_at = status, by, iso(self.clock())
        req.version += 1
        self._save()
        self._publish_one(req)
        self._publish_summary()

    def get(self, approval_id: str) -> ApprovalRequest | None:
        self.sweep()
        with self._lock:
            return self._items.get(approval_id)

    def list(self, status: str | None = None) -> list[ApprovalRequest]:
        self.sweep()
        with self._lock:
            items = sorted(self._items.values(), key=lambda r: r.deadline)
        return [r for r in items if status is None or r.status == status]

    def decide(self, approval_id: str, decision: str, *, person: str | None,
               tier: str | None, passkey_user: str | None = None,
               expected_version: int | None = None) -> ApprovalRequest:
        if decision not in DECISIONS:
            raise DecideError(422, "decision must be approve or deny")
        target = DECISIONS[decision]
        self.sweep()
        with self._lock:
            self._load()
            req = self._items.get(approval_id)
            if req is None:
                raise DecideError(404, "no such approval")
            check_authority(req, person, tier, passkey_user)
            if req.is_terminal:
                if req.status == target and req.decided_by == person:
                    return req                      # idempotent repeat
                raise DecideError(409, f"approval already {req.status}")
            if expected_version is not None and expected_version != req.version:
                raise DecideError(412, "approval changed since it was fetched (ETag mismatch)")
            self._transition(req, target, person)
        self._notify(req)
        return req

    def record_external(self, approval_id: str, status: str, by: str) -> ApprovalRequest | None:
        """Mirror a decision made via the deprecated X-Approver-Token path (no rule check:
        the shared approver token is itself the authority there)."""
        with self._lock:
            self._load()
            req = self._items.get(approval_id)
            if req is None or req.is_terminal:
                return req
            self._transition(req, status, by)
        return req

    def cancel(self, approval_id: str, by: str) -> ApprovalRequest | None:
        with self._lock:
            self._load()
            req = self._items.get(approval_id)
            if req is None or req.is_terminal:
                return req
            self._transition(req, "cancelled", by)
        self._notify(req)
        return req

    def sweep(self) -> list[ApprovalRequest]:
        """Expire past-deadline pending requests (deny) and clear resolved ones after 24h."""
        now = self.clock()
        expired: list[ApprovalRequest] = []
        with self._lock:
            self._load()
            changed = False
            for req in list(self._items.values()):
                if req.status == "pending" and parse_ts(req.deadline) <= now:
                    req.status, req.decided_at = "expired", iso(now)
                    req.version += 1
                    expired.append(req)
                    self._publish_one(req)
                    changed = True
                elif req.is_terminal and req.decided_at:
                    age = now - parse_ts(req.decided_at)
                    if age >= self.history:
                        del self._items[req.id]
                        self._cleared.discard(req.id)
                        changed = True
                    elif age >= RETAIN_RESOLVED and req.id not in self._cleared:
                        self.publisher.publish(request_topic(req.id), "", retain=True)
                        self._cleared.add(req.id)
                        changed = True
            if changed:
                self._save()
                self._publish_summary()
        for req in expired:
            self._notify(req)
        return expired

    def _notify(self, req: ApprovalRequest) -> None:
        for cb in self.on_resolved:
            cb(req)
