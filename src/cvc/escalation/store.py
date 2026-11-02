"""D27 escalation store: requests, abuse limits, single-use grants, hash-chained history.

State is a JSON file (0600, atomic replace) guarded by an fcntl lock file plus a thread lock,
so the broker and the owner CLI can share it and `consume()` is atomic across processes.
History is an append-only JSONL file; each row is hash-chained to the previous one
(same scheme as takeover/delegate history) and carries dual attribution (agent and
on_behalf_of).

Approval delivery reuses `ApprovalService` (cvc.approval.v1, MQTT, ETag + nonce, passkey).
The store mirrors the approval's outcome lazily (`sync`) on every operation.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import uuid
from collections.abc import Callable, Iterable
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path

from cvc.approvals import model as amodel
from cvc.approvals.service import ApprovalService

from .policy import Assessment, describe_cell

GENESIS = "0" * 64
MAX_PENDING = 3
MAX_PER_DAY = 10
DENY_COOLDOWN = timedelta(hours=1)
REPEAT_WINDOW = timedelta(days=7)
REPEAT_THRESHOLD = 3
PENDING, APPROVED = "pending", "approved"
TERMINAL = frozenset({"denied", "expired", "cancelled", "consumed", "revoked",
                      "grant_expired", "void"})


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


class EscalationError(Exception):
    def __init__(self, status: int, code: str, reason: str):
        super().__init__(reason)
        self.status, self.code, self.reason = status, code, reason


@dataclass
class Escalation:
    id: str
    agent: str
    agent_tier: str
    current_tier: str
    required_tier: str
    cell: str
    action: str
    data: str
    resource: str
    purpose: str
    justification: str
    on_behalf_of: str | None
    physical: bool
    approver_min_tier: str
    ttl_s: int
    approval_id: str
    token_sha256: str
    nonce_sha256: str
    created_at: str
    status: str = PENDING
    decided_by: str | None = None
    decided_at: str | None = None
    grant_expires_at: str | None = None
    uses_left: int = 0
    consumed_at: str | None = None
    revoked_by: str | None = None

    def public(self) -> dict:
        d = asdict(self)
        d.pop("token_sha256")
        d.pop("nonce_sha256")
        return d

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.agent, self.action, self.data, self.resource)


class EscalationStore:
    def __init__(self, state_path: str, approvals: ApprovalService,
                 clock: Callable[[], datetime] = amodel.now_utc,
                 max_pending: int = MAX_PENDING, max_per_day: int = MAX_PER_DAY):
        self.state_path = Path(state_path)
        self.history_path = self.state_path.with_suffix(".history.jsonl")
        self.lock_path = self.state_path.with_suffix(".lock")
        self.approvals = approvals
        self.clock = clock
        self.max_pending, self.max_per_day = max_pending, max_per_day
        self._tlock = threading.RLock()
        self._items: dict[str, Escalation] = {}
        self.non_human: set[str] = set()      # agent ids: never valid approvers

    # -- persistence ---------------------------------------------------------------
    @contextmanager
    def _locked(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        with self._tlock, open(self.lock_path, "a") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            try:
                self._load()
                yield
            finally:
                fcntl.flock(lk, fcntl.LOCK_UN)

    def _load(self) -> None:
        if self.state_path.exists():
            raw = json.loads(self.state_path.read_text(encoding="utf-8") or "{}")
            self._items = {k: Escalation(**v) for k, v in raw.get("escalations", {}).items()}
        else:
            self._items = {}

    def _save(self) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.state_path.parent, prefix=".escalations.")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"escalations": {k: asdict(v) for k, v in self._items.items()}}, fh,
                      indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.state_path)

    def _history(self, event: str, esc: Escalation | None, actor: str, **extra) -> None:
        prev = GENESIS
        rows = self.history()
        if rows:
            prev = rows[-1]["hash"]
        body = {"at": amodel.iso(self.clock()), "event": event, "actor": actor,
                "escalation": esc.id if esc else None, "agent": esc.agent if esc else None,
                "on_behalf_of": esc.on_behalf_of if esc else None, "prev": prev, **extra}
        body["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        with open(self.history_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def history(self, esc_id: str | None = None) -> list[dict]:
        if not self.history_path.exists():
            return []
        rows = [json.loads(x) for x in self.history_path.read_text(encoding="utf-8")
                .splitlines() if x.strip()]
        return [r for r in rows if esc_id is None or r.get("escalation") == esc_id]

    def verify_history(self) -> bool:
        prev = GENESIS
        for row in self.history():
            body = {k: v for k, v in row.items() if k != "hash"}
            digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
            if row.get("prev") != prev or digest != row.get("hash"):
                return False
            prev = row["hash"]
        return True

    # -- sync with the approvals pipeline -----------------------------------------
    def _sync(self) -> bool:
        now = self.clock()
        changed = False
        for esc in self._items.values():
            if esc.status == PENDING:
                ar = self.approvals.get(esc.approval_id)
                if ar is None or ar.status == "pending":
                    continue
                esc.decided_by, esc.decided_at = ar.decided_by, ar.decided_at or amodel.iso(now)
                if ar.status == "approved" and (ar.decided_by in self.non_human
                                                or not ar.decided_by):
                    esc.status = "void"
                    self._history("void_non_human_approver", esc, ar.decided_by or "?")
                elif ar.status == "approved":
                    esc.status, esc.uses_left = APPROVED, 1
                    esc.grant_expires_at = amodel.iso(amodel.parse_ts(esc.decided_at)
                                                      + timedelta(seconds=esc.ttl_s))
                    self._history("approved", esc, ar.decided_by,
                                  grant_expires_at=esc.grant_expires_at)
                else:
                    esc.status = ar.status if ar.status in TERMINAL else "denied"
                    self._history(esc.status, esc, ar.decided_by or "system")
                changed = True
            if esc.status == APPROVED and amodel.parse_ts(esc.grant_expires_at) <= now:
                esc.status, esc.uses_left = "grant_expired", 0
                self._history("grant_expired", esc, "system")
                changed = True
        return changed

    def sync(self) -> None:
        with self._locked():
            if self._sync():
                self._save()

    # -- operations ----------------------------------------------------------------
    def _check_limits(self, a: Assessment) -> None:
        now = self.clock()
        mine = [e for e in self._items.values() if e.agent == a.agent]
        key = (a.agent, a.action, a.data, a.resource)
        if any(e.status == PENDING and e.key == key for e in mine):
            raise EscalationError(409, "duplicate", "an identical escalation is already pending")
        if sum(e.status == PENDING for e in mine) >= self.max_pending:
            raise EscalationError(429, "too_many_pending",
                                  f"at most {self.max_pending} pending escalations per agent")
        day = [e for e in mine if now - amodel.parse_ts(e.created_at) < timedelta(days=1)]
        if len(day) >= self.max_per_day:
            raise EscalationError(429, "daily_limit",
                                  f"at most {self.max_per_day} escalations per agent per day")
        for e in mine:
            if e.key == key and e.status == "denied" and e.decided_at and \
                    now - amodel.parse_ts(e.decided_at) < DENY_COOLDOWN:
                raise EscalationError(429, "denied_cooldown",
                                      "this exact request was denied less than 1 h ago")

    def _repeat_suggestion(self, a: Assessment) -> str | None:
        now = self.clock()
        n = 1 + sum(1 for e in self._items.values()
                if e.agent == a.agent and e.action == a.action and e.data == a.data
                and now - amodel.parse_ts(e.created_at) < REPEAT_WINDOW)
        if n >= REPEAT_THRESHOLD:
            return (f"{a.agent} escalated {a.data}/{a.action} {n} times in 7 days; "
                    f"consider changing its tier or role grants properly in the registry")
        return None

    def request(self, a: Assessment, token: str, *, urgency: str = "normal",
                details_url: str | None = None) -> tuple[Escalation, str, str | None]:
        """Create a pending escalation + approval card. Returns (record, nonce, suggestion).

        The nonce is shown to the agent once; only its hash is stored."""
        if a.already_permitted:
            raise EscalationError(409, "already_permitted",
                                  "the agent's tier already allows this action")
        now = self.clock()
        with self._locked():
            if self._sync():
                self._save()
            self._check_limits(a)
            esc_id = str(uuid.uuid4())
            nonce = secrets.token_urlsafe(24)
            requested = a.required_tier
            ar = amodel.new_request(
                agent=a.agent, agent_tier=a.agent_tier, on_behalf_of=a.on_behalf_of,
                intent=f"escalation: {a.action} {a.data} {a.resource}"[:200],
                summary=(f"{a.agent} (tier {a.current_tier}, cell "
                         f"{describe_cell(a.cell)}) asks to {a.action} {a.data} data on "
                         f"{a.resource} once. Purpose: {a.purpose}. "
                         f"Justification: {a.justification}")[:512],
                if_approved=(f"one use of {a.action} on {a.resource}, valid "
                             f"{a.ttl_s // 60} min, bound to this agent's token; "
                             f"a second use is denied")[:512],
                if_denied="nothing happens; the same request is blocked for 1 h",
                data=a.data, action=a.action, urgency=urgency, physical=a.physical,
                details_url=details_url, now=now)
            # The grant rule sets the approver. D18's risk floor (red -> owner, which every
            # denied cell would hit) is kept only for physical actuation.
            order = amodel.PERSON_RANK
            if not a.physical or order[a.approver_min_tier] > order[ar.approver_min_tier]:
                ar.approver_min_tier = a.approver_min_tier
            ar.kind = "escalation"
            ar.escalation = {"current_tier": a.current_tier, "requested_tier": requested,
                             "resource": a.resource, "uses": 1, "ttl_s": a.ttl_s,
                             "physical": a.physical, "owner_only": a.owner_only}
            errs = amodel.validate(ar.to_dict())
            if errs:
                raise EscalationError(422, "invalid", "; ".join(errs))
            esc = Escalation(
                id=esc_id, agent=a.agent, agent_tier=a.agent_tier,
                current_tier=a.current_tier, required_tier=requested, cell=a.cell,
                action=a.action, data=a.data, resource=a.resource, purpose=a.purpose,
                justification=a.justification, on_behalf_of=a.on_behalf_of,
                physical=a.physical, approver_min_tier=ar.approver_min_tier, ttl_s=a.ttl_s,
                approval_id=ar.id, token_sha256=sha256(token), nonce_sha256=sha256(nonce),
                created_at=amodel.iso(now))
            suggestion = self._repeat_suggestion(a)
            self._items[esc_id] = esc
            self._save()
            self._history("requested", esc, a.agent, action=a.action, data=a.data,
                          resource=a.resource, approval_id=ar.id,
                          approver_min_tier=ar.approver_min_tier)
            if suggestion:
                self._history("audit_suggestion", esc, "system", suggestion=suggestion)
        self.approvals.submit(ar)
        return esc, nonce, suggestion

    def get(self, esc_id: str) -> Escalation | None:
        with self._locked():
            if self._sync():
                self._save()
            return self._items.get(esc_id)

    def list(self, agent: str | None = None, status: str | None = None) -> list[Escalation]:
        with self._locked():
            if self._sync():
                self._save()
            rows = sorted(self._items.values(), key=lambda e: e.created_at)
        return [e for e in rows if (agent is None or e.agent == agent)
                and (status is None or e.status == status)]

    def consume(self, esc_id: str | None, *, agent: str, token: str, resource: str,
                nonce: str | None, action: str | None = None) -> Escalation:
        """Atomically use a grant once. Raises EscalationError(403) on any mismatch."""
        if not esc_id or not nonce:
            raise EscalationError(403, "missing", "escalation id and nonce required")
        with self._locked():
            synced = self._sync()
            esc = self._items.get(esc_id)

            def deny(code: str, reason: str):
                if synced:
                    self._save()
                if esc is not None:
                    self._history("use_denied", esc, agent, code=code)
                raise EscalationError(403, code, reason)

            if esc is None or esc.agent != agent:
                deny("unknown", "no such escalation for this agent")
            if esc.status == "consumed":
                deny("used", "escalation grant already used")
            if esc.status != APPROVED or esc.uses_left < 1:
                deny("not_approved", f"escalation is {esc.status}")
            if not hmac.compare_digest(esc.token_sha256, sha256(token)):
                deny("token", "grant is bound to a different agent token")
            if not hmac.compare_digest(esc.nonce_sha256, sha256(nonce)):
                deny("nonce", "nonce does not match")
            if esc.resource != resource.lower() and esc.resource != resource:
                deny("resource", "grant covers a different resource")
            if action is not None and action != esc.action:
                deny("action", "grant covers a different action")
            esc.uses_left -= 1
            esc.status, esc.consumed_at = "consumed", amodel.iso(self.clock())
            self._save()
            self._history("consumed", esc, agent, resource=esc.resource)
            return esc

    def revoke(self, esc_id: str, by: str) -> Escalation:
        """Owner revokes an unused grant (or withdraws a pending request)."""
        with self._locked():
            self._sync()
            esc = self._items.get(esc_id)
            if esc is None:
                raise EscalationError(404, "unknown", "no such escalation")
            if esc.status not in (PENDING, APPROVED):
                raise EscalationError(409, "terminal", f"escalation already {esc.status}")
            was = esc.status
            esc.status, esc.uses_left, esc.revoked_by = "revoked", 0, by
            self._save()
            self._history("revoked", esc, by, was=was)
        if was == PENDING:
            self.approvals.cancel(esc.approval_id, by)
        return esc

    def suggestions(self) -> list[dict]:
        return [r for r in self.history() if r["event"] == "audit_suggestion"]

    def mark_non_human(self, ids: Iterable[str]) -> None:
        self.non_human = set(ids)
