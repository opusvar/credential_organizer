"""Agent-tier enforcement: short-lived scoped session tokens + human approval records.

Tiers (read from the ACL `tier:` field; absent/unknown -> `scoped`, the most restrictive
non-high default):

- ``scoped``    — automation agent. Session tokens live at most 15 minutes.
- ``low``       — low-privilege agent. Session tokens live at most 15 minutes.
- ``medium``    — medium-privilege agent. Session tokens live at most 10 minutes.
- ``assistant`` — acts on behalf of a person. Every audit record carries dual attribution
                  (agent id + ``on_behalf_of``). Missing ``on_behalf_of`` -> deny.
                  Ranked at ``medium`` (an assistant is capped at medium privilege).
- ``high``      — powerful agent. Any request against an ACL entry marked
                  ``physical: true`` is denied until a human approves a pending approval
                  record for exactly that agent/credential/purpose. Approvals are single-use.

Only sha256 digests of session tokens are kept; the plaintext is returned to the caller once.
State is in-memory: a broker restart revokes every session token and pending approval
(fail-closed).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field

TIERS = ("scoped", "low", "medium", "high", "assistant")
DEFAULT_TIER = "scoped"

# Privilege ladder: scoped < low < medium < high. `assistant` is capped at medium.
TIER_RANK = {"scoped": 0, "low": 1, "medium": 2, "high": 3, "assistant": 2}

# Session-token TTL by tier, seconds. Every tier is capped at 15 minutes; higher is shorter.
MAX_TTL = 15 * 60
TIER_TTL = {"scoped": MAX_TTL, "low": MAX_TTL, "medium": 10 * 60, "high": 5 * 60,
            "assistant": MAX_TTL}

SESSION_PREFIX = "cvcs_"


def normalize_tier(raw: object) -> str:
    t = str(raw or "").strip().lower()
    return t if t in TIERS else DEFAULT_TIER


def tier_rank(tier: str) -> int:
    """Position on the privilege ladder (unknown -> scoped)."""
    return TIER_RANK[normalize_tier(tier)]


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@dataclass
class SessionToken:
    agent: str
    tier: str
    scope: frozenset[str]          # lowercased credentials this token may touch
    expires: float                 # time.time() epoch


class SessionStore:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._tokens: dict[str, SessionToken] = {}

    def issue(self, agent: str, tier: str, scope: list[str], ttl: int | None = None
              ) -> tuple[str, SessionToken]:
        cap = TIER_TTL[tier]
        ttl = cap if ttl is None else max(1, min(int(ttl), cap))
        token = SESSION_PREFIX + secrets.token_urlsafe(32)
        rec = SessionToken(agent=agent, tier=tier,
                           scope=frozenset(c.lower() for c in scope),
                           expires=self._clock() + ttl)
        with self._lock:
            self._purge()
            self._tokens[_sha256(token)] = rec
        return token, rec

    def resolve(self, agent: str, token: str) -> SessionToken | None:
        digest = _sha256(token)
        with self._lock:
            self._purge()
            for key, rec in self._tokens.items():
                if hmac.compare_digest(key, digest):
                    return rec if rec.agent == agent else None
        return None

    def _purge(self) -> None:
        now = self._clock()
        for k in [k for k, r in self._tokens.items() if r.expires <= now]:
            del self._tokens[k]


@dataclass
class Approval:
    id: str
    agent: str
    credential: str
    purpose: str
    status: str = "pending"        # pending | approved | consumed | denied
    approver: str | None = None
    created: float = field(default_factory=time.time)
    ttl: float = 15 * 60           # = the ApprovalRequest deadline window (D18, <= 24h)


APPROVAL_TTL = 15 * 60


class ApprovalStore:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._items: dict[str, Approval] = {}

    def create(self, agent: str, credential: str, purpose: str, ttl: float | None = None,
               approval_id: str | None = None) -> Approval:
        a = Approval(id=approval_id or str(uuid.uuid4()), agent=agent,
                     credential=credential.lower(), purpose=purpose, created=self._clock(),
                     ttl=APPROVAL_TTL if ttl is None else float(ttl))
        with self._lock:
            self._items[a.id] = a
        return a

    def get(self, approval_id: str) -> Approval | None:
        with self._lock:
            a = self._items.get(approval_id)
            if a and self._clock() - a.created > a.ttl:
                del self._items[approval_id]
                return None
            return a

    def approve(self, approval_id: str, approver: str) -> Approval | None:
        a = self.get(approval_id)
        with self._lock:
            if a is None or a.status != "pending":
                return None
            a.status = "approved"
            a.approver = approver
            return a

    def deny(self, approval_id: str, approver: str | None = None) -> Approval | None:
        """Denied / expired / cancelled: the record can never be consumed."""
        a = self.get(approval_id)
        with self._lock:
            if a is None or a.status != "pending":
                return None
            a.status = "denied"
            a.approver = approver
            return a

    def consume(self, approval_id: str | None, agent: str, credential: str, purpose: str) -> bool:
        """Single-use: True only for an approved record matching agent/credential/purpose."""
        if not approval_id:
            return False
        a = self.get(approval_id)
        with self._lock:
            if (a is None or a.status != "approved" or a.agent != agent
                    or a.credential != credential.lower() or a.purpose != purpose):
                return False
            a.status = "consumed"
            return True
