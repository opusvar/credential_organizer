"""`cvc.approval.v1` — the ApprovalRequest record and its validation.

An approval request is what a human sees on their phone / HA dashboard: who is asking, what
they intend, what happens either way, and how risky it is. It must never carry a secret:
validation rejects secret-looking keys anywhere and secret-looking values in free text.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

SCHEMA = "cvc.approval.v1"
URGENCIES = ("low", "normal", "urgent")
RISKS = ("green", "amber", "red")
STATUSES = ("pending", "approved", "denied", "expired", "cancelled")
TERMINAL = frozenset({"approved", "denied", "expired", "cancelled"})
DATA_LEVELS = ("public", "internal", "private", "secret")
ACTIONS = ("read", "relay", "write", "act", "delegate")
PERSON_TIERS = ("guest-short", "guest-long", "media-only", "low", "medium", "high", "admin",
                "owner")
PERSON_RANK = {t: i for i, t in enumerate(PERSON_TIERS)}
AGENT_TIERS = ("scoped", "low", "medium", "high", "assistant")

DEFAULT_DEADLINE = timedelta(minutes=15)
MAX_DEADLINE = timedelta(hours=24)
# Minimum human tier allowed to decide, by risk.
MIN_TIER_BY_RISK = {"green": "high", "amber": "admin", "red": "owner"}

_MAX_TEXT = 512
_SECRET_KEYS = frozenset({"password", "passwd", "secret", "token", "api_key", "apikey",
                          "private_key", "p12", "pin", "puk", "management_key", "session",
                          "authorization", "bearer", "cookie", "otp", "totp"})
_SECRET_SUFFIXES = ("_password", "_secret", "_token", "_key")
# Values that look like credentials: bearer tokens, cvc session tokens, PEM blocks, JWTs,
# key=value assignments of secret-ish names, long high-entropy blobs.
_SECRET_VALUE = re.compile(
    r"(?i)(bearer\s+\S{8,}|cvcs_\S+|-----BEGIN [A-Z ]*PRIVATE KEY|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.|"
    r"\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+|"
    r"\b[A-Za-z0-9+/_-]{40,}={0,2})")
_UUID = re.compile(r"^[0-9a-f-]{36}$")

try:  # D16 matrix, when the access package is present
    from cvc.access.classify import APPROVAL as _P
    from cvc.access.classify import DENIED as _D
    from cvc.access.classify import ceiling as _ceiling
except ImportError:  # pragma: no cover - access package always ships today
    _ceiling = None


class ValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def now_utc() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


def derive_risk(action: str | None, data: str | None = None, agent_tier: str | None = None
                ) -> str:
    """D16 cell -> traffic light.

    Secret data or an `act` is red. Otherwise by action (write/delegate amber, else green),
    raised to amber when the agent's D16 matrix cell says approval-required (P) and to red
    when the cell denies (D).
    """
    if data == "secret" or action == "act":
        return "red"
    base = "amber" if action in ("write", "delegate") else "green"
    if (_ceiling is not None and data in DATA_LEVELS and action in ACTIONS
            and agent_tier in AGENT_TIERS):
        cell = _ceiling(agent_tier, data, action)
        if cell == _D:
            return "red"
        if cell == _P and base == "green":
            return "amber"
    return base


@dataclass
class Requester:
    agent: str
    tier: str
    sponsor: str | None = None
    on_behalf_of: str | None = None


@dataclass
class ApprovalRequest:
    id: str
    created_at: str
    deadline: str
    urgency: str
    requester: Requester
    intent: str
    summary: str
    labels: dict[str, str | None]
    risk: str
    if_approved: str
    if_denied: str
    approver_min_tier: str
    requires_passkey: bool
    details_url: str | None = None
    status: str = "pending"
    decided_by: str | None = None
    decided_at: str | None = None
    on_timeout: str = "deny"
    schema: str = SCHEMA

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ApprovalRequest:
        errs = validate(d)
        if errs:
            raise ValidationError(errs)
        d = dict(d)
        d["requester"] = Requester(**d["requester"])
        return cls(**d)


def new_request(*, agent: str, agent_tier: str, intent: str, summary: str, if_approved: str,
                if_denied: str, data: str | None = None, action: str | None = None,
                urgency: str = "normal", deadline_s: int | None = None,
                sponsor: str | None = None, on_behalf_of: str | None = None,
                details_url: str | None = None, physical: bool = False,
                now: datetime | None = None, id: str | None = None) -> ApprovalRequest:
    """Build and validate a pending request. Deadline defaults to 15 min, capped at 24 h."""
    now = now or now_utc()
    window = DEFAULT_DEADLINE if deadline_s is None else timedelta(seconds=int(deadline_s))
    if window <= timedelta(0):
        raise ValidationError(["deadline must be in the future"])
    window = min(window, MAX_DEADLINE)
    if physical and action is None:
        action = "act"
    risk = "red" if physical else derive_risk(action, data, agent_tier)
    req = ApprovalRequest(
        id=id or str(uuid.uuid4()), created_at=iso(now), deadline=iso(now + window),
        urgency=urgency, requester=Requester(agent, agent_tier, sponsor, on_behalf_of),
        intent=intent, summary=summary, labels={"data": data, "action": action}, risk=risk,
        if_approved=if_approved, if_denied=if_denied,
        approver_min_tier=MIN_TIER_BY_RISK[risk],
        requires_passkey=bool(physical or action == "act"), details_url=details_url)
    errs = validate(req.to_dict())
    if errs:
        raise ValidationError(errs)
    return req


def scan_secrets(node: Any, path: str = "") -> list[str]:
    """Secret-looking keys anywhere, or secret-looking string values (no secrets, ever)."""
    errs: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}" if path else str(k)
            kl = str(k).lower()
            if kl in _SECRET_KEYS or kl.endswith(_SECRET_SUFFIXES):
                errs.append(f"{p}: secret-looking field not allowed in an approval")
            errs += scan_secrets(v, p)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            errs += scan_secrets(v, f"{path}[{i}]")
    elif isinstance(node, str) and not _UUID.match(node) and _SECRET_VALUE.search(node):
        errs.append(f"{path}: value looks like a secret; approvals never carry secrets")
    return errs


_REQUIRED_STR = ("id", "created_at", "deadline", "intent", "summary", "if_approved",
                 "if_denied")
_OPTIONAL = {"details_url", "decided_by", "decided_at"}
_KEYS = {"schema", "id", "created_at", "deadline", "urgency", "requester", "intent", "summary",
         "labels", "risk", "if_approved", "if_denied", "on_timeout", "approver_min_tier",
         "requires_passkey", "status"} | _OPTIONAL


def validate(d: Any) -> list[str]:
    """Return a list of problems (empty = a valid `cvc.approval.v1` record)."""
    if not isinstance(d, dict):
        return ["approval must be an object"]
    errs: list[str] = []
    unknown = set(d) - _KEYS
    if unknown:
        errs.append(f"unknown fields: {sorted(unknown)}")
    missing = (_KEYS - _OPTIONAL) - set(d)
    if missing:
        return errs + [f"missing fields: {sorted(missing)}"] + scan_secrets(d)
    if d["schema"] != SCHEMA:
        errs.append(f"schema must be {SCHEMA!r}")
    for k in _REQUIRED_STR:
        if not isinstance(d[k], str) or not d[k].strip():
            errs.append(f"{k}: required non-empty string")
        elif len(d[k]) > _MAX_TEXT:
            errs.append(f"{k}: longer than {_MAX_TEXT} chars")
    for k, allowed in (("urgency", URGENCIES), ("risk", RISKS), ("status", STATUSES),
                       ("approver_min_tier", PERSON_TIERS)):
        if d[k] not in allowed:
            errs.append(f"{k}: must be one of {list(allowed)}")
    if d["on_timeout"] != "deny":
        errs.append("on_timeout: must be 'deny'")
    if not isinstance(d["requires_passkey"], bool):
        errs.append("requires_passkey: must be a boolean")
    r = d["requester"]
    if (not isinstance(r, dict) or set(r) - {"agent", "tier", "sponsor", "on_behalf_of"}
            or not r.get("agent") or r.get("tier") not in AGENT_TIERS):
        errs.append("requester: needs agent and a valid agent tier "
                    "(fields agent, tier, sponsor, on_behalf_of)")
    elif r["tier"] == "assistant" and not r.get("on_behalf_of"):
        errs.append("requester.on_behalf_of: required for assistant tier")
    lab = d["labels"]
    if not isinstance(lab, dict) or set(lab) != {"data", "action"}:
        errs.append("labels: must be {data, action}")
    else:
        if lab["data"] is not None and lab["data"] not in DATA_LEVELS:
            errs.append(f"labels.data: must be one of {list(DATA_LEVELS)}")
        if lab["action"] is not None and lab["action"] not in ACTIONS:
            errs.append(f"labels.action: must be one of {list(ACTIONS)}")
        if lab["action"] == "act" and d["requires_passkey"] is not True:
            errs.append("requires_passkey: must be true for act")
    try:
        span = parse_ts(d["deadline"]) - parse_ts(d["created_at"])
        if span > MAX_DEADLINE or span <= timedelta(0):
            errs.append("deadline: must be after created_at and at most 24h later")
    except (TypeError, ValueError, AttributeError):
        errs.append("created_at/deadline: must be ISO-8601 timestamps")
    if d["status"] in ("approved", "denied", "cancelled") and not d.get("decided_by"):
        errs.append("decided_by: required once decided")
    return errs + scan_secrets(d)
