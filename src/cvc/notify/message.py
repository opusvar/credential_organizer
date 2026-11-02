"""Build push messages. The message rule is enforced here, not by callers.

An approval push carries ONLY: agent id, short intent (<= 80 chars, truncated), urgency,
minutes left, and a deep link to the dashboard approval card. Never the summary, credential
names, accounts, addresses, IPs or secrets. If the agent id / intent fails the secret scan
(cvc.approvals.model.scan_secrets + cvc.audit.findings.assert_no_secrets) or the extra
sensitive-value scan below, the text drops to GENERIC_TEXT. Audit pushes carry only counts.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime

from cvc.approvals.model import parse_ts, scan_secrets
from cvc.audit.findings import assert_no_secrets

GENERIC_TEXT = "Approval needed (open dashboard)"
MAX_INTENT = 80
PRIORITY = {"urgent": 5, "normal": 3, "low": None}   # low -> no push (daily digest)

_SENSITIVE = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b"                  # IPv4
    r"|[0-9a-f]{0,4}:[0-9a-f]{0,4}:[0-9a-f:]{2,}"    # IPv6-ish
    r"|[\w.+-]+@[\w-]+"                              # emails / user@host
    r"|https?://|www\."                              # URLs
    r"|\b[\w-]+\.(?:com|net|org|io|dev|app|ts\.net|local|lan|home|arpa)\b"  # hostnames
    r"|\b\d{6,}\b"                                   # account / card-like numbers
    r"|passw|passkey|secret|token|api[-_ ]?key|login|account|credential|ssn|iban|pin\b",
    re.IGNORECASE)
_CTRL = re.compile(r"[\x00-\x1f\x7f]+")


@dataclass(frozen=True)
class Message:
    title: str
    body: str
    priority: int
    click: str | None = None
    tags: str = ""


def truncate(s: str, n: int = MAX_INTENT) -> str:
    s = " ".join(_CTRL.sub(" ", s or "").split())
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def is_clean(*values: str) -> bool:
    payload = {"v": list(values)}
    if scan_secrets(payload):
        return False
    try:
        assert_no_secrets(payload)
    except ValueError:
        return False
    return not any(_SENSITIVE.search(v or "") for v in values)


def minutes_left(deadline: str, now: datetime) -> int:
    return max(0, math.ceil((parse_ts(deadline) - now).total_seconds() / 60))


def approval_message(req, now: datetime, card_url: str, *, escalated: bool = False
                     ) -> Message | None:
    """None for low urgency (digest only)."""
    prio = PRIORITY.get(req.urgency, 3)
    if prio is None:
        return None
    agent = truncate(req.requester.agent, 40)
    intent = truncate(req.intent)
    mins = minutes_left(req.deadline, now)
    if is_clean(agent, intent):
        body = f"{agent}: {intent} ({mins} min left)"
    else:
        body = f"{GENERIC_TEXT} ({mins} min left)"
    noun = "Escalation" if getattr(req, "kind", "approval") == "escalation" else "Approval"
    title = ("Escalated: " if escalated else "") + f"{noun} needed [{req.urgency}]"
    return Message(title, body, prio, card_url, "warning" if prio == 5 else "bell")


def audit_message(new_by_severity: dict[str, int], dashboard_url: str) -> Message | None:
    """Counts only, e.g. '1 new error finding'. None if nothing new at warn/error."""
    parts = []
    for sev in ("error", "warn"):
        n = int(new_by_severity.get(sev, 0))
        if n:
            parts.append(f"{n} new {sev} finding{'s' if n != 1 else ''}")
    if not parts:
        return None
    prio = 4 if new_by_severity.get("error") else 3
    return Message("cvc audit", ", ".join(parts), prio, dashboard_url, "shield")


def digest_message(pending: int, low: int, audit_warn: int, audit_error: int,
                   dashboard_url: str) -> Message:
    body = (f"{pending} pending approval{'s' if pending != 1 else ''} ({low} low); "
            f"audit open: {audit_error} error, {audit_warn} warn")
    return Message("cvc daily digest", body, 2, dashboard_url, "calendar")
