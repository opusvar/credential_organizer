"""cvc.notify: redaction, priority, quiet hours, escalation, failover, token hygiene."""
from __future__ import annotations

import logging
from datetime import UTC, datetime, time, timedelta

import pytest

from cvc.approvals.model import new_request
from cvc.approvals.service import ApprovalService
from cvc.audit import publish as audit_publish
from cvc.notify import hooks
from cvc.notify.config import Backend, NotifyConfig, parse_quiet
from cvc.notify.message import GENERIC_TEXT, approval_message, audit_message
from cvc.notify.notifier import Notifier, in_quiet
from cvc.notify.ntfy import NtfySender

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)          # noon UTC (tz pinned to UTC)
TOKEN_D, TOKEN_C = "tk_primary_FAKE_0123456789", "tk_fallback_FAKE_9876543210"
PEOPLE = {
    "alex": {"tier": "owner", "notify": {"ntfy_topic": "cvc-alex-k3j9"}},
    "sam": {"tier": "admin"},
    "kim": {"tier": "high", "notify": {"ntfy_topic": "cvc-kim-p2x8"}},
    "old": {"tier": "admin", "status": "removed", "notify": {"ntfy_topic": "cvc-old"}},
}


class FakeHTTP:
    def __init__(self, statuses: dict[str, list[int]] | None = None):
        self.calls: list[tuple[str, bytes, dict]] = []
        self.statuses = statuses or {}

    def __call__(self, url, body, headers, timeout):
        self.calls.append((url, body, dict(headers)))
        for prefix, seq in self.statuses.items():
            if url.startswith(prefix):
                s = seq.pop(0) if len(seq) > 1 else seq[0]
                if s == -1:
                    raise OSError("connection refused")
                return s
        return 200


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("CVC_NTFY_TOKEN_1", TOKEN_D)
    monkeypatch.setenv("CVC_NTFY_TOKEN_2", TOKEN_C)
    yield
    hooks.set_notifier(hooks._UNSET)


BACKENDS = [Backend("https://ntfy.example.com", "CVC_NTFY_TOKEN_1"),
            Backend("https://ntfy.sh", "CVC_NTFY_TOKEN_2")]


def make(http=None, quiet=None, clock=lambda: T0, **kw):
    cfg = NotifyConfig(backends=BACKENDS, dashboard_url="https://dash.example.com",
                       topics={"sam": "cvc-sam-env1"}, people=PEOPLE, quiet=quiet, tz="UTC",
                       state_path=None, **kw)
    http = http or FakeHTTP()
    sender = NtfySender(BACKENDS, post=http, attempts=2, sleep=lambda s: None)
    return Notifier(cfg, sender=sender, clock=clock), http


def req(intent="Post weekly summary to family chat", urgency="normal", minutes=20,
        summary="details", **kw):
    kw.setdefault("agent", "agent-research")
    kw.setdefault("agent_tier", "medium")
    return new_request(intent=intent, summary=summary, if_approved="posts",
                       if_denied="skips", urgency=urgency, deadline_s=minutes * 60, now=T0,
                       data="internal", action="relay", **kw)


# -- message rule -------------------------------------------------------------------------
def test_message_contains_only_allowed_fields():
    r = req(summary="uses the bank login alex@example.com from 10.0.0.5")
    m = approval_message(r, T0, "https://dash.example.com/agents/approvals/" + r.id)
    assert m.body == "agent-research: Post weekly summary to family chat (20 min left)"
    assert m.click.endswith(r.id)
    for leak in ("bank", "example.com from", "10.0.0.5", "details"):
        assert leak not in m.body + m.title


def test_intent_truncated_to_80():
    m = approval_message(req(intent="Tidy " + "notes " * 40), T0, "https://d/x")
    intent = m.body.split(": ", 1)[1].rsplit(" (", 1)[0]
    assert len(intent) <= 80 and intent.endswith("…")


@pytest.mark.parametrize("intent", [
    "Use password for bank", "Connect to 100.64.0.7", "Mail alex@example.com",
    "Open https://example.com/x", "Rotate api_key now", "Pay account 12345678",
    "Log into vault.example.net", "-----BEGIN PRIVATE KEY",
])
def test_sensitive_intent_drops_to_generic(intent):
    r = req()
    r.intent = intent                         # bypass submit validation: defence in depth
    m = approval_message(r, T0, "https://d/x")
    assert m.body == f"{GENERIC_TEXT} (20 min left)"
    assert intent not in m.body


def test_audit_message_counts_only():
    assert audit_message({"error": 1}, "https://d").body == "1 new error finding"
    assert audit_message({"warn": 2, "error": 3}, "https://d").body == \
        "3 new error findings, 2 new warn findings"
    assert audit_message({"info": 4}, "https://d") is None


# -- priority -----------------------------------------------------------------------------
def test_priority_mapping():
    assert approval_message(req(urgency="urgent"), T0, "u").priority == 5
    assert approval_message(req(urgency="normal"), T0, "u").priority == 3
    assert approval_message(req(urgency="low"), T0, "u") is None


def test_low_urgency_not_pushed_but_in_digest():
    n, http = make()
    n.state["last_digest"] = T0.date().isoformat()
    n.on_submitted(req(urgency="low"))
    assert http.calls == []
    n.state["last_digest"] = None
    n.tick([req(urgency="low")], now=T0)
    assert len(http.calls) == 1 and b"1 pending approval (1 low)" in http.calls[0][1]
    assert http.calls[0][2]["Priority"] == "2"


# -- routing / quiet hours ---------------------------------------------------------------
def test_routing_order_and_inactive_excluded():
    n, _ = make()
    r = req()                                 # green -> min tier high
    assert n.approvers(r) == ["sam", "kim", "alex"]
    a = req(agent_tier="assistant", on_behalf_of="kim")
    assert n.approvers(a) == ["kim", "alex"]


def test_quiet_hours_window():
    q = parse_quiet("22:00-07:00")
    assert in_quiet(time(23, 30), q) and in_quiet(time(6, 59), q)
    assert not in_quiet(time(7, 0), q) and not in_quiet(time(12, 0), q)
    assert parse_quiet("") is None


def test_quiet_hours_defer_normal_but_not_urgent():
    night = datetime(2026, 11, 1, 23, 0, tzinfo=UTC)
    n, http = make(quiet=parse_quiet("22:00-07:00"), clock=lambda: night)
    n.state["last_digest"] = night.date().isoformat()
    normal = new_request(agent="agent-research", agent_tier="medium", intent="Sort photos",
                         summary="s", if_approved="a", if_denied="d", deadline_s=12 * 3600,
                         now=night)
    n.on_submitted(normal)
    assert http.calls == [] and len(n.state["deferred"]) == 1
    urgent = req(urgency="urgent")
    n.on_submitted(urgent)
    assert len(http.calls) == 1 and http.calls[0][2]["Priority"] == "5"
    morning = datetime(2026, 11, 2, 7, 5, tzinfo=UTC)
    n.state["last_digest"] = morning.date().isoformat()
    n.state["escalated"].append(normal.id)
    n.tick([normal], now=morning)
    assert len(http.calls) == 2 and b"Sort photos" in http.calls[1][1]
    assert n.state["deferred"] == []


# -- escalation ---------------------------------------------------------------------------
def test_escalation_at_half_deadline():
    clock = {"now": T0}
    n, http = make(clock=lambda: clock["now"])
    n.state["last_digest"] = T0.date().isoformat()
    r = req(minutes=20)
    n.on_submitted(r)
    assert [c[0] for c in http.calls] == ["https://ntfy.example.com/cvc-sam-env1"]
    n.tick([r], now=T0 + timedelta(minutes=9, seconds=59))
    assert len(http.calls) == 1
    n.tick([r], now=T0 + timedelta(minutes=10))
    assert http.calls[1][0] == "https://ntfy.example.com/cvc-kim-p2x8"
    assert http.calls[1][2]["Title"].startswith("Escalated")
    n.tick([r], now=T0 + timedelta(minutes=15))
    assert len(http.calls) == 2                       # escalates once


def test_escalation_owner_fallback_and_decided_skipped():
    n, http = make()
    n.state["last_digest"] = T0.date().isoformat()
    a = req(agent_tier="assistant", on_behalf_of="kim")
    n.on_submitted(a)
    n.tick([a], now=T0 + timedelta(minutes=11))
    assert http.calls[-1][0].endswith("/cvc-alex-k3j9")
    b = req()
    n.on_submitted(b)
    b.status = "approved"
    before = len(http.calls)
    n.tick([b], now=T0 + timedelta(minutes=11))
    assert len(http.calls) == before


# -- failover / retries / token hygiene ---------------------------------------------------
def test_failover_d_to_c_with_retries():
    http = FakeHTTP({"https://ntfy.example.com": [503, -1]})
    n, _ = make(http=http)
    n.on_submitted(req(urgency="urgent"))
    urls = [c[0] for c in http.calls]
    assert urls == ["https://ntfy.example.com/cvc-sam-env1"] * 2 + ["https://ntfy.sh/cvc-sam-env1"]
    assert http.calls[0][2]["Authorization"] == f"Bearer {TOKEN_D}"
    assert http.calls[2][2]["Authorization"] == f"Bearer {TOKEN_C}"
    assert n.sender.sent == 1


def test_failover_c_to_d_when_c_is_primary():
    http = FakeHTTP({"https://ntfy.sh": [401]})
    sender = NtfySender(list(reversed(BACKENDS)), post=http, sleep=lambda s: None)
    from cvc.notify.message import Message
    assert sender.send("t", Message("x", "y", 3))
    assert [c[0] for c in http.calls] == ["https://ntfy.sh/t", "https://ntfy.example.com/t"]


def test_all_backends_down_never_raises_and_logs_no_secrets(caplog):
    caplog.set_level(logging.DEBUG)
    http = FakeHTTP({"https://": [-1]})
    n, _ = make(http=http)
    r = req(intent="Archive old receipts")
    n.on_submitted(r)
    n.tick([r], now=T0 + timedelta(minutes=11))
    assert n.sender.failed >= 1
    text = caplog.text
    for s in (TOKEN_D, TOKEN_C, "cvc-sam-env1", "Archive old receipts", "alex", "kim"):
        assert s not in text
    assert "sent=0" in text


def test_hook_failure_never_changes_approval(tmp_path):
    class Boom:
        def on_submitted(self, r):
            raise RuntimeError("boom")
    hooks.set_notifier(Boom())
    svc = ApprovalService(state_path=str(tmp_path / "s.json"), clock=lambda: T0)
    r = svc.submit(req())
    assert svc.get(r.id).status == "pending"
    out = svc.decide(r.id, "approve", person="alex", tier="owner")
    assert out.status == "approved"


def test_service_hook_sends(tmp_path):
    n, http = make()
    hooks.set_notifier(n)
    ApprovalService(clock=lambda: T0).submit(req(urgency="urgent"))
    assert len(http.calls) == 1


def test_audit_hook_new_counts_to_owners():
    n, http = make()
    hooks.set_notifier(n)
    now = "2026-11-01T12:00:00Z"
    findings = {"a": {"status": "open", "severity": "error", "first_seen": now,
                      "last_seen": now, "title": "x"},
                "b": {"status": "open", "severity": "warn", "first_seen": "2026-10-01",
                      "last_seen": now, "title": "y"}}
    summary = {"open": {"info": 0, "warn": 1, "error": 1}, "open_total": 2}
    audit_publish.build_messages(findings, summary)
    assert len(http.calls) == 1
    url, body, _ = http.calls[0]
    assert url.endswith("/cvc-alex-k3j9") and body == b"1 new error finding"
    assert n.state["audit_open"]["warn"] == 1


def test_config_from_env(monkeypatch):
    env = {"CVC_NTFY_SERVERS": "https://ntfy.example.com, https://ntfy.sh",
           "CVC_NTFY_TOPICS": "sam=cvc-sam-env1", "CVC_NOTIFY_QUIET": "23:00-06:00"}
    cfg = NotifyConfig.from_env(None, PEOPLE, env=env)
    assert [b.url for b in cfg.backends] == ["https://ntfy.example.com", "https://ntfy.sh"]
    assert cfg.topic_for("alex") == "cvc-alex-k3j9" and cfg.topic_for("sam") == "cvc-sam-env1"
    assert cfg.card_url("abc") == "https://dashboard.cvc.example.ts.net/agents/approvals/abc"
    assert TOKEN_D not in repr(cfg)
    assert NotifyConfig.from_env(None, env={}) is None
