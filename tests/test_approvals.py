"""D18 approvals: schema, secret rejection, risk mapping, publishing, decide rules, expiry."""
import json
from datetime import UTC, datetime, timedelta

import pytest

from cvc.approvals import cli
from cvc.approvals.model import (
    SCHEMA,
    ValidationError,
    derive_risk,
    new_request,
    validate,
)
from cvc.approvals.publisher import SUMMARY_TOPIC, discovery_config, from_env
from cvc.approvals.service import ApprovalService, DecideError, check_authority


class FakePublisher:
    def __init__(self):
        self.msgs: list[tuple[str, str, bool]] = []

    def publish(self, topic, payload, retain):
        self.msgs.append((topic, payload, retain))

    def last(self, topic):
        return next(p for t, p, _ in reversed(self.msgs) if t == topic)


class Clock:
    def __init__(self):
        self.t = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)

    def __call__(self):
        return self.t


def _req(clock=None, **kw):
    base = {"agent": "bot", "agent_tier": "high", "intent": "unlock the garage",
                "summary": "open garage for delivery", "if_approved": "garage opens",
                "if_denied": "stays shut", "now": clock() if clock else None}
    base.update(kw)
    return new_request(**base)


# -- schema -------------------------------------------------------------------------
def test_new_request_valid_and_defaults():
    r = _req(action="read", data="internal")
    d = r.to_dict()
    assert d["schema"] == SCHEMA and validate(d) == []
    assert d["on_timeout"] == "deny" and d["status"] == "pending"
    span = datetime.fromisoformat(d["deadline"]) - \
        datetime.fromisoformat(d["created_at"])
    assert span == timedelta(minutes=15)


def test_deadline_capped_at_24h():
    r = _req(deadline_s=10 * 86400)
    assert validate(r.to_dict()) == []
    with pytest.raises(ValidationError):
        _req(deadline_s=0)


def test_schema_rejects_bad_fields():
    d = _req().to_dict()
    assert validate({**d, "urgency": "asap"})
    assert validate({**d, "on_timeout": "approve"})
    assert validate({**d, "bogus": 1})
    assert validate({k: v for k, v in d.items() if k != "intent"})
    assert validate({**d, "status": "approved"})  # decided_by required
    assert validate({**d, "requester": {"agent": "a", "tier": "assistant"}})  # needs obo


# -- secrets ------------------------------------------------------------------------
@pytest.mark.parametrize("text", ["password=hunter2", "use Bearer abcdefghijklmnop",
                                  "token: cvcs_xyz", "-----BEGIN RSA PRIVATE KEY-----",
                                  "A" * 48])
def test_secret_values_rejected(text):
    with pytest.raises(ValidationError):
        _req(summary=text)


def test_secret_keys_rejected():
    d = _req().to_dict()
    d["requester"] = {**d["requester"], "api_token": "x"}
    assert any("secret" in e for e in validate(d))


# -- risk ---------------------------------------------------------------------------
def test_risk_mapping():
    assert derive_risk("act") == "red"
    assert derive_risk("read", "secret") == "red"
    assert derive_risk("write") == "amber"
    assert derive_risk("read") == "green"
    assert derive_risk(None) == "green"
    # D16 cell: medium writing private data needs approval -> amber; low writing -> denied -> red
    assert derive_risk("read", "private", "low") == "red"
    r = _req(action="act")
    assert r.risk == "red" and r.requires_passkey and r.approver_min_tier == "owner"
    assert _req(physical=True).labels["action"] == "act"


# -- publishing ---------------------------------------------------------------------
def test_publish_topics_and_retain():
    pub = FakePublisher()
    svc = ApprovalService(publisher=pub)
    r = svc.submit(_req())
    topics = {t: retain for t, _, retain in pub.msgs}
    assert topics[f"cvc/approvals/{r.id}"] is True
    assert topics[SUMMARY_TOPIC] is True
    assert topics["homeassistant/sensor/cvc_pending_approvals/config"] is True
    summary = json.loads(pub.last(SUMMARY_TOPIC))
    assert summary["pending"] == 1 and summary["most_urgent_deadline"] == r.deadline
    cfg = json.loads(discovery_config()[1])
    assert cfg["state_topic"] == SUMMARY_TOPIC and cfg["unique_id"] == "cvc_pending_approvals"


def test_from_env_is_opt_in(monkeypatch):
    monkeypatch.delenv("MQTT_HOST", raising=False)
    monkeypatch.delenv("CVC_APPROVALS_MQTT", raising=False)
    assert type(from_env()).__name__ == "NullPublisher"
    monkeypatch.setenv("MQTT_HOST", "h")
    assert type(from_env()).__name__ == "MqttPublisher"


def test_resolved_updated_then_cleared_after_24h():
    pub, clock = FakePublisher(), Clock()
    svc = ApprovalService(publisher=pub, clock=clock)
    r = svc.submit(_req(clock))
    svc.decide(r.id, "deny", person="nat", tier="owner")
    assert json.loads(pub.last(f"cvc/approvals/{r.id}"))["status"] == "denied"
    clock.t += timedelta(hours=25)
    svc.sweep()
    assert (f"cvc/approvals/{r.id}", "", True) in pub.msgs
    assert svc.get(r.id).status == "denied"     # retained cleared; record kept as history


# -- decide rules -------------------------------------------------------------------
def test_wrong_tier_rejected():
    r = _req(action="write")  # amber -> admin
    with pytest.raises(DecideError) as e:
        check_authority(r, "kid", "medium", None)
    assert e.value.status_code == 403
    check_authority(r, "adm", "admin", None)


def test_missing_passkey_rejected():
    r = _req(action="act")
    with pytest.raises(DecideError, match="passkey"):
        check_authority(r, "nat", "owner", None)
    with pytest.raises(DecideError, match="passkey"):
        check_authority(r, "nat", "owner", "someone-else")
    check_authority(r, "nat", "owner", "nat")


def test_assistant_routing():
    r = _req(agent_tier="assistant", on_behalf_of="alex", action="write")
    check_authority(r, "alex", "medium", None)        # own errand, below min tier ok
    check_authority(r, "nat", "owner", None)
    with pytest.raises(DecideError, match="on_behalf_of"):
        check_authority(r, "adm", "admin", None)


def test_unknown_identity_rejected():
    with pytest.raises(DecideError):
        check_authority(_req(), None, "owner", None)
    with pytest.raises(DecideError):
        check_authority(_req(), "x", "superuser", None)


def test_timeout_is_deny():
    pub, clock = FakePublisher(), Clock()
    svc = ApprovalService(publisher=pub, clock=clock)
    r = svc.submit(_req(clock))
    clock.t += timedelta(minutes=16)
    assert [x.id for x in svc.sweep()] == [r.id]
    assert svc.get(r.id).status == "expired"
    assert json.loads(pub.last(SUMMARY_TOPIC))["pending"] == 0
    with pytest.raises(DecideError) as e:
        svc.decide(r.id, "approve", person="nat", tier="owner")
    assert e.value.status_code == 409


def test_idempotent_decide():
    svc = ApprovalService(publisher=FakePublisher())
    r = svc.submit(_req())
    a = svc.decide(r.id, "approve", person="nat", tier="owner")
    b = svc.decide(r.id, "approve", person="nat", tier="owner")
    assert a.status == b.status == "approved" and a.decided_at == b.decided_at
    with pytest.raises(DecideError) as e:
        svc.decide(r.id, "deny", person="nat", tier="owner")
    assert e.value.status_code == 409


def test_state_file_shared_and_cli(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("MQTT_HOST", raising=False)
    state = tmp_path / "a.json"
    svc = ApprovalService(publisher=FakePublisher(), state_path=str(state))
    r = svc.submit(_req(action="act"))
    assert cli.main(["--state", str(state), "list"]) == 0
    assert r.id in capsys.readouterr().out
    assert cli.main(["--state", str(state), "decide", r.id, "approve", "--as", "nat"]) == 2
    assert cli.main(["--state", str(state), "decide", r.id, "approve", "--as", "nat",
                     "--passkey-verified"]) == 0
    assert svc.get(r.id).status == "approved"
    assert cli.main(["--state", str(state), "show", r.id]) == 0


def test_version_bumps_and_expected_version():
    svc = ApprovalService(publisher=FakePublisher())
    r = svc.submit(_req())
    assert r.version == 1 and r.etag == f'"{r.id}.v1"'
    with pytest.raises(DecideError) as e:
        svc.decide(r.id, "approve", person="nat", tier="owner", expected_version=3)
    assert e.value.status_code == 412
    assert svc.decide(r.id, "approve", person="nat", tier="owner",
                      expected_version=1).version == 2


def test_history_kept_90_days(tmp_path):
    pub, clock = FakePublisher(), Clock()
    state = tmp_path / "s.json"
    svc = ApprovalService(publisher=pub, clock=clock, state_path=str(state))
    r = svc.submit(_req(clock))
    svc.decide(r.id, "deny", person="nat", tier="owner")
    clock.t += timedelta(days=2)
    svc.sweep()
    svc.sweep()
    clears = [m for m in pub.msgs if m == (f"cvc/approvals/{r.id}", "", True)]
    assert len(clears) == 1                      # cleared once from MQTT
    assert svc.get(r.id).status == "denied"      # still in history
    assert r.id in json.loads(state.read_text())["cleared"]
    clock.t += timedelta(days=89)
    svc.sweep()
    assert svc.get(r.id) is None
    assert ApprovalService(history_days=1).history == timedelta(days=1)
