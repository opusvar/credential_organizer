"""D27 agent escalation: policy, normalizer, store (limits, grants), broker, CLI."""
import hashlib
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from cvc.approvals import model as amodel
from cvc.approvals.service import ApprovalService, DecideError
from cvc.broker import app as app_mod
from cvc.broker.acl import Acl
from cvc.broker.audit import AuditLog
from cvc.broker.tiers import ApprovalStore, SessionStore
from cvc.escalation import EscalationError, EscalationRefused, EscalationStore, evaluate
from cvc.escalation import cli as esc_cli
from cvc.escalation.policy import approver_min_tier, required_tier
from cvc.escalation.text import TextError, normalize
from cvc.notify.message import approval_message

C1 = "11111111-1111-4111-8111-111111111111"
C2 = "22222222-2222-4222-8222-222222222222"


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def req(**kw):
    base = {"action": "write", "data": "internal", "resource": "task:nightly-report",
            "purpose": "create the nightly report task", "justification": "owner asked for it"}
    base.update(kw)
    return base


class Clock:
    def __init__(self):
        self.t = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


class Pub:
    def __init__(self):
        self.msgs = []

    def publish(self, topic, payload, retain):
        self.msgs.append((topic, payload, retain))


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(tmp_path, clock):
    svc = ApprovalService(publisher=Pub(), state_path=str(tmp_path / "ap.json"), clock=clock)
    return EscalationStore(str(tmp_path / "esc.json"), svc, clock=clock)


def approve(store, esc, person="olive", tier="owner", decision="approve"):
    ar = store.approvals.get(esc.approval_id)
    store.approvals.decide(esc.approval_id, decision, person=person, tier=tier,
                           passkey_user=person if ar.requires_passkey else None)


# ── text normalizer ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad,code", [
    ("a\tb", "invalid_whitespace"), ("a\nb", "invalid_whitespace"),
    ("a\u00a0b", "invalid_whitespace"), ("a\u2003b", "invalid_whitespace"),
    ("a\u200bb", "invalid_whitespace"), ("a\u202eb", "invalid_whitespace"),
    ("a\u00adb", "invalid_whitespace"), ("a\x07b", "invalid_characters"),
    ("a\ue000b", "invalid_characters"), ("a\ud800b", "invalid_encoding"),
    ("a\ufffeb", "invalid_encoding"), ("   ", "empty"), ("", "empty"), (5, "invalid_type"),
])
def test_normalizer_rejects(bad, code):
    with pytest.raises(TextError) as e:
        normalize(bad, "purpose")
    assert e.value.code == code


def test_normalizer_cleans():
    assert normalize("  fix   the  thing ", "p") == "fix the thing"
    assert normalize("cafe\u0301", "p") == "caf\u00e9"
    assert normalize("ok \U0001F44D", "p") == "ok \U0001F44D"
    assert normalize("a" + "\u0301" * 10, "p") == "\u00e1" + "\u0301" * 3
    with pytest.raises(TextError):
        normalize("x" * 600, "p")


# ── policy ──────────────────────────────────────────────────────────────────────────
def test_required_and_approver_tiers():
    assert required_tier("internal", "write") == "medium"
    assert required_tier("private", "write") == "high"
    assert required_tier("private", "act") == "medium"      # P at medium
    assert required_tier("secret", "read") == "owner"
    assert approver_min_tier("low", "internal", "read") == ("high", False)
    assert approver_min_tier("medium", "internal", "write") == ("admin", False)
    assert approver_min_tier("high", "private", "write") == ("owner", True)
    assert approver_min_tier("medium", "secret", "read") == ("owner", True)
    assert approver_min_tier("high", "internal", "delegate") == ("owner", True)


def test_low_agent_write_is_escalatable():
    a = evaluate("bot", "low", req())
    assert not a.already_permitted and a.cell == "D"
    assert (a.current_tier, a.required_tier, a.approver_min_tier) == ("low", "medium", "admin")
    assert a.ttl_s == 900


def test_already_permitted():
    assert evaluate("bot", "low", req(action="read")).already_permitted
    assert evaluate("bot", "medium", req()).already_permitted


def test_effective_row_caps():
    a = evaluate("bot", "medium", req(), effective_row="low")
    assert not a.already_permitted and a.current_tier == "low"


def test_approval_cell_is_escalatable():
    a = evaluate("bot", "medium", req(action="act", data="public", resource="system:mailer"))
    assert a.cell == "P" and not a.already_permitted


@pytest.mark.parametrize("res", ["credential:*", "ha:light.*", "system:all", "task:any",
                                 "system:ha/#", "system:a+b", "task:", "credential:abc",
                                 "ha:lights", "system:x y", "system:../etc", "nokind",
                                 "files:x", "system:ha/"])
def test_wildcards_and_bad_resources_rejected(res):
    with pytest.raises(EscalationRefused) as e:
        evaluate("bot", "low", req(resource=res))
    assert e.value.code == "invalid"


@pytest.mark.parametrize("res", ["owner-key:yubikey-1", "takeover:estate", "delegation:all",
                                 "tier:bot", "role:writer", "grant:other-bot",
                                 "agent:other-bot"])
def test_hard_ceilings_refused(res):
    with pytest.raises(EscalationRefused) as e:
        evaluate("bot", "high", req(action="delegate", resource=res))
    assert e.value.code == "hard_ceiling" and e.value.status == 403
    assert e.value.reason


def test_delegate_whole_system_is_hard_ceiling():
    with pytest.raises(EscalationRefused) as e:
        evaluate("bot", "medium", req(action="delegate", resource="system:ltaskq"))
    assert e.value.code == "hard_ceiling"


@pytest.mark.parametrize("patch,msg", [
    ({"action": "write,act"}, "action"), ({"action": "*"}, "action"),
    ({"data": "everything"}, "data"), ({"extra": 1}, "unknown fields"),
    ({"ttl_s": 30}, "ttl_s"), ({"ttl_s": 24 * 3600 + 1}, "ttl_s"), ({"ttl_s": True}, "ttl_s"),
    ({"physical": "yes"}, "physical"), ({"on_behalf_of": "Bad Name"}, "on_behalf_of"),
    ({"purpose": "a\tb"}, "invalid_whitespace"), ({"justification": ""}, "empty"),
])
def test_invalid_fields(patch, msg):
    with pytest.raises(EscalationRefused) as e:
        evaluate("bot", "low", req(**patch))
    assert msg in e.value.reason


def test_assistant_needs_on_behalf_of():
    with pytest.raises(EscalationRefused):
        evaluate("asst", "assistant", req(data="private"))
    a = evaluate("asst", "assistant", req(data="private"), on_behalf_of_default="alex")
    assert a.on_behalf_of == "alex"


def test_ha_act_is_physical_and_never_already_permitted():
    a = evaluate("orc", "high", req(action="act", data="private", resource="ha:lock.front"))
    assert a.physical and not a.already_permitted


def test_ttl_24h_max_allowed():
    assert evaluate("bot", "low", req(ttl_s=24 * 3600)).ttl_s == 24 * 3600


# ── store ───────────────────────────────────────────────────────────────────────────
def test_request_creates_escalation_card(store):
    esc, nonce, sugg = store.request(evaluate("bot", "low", req()), "tok")
    assert esc.status == "pending" and nonce and sugg is None
    ar = store.approvals.get(esc.approval_id)
    assert ar.kind == "escalation" and ar.on_timeout == "deny"
    assert ar.escalation["current_tier"] == "low"
    assert ar.escalation["requested_tier"] == "medium"
    assert ar.approver_min_tier == "admin"
    assert "if" not in ar.if_approved[:0] and "second use is denied" in ar.if_approved
    assert "1 h" in ar.if_denied
    assert amodel.validate(ar.to_dict()) == []
    raw = json.loads((store.state_path).read_text())
    assert nonce not in json.dumps(raw) and "tok" not in json.dumps(raw).split('"')
    assert oct(store.state_path.stat().st_mode)[-3:] == "600"


def test_already_permitted_creates_nothing(store):
    with pytest.raises(EscalationError) as e:
        store.request(evaluate("bot", "medium", req()), "tok")
    assert e.value.code == "already_permitted"
    assert store.list() == []


def test_single_use_grant(store):
    esc, nonce, _ = store.request(evaluate("bot", "low", req()), "tok")
    with pytest.raises(EscalationError) as e:
        store.consume(esc.id, agent="bot", token="tok", resource=esc.resource, nonce=nonce)
    assert e.value.code == "not_approved"
    approve(store, esc, person="ada", tier="admin")
    got = store.consume(esc.id, agent="bot", token="tok", resource=esc.resource, nonce=nonce)
    assert got.status == "consumed"
    with pytest.raises(EscalationError) as e:
        store.consume(esc.id, agent="bot", token="tok", resource=esc.resource, nonce=nonce)
    assert e.value.code == "used"
    assert store.verify_history()
    events = [r["event"] for r in store.history(esc.id)]
    assert events == ["requested", "use_denied", "approved", "consumed", "use_denied"]


@pytest.mark.parametrize("kw,code", [
    ({"token": "other"}, "token"), ({"nonce": "wrong"}, "nonce"),
    ({"resource": "task:other"}, "resource"), ({"agent": "evil"}, "unknown"),
    ({"action": "act"}, "action"), ({"nonce": None}, "missing"),
])
def test_grant_bindings(store, kw, code):
    esc, nonce, _ = store.request(evaluate("bot", "low", req()), "tok")
    approve(store, esc)
    args = {"agent": "bot", "token": "tok", "resource": esc.resource, "nonce": nonce}
    args.update(kw)
    with pytest.raises(EscalationError) as e:
        store.consume(esc.id, **args)
    assert e.value.code == code
    # the correct use still works after a mismatched attempt
    if code != "missing":
        store.consume(esc.id, agent="bot", token="tok", resource=esc.resource, nonce=nonce)


def test_grant_expires(store, clock):
    esc, nonce, _ = store.request(evaluate("bot", "low", req(ttl_s=120)), "tok")
    approve(store, esc)
    clock.advance(seconds=121)
    with pytest.raises(EscalationError) as e:
        store.consume(esc.id, agent="bot", token="tok", resource=esc.resource, nonce=nonce)
    assert e.value.code == "not_approved"
    assert store.get(esc.id).status == "grant_expired"


def test_default_ttl_is_15_min(store, clock):
    esc, nonce, _ = store.request(evaluate("bot", "low", req()), "tok")
    approve(store, esc)
    clock.advance(minutes=14, seconds=59)
    store.consume(esc.id, agent="bot", token="tok", resource=esc.resource, nonce=nonce)


def test_timeout_is_deny(store, clock):
    esc, _, _ = store.request(evaluate("bot", "low", req()), "tok")
    clock.advance(minutes=16)
    assert store.get(esc.id).status == "expired"


def test_denied_then_cooldown(store, clock):
    a = evaluate("bot", "low", req())
    esc, _, _ = store.request(a, "tok")
    approve(store, esc, decision="deny")
    assert store.get(esc.id).status == "denied"
    with pytest.raises(EscalationError) as e:
        store.request(a, "tok")
    assert e.value.code == "denied_cooldown"
    clock.advance(minutes=61)
    store.request(a, "tok")


def test_pending_limit_and_duplicate(store):
    for i in range(3):
        store.request(evaluate("bot", "low", req(resource=f"task:t{i}")), "tok")
    with pytest.raises(EscalationError) as e:
        store.request(evaluate("bot", "low", req(resource="task:t9")), "tok")
    assert e.value.code == "too_many_pending" and e.value.status == 429
    with pytest.raises(EscalationError) as e:
        store.request(evaluate("bot", "low", req(resource="task:t0")), "tok")
    assert e.value.code == "duplicate"
    store.request(evaluate("other", "low", req(resource="task:t9")), "tok2")


def test_daily_limit(store, clock):
    for i in range(10):
        esc, _, _ = store.request(evaluate("bot", "low", req(resource=f"task:d{i}")), "tok")
        store.revoke(esc.id, "olive")
    with pytest.raises(EscalationError) as e:
        store.request(evaluate("bot", "low", req(resource="task:d99")), "tok")
    assert e.value.code == "daily_limit"
    clock.advance(hours=24, seconds=1)
    store.request(evaluate("bot", "low", req(resource="task:d99")), "tok")


def test_repeat_triggers_audit_suggestion(store):
    sugg = None
    for i in range(3):
        esc, _, sugg = store.request(evaluate("bot", "low", req(resource=f"task:r{i}")), "tok")
        store.revoke(esc.id, "olive")
    assert sugg and "consider changing its tier" in sugg
    assert len(store.suggestions()) == 1


def test_revoke_unused_grant(store):
    esc, nonce, _ = store.request(evaluate("bot", "low", req()), "tok")
    approve(store, esc)
    store.revoke(esc.id, "olive")
    with pytest.raises(EscalationError):
        store.consume(esc.id, agent="bot", token="tok", resource=esc.resource, nonce=nonce)
    with pytest.raises(EscalationError) as e:
        store.revoke(esc.id, "olive")
    assert e.value.status == 409
    with pytest.raises(EscalationError) as e:
        store.revoke("nope", "olive")
    assert e.value.status == 404


def test_revoke_pending_cancels_approval(store):
    esc, _, _ = store.request(evaluate("bot", "low", req()), "tok")
    store.revoke(esc.id, "olive")
    assert store.approvals.get(esc.approval_id).status == "cancelled"


def test_approver_tier_enforced(store):
    esc, _, _ = store.request(evaluate("bot", "low", req()), "tok")
    with pytest.raises(DecideError):
        approve(store, esc, person="hank", tier="high")       # needs admin
    approve(store, esc, person="ada", tier="admin")


def test_owner_only_for_secret(store):
    esc, _, _ = store.request(evaluate("orc", "high", req(action="read", data="secret",
                                                          resource=f"credential:{C1}")), "t")
    with pytest.raises(DecideError):
        approve(store, esc, person="ada", tier="admin")
    approve(store, esc, person="olive", tier="owner")


def test_assistant_obo_person_not_exempt(store):
    a = evaluate("asst", "assistant", req(data="private", resource=f"credential:{C1}",
                                          action="write"), on_behalf_of_default="alex")
    esc, _, _ = store.request(a, "t")
    with pytest.raises(DecideError):
        approve(store, esc, person="alex", tier="medium")
    approve(store, esc, person="olive", tier="owner")
    assert store.get(esc.id).on_behalf_of == "alex"
    rows = store.history(esc.id)
    assert all(r["on_behalf_of"] == "alex" and r["agent"] == "asst" for r in rows)


def test_physical_needs_passkey_and_human(store):
    a = evaluate("orc", "high", req(action="act", data="private", resource="ha:lock.front"))
    esc, _, _ = store.request(a, "t")
    ar = store.approvals.get(esc.approval_id)
    assert ar.requires_passkey and ar.risk == "red" and ar.approver_min_tier == "owner"
    with pytest.raises(DecideError):
        store.approvals.decide(esc.approval_id, "approve", person="olive", tier="owner")
    # an agent identity posing as an approver voids the grant
    store.mark_non_human({"robo-approver"})
    store.approvals.decide(esc.approval_id, "approve", person="robo-approver", tier="owner",
                           passkey_user="robo-approver")
    assert store.get(esc.id).status == "void"


def test_history_tamper_detected(store):
    store.request(evaluate("bot", "low", req()), "tok")
    lines = store.history_path.read_text().splitlines()
    row = json.loads(lines[0])
    row["agent"] = "someone-else"
    store.history_path.write_text(json.dumps(row) + "\n")
    assert not store.verify_history()


def test_ntfy_title_says_escalation(store, clock):
    esc, _, _ = store.request(evaluate("bot", "low", req()), "tok")
    msg = approval_message(store.approvals.get(esc.approval_id), clock(), "https://x.example.com")
    assert msg.title.startswith("Escalation needed")


def test_approval_model_rejects_bad_escalation_block(store):
    esc, _, _ = store.request(evaluate("bot", "low", req()), "tok")
    d = store.approvals.get(esc.approval_id).to_dict()
    bad = dict(d, escalation={"current_tier": "low"})
    assert any("escalation" in e for e in amodel.validate(bad))
    assert any("kind" in e for e in amodel.validate(dict(d, kind="other")))
    assert any("only allowed" in e for e in amodel.validate(dict(d, kind="approval")))


# ── broker ──────────────────────────────────────────────────────────────────────────
@pytest.fixture
def broker(tmp_path, monkeypatch, clock):
    acl = Acl({"agents": {
        "lowbot": {"token_sha256": _sha("t-low"), "tier": "low", "allow": []},
        "medbot": {"token_sha256": _sha("t-med"), "tier": "medium",
                   "allow": [{"credential": C2, "purposes": ["*"]}]},
    }})
    svc = ApprovalService(publisher=Pub(), clock=clock)
    store = EscalationStore(str(tmp_path / "esc.json"), svc, clock=clock)
    bw = MagicMock()
    bw.get_item.return_value = {"login": {"password": "pw-value"}}
    audit = AuditLog(str(tmp_path / "a.jsonl"))
    a = app_mod.app
    a.dependency_overrides.update({
        app_mod._acl: lambda: acl, app_mod._audit: lambda: audit, app_mod._bw: lambda: bw,
        app_mod._sessions: lambda: SessionStore(), app_mod._approvals: lambda: ApprovalStore(),
        app_mod._approval_service: lambda: svc, app_mod._escalations: lambda: store,
    })
    monkeypatch.setattr(app_mod, "_ops", lambda: MagicMock())
    yield TestClient(a, raise_server_exceptions=False), store, audit
    a.dependency_overrides.clear()


def _h(agent="lowbot", tok="t-low", **extra):
    return {"X-Agent-Id": agent, "Authorization": f"Bearer {tok}", **extra}


def _esc_body(**kw):
    return req(**{"action": "read", "data": "private", "resource": f"credential:{C1}", **kw})


def test_broker_escalation_end_to_end(broker):
    client, store, audit = broker
    r = client.post("/v1/escalations", json=_esc_body(), headers=_h())
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["current_tier"] == "low" and body["requested_tier"] == "medium"
    fetch = {"credential": C1, "purpose": "read once"}
    # not yet approved
    r2 = client.post("/v1/credentials/fetch", json=fetch,
                     headers=_h(**{"X-Escalation-Id": body["id"],
                                   "X-Escalation-Nonce": body["nonce"]}))
    assert r2.status_code == 403
    store.approvals.decide(body["approval_id"], "approve", person="ada", tier="admin")
    r3 = client.post("/v1/credentials/fetch", json=fetch,
                     headers=_h(**{"X-Escalation-Id": body["id"],
                                   "X-Escalation-Nonce": body["nonce"]}))
    assert r3.status_code == 200 and r3.json()["value"] == "pw-value"
    r4 = client.post("/v1/credentials/fetch", json=fetch,
                     headers=_h(**{"X-Escalation-Id": body["id"],
                                   "X-Escalation-Nonce": body["nonce"]}))
    assert r4.status_code == 403 and "already used" in r4.text
    st = client.get(f"/v1/escalations/{body['id']}", headers=_h())
    assert st.json()["status"] == "consumed" and "nonce_sha256" not in st.json()
    outcomes = [json.loads(x)["outcome"] for x in audit.path.read_text().splitlines()]
    assert f"escalation:requested:{body['id']}" in outcomes
    assert f"allow:escalation:{body['id']}" in outcomes
    assert "deny:escalation:used" in outcomes
    assert audit.verify()


def test_broker_fetch_other_credential_denied(broker):
    client, store, _ = broker
    body = client.post("/v1/escalations", json=_esc_body(), headers=_h()).json()
    store.approvals.decide(body["approval_id"], "approve", person="ada", tier="admin")
    r = client.post("/v1/credentials/fetch", json={"credential": C2, "purpose": "x"},
                    headers=_h(**{"X-Escalation-Id": body["id"],
                                  "X-Escalation-Nonce": body["nonce"]}))
    assert r.status_code == 403 and "different resource" in r.text


def test_broker_already_permitted(broker):
    client, store, _ = broker
    r = client.post("/v1/escalations", json=_esc_body(), headers=_h("medbot", "t-med"))
    assert r.status_code == 200 and r.json()["status"] == "already_permitted"
    assert store.list() == []


def test_broker_rejects_bad_auth_wildcard_and_hard_ceiling(broker):
    client, _, _ = broker
    assert client.post("/v1/escalations", json=_esc_body(),
                       headers=_h(tok="wrong")).status_code == 401
    r = client.post("/v1/escalations", json=_esc_body(resource="credential:*"), headers=_h())
    assert r.status_code == 422 and r.json()["detail"]["code"] == "invalid"
    r = client.post("/v1/escalations", json=_esc_body(resource="tier:lowbot"), headers=_h())
    assert r.status_code == 403 and r.json()["detail"]["code"] == "hard_ceiling"


def test_broker_rate_limit(broker):
    client, _, _ = broker
    for i in range(3):
        assert client.post("/v1/escalations", json=_esc_body(resource=f"task:x{i}",
                                                             action="write", data="internal"),
                           headers=_h()).status_code == 201
    r = client.post("/v1/escalations", json=_esc_body(resource="task:x9", action="write",
                                                      data="internal"), headers=_h())
    assert r.status_code == 429


def test_broker_get_escalation_other_agent_404(broker):
    client, _, _ = broker
    body = client.post("/v1/escalations", json=_esc_body(), headers=_h()).json()
    assert client.get(f"/v1/escalations/{body['id']}",
                      headers=_h("medbot", "t-med")).status_code == 404


def test_broker_normal_fetch_unchanged(broker):
    client, _, _ = broker
    r = client.post("/v1/credentials/fetch", json={"credential": C2, "purpose": "x"},
                    headers=_h("medbot", "t-med"))
    assert r.status_code == 200
    r = client.post("/v1/credentials/fetch", json={"credential": C1, "purpose": "x"},
                    headers=_h())
    assert r.status_code == 403


# ── CLI ─────────────────────────────────────────────────────────────────────────────
def test_cli_check(capsys):
    base = ["request", "--agent", "bot", "--action", "write", "--data", "internal",
            "--resource", "task:t1", "--purpose", "p", "--justification", "j", "--check"]
    assert esc_cli.main(base) == 0
    assert "approver >= admin" in capsys.readouterr().out
    assert esc_cli.main(base + ["--tier", "medium"]) == 0
    assert "already permitted" in capsys.readouterr().out
    bad = [x if x != "task:t1" else "tier:bot" for x in base]
    assert esc_cli.main(bad) == 2


def test_cli_request_needs_token(capsys):
    assert esc_cli.main(["request", "--agent", "bot", "--action", "write", "--data",
                         "internal", "--resource", "task:t1", "--purpose", "p",
                         "--justification", "j"]) == 2


def test_cli_list_show_revoke(tmp_path, capsys):
    st, ap = str(tmp_path / "e.json"), str(tmp_path / "a.json")
    store = EscalationStore(st, ApprovalService(state_path=ap))
    esc, _, _ = store.request(evaluate("bot", "low", req()), "tok")
    common = ["--state", st, "--approvals-state", ap]
    assert esc_cli.main(common + ["list"]) == 0
    assert esc.id in capsys.readouterr().out
    assert esc_cli.main(common + ["show", esc.id]) == 0
    assert json.loads(capsys.readouterr().out)["escalation"]["id"] == esc.id
    assert esc_cli.main(common + ["revoke", esc.id, "--as", "olive"]) == 0
    assert esc_cli.main(common + ["revoke", esc.id, "--as", "olive"]) == 2
    assert esc_cli.main(common + ["show", "nope"]) == 1
    assert esc_cli.main(common + ["list", "--json", "--status", "revoked"]) == 0
