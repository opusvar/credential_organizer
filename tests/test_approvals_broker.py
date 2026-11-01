"""D18 broker wiring: create -> publish, /decide auth rules, nonce, whoami, CORS, legacy path."""
import hashlib
import json
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from cvc.approvals.service import ApprovalService
from cvc.broker import app as app_mod
from cvc.broker.acl import Acl
from cvc.broker.audit import AuditLog
from cvc.broker.tiers import ApprovalStore, SessionStore

C2 = "22222222-2222-2222-2222-222222222222"
ORIGIN = "https://dash.example.ts.net"


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


class FakePublisher:
    def __init__(self):
        self.msgs = []

    def publish(self, topic, payload, retain):
        self.msgs.append((topic, payload, retain))


@pytest.fixture
def env(tmp_path, monkeypatch):
    allow = [{"credential": C2, "purposes": ["*"], "physical": True}]
    acl = Acl({"agents": {
        "hi": {"token_sha256": _sha("t-hi"), "tier": "high", "allow": allow},
        "asst": {"token_sha256": _sha("t-asst"), "tier": "assistant", "on_behalf_of": "alex",
                 "allow": [{"credential": C2, "purposes": ["*"]}]},
    }})
    pub = FakePublisher()
    svc, store = ApprovalService(publisher=pub), ApprovalStore()
    bw = MagicMock()
    bw.get_item.return_value = {"login": {"password": "pw-value"}}
    a = app_mod.app
    a.dependency_overrides.update({
        app_mod._acl: lambda: acl, app_mod._audit: lambda: AuditLog(str(tmp_path / "a.jsonl")),
        app_mod._bw: lambda: bw, app_mod._sessions: lambda: SessionStore(),
        app_mod._approvals: lambda: store, app_mod._approval_service: lambda: svc,
    })
    monkeypatch.setattr(app_mod, "_approval_service", lambda: svc)
    monkeypatch.setattr(app_mod, "_ops", lambda: MagicMock())
    monkeypatch.setattr(app_mod, "_NONCES", app_mod._NonceStore())
    monkeypatch.setenv("CVC_TRUST_TIERGATE", "1")
    monkeypatch.setenv("CVC_DASHBOARD_ORIGIN", ORIGIN)
    monkeypatch.setenv("CVC_APPROVER_TOKEN_SHA256", _sha("human"))
    yield TestClient(a, raise_server_exceptions=False), svc, pub
    a.dependency_overrides.clear()


def _create(client, agent="hi", tok="t-hi", **body):
    r = client.post("/v1/approvals", json={"credential": C2, "purpose": "open garage", **body},
                    headers={"X-Agent-Id": agent, "Authorization": f"Bearer {tok}"})
    assert r.status_code == 201, r.text
    return r.json()


def _id(person, tier, passkey=None):
    h = {"X-Cvc-Person": person, "X-Cvc-Tier": tier}
    if passkey:
        h["X-authentik-username"] = passkey
    return h


def _decide(client, aid, decision, hdrs, nonce=None):
    if nonce is None:
        nonce = client.get("/v1/approvals/nonce", headers=hdrs).json()["nonce"]
    return client.post(f"/v1/approvals/{aid}/decide",
                       json={"decision": decision, "nonce": nonce}, headers=hdrs)


def _fetch(client, aid):
    return client.post("/v1/credentials/fetch", json={"credential": C2, "purpose": "open garage"},
                       headers={"X-Agent-Id": "hi", "Authorization": "Bearer t-hi",
                                "X-Approval-Id": aid})


def test_create_publishes_request(env):
    client, _, pub = env
    body = _create(client, intent="open the garage", summary="parcel delivery",
                   if_approved="door opens 2 min", if_denied="parcel left outside",
                   urgency="urgent", deadline_s=600)
    assert body["risk"] == "red" and body["requires_passkey"]
    _topic, payload, retain = next(m for m in pub.msgs if m[0] == f"cvc/approvals/{body['id']}")
    assert retain and json.loads(payload)["urgency"] == "urgent"


def test_create_rejects_secret(env):
    client, _, _ = env
    r = client.post("/v1/approvals",
                    json={"credential": C2, "purpose": "p", "summary": "password=hunter2"},
                    headers={"X-Agent-Id": "hi", "Authorization": "Bearer t-hi"})
    assert r.status_code == 422


def test_decide_then_fetch_single_use(env):
    client, _, _ = env
    aid = _create(client)["id"]
    assert _fetch(client, aid).status_code == 403
    assert _decide(client, aid, "approve", _id("nat", "owner")).status_code == 403  # no passkey
    r = _decide(client, aid, "approve", _id("nat", "owner", "nat"))
    assert r.status_code == 200 and r.json()["status"] == "approved"
    assert _fetch(client, aid).status_code == 200
    assert _fetch(client, aid).status_code == 403


def test_decide_wrong_tier_and_deny(env):
    client, _, _ = env
    aid = _create(client)["id"]
    assert _decide(client, aid, "approve", _id("adm", "admin", "adm")).status_code == 403
    assert _decide(client, aid, "deny", _id("nat", "owner", "nat")).json()["status"] == "denied"
    assert _fetch(client, aid).status_code == 403


def test_assistant_routing_via_endpoint(env):
    client, _, _ = env
    aid = _create(client, agent="asst", tok="t-asst", action="write")["id"]
    assert _decide(client, aid, "approve", _id("adm", "admin")).status_code == 403
    assert _decide(client, aid, "approve", _id("alex", "medium")).status_code == 200


def test_untrusted_tiergate_rejected(env, monkeypatch):
    client, _, _ = env
    aid = _create(client)["id"]
    monkeypatch.delenv("CVC_TRUST_TIERGATE")
    r = client.post(f"/v1/approvals/{aid}/decide", json={"decision": "approve", "nonce": "x" * 10},
                    headers=_id("nat", "owner", "nat"))
    assert r.status_code == 403
    assert client.get("/v1/whoami", headers=_id("nat", "owner")).status_code == 403


def test_nonce_single_use_and_person_bound(env):
    client, _, _ = env
    aid = _create(client)["id"]
    n = client.get("/v1/approvals/nonce", headers=_id("nat", "owner")).json()["nonce"]
    assert _decide(client, aid, "deny", _id("other", "owner"), nonce=n).status_code == 403
    n = client.get("/v1/approvals/nonce", headers=_id("nat", "owner")).json()["nonce"]
    assert _decide(client, aid, "deny", _id("nat", "owner", "nat"), nonce=n).status_code == 200
    assert _decide(client, aid, "deny", _id("nat", "owner", "nat"), nonce=n).status_code == 403


def test_whoami(env):
    client, _, _ = env
    r = client.get("/v1/whoami", headers=_id("nat", "owner", "nat"))
    assert r.json() == {"person": "nat", "tier": "owner", "passkey": True}


def test_cors_origin_and_json_only(env):
    client, _, _ = env
    aid = _create(client)["id"]
    bad = client.get("/v1/whoami", headers={**_id("nat", "owner"), "Origin": "https://evil"})
    assert bad.status_code == 403
    ok = client.get("/v1/whoami", headers={**_id("nat", "owner"), "Origin": ORIGIN})
    assert ok.headers["access-control-allow-origin"] == ORIGIN
    pre = client.options(f"/v1/approvals/{aid}/decide", headers={"Origin": ORIGIN})
    assert pre.status_code == 204
    form = client.post(f"/v1/approvals/{aid}/decide", data={"decision": "approve"},
                       headers=_id("nat", "owner", "nat"))
    assert form.status_code == 415


def test_expiry_denies_fetch(env):
    client, svc, _ = env
    aid = _create(client)["id"]
    svc.clock = lambda: __import__("datetime").datetime.now(
        __import__("datetime").UTC) + __import__("datetime").timedelta(hours=1)
    assert _fetch(client, aid).status_code == 403
    assert svc.get(aid).status == "expired"


def test_legacy_approver_token_still_works(env):
    client, svc, _ = env
    aid = _create(client)["id"]
    r = client.post(f"/v1/approvals/{aid}/approve", json={"approver": "nat"},
                    headers={"X-Approver-Token": "human"})
    assert r.status_code == 200
    assert svc.get(aid).status == "approved"
    assert _fetch(client, aid).status_code == 200
