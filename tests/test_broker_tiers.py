"""Agent-tier enforcement: session-token TTL/scope, high-tier physical approvals,
assistant dual attribution."""
import hashlib
import json
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from cvc.broker import app as app_mod
from cvc.broker.acl import Acl
from cvc.broker.audit import AuditEvent, AuditLog
from cvc.broker.tiers import MAX_TTL, TIER_TTL, ApprovalStore, SessionStore, normalize_tier

C1 = "11111111-1111-1111-1111-111111111111"
C2 = "22222222-2222-2222-2222-222222222222"
SECRET = "s3cr3t-value-xyz"


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _acl_data():
    allow = [{"credential": C1, "purposes": ["*"]},
             {"credential": C2, "purposes": ["*"], "physical": True}]
    return {"agents": {
        "plain": {"token_sha256": _sha("t-plain"), "allow": allow},
        "hi": {"token_sha256": _sha("t-hi"), "tier": "high", "allow": allow},
        "asst": {"token_sha256": _sha("t-asst"), "tier": "assistant",
                 "on_behalf_of": "alex", "allow": allow},
        "asst-noobo": {"token_sha256": _sha("t-x"), "tier": "assistant", "allow": allow},
    }}


@pytest.fixture
def env(tmp_path, monkeypatch):
    acl = Acl(_acl_data())
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    sessions, approvals = SessionStore(), ApprovalStore()
    bw = MagicMock()
    bw.get_item.return_value = {"login": {"password": SECRET}}
    ops = MagicMock()
    a = app_mod.app
    a.dependency_overrides.update({
        app_mod._acl: lambda: acl, app_mod._audit: lambda: audit, app_mod._bw: lambda: bw,
        app_mod._sessions: lambda: sessions, app_mod._approvals: lambda: approvals,
    })
    monkeypatch.setattr(app_mod, "_ops", lambda: ops)
    monkeypatch.setenv("CVC_APPROVER_TOKEN_SHA256", _sha("human"))
    client = TestClient(a, raise_server_exceptions=False)
    yield client, tmp_path / "audit.jsonl", audit
    a.dependency_overrides.clear()


def _fetch(client, agent, tok, cred, **hdr):
    return client.post("/v1/credentials/fetch",
                       json={"credential": cred, "purpose": "p"},
                       headers={"X-Agent-Id": agent, "Authorization": f"Bearer {tok}", **hdr})


def _records(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def test_tier_default_scoped():
    acl = Acl(_acl_data())
    assert acl.tier("plain") == "scoped"
    assert acl.tier("ghost") == "scoped"
    assert normalize_tier("bogus") == "scoped"
    assert acl.tier("hi") == "high"


def test_ttls_capped_at_15_minutes():
    assert TIER_TTL["scoped"] <= 15 * 60
    assert all(v <= MAX_TTL for v in TIER_TTL.values())
    now = [1000.0]
    s = SessionStore(clock=lambda: now[0])
    tok, rec = s.issue("a", "scoped", [C1], ttl=999999)
    assert rec.expires - 1000.0 == MAX_TTL
    assert s.resolve("a", tok) is not None
    assert s.resolve("b", tok) is None           # bound to agent
    now[0] += MAX_TTL + 1
    assert s.resolve("a", tok) is None           # expired


def test_issue_and_use_session_token(env):
    client, path, _ = env
    r = client.post("/v1/tokens/issue", json={"credentials": [C1]},
                    headers={"X-Agent-Id": "plain", "Authorization": "Bearer t-plain"})
    assert r.status_code == 200
    body = r.json()
    assert body["tier"] == "scoped" and body["expires_in"] <= 900
    tok = body["token"]
    assert _fetch(client, "plain", tok, C1).status_code == 200
    assert _fetch(client, "plain", tok, C2).status_code == 403   # outside scope
    # session token cannot mint another
    r2 = client.post("/v1/tokens/issue", json={"credentials": [C1]},
                     headers={"X-Agent-Id": "plain", "Authorization": f"Bearer {tok}"})
    assert r2.status_code == 401
    assert tok not in path.read_text()


def test_issue_scope_must_be_subset(env):
    client, _, _ = env
    r = client.post("/v1/tokens/issue",
                    json={"credentials": ["33333333-3333-3333-3333-333333333333"]},
                    headers={"X-Agent-Id": "plain", "Authorization": "Bearer t-plain"})
    assert r.status_code == 403


def test_high_tier_physical_requires_approval(env):
    client, path, audit = env
    assert _fetch(client, "hi", "t-hi", C1).status_code == 200      # non-physical OK
    assert _fetch(client, "hi", "t-hi", C2).status_code == 403      # physical denied

    r = client.post("/v1/approvals", json={"credential": C2, "purpose": "p"},
                    headers={"X-Agent-Id": "hi", "Authorization": "Bearer t-hi"})
    assert r.status_code == 201
    aid = r.json()["id"]
    assert _fetch(client, "hi", "t-hi", C2, **{"X-Approval-Id": aid}).status_code == 403

    bad = client.post(f"/v1/approvals/{aid}/approve", json={"approver": "alex"},
                      headers={"X-Approver-Token": "wrong"})
    assert bad.status_code == 401
    ok = client.post(f"/v1/approvals/{aid}/approve", json={"approver": "alex"},
                     headers={"X-Approver-Token": "human"})
    assert ok.status_code == 200 and ok.json()["status"] == "approved"

    st = client.get(f"/v1/approvals/{aid}",
                    headers={"X-Agent-Id": "hi", "Authorization": "Bearer t-hi"})
    assert st.json()["status"] == "approved"

    r = _fetch(client, "hi", "t-hi", C2, **{"X-Approval-Id": aid})
    assert r.status_code == 200
    # single use
    assert _fetch(client, "hi", "t-hi", C2, **{"X-Approval-Id": aid}).status_code == 403
    assert audit.verify()
    assert SECRET not in path.read_text()


def test_approval_bound_to_agent(env):
    client, _, _ = env
    aid = client.post("/v1/approvals", json={"credential": C2, "purpose": "p"},
                      headers={"X-Agent-Id": "plain", "Authorization": "Bearer t-plain"}
                      ).json()["id"]
    client.post(f"/v1/approvals/{aid}/approve", json={"approver": "n"},
                headers={"X-Approver-Token": "human"})
    assert _fetch(client, "hi", "t-hi", C2, **{"X-Approval-Id": aid}).status_code == 403


def test_approve_unconfigured_fails_closed(env, monkeypatch):
    client, _, _ = env
    monkeypatch.delenv("CVC_APPROVER_TOKEN_SHA256")
    r = client.post("/v1/approvals/x/approve", json={"approver": "n"},
                    headers={"X-Approver-Token": "human"})
    assert r.status_code == 503


def test_scoped_physical_not_gated(env):
    client, _, _ = env
    assert _fetch(client, "plain", "t-plain", C2).status_code == 200


def test_assistant_dual_attribution(env):
    client, path, audit = env
    assert _fetch(client, "asst", "t-asst", C1).status_code == 200
    assert _fetch(client, "asst", "t-asst", "44444444-4444-4444-4444-444444444444"
                  ).status_code == 403
    recs = _records(path)
    assert all(r["agent"] == "asst" and r["on_behalf_of"] == "alex" for r in recs)
    assert audit.verify()
    assert SECRET not in path.read_text()


def test_assistant_without_obo_denied(env):
    client, _, _ = env
    assert _fetch(client, "asst-noobo", "t-x", C1).status_code == 403


def test_audit_obo_tamper_detected(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    log.record(AuditEvent(agent="a", credential="c", purpose="p", outcome="allow",
                          on_behalf_of="alex"))
    assert log.verify()
    p = tmp_path / "a.jsonl"
    p.write_text(p.read_text().replace("alex", "mallory"))
    assert not log.verify()


# --- low / medium tiers --------------------------------------------------------------

def test_low_medium_tiers_and_ladder():
    from cvc.broker.tiers import tier_rank
    assert normalize_tier("low") == "low"
    assert normalize_tier("MEDIUM") == "medium"
    assert normalize_tier("bogus") == "scoped"
    assert normalize_tier(None) == "scoped"
    assert TIER_TTL == {"scoped": 900, "low": 900, "medium": 600, "high": 300,
                        "assistant": 900}
    assert (tier_rank("scoped") < tier_rank("low") < tier_rank("medium")
            < tier_rank("high"))
    assert tier_rank("assistant") == tier_rank("medium")


def test_medium_session_ttl_capped():
    s = SessionStore(clock=lambda: 0.0)
    _, rec = s.issue("a", "medium", [C1], ttl=9999)
    assert rec.expires == 600
    _, rec = s.issue("a", "low", [C1])
    assert rec.expires == MAX_TTL


def test_acl_tier_low_medium():
    acl = Acl({"agents": {"l": {"tier": "low"}, "m": {"tier": "medium"}, "x": {}}})
    assert acl.tier("l") == "low" and acl.tier("m") == "medium" and acl.tier("x") == "scoped"


# --- require_session_token -----------------------------------------------------------

def _enforce_env(tmp_path, monkeypatch, data):
    acl = Acl(data)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    sessions = SessionStore()
    bw = MagicMock()
    bw.get_item.return_value = {"login": {"password": SECRET}}
    a = app_mod.app
    a.dependency_overrides.update({
        app_mod._acl: lambda: acl, app_mod._audit: lambda: audit, app_mod._bw: lambda: bw,
        app_mod._sessions: lambda: sessions, app_mod._approvals: lambda: ApprovalStore(),
    })
    monkeypatch.setattr(app_mod, "_ops", lambda: MagicMock())
    return TestClient(a, raise_server_exceptions=False)


def _mint(client, agent, tok, creds):
    r = client.post("/v1/tokens/issue", json={"credentials": creds},
                    headers={"X-Agent-Id": agent, "Authorization": f"Bearer {tok}"})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _data(top=False, agent_flag=False):
    agent = {"token_sha256": _sha("t-a"), "tier": "low",
             "allow": [{"credential": C1, "purposes": ["*"]},
                       {"credential": "backup", "purposes": ["*"]}]}
    if agent_flag:
        agent["require_session_token"] = True
    d = {"agents": {"a": agent}}
    if top:
        d["require_session_token"] = True
    return d


@pytest.mark.parametrize("top,agent_flag,envvar", [
    (True, False, False), (False, True, False), (False, False, True)])
def test_require_session_token_rejects_service_token(tmp_path, monkeypatch,
                                                     top, agent_flag, envvar):
    if envvar:
        monkeypatch.setenv("CVC_REQUIRE_SESSION_TOKEN", "1")
    else:
        monkeypatch.delenv("CVC_REQUIRE_SESSION_TOKEN", raising=False)
    client = _enforce_env(tmp_path, monkeypatch, _data(top, agent_flag))
    try:
        assert _fetch(client, "a", "t-a", C1).status_code == 401
        r = client.post("/v1/backup/trigger", json={"purpose": "p"},
                        headers={"X-Agent-Id": "a", "Authorization": "Bearer t-a"})
        assert r.status_code == 401
        sess = _mint(client, "a", "t-a", [C1])
        assert _fetch(client, "a", sess, C1).status_code == 200
        log = (tmp_path / "audit.jsonl").read_text()
        assert sess not in log and SECRET not in log
    finally:
        app_mod.app.dependency_overrides.clear()


def test_require_session_token_default_off(tmp_path, monkeypatch):
    monkeypatch.delenv("CVC_REQUIRE_SESSION_TOKEN", raising=False)
    client = _enforce_env(tmp_path, monkeypatch, _data())
    try:
        assert _fetch(client, "a", "t-a", C1).status_code == 200
    finally:
        app_mod.app.dependency_overrides.clear()
