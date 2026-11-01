"""ETag visibility: history, check-etag, owner-only debug endpoints, rejection log."""
import json

import pytest
from fastapi.testclient import TestClient

from cvc.approvals import cli
from cvc.approvals import inspect as insp_mod
from cvc.approvals.model import new_request
from cvc.approvals.service import ApprovalService
from cvc.broker import app as app_mod
from cvc.broker.tiers import ApprovalStore

OWNER = {"X-Cvc-Person": "alex", "X-Cvc-Tier": "owner", "X-Real-Ip": "100.64.1.2"}


class Pub:
    def __init__(self):
        self.msgs = []

    def publish(self, topic, payload, retain):
        self.msgs.append((topic, payload, retain))


def _req(**kw):
    return new_request(agent="hi", agent_tier="high", intent="read x", summary="read x",
                       if_approved="reads", if_denied="nothing", data="internal",
                       action="read", **kw)


@pytest.fixture
def svc(tmp_path):
    s = ApprovalService(publisher=Pub(), state_path=str(tmp_path / "approvals.json"))
    insp_mod.attach(s)
    return s


def test_history_grows_on_each_event(svc):
    r = svc.submit(_req())
    insp = insp_mod.attach(svc)
    assert [h["event"] for h in insp.history(r.id)] == ["created"]
    svc.decide(r.id, "approve", person="alex", tier="owner")
    h = insp.history(r.id)
    assert [x["event"] for x in h] == ["created", "decided"]
    assert h[-1]["version"] == 2 and h[-1]["actor"] == "alex" and h[-1]["status"] == "approved"
    assert h[-1]["etag"] == svc.get(r.id).etag and h[-1]["mqtt_published_at"]
    r2 = svc.submit(_req())
    svc.cancel(r2.id, "hi")
    assert insp.history(r2.id)[-1]["event"] == "cancelled"
    r3 = svc.submit(_req())
    svc.record_external(r3.id, "approved", "alex")
    assert insp.history(r3.id)[-1]["event"] == "legacy-approve"
    # persisted in the sidecar: a fresh inspector sees the same history
    other = insp_mod.attach(ApprovalService(state_path=str(svc.state_path)))
    assert len(other.history(r.id)) == 2


def test_expiry_recorded(tmp_path):
    from datetime import timedelta

    from cvc.approvals.model import now_utc
    t = [now_utc()]
    s = ApprovalService(publisher=Pub(), clock=lambda: t[0])
    insp = insp_mod.attach(s)
    r = s.submit(_req(now=t[0], deadline_s=60))
    t[0] += timedelta(minutes=2)
    s.sweep()
    assert insp.history(r.id)[-1]["event"] == "expired"
    assert insp.history(r.id)[-1]["actor"] == "system"


def test_check_etag_current_stale_unknown(svc, capsys):
    r = svc.submit(_req())
    v1 = r.etag
    svc.decide(r.id, "deny", person="alex", tier="owner")
    insp = insp_mod.attach(svc)
    assert insp.check_etag(r.id, svc.get(r.id).etag)["result"] == "current"
    st = insp.check_etag(r.id, v1)
    assert st["result"] == "stale" and st["was"]["event"] == "created"
    assert [c["event"] for c in st["changes_since"]] == ["decided"]
    assert insp.check_etag(r.id, '"other.v1"')["result"] == "unknown"
    assert insp.check_etag(r.id, f'"{r.id}.v9"')["result"] == "unknown"
    assert insp.check_etag("nope", '"nope.v1"')["result"] == "unknown"
    state = str(svc.state_path)
    assert cli.main(["--state", state, "check-etag", r.id, v1, "--json"]) == 3
    assert json.loads(capsys.readouterr().out)["result"] == "stale"
    assert cli.main(["--state", state, "etag", r.id, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["version"] == 2
    assert cli.main(["--state", state, "history", r.id]) == 0
    assert "decided" in capsys.readouterr().out
    snap = svc.state_path.with_name("snap.json")
    snap.write_text(json.dumps({f"cvc/approvals/{r.id}": json.dumps({"version": 1,
                                                                   "status": "pending"}),
                               "cvc/approvals/ghost": "{}"}))
    assert cli.main(["--state", state, "diag", "--json", "--mqtt-snapshot", str(snap)]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["counts"] == {"denied": 1}
    assert {m["kind"] for m in d["mqtt_mismatches"]} == {"stale-retained", "orphan-retained"}


@pytest.fixture
def client(svc, tmp_path, monkeypatch):
    a = app_mod.app
    a.dependency_overrides.update({app_mod._approval_service: lambda: svc,
                                   app_mod._approvals: lambda: ApprovalStore()})
    monkeypatch.setattr(app_mod, "_approval_service", lambda: svc)
    monkeypatch.setattr(app_mod, "_NONCES", app_mod._NonceStore())
    monkeypatch.setenv("CVC_TRUST_TIERGATE", "1")
    monkeypatch.setenv("CVC_DASHBOARD_ORIGIN", "https://dash.example.ts.net")
    yield TestClient(a, raise_server_exceptions=False)
    a.dependency_overrides.clear()


def test_endpoints_owner_only_and_tailnet(client, svc):
    r = svc.submit(_req())
    for path in (f"/v1/approvals/{r.id}/etag", f"/v1/approvals/{r.id}/history",
                 "/v1/approvals/diag"):
        assert client.get(path, headers=OWNER).status_code == 200, path
        assert client.get(path, headers={**OWNER, "X-Cvc-Tier": "admin"}).status_code == 403
        assert client.get(path, headers={**OWNER, "X-Real-Ip": "10.0.0.5"}).status_code == 403
        assert client.get(path, headers={**OWNER, "Origin": "https://evil.example"}
                          ).status_code == 403
    assert client.get(f"/v1/approvals/{r.id}/etag", headers=OWNER).json()["etag"] == r.etag
    assert client.get("/v1/approvals/missing/etag", headers=OWNER).status_code == 404


def test_rejection_log_and_no_nonce_values(client, svc):
    r = svc.submit(_req())
    hdr = {"X-Cvc-Person": "alex", "X-Cvc-Tier": "owner"}
    nonces = []
    for if_match, code in ((None, 428), (f'"{r.id}.v7"', 412), ('"x.v1"', 412)):
        n = client.get("/v1/approvals/nonce", headers=hdr).json()["nonce"]
        nonces.append(n)
        h = dict(hdr)
        if if_match:
            h["If-Match"] = if_match
        resp = client.post(f"/v1/approvals/{r.id}/decide", headers=h,
                           json={"decision": "approve", "nonce": n})
        assert resp.status_code == code
    d = client.get("/v1/approvals/diag", headers=OWNER).json()
    rej = d["recent_rejections"]
    assert [x["code"] for x in rej] == [428, 412, 412]
    assert rej[1]["presented_etag"] == f'"{r.id}.v7"' and rej[1]["current_etag"] == r.etag
    assert all(x["person"] == "alex" and x["id"] == r.id for x in rej)
    assert d["nonces_global"]["issued_count"] == 3
    info = client.get(f"/v1/approvals/{r.id}/etag", headers=OWNER).json()
    assert info["nonces"]["consumed_count"] == 1      # only the 412-from-service call
    dump = svc.state_path.with_name(svc.state_path.name + ".inspect.json").read_text()
    dump += json.dumps(d) + json.dumps(info)
    assert not any(n in dump for n in nonces)


def test_rejection_ring_is_bounded(svc):
    insp = insp_mod.attach(svc)
    for i in range(insp_mod.REJECTIONS_MAX + 5):
        insp.record_rejection("x", 412, f'"x.v{i}"', "alex")
    rej = insp.snapshot()["rejections"]
    assert len(rej) == insp_mod.REJECTIONS_MAX and rej[-1]["presented_etag"].endswith(
        f'v{insp_mod.REJECTIONS_MAX + 4}"')
