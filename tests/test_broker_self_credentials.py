"""Service self-credentials (D27): ACL flag, ownership, fixed purposes, audit."""
import hashlib
import json
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from cvc.broker import app as app_mod
from cvc.broker.acl import SELF_CREDENTIAL_PURPOSES, Acl
from cvc.broker.audit import AuditLog

U1 = "11111111-1111-1111-1111-111111111111"
U2 = "22222222-2222-2222-2222-222222222222"


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _entry(**kw):
    e = {"credential": U1, "self_credentials": True, "owner_agent": "dash",
         "purposes": ["dashboard-login-verify"]}
    e.update(kw)
    return e


def _acl(entry, agent="dash"):
    return Acl({"agents": {agent: {"token_sha256": _sha("tok"), "allow": [entry]}}})


def test_fixed_purpose_list():
    assert {"dashboard-login-verify", "dashboard-confirm-hmac"} <= SELF_CREDENTIAL_PURPOSES


def test_valid_self_credential_allowed():
    d = _acl(_entry()).authorize("dash", U1, "dashboard-login-verify")
    assert d.allowed and d.reason == "self-credential allow"


@pytest.mark.parametrize("entry,purpose", [
    (_entry(owner_agent="other-svc"), "dashboard-login-verify"),   # someone else's item
    (_entry(owner_agent=None), "dashboard-login-verify"),          # no owner tag
    (_entry(purposes=["*"]), "dashboard-login-verify"),            # wildcard
    (_entry(purposes=["exfil"]), "exfil"),                         # not in fixed list
    (_entry(purposes=[]), "dashboard-login-verify"),               # empty
    (_entry(), "dashboard-confirm-hmac"),                          # fixed but not granted
])
def test_self_credential_rejections(entry, purpose):
    assert not _acl(entry).authorize("dash", U1, purpose).allowed


def test_other_principal_secret_denied():
    assert not _acl(_entry()).authorize("dash", U2, "dashboard-login-verify").allowed


@pytest.mark.parametrize("entry", [
    _entry(owner_agent="other-svc"), _entry(owner_agent=None), _entry(purposes=["*"]),
    _entry(purposes=["exfil"]), _entry(purposes=[]), _entry(credential="backup"),
])
def test_load_rejects_bad_self_credential_entries(tmp_path, entry):
    p = tmp_path / "acl.yaml"
    p.write_text(json.dumps({"agents": {"dash": {"token_sha256": "x", "allow": [entry]}}}))
    with pytest.raises(ValueError):
        Acl.load(str(p))


def _client(tmp_path, entry):
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    bw = MagicMock()
    bw.get_item.return_value = {"login": {"password": "hash-value"}}
    app_mod.app.dependency_overrides.update({
        app_mod._acl: lambda: _acl(entry),
        app_mod._audit: lambda: audit,
        app_mod._bw: lambda: bw,
    })
    return TestClient(app_mod.app, raise_server_exceptions=False), tmp_path / "audit.jsonl"


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app_mod.app.dependency_overrides.clear()


def _fetch(client, purpose):
    return client.post("/v1/credentials/fetch",
                       headers={"X-Agent-Id": "dash", "Authorization": "Bearer tok"},
                       json={"credential": U1, "field": "password", "purpose": purpose})


def _records(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def test_fetch_audited_as_self_credential(tmp_path):
    client, log = _client(tmp_path, _entry())
    r = _fetch(client, "dashboard-login-verify")
    assert r.status_code == 200 and r.json()["value"] == "hash-value"
    assert _records(log)[-1]["outcome"] == "allow:self-credential"


def test_fetch_wrong_owner_denied_and_audited(tmp_path):
    client, log = _client(tmp_path, _entry(owner_agent="other-svc"))
    assert _fetch(client, "dashboard-login-verify").status_code == 403
    assert _records(log)[-1]["outcome"].startswith("deny:")


def test_fetch_unlisted_purpose_denied(tmp_path):
    client, log = _client(tmp_path, _entry())
    assert _fetch(client, "dashboard-confirm-hmac").status_code == 403
    assert _records(log)[-1]["outcome"].startswith("deny:")
