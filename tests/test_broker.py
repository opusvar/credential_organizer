"""Security-core tests for the broker: default-deny ACL + append-only audit chain.
No FastAPI/network needed — these exercise the enforcement primitives directly.
"""
import hashlib
import json
import threading

import pytest
from fastapi.testclient import TestClient

from cvc.broker.acl import Acl
from cvc.broker.audit import AuditEvent, AuditLog


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _acl() -> Acl:
    return Acl({
        "agents": {
            "a1": {
                "token_sha256": _sha("tok1"),
                "allow": [{"credential": "svc-login", "purposes": ["pay"]}],
            },
            "locked": {"token_sha256": _sha("tok2"), "allow": []},
        }
    })


def test_authenticate():
    acl = _acl()
    assert acl.authenticate("a1", "tok1")
    assert not acl.authenticate("a1", "wrong")
    assert not acl.authenticate("ghost", "tok1")   # unknown agent


def test_authorize_default_deny():
    acl = _acl()
    assert acl.authorize("a1", "svc-login", "pay").allowed          # explicit allow
    assert not acl.authorize("a1", "svc-login", "exfil").allowed    # wrong purpose
    assert not acl.authorize("a1", "other", "pay").allowed          # unlisted credential
    assert not acl.authorize("locked", "svc-login", "pay").allowed  # empty allow list
    assert not acl.authorize("ghost", "svc-login", "pay").allowed   # unknown agent


def test_audit_append_and_verify(tmp_path):
    log = AuditLog(str(tmp_path / "access.jsonl"))
    log.record(AuditEvent(agent="a1", credential="svc-login", purpose="pay", outcome="allow"))
    log.record(AuditEvent(agent="a1", credential="x", purpose="pay", outcome="deny:no allow entry"))
    assert log.verify()

    # Tampering breaks the chain.
    p = tmp_path / "access.jsonl"
    lines = p.read_text().splitlines()
    lines[0] = lines[0].replace('"allow"', '"deny:allow"')
    p.write_text("\n".join(lines) + "\n")
    assert not log.verify()


def test_audit_verify_corrupt_json_line(tmp_path):
    """A non-JSON line in the log must cause verify() to return False, not raise."""
    log = AuditLog(str(tmp_path / "corrupt.jsonl"))
    log.record(AuditEvent(agent="a1", credential="c", purpose="p", outcome="allow"))

    p = tmp_path / "corrupt.jsonl"
    p.write_text(p.read_text() + "NOT JSON\n")

    # Must return False, never raise.
    result = log.verify()
    assert result is False


# ── new: concurrency ──────────────────────────────────────────────────────────

def test_audit_concurrent_writes_verify(tmp_path):
    """Concurrent writers must not corrupt the chain."""
    log = AuditLog(str(tmp_path / "concurrent.jsonl"))
    errors: list[Exception] = []

    def _write(i: int) -> None:
        try:
            log.record(AuditEvent(agent=f"a{i}", credential="cred", purpose="p", outcome="allow"))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_write, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Writer errors: {errors}"
    assert log.verify(), "Chain broken after concurrent writes"


# ── new: ACL — empty purposes → deny; non-UUID credential rejected at load ────

def test_acl_empty_purposes_denies():
    """Empty/None/missing purposes must deny (not implicitly allow any purpose)."""
    acl = Acl({
        "agents": {
            "a1": {
                "token_sha256": _sha("tok"),
                "allow": [
                    {"credential": "svc-login"},               # no purposes key
                    {"credential": "svc2", "purposes": []},    # empty list
                    {"credential": "svc3", "purposes": None},  # null
                    {"credential": "svc4", "purposes": ["*"]}, # wildcard = allowed
                ],
            }
        }
    })
    assert not acl.authorize("a1", "svc-login", "any").allowed
    assert not acl.authorize("a1", "svc2", "any").allowed
    assert not acl.authorize("a1", "svc3", "any").allowed
    assert acl.authorize("a1", "svc4", "any").allowed


def test_acl_non_uuid_credential_rejected_at_load(tmp_path):
    """Acl.load() must raise ValueError for credential entries that aren't UUIDs."""
    acl_yaml = tmp_path / "acl.yaml"
    valid_uuid = "12345678-1234-1234-1234-123456789012"
    acl_yaml.write_text(
        f"agents:\n  a1:\n    token_sha256: abc\n    allow:\n"
        f"      - credential: not-a-uuid\n        purposes: ['p']\n"
    )
    with pytest.raises(ValueError, match="not a UUID"):
        Acl.load(str(acl_yaml))

    # A proper UUID passes.
    acl_yaml.write_text(
        f"agents:\n  a1:\n    token_sha256: abc\n    allow:\n"
        f"      - credential: \"{valid_uuid}\"\n        purposes: ['p']\n"
    )
    Acl.load(str(acl_yaml))  # should not raise


# ── new: broker HTTP — /docs returns 404; /v1/audit/verify requires auth ──────

def _make_app_client(tmp_path):
    """Return a TestClient with a real config pointing at tmp_path."""
    import os
    from unittest.mock import patch

    from cvc import config as cfg_mod
    from cvc.broker.app import app

    # Build a Config by loading from env so we don't need to know all fields.
    import os
    env_patch = {
        "BROKER_ACL": str(tmp_path / "acl.yaml"),
        "AUDIT_LOG": str(tmp_path / "audit.jsonl"),
        "BROKER_BIND": "127.0.0.1",
        "BROKER_PORT": "8710",
    }
    with patch.dict(os.environ, env_patch):
        cfg = cfg_mod.load()
    acl_yaml = tmp_path / "acl.yaml"
    valid_uuid = "12345678-1234-1234-1234-123456789012"
    acl_yaml.write_text(
        f"agents:\n  agent1:\n    token_sha256: {_sha('goodtoken')}\n"
        f"    allow:\n      - credential: \"{valid_uuid}\"\n        purposes: ['*']\n"
    )
    with patch.object(cfg_mod, "load", return_value=cfg), \
         patch.dict(os.environ, env_patch):
        client = TestClient(app, raise_server_exceptions=False)
        yield client, valid_uuid


def test_broker_docs_disabled(tmp_path):
    for url in ("/docs", "/redoc", "/openapi.json"):
        gen = _make_app_client(tmp_path)
        client, _ = next(gen)
        assert client.get(url).status_code == 404, f"{url} should be 404"


def test_broker_audit_verify_requires_auth(tmp_path):
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    # No auth headers
    r = client.get("/v1/audit/verify")
    assert r.status_code in (401, 422)
    # Bad token
    r = client.get("/v1/audit/verify",
                   headers={"x-agent-id": "agent1", "authorization": "Bearer badtoken"})
    assert r.status_code == 401
    # Good token
    r = client.get("/v1/audit/verify",
                   headers={"x-agent-id": "agent1", "authorization": f"Bearer goodtoken"})
    assert r.status_code == 200
    assert r.json()["intact"] is True


def test_broker_body_size_limit(tmp_path):
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    oversized_body = "x" * (9 * 1024)  # 9 KB > 8 KB limit
    r = client.post(
        "/v1/credentials/fetch",
        content=oversized_body,
        headers={
            "x-agent-id": "agent1",
            "authorization": "Bearer goodtoken",
            "content-type": "application/json",
        },
    )
    assert r.status_code == 413


def test_broker_field_length_enforced(tmp_path):
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    r = client.post(
        "/v1/credentials/fetch",
        json={"credential": "x" * 300, "purpose": "p"},
        headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"},
    )
    assert r.status_code == 422


# ── B5: core invariant — audit written before secret returned ─────────────────

def test_fetch_denied_writes_deny_audit(tmp_path):
    """403 deny must be recorded in the audit log with outcome starting 'deny:'."""
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    ungranted = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    r = client.post(
        "/v1/credentials/fetch",
        json={"credential": ungranted, "purpose": "test"},
        headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"},
    )
    assert r.status_code == 403

    audit_path = tmp_path / "audit.jsonl"
    lines = [l for l in audit_path.read_text().splitlines() if l.strip()]
    assert len(lines) == 1, f"Expected 1 audit record, got {len(lines)}"
    rec = json.loads(lines[0])
    assert rec["outcome"].startswith("deny:"), f"Expected deny outcome, got {rec['outcome']!r}"
    assert rec["credential"] == ungranted
    assert rec["agent"] == "agent1"


def test_fetch_allowed_writes_allow_audit_before_vault(tmp_path):
    """Allowed credential: audit record 'allow' is written even if vault returns an error."""
    gen = _make_app_client(tmp_path)
    client, valid_uuid = next(gen)
    r = client.post(
        "/v1/credentials/fetch",
        json={"credential": valid_uuid, "purpose": "test"},
        headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"},
    )
    # Vault isn't available in tests so expect 502 (VaultError) or any non-auth error.
    assert r.status_code not in (401, 403), f"Should not be rejected at auth/authz, got {r.status_code}"

    audit_path = tmp_path / "audit.jsonl"
    lines = [l for l in audit_path.read_text().splitlines() if l.strip()]
    assert len(lines) == 1, f"Expected 1 audit record, got {len(lines)}"
    rec = json.loads(lines[0])
    assert rec["outcome"] == "allow", f"Expected 'allow', got {rec['outcome']!r}"
    assert rec["credential"] == valid_uuid
    assert rec["agent"] == "agent1"


# ── B1 complement: verify() must return False, not raise, on tampered lines ───

@pytest.mark.xfail(
    strict=False,
    reason="BUG: verify() raises KeyError instead of returning False when a required field is missing",
)
def test_verify_missing_field_returns_false_not_raises(tmp_path):
    """Deleting a required field from a valid JSON record must return False, not KeyError."""
    log = AuditLog(str(tmp_path / "chain.jsonl"))
    log.record(AuditEvent(agent="a1", credential="cred", purpose="p", outcome="allow"))

    p = tmp_path / "chain.jsonl"
    rec = json.loads(p.read_text().strip())
    del rec["agent"]  # remove a field that verify() references
    p.write_text(json.dumps(rec) + "\n")

    result = log.verify()
    assert result is False


@pytest.mark.xfail(
    strict=False,
    reason="BUG: verify() raises AttributeError instead of returning False for non-object JSON",
)
def test_verify_non_object_json_returns_false_not_raises(tmp_path):
    """A line with valid non-object JSON (e.g. 123) must return False, not AttributeError."""
    log = AuditLog(str(tmp_path / "chain2.jsonl"))
    log.record(AuditEvent(agent="a1", credential="cred", purpose="p", outcome="allow"))

    p = tmp_path / "chain2.jsonl"
    # Replace the entire log with a non-object JSON value.
    p.write_text("123\n")

    result = log.verify()
    assert result is False


# ── B4: ACL null token_sha256 must return False, not raise TypeError ──────────

@pytest.mark.xfail(
    strict=False,
    reason="BUG: authenticate() raises TypeError when token_sha256 is None",
)
def test_acl_authenticate_null_token_sha256_returns_false():
    """token_sha256: null in ACL must cause authenticate() to return False, not raise."""
    acl = Acl({
        "agents": {
            "a_null": {
                "token_sha256": None,
                "allow": [],
            }
        }
    })
    result = acl.authenticate("a_null", "anytoken")
    assert result is False


def test_acl_authenticate_missing_token_sha256_returns_false():
    """Missing token_sha256 key must cause authenticate() to return False, not raise."""
    acl = Acl({
        "agents": {
            "a_missing": {
                "allow": [],
                # token_sha256 key absent entirely
            }
        }
    })
    result = acl.authenticate("a_missing", "anytoken")
    assert result is False
