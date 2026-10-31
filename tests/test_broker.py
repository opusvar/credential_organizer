"""Security-core tests for the broker: default-deny ACL + append-only audit chain.
No FastAPI/network needed — these exercise the enforcement primitives directly.
"""
import hashlib
import json
import subprocess
import sys
import threading
from unittest.mock import MagicMock, patch

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
    assert r.status_code == 200, r.text
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


# ── POST /v1/backup/trigger (D9 on-demand backup) ─────────────────────────────
#
# subprocess.run is patched in the app module for every test that gets past authz, so no
# `cvc.backup` child process, `bw` invocation, or onedrive sync ever runs.

def _grant_backup(tmp_path, purposes='["manual-trigger", "scheduled"]') -> None:
    """Rewrite the ACL from _make_app_client to also grant the "backup" capability.

    Safe to call after the client exists: the _acl() dependency re-reads the file on every
    request. Also asserts the non-UUID sentinel survives Acl.load()'s UUID validation.
    """
    valid_uuid = "12345678-1234-1234-1234-123456789012"
    (tmp_path / "acl.yaml").write_text(
        f"agents:\n  agent1:\n    token_sha256: {_sha('goodtoken')}\n"
        f"    allow:\n      - credential: \"{valid_uuid}\"\n        purposes: ['*']\n"
        f"      - credential: \"backup\"\n        purposes: {purposes}\n"
    )


def _fake_completed(returncode=0, stdout="backup: exported to /backups/b.json\n", stderr=""):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def test_backup_trigger_requires_auth(tmp_path):
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    _grant_backup(tmp_path)

    with patch("cvc.broker.app.subprocess.run") as run:
        # No headers at all — FastAPI rejects the missing required headers.
        r = client.post("/v1/backup/trigger", json={"purpose": "manual-trigger"})
        assert r.status_code in (401, 422), r.status_code

        # Known agent, wrong token.
        r = client.post(
            "/v1/backup/trigger",
            json={"purpose": "manual-trigger"},
            headers={"x-agent-id": "agent1", "authorization": "Bearer badtoken"},
        )
        assert r.status_code == 401

        # Unknown agent.
        r = client.post(
            "/v1/backup/trigger",
            json={"purpose": "manual-trigger"},
            headers={"x-agent-id": "ghost", "authorization": "Bearer goodtoken"},
        )
        assert r.status_code == 401

    # The core invariant: an unauthenticated caller must never start a backup.
    run.assert_not_called()


def test_backup_trigger_runs_backup_subprocess(tmp_path):
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    _grant_backup(tmp_path)

    with patch("cvc.broker.app.subprocess.run", return_value=_fake_completed()) as run:
        r = client.post(
            "/v1/backup/trigger",
            json={"purpose": "manual-trigger"},
            headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"},
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["triggered"] is True
    assert body["exit_code"] == 0
    assert "exported to" in body["log"]

    run.assert_called_once()
    argv = run.call_args[0][0]
    # Run as a module via the current interpreter — not a shell string, not `cvc-backup`
    # off PATH, so the broker's own venv is what executes the pipeline.
    assert argv[1:] == ["-m", "cvc.backup"]
    assert argv[0] == sys.executable
    kwargs = run.call_args[1]
    assert kwargs["timeout"] == 600, "must outlive a multi-minute bw export"
    assert kwargs["capture_output"] is True
    assert "BACKUP_DIR" in kwargs["env"]


def test_backup_trigger_returns_200_even_on_backup_failure(tmp_path):
    """200 means the TRIGGER worked; the backup's own result is in exit_code."""
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    _grant_backup(tmp_path)

    failed = _fake_completed(returncode=1, stdout="", stderr="ERROR: vault auth failed")
    with patch("cvc.broker.app.subprocess.run", return_value=failed):
        r = client.post(
            "/v1/backup/trigger",
            json={"purpose": "scheduled"},
            headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"},
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["triggered"] is True
    assert body["exit_code"] == 1
    # stderr can carry `bw` diagnostics — it must not be echoed to the caller.
    assert "vault auth failed" not in r.text


def test_backup_trigger_acl_deny(tmp_path):
    """An agent without the backup capability gets 403 and starts no subprocess."""
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    # Default ACL from _make_app_client grants only the test UUID — no "backup" entry.

    with patch("cvc.broker.app.subprocess.run") as run:
        r = client.post(
            "/v1/backup/trigger",
            json={"purpose": "manual-trigger"},
            headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"},
        )

    assert r.status_code == 403, r.text
    run.assert_not_called()

    # The deny must be on the record before anything else happens.
    lines = [l for l in (tmp_path / "audit.jsonl").read_text().splitlines() if l.strip()]
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["outcome"].startswith("deny:")
    assert rec["credential"] == "backup"


def test_backup_trigger_denies_unlisted_purpose(tmp_path):
    """Purpose-bound: the capability is granted, but not for this purpose."""
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    _grant_backup(tmp_path, purposes='["scheduled"]')

    with patch("cvc.broker.app.subprocess.run") as run:
        r = client.post(
            "/v1/backup/trigger",
            json={"purpose": "manual-trigger"},
            headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"},
        )
    assert r.status_code == 403, r.text
    run.assert_not_called()


def test_backup_trigger_audits_allow_before_running(tmp_path):
    """Same invariant as a credential fetch: the grant is recorded before the vault is touched."""
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    _grant_backup(tmp_path)

    audit_path = tmp_path / "audit.jsonl"

    def _assert_audited_first(*a, **k):
        lines = [l for l in audit_path.read_text().splitlines() if l.strip()]
        assert len(lines) == 1, "audit record must exist before the backup starts"
        assert json.loads(lines[0])["outcome"] == "allow"
        return _fake_completed()

    with patch("cvc.broker.app.subprocess.run", side_effect=_assert_audited_first):
        r = client.post(
            "/v1/backup/trigger",
            json={"purpose": "manual-trigger"},
            headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"},
        )
    assert r.status_code == 200, r.text

    rec = json.loads(audit_path.read_text().splitlines()[0])
    assert rec == {**rec, "agent": "agent1", "credential": "backup",
                   "purpose": "manual-trigger", "outcome": "allow"}


def test_backup_trigger_503_when_subprocess_cannot_start(tmp_path):
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    _grant_backup(tmp_path)

    with patch("cvc.broker.app.subprocess.run", side_effect=OSError("fork failed")):
        r = client.post(
            "/v1/backup/trigger",
            json={"purpose": "manual-trigger"},
            headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"},
        )
    assert r.status_code == 503, r.text
    assert "fork failed" not in r.text


def test_backup_trigger_504_on_timeout(tmp_path):
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    _grant_backup(tmp_path)

    timeout = subprocess.TimeoutExpired(cmd="cvc.backup", timeout=600)
    with patch("cvc.broker.app.subprocess.run", side_effect=timeout):
        r = client.post(
            "/v1/backup/trigger",
            json={"purpose": "manual-trigger"},
            headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"},
        )
    assert r.status_code == 504, r.text


def test_acl_backup_sentinel_loads_but_other_non_uuids_still_rejected(tmp_path):
    """The sentinel exemption must be a closed allowlist, not a hole in the UUID rule."""
    acl_yaml = tmp_path / "sentinel-acl.yaml"

    acl_yaml.write_text(
        "agents:\n  a1:\n    token_sha256: abc\n    allow:\n"
        "      - credential: \"backup\"\n        purposes: ['manual-trigger']\n"
    )
    acl = Acl.load(str(acl_yaml))  # must not raise
    assert acl.authorize("a1", "backup", "manual-trigger").allowed
    assert not acl.authorize("a1", "backup", "exfil").allowed

    # A different non-UUID string is still a load-time error.
    acl_yaml.write_text(
        "agents:\n  a1:\n    token_sha256: abc\n    allow:\n"
        "      - credential: \"restore\"\n        purposes: ['p']\n"
    )
    with pytest.raises(ValueError, match="not a UUID"):
        Acl.load(str(acl_yaml))


# ── /readyz — vault-touching readiness probe ───────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_readyz_cache(monkeypatch):
    """The /readyz TTL cache is a module global — reset it before every test so
    results don't leak between tests regardless of run order."""
    import cvc.broker.app as app_mod
    monkeypatch.setattr(app_mod, "_readyz_cache", None)
    monkeypatch.setattr(app_mod, "_readyz_last_reported", None)


def test_readyz_ready_when_unlocked(tmp_path, monkeypatch):
    import cvc.broker.app as app_mod

    monkeypatch.setattr(app_mod, "_session", lambda: "fake-session-key")
    monkeypatch.setattr(app_mod, "_run", lambda *a, **k: json.dumps({"status": "unlocked"}))

    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    r = client.get("/readyz")
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "ready", "vault": "unlocked"}
    assert r.headers["cache-control"] == "no-store"


def test_readyz_not_ready_when_locked(tmp_path, monkeypatch):
    import cvc.broker.app as app_mod

    monkeypatch.setattr(app_mod, "_session", lambda: "fake-session-key")
    monkeypatch.setattr(app_mod, "_run", lambda *a, **k: json.dumps({"status": "locked"}))

    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "not ready", "vault": "locked"}


def test_readyz_vault_unreachable_on_vault_error(tmp_path, monkeypatch):
    import cvc.broker.app as app_mod
    from cvc.vault.client import VaultError

    monkeypatch.setattr(app_mod, "_session", lambda: "fake-session-key")

    def _raise(*a, **k):
        raise VaultError("vault command failed")

    monkeypatch.setattr(app_mod, "_run", _raise)

    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "not ready", "vault": "vault-unreachable"}


def test_readyz_session_missing(tmp_path, monkeypatch):
    import cvc.broker.app as app_mod
    from cvc.vault.client import VaultError

    def _raise():
        raise VaultError("BW_SESSION not set — run `bw unlock` and export the session key")

    monkeypatch.setattr(app_mod, "_session", _raise)

    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "not ready", "vault": "session-missing"}


def test_readyz_requires_no_auth(tmp_path, monkeypatch):
    """/readyz must be reachable with no headers at all — kubelet cannot present credentials."""
    import cvc.broker.app as app_mod

    monkeypatch.setattr(app_mod, "_session", lambda: "fake-session-key")
    monkeypatch.setattr(app_mod, "_run", lambda *a, **k: json.dumps({"status": "unlocked"}))

    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    r = client.get("/readyz")  # no x-agent-id, no authorization header
    assert r.status_code == 200, r.text


# ── F11: measured body limit, backup single-flight, stderr logging ────────────

def _chunks(*parts):
    def gen():
        for p in parts:
            yield p
    return gen()


def test_body_limit_chunked_oversize_413(tmp_path):
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    r = client.post(
        "/v1/credentials/fetch",
        content=_chunks(b"x" * 5000, b"x" * 5000),  # no Content-Length (chunked)
        headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken",
                 "content-type": "application/json"},
    )
    assert r.status_code == 413


def test_body_limit_chunked_small_body_passes_through(tmp_path):
    gen = _make_app_client(tmp_path)
    client, valid_uuid = next(gen)
    body = json.dumps({"credential": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "purpose": "t"}).encode()
    r = client.post(
        "/v1/credentials/fetch",
        content=_chunks(body[:10], body[10:]),
        headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken",
                 "content-type": "application/json"},
    )
    assert r.status_code == 403, r.text  # body was re-injected and parsed; ACL denied


def test_backup_trigger_logs_redacted_stderr_tail(tmp_path, caplog):
    import logging
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    _grant_backup(tmp_path)
    stderr = "boom: export failed\nBW_SESSION=abc123\nmaster password wrong\n" + "z" * 5000
    with patch("cvc.broker.app.subprocess.run",
               return_value=_fake_completed(returncode=1, stdout="", stderr=stderr)), \
         caplog.at_level(logging.WARNING, logger="cvc.broker.app"):
        r = client.post("/v1/backup/trigger", json={"purpose": "scheduled"},
                        headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"})
    assert r.status_code == 200, r.text
    text = "\n".join(rec.getMessage() for rec in caplog.records if rec.levelno == logging.WARNING)
    assert "backup_trigger_failed" in text
    assert "abc123" not in text and "password" not in text
    assert len(text) < 900


def test_backup_trigger_single_flight_409(tmp_path):
    from cvc.broker import app as app_mod
    gen = _make_app_client(tmp_path)
    client, _ = next(gen)
    _grant_backup(tmp_path)
    assert app_mod._backup_lock.acquire(blocking=False)
    try:
        with patch("cvc.broker.app.subprocess.run") as run:
            r = client.post("/v1/backup/trigger", json={"purpose": "scheduled"},
                            headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"})
        run.assert_not_called()
    finally:
        app_mod._backup_lock.release()
    assert r.status_code == 409, r.text
    assert "already in progress" in r.json()["detail"]
    recs = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines() if l.strip()]
    assert recs[-1]["outcome"] == "deny:busy"
    # lock released: next call proceeds
    with patch("cvc.broker.app.subprocess.run", return_value=_fake_completed()):
        r = client.post("/v1/backup/trigger", json={"purpose": "scheduled"},
                        headers={"x-agent-id": "agent1", "authorization": "Bearer goodtoken"})
    assert r.status_code == 200, r.text
