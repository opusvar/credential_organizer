"""Security-core tests for the broker: default-deny ACL + append-only audit chain.
No FastAPI/network needed — these exercise the enforcement primitives directly.
"""
import hashlib

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
