"""Tests for the D24 audit admin process (cvc.audit). All data synthetic."""
from __future__ import annotations

import datetime as dt
import json
import os

import pytest
import yaml

from cvc.audit import checks as C
from cvc.audit.cli import main, run
from cvc.audit.findings import (
    SCHEMA,
    Finding,
    StateFile,
    assert_no_secrets,
    finding_id,
    merge,
)
from cvc.audit.publish import SUMMARY_TOPIC, MqttPublisher, build_messages
from cvc.broker.audit import AuditEvent, AuditLog

NOW = dt.datetime(2026, 11, 1, 12, 0, tzinfo=dt.UTC)
FP = "ab" * 32


def _key(owner, serial, status="active", role=None):
    k = {"owner": owner, "model": "YubiKey 5C", "serial": serial, "uses": ["piv-device-cert"],
         "location": "on-person", "enrolled": dt.date(2026, 10, 1), "status": status}
    if role:
        k["role"] = role
    return k


def _dev(owner, status="active", hk=None, history=None):
    d = {"owner": owner, "kind": "phone", "roles": ["svc"],
         "cert": {"storage": "yubikey-piv" if hk else "p12", "hardware_key": hk,
                  "serial": "0a1b", "fingerprint_sha256": FP,
                  "not_after": dt.date(2027, 6, 1), "status": status}}
    if history:
        d["history"] = history
    return d


def base() -> dict:
    return {
        "version": 1,
        "systems": {"workers": {"kind": "http"}},
        "roles": {"svc": {"grants": [{"system": "workers", "paths": ["/"]}]}},
        "agents": {},
        "people": {
            "alex": {"email": "alex@local", "tier": "owner",
                     "history": [{"date": dt.date(2026, 10, 30),
                                  "event": "passwordless-block"}]},
            "gina": {"email": "gina@local", "tier": "guest-short", "granted_by": "alex",
                     "expires": dt.date(2026, 10, 20)},
        },
        "hardware_keys": {"yk-alex": _key("alex", 111, role="primary")},
        "devices": {
            "gina-phone": _dev("gina"),
            "alex-old": _dev("alex", history=[{"date": dt.date(2026, 10, 1), "event": "lost"}]),
            "alex-ok": _dev("alex"),
        },
    }


@pytest.fixture
def reg(tmp_path):
    p = tmp_path / "registry.yaml"
    p.write_text(yaml.safe_dump(base(), sort_keys=False))
    return p


def ctx(**kw) -> C.Context:
    kw.setdefault("run", lambda args: "Result=success\nExecMainStatus=0\nActiveState=inactive\n")
    return C.Context(now=NOW, **kw)


def by(findings, check):
    return [f for f in findings if f.check == check]


# ── ids / state ────────────────────────────────────────────────────────────
def test_stable_ids():
    a = Finding("devices", "devices.x", "error", "one wording")
    b = Finding("devices", "devices.x", "warn", "another wording")
    assert a.id == b.id == finding_id("devices", "devices.x")
    assert a.id != Finding("guests", "devices.x", "warn", "t").id
    d = a.to_dict()
    assert d["schema"] == SCHEMA and d["id"] == a.id and "subject" not in d
    assert set(d) == {"schema", "id", "check", "severity", "title", "detail", "suggested_fix",
                      "first_seen", "last_seen", "status"}


def test_bad_severity():
    with pytest.raises(ValueError):
        Finding("x", "y", "warning", "t")


def test_merge_first_seen_and_resolve(tmp_path):
    st = StateFile(tmp_path / "s" / "findings.json")
    m1 = merge(st.load(), [Finding("c", "a", "warn", "A"), Finding("c", "b", "info", "B")], "t1")
    st.save(m1, "t1")
    assert oct(st.path.stat().st_mode & 0o777) == "0o600"
    m2 = merge(st.load(), [Finding("c", "a", "warn", "A")], "t2")
    a, b = m2[finding_id("c", "a")], m2[finding_id("c", "b")]
    assert (a["first_seen"], a["last_seen"], a["status"]) == ("t1", "t2", "open")
    assert (b["status"], b["last_seen"], b["first_seen"]) == ("resolved", "t2", "t1")
    m3 = merge(m2, [Finding("c", "b", "info", "B")], "t3")   # reopened -> new first_seen
    assert m3[finding_id("c", "b")]["first_seen"] == "t3"
    assert m3[finding_id("c", "a")]["status"] == "resolved"


# ── checks ─────────────────────────────────────────────────────────────────
def test_registry_check(reg, tmp_path):
    f = C.registry_check(ctx(registry_path=str(reg)))
    assert f and all(x.check == "registry" for x in f)
    assert any(x.severity == "warn" and "owner hardware key" in x.title for x in f)
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nsystems: {x: {kind: nope}}\n")
    [e] = C.registry_check(ctx(registry_path=str(bad)))
    assert e.severity == "error" and "invalid" in e.title
    [w] = C.registry_check(ctx())
    assert w.severity == "warn"


def test_guests_check(reg):
    f = C.guests_check(ctx(registry_path=str(reg)))
    subj = {x.subject: x for x in f}
    assert subj["people.gina:expired"].severity == "warn"
    left = subj["people.gina:leftovers"]
    assert left.severity == "error" and "gina-phone" in left.detail


def test_guests_checked_out_clean(tmp_path):
    d = base()
    d["people"]["gina"]["status"] = "checked-out"
    del d["devices"]["gina-phone"]
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(d))
    assert C.guests_check(ctx(registry_path=str(p))) == []


def test_devices_check(reg):
    [f] = C.devices_check(ctx(registry_path=str(reg)))
    assert f.subject == "devices.alex-old" and f.severity == "error" and "lost" in f.title


def test_devices_suspended_key_not_flagged():
    from cvc.access.model import parse_registry
    d = base()
    d["hardware_keys"]["yk-2"] = _key("alex", 222, status="suspended")
    d["devices"]["alex-mac"] = _dev("alex", hk="yk-2")
    r = parse_registry(d)
    assert [f.subject for f in C.devices_check(ctx(_registry=r))] == ["devices.alex-old"]


def test_owner_keys_check(reg, tmp_path):
    [w] = C.owner_keys_check(ctx(registry_path=str(reg)))
    assert w.severity == "warn"
    d = base()
    d["hardware_keys"]["yk-alex"]["status"] = "lost"
    d["devices"]["alex-mac"] = {"owner": "alex", "kind": "laptop", "roles": ["svc"]}
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(d))
    from cvc.access.model import parse_registry
    [e] = C.owner_keys_check(ctx(_registry=parse_registry(d)))
    assert e.severity == "error"
    d["hardware_keys"]["yk-b"] = _key("alex", 333)
    d["hardware_keys"]["yk-c"] = _key("alex", 444)
    assert C.owner_keys_check(ctx(_registry=parse_registry(d))) == []


def test_rotation_check_counts_names_no_secrets():
    old = "2025-01-01T00:00:00.000Z"
    items = [
        {"type": 1, "name": "Old Site", "login": {"password": "hunter2-hunter2",
                                                  "passwordRevisionDate": old}},
        {"type": 1, "name": "Fresh", "login": {"password": "x" * 20,
                                               "passwordRevisionDate": "2026-10-01T00:00:00Z"}},
        {"type": 1, "name": "Created old", "creationDate": old,
         "revisionDate": "2026-10-31T00:00:00Z", "login": {"password": "p" * 20}},
        {"type": 1, "name": "No password", "creationDate": old, "login": {}},
        {"type": 2, "name": "Note", "creationDate": old},
    ]
    [f] = C.rotation_check(ctx(vault_items=lambda: items))
    assert "2 credentials" in f.title and "Old Site" in f.detail and "Created old" in f.detail
    assert "hunter2" not in json.dumps(f.to_dict())
    assert C.rotation_check(ctx()) == []                       # no source -> skipped

    def boom():
        raise RuntimeError("BW_SESSION=abc")
    [e] = C.rotation_check(ctx(vault_items=boom))
    assert "abc" not in json.dumps(e.to_dict())


def _seed_takeover(state, initiated):
    from cvc.takeover.model import TakeoverRecord, TakeoverStore
    rec = TakeoverRecord(id="to-1", initiator="alice", target="alex", initiated_at=initiated,
                         initiator_cert_fingerprint=FP, initiator_key="yk-alice",
                         target_key="yk-alex", elevation_method="passkey",
                         vw_view_grant="g1", vw_takeover_grant="g2")
    TakeoverStore(state).save(rec, "initiated", "alice", NOW)


def _seed_delegation(state):
    from cvc.delegate.model import DelegationRecord, DelegationStore
    rec = DelegationRecord(id="dg-1", delegator="alex", recipient="alice",
                           started_at=(NOW - dt.timedelta(hours=1)).isoformat(),
                           delegator_cert_fingerprint=FP, factor="passkey",
                           elevation_method="passkey", sections=["s"], preview=[])
    DelegationStore(state).save(rec, "started", "alex", NOW)


def test_takeovers_check(tmp_path):
    _seed_takeover(tmp_path / "to", (NOW - dt.timedelta(days=20)).isoformat())
    _seed_delegation(tmp_path / "dg")
    before = sorted(os.listdir(tmp_path / "to"))
    f = C.takeovers_check(ctx(takeover_dir=str(tmp_path / "to"), delegate_dir=str(tmp_path / "dg")))
    s = {x.subject: x for x in f}
    assert "70 days left" in s["takeover.to-1"].detail and "viewer" in s["takeover.to-1"].detail
    assert "delegation.dg-1" in s
    assert sorted(os.listdir(tmp_path / "to")) == before        # read-only
    (tmp_path / "to" / "history.jsonl").write_text('{"tampered": true}\n')
    f = C.takeovers_check(ctx(takeover_dir=str(tmp_path / "to")))
    assert any(x.subject == "takeover:history" for x in f)
    assert C.takeovers_check(ctx(takeover_dir=str(tmp_path / "none"))) == []


def test_passwordless_check(reg):
    [f] = C.passwordless_check(ctx(registry_path=str(reg)))
    assert "alex" in f.title and "5 days left" in f.detail
    later = C.Context(now=NOW + dt.timedelta(days=10), registry_path=str(reg))
    assert C.passwordless_check(later) == []


def test_backup_check(tmp_path):
    bd = tmp_path / "b"
    bd.mkdir()
    calls = []

    def ok(args):
        calls.append(args)
        return "Result=success\nExecMainStatus=0\n"
    [e] = C.backup_check(ctx(backup_dir=str(bd), run=ok))
    assert e.subject == "backup:files" and "No backup" in e.title
    assert calls[0][:3] == ["systemctl", "--user", "show"]
    f = bd / "export.json.enc"
    f.write_text("x")
    old = NOW.timestamp() - 10 * 86400
    os.utime(f, (old, old))
    [e] = C.backup_check(ctx(backup_dir=str(bd), run=ok))
    assert "stale" in e.title
    os.utime(f, (NOW.timestamp(), NOW.timestamp()))
    assert C.backup_check(ctx(backup_dir=str(bd), run=ok)) == []
    [e] = C.backup_check(ctx(backup_dir=str(bd), run=lambda a: "Result=exit-code\n"
                                                                 "ExecMainStatus=1\n"))
    assert e.subject == "backup:unit" and e.severity == "error"
    [w] = C.backup_check(ctx(backup_dir=str(bd), run=lambda a: ""))
    assert w.severity == "warn"


def test_broker_audit_check(tmp_path):
    p = tmp_path / "access.jsonl"
    log = AuditLog(str(p))
    ts = (NOW - dt.timedelta(minutes=5)).isoformat()
    for _ in range(3):
        log.record(AuditEvent("bad-agent", "github", "x", "deny:acl", ts=ts))
    log.record(AuditEvent("bad-agent", "github", "x", "deny:acl",
                          ts=(NOW - dt.timedelta(hours=3)).isoformat()))
    log.record(AuditEvent("good", "github", "x", "allow", ts=ts))
    assert C.broker_audit_check(ctx(audit_log=str(p), deny_threshold=4)) == []
    [f] = C.broker_audit_check(ctx(audit_log=str(p), deny_threshold=3))
    assert f.subject == "broker_audit:deny:bad-agent" and "3 denials" in f.detail
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:1] + lines[2:]) + "\n")       # delete a line
    f = C.broker_audit_check(ctx(audit_log=str(p), deny_threshold=99))
    assert [x.subject for x in f] == ["broker_audit:chain"]
    assert C.broker_audit_check(ctx(audit_log=str(tmp_path / "missing"))) == []
    assert not (tmp_path / "missing").exists()


def test_crashing_check_is_contained(monkeypatch):
    def bad(c):
        raise KeyError("x")
    monkeypatch.setitem(C.CHECKS, "bad", bad)
    [f] = C.run_checks(ctx(), ["bad"])
    assert f.severity == "error" and f.subject == "bad:crash"


# ── publishing ─────────────────────────────────────────────────────────────
class FakePublisher:
    def __init__(self):
        self.msgs = []

    def publish(self, messages):
        self.msgs += messages


def test_run_publishes_and_payloads_have_no_secrets(reg, tmp_path):
    pub = FakePublisher()
    st = StateFile(tmp_path / "f.json")
    c = ctx(registry_path=str(reg), backup_dir=str(tmp_path),
            vault_items=lambda: [{"type": 1, "name": "Old", "login": {
                "password": "S3cretPassw0rd!", "passwordRevisionDate": "2024-01-01T00:00:00Z"}}])
    merged, _ = run(c, st, pub)
    topics = dict(pub.msgs)
    assert "homeassistant/sensor/cvc_audit_open/config" in topics
    disc = json.loads(topics["homeassistant/sensor/cvc_audit_open/config"])
    assert disc["unique_id"] == "cvc_audit_open" and disc["state_topic"] == SUMMARY_TOPIC
    s = json.loads(topics[SUMMARY_TOPIC])
    assert s["open"]["error"] >= 2 and s["last_run"] == NOW.isoformat(timespec="seconds")
    assert set(s["open"]) == {"info", "warn", "error"}
    for fid in merged:
        assert json.loads(topics[f"cvc/audits/{fid}"])["schema"] == SCHEMA
    blob = json.dumps(pub.msgs)
    assert "S3cretPassw0rd" not in blob and FP not in blob
    assert st.path.exists()


def test_dry_run_writes_nothing(reg, tmp_path):
    pub = FakePublisher()
    st = StateFile(tmp_path / "f.json")
    run(ctx(registry_path=str(reg)), st, pub, dry_run=True)
    assert pub.msgs == [] and not st.path.exists()


def test_assert_no_secrets():
    assert_no_secrets({"title": "ok", "detail": "items: GitHub"})
    for bad in ({"password": "x"}, {"detail": "-----BEGIN PRIVATE KEY-----"},
                {"detail": FP}, {"x": ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIi.sig"]}):
        with pytest.raises(ValueError):
            assert_no_secrets(bad)
    with pytest.raises(ValueError):
        build_messages({"a": {"detail": "token " + "f" * 64}}, {"open": {}})


def test_mqtt_publisher_with_fake_client(monkeypatch):
    monkeypatch.setenv("MQTT_PASSWORD", "pw")

    class Info:
        def wait_for_publish(self, t):
            pass

    class Client:
        def __init__(self):
            self.log = []

        def username_pw_set(self, u, p):
            self.log.append(("auth", u, p))

        def connect(self, h, p, keepalive):
            self.log.append(("connect", h, p))

        def loop_start(self):
            pass

        def loop_stop(self):
            pass

        def publish(self, t, payload, qos, retain):
            self.log.append(("pub", t, retain))
            return Info()

        def disconnect(self):
            self.log.append(("disc",))
    c = Client()
    MqttPublisher("h", 1883, "u", client_factory=lambda: c).publish([("t", "{}")])
    assert c.log == [("auth", "u", "pw"), ("connect", "h", 1883), ("pub", "t", True), ("disc",)]


def test_mqtt_from_env_uses_site(monkeypatch):
    from cvc.site import Site
    p = MqttPublisher.from_env(Site(node_ip="100.64.9.9"))
    assert (p.host, p.port, p.username) == ("100.64.9.9", 1883, None)
    monkeypatch.setenv("MQTT_HOST", "broker")
    monkeypatch.setenv("MQTT_USERNAME", "audit")
    p = MqttPublisher.from_env(Site())
    assert (p.host, p.username) == ("broker", "audit")


def test_cli_stdout_and_dry_run(reg, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(C, "systemctl_runner", lambda a: "")
    state = tmp_path / "st.json"
    pub = FakePublisher()
    assert main(["run", "--registry", str(reg), "--state", str(state), "--dry-run",
                 "--check", "devices"], publisher=pub) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["open"]["error"] == 1 and not state.exists() and pub.msgs == []
    assert main(["run", "--registry", str(reg), "--state", str(state), "--stdout",
                 "--check", "owner_keys"], publisher=pub) == 0
    assert json.loads(capsys.readouterr().out)["findings"][0]["check"] == "owner_keys"
    assert state.exists() and pub.msgs == []
    assert main(["run", "--registry", str(reg), "--state", str(state),
                 "--check", "owner_keys"], publisher=pub) == 0
    assert pub.msgs
