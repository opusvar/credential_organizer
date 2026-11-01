"""Owner takeover flow (D15): every refusal plus happy paths, with a fake clock and fakes."""
from __future__ import annotations

import datetime as dt
from datetime import UTC, datetime, timedelta

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cvc.takeover import flow
from cvc.takeover.api import make_router
from cvc.takeover.model import TakeoverError, TakeoverStore
from cvc.takeover.recovery import RecoveryPasswordStore
from cvc.takeover.verifiers import KeyReading
from cvc.takeover.vw import EmergencyGrant, VaultItem, build_plan

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
PEM = serialization.Encoding.PEM


# ── PKI fixtures ────────────────────────────────────────────────────────────
def _cert(subject, key, issuer, issuer_key, ca, uris=(), start=None, days=365):
    start = start or T0 - timedelta(days=1)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, subject)])).issuer_name(x509.Name([x509.NameAttribute(
            NameOID.COMMON_NAME, issuer)])).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(start)
         .not_valid_after(start + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if uris:
        b = b.add_extension(x509.SubjectAlternativeName(
            [x509.UniformResourceIdentifier(u) for u in uris]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


class PKI:
    def __init__(self):
        self.rk, self.ik = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(
            ec.SECP256R1())
        self.root = _cert("root", self.rk, "root", self.rk, True)
        self.inter = _cert("inter", self.ik, "root", self.rk, True)

    def leaf(self, tier="owner", person="nathan", signer=None, days=365):
        k = ec.generate_private_key(ec.SECP256R1())
        ik = signer or self.ik
        return _cert("dev", k, "inter", ik, False,
                     (f"urn:cvc:tier:{tier}", f"urn:cvc:person:{person}"), days=days)


def fp(c):
    return c.fingerprint(hashes.SHA256()).hex()


# ── fakes ───────────────────────────────────────────────────────────────────
class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now

    def days(self, n):
        self.now = T0 + timedelta(days=n, hours=1)


class Reader:
    def __init__(self):
        self.serial, self.attested = "111", True

    def read(self):
        return KeyReading(self.serial, self.attested)


class VW:
    def __init__(self, take_wait=90):
        self.grants = [EmergencyGrant("g-view", "dana@local", "view", 15),
                       EmergencyGrant("g-take", "dana@local", "takeover", 90),
                       EmergencyGrant("g-take180", "dana@local", "takeover", 180)]
        self.calls = []

    def granted(self):
        return self.grants

    def initiate(self, g):
        self.calls.append(("initiate", g))

    def reject(self, g):
        self.calls.append(("reject", g))

    def view(self, g):
        self.calls.append(("view", g))
        return 3

    def takeover(self, g):
        self.calls.append(("takeover", g))


class Elev:
    method = "passkey"

    def __init__(self, ok=True):
        self.ok = ok

    def verify(self, person, email):
        return self.ok


class Notifier:
    def __init__(self):
        self.sent = []

    def notify(self, person, event, message):
        self.sent.append((person, event, message))


class Inventory:
    def items_for(self, person):
        return [VaultItem("i1", "bank"), VaultItem("i2", "wifi", "org-home"),
                VaultItem("i3", "alarm", "org-home")]


class Executor:
    def __init__(self):
        self.applied = None

    def apply(self, steps, target, initiator):
        self.applied = (steps, target, initiator)


def key(owner, serial, status="active"):
    return {"owner": owner, "model": "YubiKey 5C", "serial": serial,
            "uses": ["fido2-vaultwarden", "piv-device-cert", "recovery"],
            "location": "on-person", "enrolled": dt.date(2026, 10, 1), "status": status}


def registry(leaf_fp):
    return {
        "version": 1,
        "systems": {"workers": {"kind": "http"}},
        "roles": {"home-services": {"grants": [{"system": "workers", "paths": ["/"]}]}},
        "people": {
            "nathan": {"email": "nathan@local", "tier": "owner"},
            "dana": {"email": "dana@local", "tier": "owner", "granted_by": "nathan"},
            "alice": {"email": "alice@local", "tier": "medium", "granted_by": "dana"},
        },
        "agents": {"dana-assistant": {"tier": "assistant", "owner": "dana",
                                      "token_sha256": "cd" * 32, "roles": ["home-services"]}},
        "hardware_keys": {"yk-nathan": key("nathan", 111), "yk-dana": key("dana", 333),
                          "yk-dana-backup": key("dana", 334), "yk-alice": key("alice", 222),
                          "yk-dana-old": key("dana", 335, "revoked")},
        "devices": {
            "nathan-mac": {"owner": "nathan", "kind": "laptop", "roles": ["home-services"],
                           "cert": {"storage": "yubikey-piv", "hardware_key": "yk-nathan",
                                    "serial": "beef", "fingerprint_sha256": leaf_fp,
                                    "not_after": dt.date(2027, 10, 1), "status": "active"}},
            "dana-mac": {"owner": "dana", "kind": "laptop", "roles": ["home-services"],
                         "cert": {"storage": "yubikey-piv", "hardware_key": "yk-dana",
                                  "serial": "cafe", "fingerprint_sha256": "ef" * 32,
                                  "not_after": dt.date(2027, 10, 1), "status": "active"}},
        },
    }


class Env:
    def __init__(self, tmp_path):
        self.pki = PKI()
        self.leaf = self.pki.leaf()
        self.reg = tmp_path / "registry.yaml"
        self.data = registry(fp(self.leaf))
        self.save()
        self.clock, self.reader, self.vw, self.notifier = Clock(), Reader(), VW(), Notifier()
        self.store = TakeoverStore(tmp_path / "state")
        self.recovery = RecoveryPasswordStore(tmp_path / "state", ask=lambda _: self.pw)
        self.pw = "correct horse battery staple"
        self.deps = flow.Deps(self.reg, self.store, self.vw, self.reader, self.clock,
                              self.notifier)

    def save(self):
        self.reg.write_text(yaml.safe_dump(self.data, sort_keys=False))

    def load(self):
        return yaml.safe_load(self.reg.read_text())

    def pem(self, c):
        return c.public_bytes(PEM)

    def wizard(self, upto=6, target="dana", target_serial="333", recovery=False, leaf=None):
        w = flow.StartWizard(self.deps)
        steps = [
            lambda: w.step1_cert("nathan", self.pem(leaf or self.leaf),
                                 [self.pem(self.pki.inter)], self.pem(self.pki.root)),
            lambda: (setattr(self.reader, "serial", "111"), w.step2_initiator_key()),
            lambda: w.step3_elevate(Elev()),
            lambda: w.step4_target(target),
            (lambda: w.step5_recovery_password(self.recovery)) if recovery else
            (lambda: (setattr(self.reader, "serial", target_serial), w.step5_target_key())),
            lambda: w.step6_start(),
        ]
        out = None
        for s in steps[:upto]:
            out = s()
        return w, out


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# ── happy paths ─────────────────────────────────────────────────────────────
def test_full_key_path(env):
    _, rec = env.wizard()
    assert rec.path == "key" and rec.target_key == "yk-dana" and rec.wait_days == 90
    assert env.vw.calls == [("initiate", "g-view"), ("initiate", "g-take")]
    assert [n[0] for n in env.notifier.sent] == ["dana"]       # day 0 banner
    assert rec.phase(env.clock()) == "requested"
    with pytest.raises(TakeoverError, match="day 15"):
        flow.view(env.deps, rec.id)
    env.clock.days(15)
    env.reader.serial = "111"
    assert flow.view(env.deps, rec.id) == 3
    env.clock.days(90)
    ex = Executor()
    lines = []
    flow.complete(env.deps, rec.id, Inventory(), ex, out=lines.append)
    data = env.load()
    assert data["hardware_keys"]["yk-dana"]["owner"] == "nathan"
    assert data["hardware_keys"]["yk-dana-backup"]["owner"] == "nathan"
    assert data["devices"]["dana-mac"]["cert"]["status"] == "revoked"
    assert data["people"]["dana"]["status"] == "taken-over"
    assert data["people"]["alice"]["granted_by"] == "nathan"
    assert "dana-assistant" not in data["agents"]
    assert ("takeover", "g-take") in env.vw.calls
    assert any("step ca revoke cafe" in x for x in lines)
    actions = [s.action for s in ex.applied[0]]
    assert actions == ["copy-to-initiator", "transfer-org-ownership"]   # org: ownership, 1 step
    assert env.store.get(rec.id).status == "completed"
    assert env.store.verify_history()


def test_backup_key_accepted(env):
    _, rec = env.wizard(target_serial="334")
    assert rec.target_key == "yk-dana-backup" and rec.wait_days == 90


def test_rebind_agents(env):
    _, rec = env.wizard()
    env.clock.days(90)
    env.reader.serial = "111"
    flow.complete(env.deps, rec.id, Inventory(), None, rebind_agents=True, out=lambda _: None)
    assert env.load()["agents"]["dana-assistant"]["owner"] == "nathan"


def test_recovery_password_path(env):
    env.recovery.set("dana", T0.isoformat())
    stored = (env.store.dir / "recovery.json").read_text()
    assert env.pw not in stored
    _, rec = env.wizard(recovery=True)
    assert rec.path == "recovery-password" and rec.target_key is None and rec.wait_days == 180
    assert ("initiate", "g-take180") in env.vw.calls
    env.clock.days(15)
    env.reader.serial = "111"
    assert flow.view(env.deps, rec.id) == 3                     # viewer still at day 15
    for d in (7, 14, 85, 170):
        env.clock.days(d)
        flow.tick(env.deps)
    assert env.store.get(rec.id).notified == [0, 7, 14, 85, 170]
    assert "recovery password" in env.notifier.sent[-1][2]
    env.clock.days(179)
    with pytest.raises(TakeoverError, match="day 180"):
        flow.complete(env.deps, rec.id, Inventory(), out=lambda _: None)
    env.clock.days(180)
    flow.complete(env.deps, rec.id, Inventory(), out=lambda _: None)
    assert env.store.get(rec.id).status == "completed"


def test_recovery_password_wrong(env):
    env.recovery.set("dana", T0.isoformat())
    env.pw = "wrong wrong wrong wrong"
    with pytest.raises(TakeoverError, match="recovery password"):
        env.wizard(recovery=True)


def test_recovery_password_not_set(env):
    with pytest.raises(TakeoverError, match="no sealed recovery password"):
        env.wizard(recovery=True)


def test_recovery_password_rotate_and_min_len(env):
    assert env.recovery.set("dana", "t") is False
    env.pw = "another long passphrase!"
    assert env.recovery.set("dana", "t") is True
    env.pw = "short"
    with pytest.raises(TakeoverError, match="at least"):
        env.recovery.set("dana", "t")


def test_notifications_key_path(env):
    _, rec = env.wizard()
    for d in (3, 7, 14, 85, 89):
        env.clock.days(d)
        flow.tick(env.deps)
    assert env.store.get(rec.id).notified == [0, 7, 14, 85]


def test_banner_api(env):
    env.wizard()
    app = FastAPI()
    app.include_router(make_router(env.store, env.clock))
    c = TestClient(app)
    b = c.get("/v1/takeover/banner", params={"person": "dana"}).json()
    assert b["active"] and b["takeovers"][0]["state"] == "takeover request in progress"
    assert b["takeovers"][0]["path"] == "key"
    assert not c.get("/v1/takeover/banner", params={"person": "nathan"}).json()["active"]


def test_cancel_by_target(env):
    _, rec = env.wizard()
    env.clock.days(60)
    env.reader.serial = "334"                                  # backup key works for cancel
    flow.cancel(env.deps, rec.id)
    assert ("reject", "g-view") in env.vw.calls and ("reject", "g-take") in env.vw.calls
    env.clock.days(90)
    env.reader.serial = "111"
    with pytest.raises(TakeoverError, match="already cancelled"):
        flow.complete(env.deps, rec.id, Inventory(), out=lambda _: None)


# ── refusals ────────────────────────────────────────────────────────────────
def test_wrong_tier_cert(env):
    with pytest.raises(TakeoverError, match="tier"):
        env.wizard(1, leaf=env.pki.leaf(tier="medium"))


def test_cert_other_person(env):
    with pytest.raises(TakeoverError, match="belongs to"):
        env.wizard(1, leaf=env.pki.leaf(person="dana"))


def test_cert_untrusted_chain(env):
    rogue = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(TakeoverError, match="chain"):
        env.wizard(1, leaf=env.pki.leaf(signer=rogue))


def test_cert_revoked_in_registry(env):
    env.data["devices"]["nathan-mac"]["cert"]["status"] = "revoked"
    env.save()
    with pytest.raises(TakeoverError, match="revoked"):
        env.wizard(1)


def test_cert_expired_in_registry(env):
    env.data["devices"]["nathan-mac"]["cert"]["not_after"] = dt.date(2026, 10, 1)
    env.save()
    with pytest.raises(TakeoverError, match="expired"):
        env.wizard(1)


def test_cert_unregistered(env):
    with pytest.raises(TakeoverError, match="not registered"):
        env.wizard(1, leaf=env.pki.leaf())


def test_initiator_key_wrong_owner(env):
    w, _ = env.wizard(1)
    env.reader.serial = "333"
    with pytest.raises(TakeoverError, match="registered to 'dana'"):
        w.step2_initiator_key()


def test_initiator_key_not_attested(env):
    w, _ = env.wizard(1)
    env.reader.attested = False
    with pytest.raises(TakeoverError, match="attestation"):
        w.step2_initiator_key()


def test_elevation_failure(env):
    w, _ = env.wizard(2)
    with pytest.raises(TakeoverError, match="elevation failed"):
        w.step3_elevate(Elev(ok=False))


def test_steps_out_of_order(env):
    w = flow.StartWizard(env.deps)
    with pytest.raises(TakeoverError, match="steps 1..3"):
        w.step4_target("dana")


def test_same_person(env):
    with pytest.raises(TakeoverError, match="same person"):
        env.wizard(4, target="nathan")


def test_target_not_owner(env):
    with pytest.raises(TakeoverError, match="not an active owner"):
        env.wizard(4, target="alice")


def test_target_key_wrong_owner(env):
    with pytest.raises(TakeoverError, match="registered to 'nathan'"):
        env.wizard(5, target_serial="111")


def test_target_key_revoked(env):
    with pytest.raises(TakeoverError, match="revoked"):
        env.wizard(5, target_serial="335")


def test_missing_vw_grant(env):
    env.vw.grants = [g for g in env.vw.grants if g.type != "takeover"]
    with pytest.raises(TakeoverError, match="pre-provision"):
        env.wizard()
    assert env.store.all() == {}


def test_duplicate_open_takeover(env):
    env.wizard()
    with pytest.raises(TakeoverError, match="open takeover"):
        env.wizard(4)


@pytest.mark.parametrize("day", [14, 89])
def test_early_complete_refused(env, day):
    _, rec = env.wizard()
    env.clock.days(day)
    env.reader.serial = "111"
    with pytest.raises(TakeoverError, match="day 90"):
        flow.complete(env.deps, rec.id, Inventory(), out=lambda _: None)
    assert env.load()["people"]["dana"].get("status", "active") == "active"


def test_complete_needs_initiator_key(env):
    _, rec = env.wizard()
    env.clock.days(90)
    env.reader.serial = "222"
    with pytest.raises(TakeoverError, match="registered to 'alice'"):
        flow.complete(env.deps, rec.id, Inventory(), out=lambda _: None)


def test_cancel_by_non_target(env):
    _, rec = env.wizard()
    env.reader.serial = "111"
    with pytest.raises(TakeoverError, match="only dana can cancel"):
        flow.cancel(env.deps, rec.id)
    assert env.store.get(rec.id).status == "pending"


def test_guard_violation_direct(env):
    _, rec = env.wizard()
    data = env.load()
    data["people"]["nathan"]["tier"] = "medium"
    with pytest.raises(Exception, match="zero active owner hardware keys"):
        flow.apply_account_takeover(data, rec, dt.date(2027, 1, 30), False)


def test_history_tamper_detected(env):
    env.wizard()
    p = env.store.history_path
    p.write_text(p.read_text().replace("started", "stArted"))
    assert not env.store.verify_history()


def test_plan_org_items_not_copied():
    steps = build_plan(Inventory().items_for("dana"), "dana", "nathan")
    assert [(s.action, s.ref) for s in steps] == [("copy-to-initiator", "i1"),
                                                  ("transfer-org-ownership", "org-home")]
