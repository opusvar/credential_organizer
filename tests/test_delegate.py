"""Voluntary delegation (D17): wizard, 48h window, execution, refusals. Fake clock + fakes."""
from __future__ import annotations

import datetime as dt
from datetime import timedelta

import pytest
import yaml
from test_takeover import PKI, T0, Clock, Elev, Notifier, Reader, fp, key

from cvc.delegate import flow
from cvc.delegate.model import SECTIONS, DelegationError, DelegationStore
from cvc.delegate.plan import REVOKE_TEXT, VaultEntry
from cvc.takeover.__main__ import main as cvc_main
from cvc.takeover.verifiers import KeyReading


class Hours(Clock):
    def hours(self, n):
        self.now = T0 + timedelta(hours=n)


class Password(Elev):
    method = "vaultwarden-password"


class Inv:
    def __init__(self):
        self.items = [VaultEntry("v1", "bank", folder="money", data_class="private"),
                      VaultEntry("v2", "wifi", folder="home", data_class="internal"),
                      VaultEntry("v3", "shared", organization_id="org-home")]
        self.orgs = []

    def items_for(self, person):
        return self.items

    def orgs_for(self, person):
        return self.orgs


class Executor:
    def __init__(self):
        self.applied = None

    def apply(self, steps, a, b):
        self.applied = (steps, a, b)


def dev(owner, fpr, serial, hw=None):
    return {"owner": owner, "kind": "laptop", "roles": ["home-services"],
            "cert": {"storage": "yubikey-piv" if hw else "p12", **({"hardware_key": hw} if hw
                                                                   else {}),
                     "serial": serial, "fingerprint_sha256": fpr,
                     "not_after": dt.date(2027, 10, 1), "status": "active"}}


class Env:
    def __init__(self, tmp_path):
        self.pki = PKI()
        self.leaf = {"nathan": self.pki.leaf(), "alice": self.pki.leaf("medium", "alice")}
        self.reg = tmp_path / "registry.yaml"
        self.data = {
            "version": 1,
            "systems": {"workers": {"kind": "http"}},
            "roles": {"home-services": {"grants": [{"system": "workers", "paths": ["/"]}]}},
            "people": {
                "nathan": {"email": "nathan@local", "tier": "owner"},
                "dana": {"email": "dana@local", "tier": "owner", "granted_by": "nathan"},
                "alice": {"email": "alice@local", "tier": "medium", "granted_by": "nathan"},
                "lou": {"email": "lou@local", "tier": "low", "granted_by": "alice"},
                "mia": {"email": "mia@local", "tier": "medium", "granted_by": "alice"},
            },
            "agents": {
                "orch": {"tier": "high", "owner": "nathan", "token_sha256": "ab" * 32,
                         "roles": ["home-services"]},
                "alice-bot": {"tier": "medium", "owner": "alice", "token_sha256": "cd" * 32,
                              "roles": ["home-services"]},
            },
            "hardware_keys": {"yk-nathan": key("nathan", 111),
                              "yk-nathan-backup": {**key("nathan", 112), "location": "home-safe"},
                              "yk-dana": key("dana", 333)},
            "devices": {"nathan-mac": dev("nathan", fp(self.leaf["nathan"]), "beef", "yk-nathan"),
                        "alice-phone": dev("alice", fp(self.leaf["alice"]), "a1ce")},
        }
        self.save()
        self.clock, self.reader, self.notifier = Hours(), Reader(), Notifier()
        self.store = DelegationStore(tmp_path / "state")
        self.deps = flow.Deps(self.reg, self.store, self.reader, self.clock, self.notifier)
        self.inv = Inv()

    def save(self):
        self.reg.write_text(yaml.safe_dump(self.data, sort_keys=False))

    def load(self):
        return yaml.safe_load(self.reg.read_text())

    def wizard(self, delegator="nathan", recipient="dana", sections=None, upto=8,
               factor=None, typed=None):
        w = flow.StartWizard(self.deps)
        pem = self.leaf[delegator].public_bytes(yaml_pem())
        w.step1_cert(delegator, pem, [self.pki.inter.public_bytes(yaml_pem())],
                     self.pki.root.public_bytes(yaml_pem()))
        self.reader.serial = "111"
        w.step2_factor(factor if factor is not None else (None if delegator == "nathan"
                                                          else PasskeyOK()))
        w.step3_elevate(Elev())
        w.step4_recipient(recipient)
        preview = w.step5_preview(self.inv)
        if upto == 5:
            return w, preview
        sel = w.step6_select(sections)
        w.step7_confirm(sel, typed or recipient)
        return w, w.step8_start()


def yaml_pem():
    from cryptography.hazmat.primitives import serialization
    return serialization.Encoding.PEM


class PasskeyOK(Elev):
    method = "passkey"


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# ── happy path: owner -> owner, full ────────────────────────────────────────
def test_owner_to_owner_full(env):
    _, rec = env.wizard()
    assert rec.sections == list(SECTIONS)
    assert {p for p, ev, _ in env.notifier.sent if ev == "delegation-started"} == \
        {"nathan", "dana"}
    assert flow.status(env.deps, rec.id).startswith("[~] revocable")
    env.clock.hours(48)
    assert flow.status(env.deps, rec.id).startswith("[..] pending")
    lines, ex = [], Executor()
    flow.complete(env.deps, rec.id, env.inv, ex, out=lines.append)
    d = env.load()
    assert d["hardware_keys"]["yk-nathan"]["owner"] == "dana"
    assert d["hardware_keys"]["yk-nathan-backup"]["owner"] == "dana"
    assert d["devices"]["nathan-mac"]["owner"] == "dana"
    assert d["devices"]["nathan-mac"]["cert"]["status"] == "revoked"
    assert any("step ca revoke beef" in x for x in lines)
    assert d["agents"]["orch"]["owner"] == "dana" and d["agents"]["orch"]["tier"] == "high"
    assert d["people"]["alice"]["granted_by"] == "dana"
    assert d["people"]["nathan"]["tier"] == "low"
    assert [s.action for s in ex.applied[0]] == ["copy-to-recipient", "copy-to-recipient"]
    assert any("backup" in x and "yk-nathan-backup" in x for x in lines)
    assert env.store.get(rec.id).status == "executed"
    assert flow.status(env.deps, rec.id).startswith("[ok] executed")
    assert env.store.verify_history()


# ── 48h window ──────────────────────────────────────────────────────────────
def test_revoke_hour_47_ok(env):
    _, rec = env.wizard()
    env.clock.hours(47)
    env.reader.serial = "111"
    flow.revoke(env.deps, rec.id)
    assert env.store.get(rec.id).status == "revoked"
    assert env.load() == env.data                             # nothing moved
    assert {p for p, ev, _ in env.notifier.sent if ev == "delegation-revoked"} == \
        {"nathan", "dana"}


def test_revoke_hour_49_refused(env):
    _, rec = env.wizard()
    env.clock.hours(49)
    with pytest.raises(DelegationError, match="new delegation back"):
        flow.revoke(env.deps, rec.id)
    flow.complete(env.deps, rec.id, env.inv, out=lambda _: None)
    with pytest.raises(DelegationError, match="already executed"):
        flow.revoke(env.deps, rec.id)


def test_revoke_needs_delegator_key(env):
    _, rec = env.wizard()
    env.reader.serial = "333"
    with pytest.raises(DelegationError, match="registered to 'dana'"):
        flow.revoke(env.deps, rec.id)


def test_decline_hour_10(env):
    _, rec = env.wizard()
    env.clock.hours(10)
    with pytest.raises(DelegationError, match="only dana can decline"):
        flow.decline(env.deps, rec.id, Elev(ok=False))
    flow.decline(env.deps, rec.id, PasskeyOK())
    assert flow.status(env.deps, rec.id).startswith("[x] declined")
    env.clock.hours(50)
    with pytest.raises(DelegationError, match="already declined"):
        flow.complete(env.deps, rec.id, env.inv)
    assert env.load() == env.data


def test_complete_before_48h_refused(env):
    _, rec = env.wizard()
    env.clock.hours(47)
    with pytest.raises(DelegationError, match="can execute after"):
        flow.complete(env.deps, rec.id, env.inv)


# ── D14 guard ───────────────────────────────────────────────────────────────
def test_zero_owner_keys_refused_at_preview(env):
    env.data["people"]["dana"]["tier"] = "high"              # nathan is the only owner
    env.save()
    w, preview = env.wizard(recipient="alice", upto=5)
    assert f"[{REVOKE_TEXT}] yk-nathan" in preview
    with pytest.raises(DelegationError, match="zero active owner hardware keys"):
        w.step6_select()
    assert w.step6_select(["vault", "devices"]) == ["vault", "devices"]


def test_zero_owner_keys_refused_at_execution(env):
    _, rec = env.wizard(recipient="alice")                    # dana still holds an owner key
    data = env.load()
    data["hardware_keys"]["yk-dana"]["status"] = "lost"
    env.reg.write_text(yaml.safe_dump(data, sort_keys=False))
    env.clock.hours(49)
    with pytest.raises(DelegationError, match="zero active owner hardware keys"):
        flow.complete(env.deps, rec.id, env.inv)
    assert env.store.get(rec.id).status == "refused"
    assert flow.status(env.deps, rec.id).startswith("[!] refused")
    assert env.load()["hardware_keys"]["yk-nathan"]["owner"] == "nathan"


# ── ceilings ────────────────────────────────────────────────────────────────
def test_medium_to_low_revokes_medium_items(env):
    w, preview = env.wizard(delegator="alice", recipient="lou", upto=5)
    assert f"[{REVOKE_TEXT}] bank (folder money, private)" in preview
    assert "[transfer] wifi (folder home, internal)" in preview
    assert f"[{REVOKE_TEXT}] people.mia (tier medium)" in preview
    assert "alice-bot (tier medium) (new sponsor lou; effective tier low)" in preview
    sel = w.step6_select()
    w.step7_confirm(sel, "lou")
    rec = w.step8_start()
    started = [m for _, ev, m in env.notifier.sent if ev == "delegation-started"]
    assert "Will be REVOKED" in started[0] and "bank" in started[0]
    env.clock.hours(48)
    ex = Executor()
    flow.complete(env.deps, rec.id, env.inv, ex, out=lambda _: None)
    d = env.load()
    assert d["people"]["mia"]["expires"] == (T0 + timedelta(hours=48)).date()        # grant revoked
    assert d["people"]["mia"].get("granted_by") == "alice"
    assert d["agents"]["alice-bot"]["owner"] == "lou"
    assert d["agents"]["alice-bot"]["tier"] == "low"
    assert d["people"]["alice"]["tier"] == "low"
    assert d["devices"]["alice-phone"]["owner"] == "lou"
    acts = {(s.action, s.ref) for s in ex.applied[0]}
    assert acts == {("revoke-from-delegator", "v1"), ("copy-to-recipient", "v2")}


def test_high_orchestrator_to_medium_caps(env):
    _, rec = env.wizard(recipient="alice", sections=["agents"])
    env.clock.hours(48)
    flow.complete(env.deps, rec.id, env.inv, out=lambda _: None)
    d = env.load()
    assert d["agents"]["orch"] == {**env.data["agents"]["orch"], "owner": "alice",
                                   "tier": "medium"}
    assert d["people"]["nathan"]["tier"] == "owner"


def test_guest_recipient_agent_expires_with_guest(env):
    env.data["people"]["gina"] = {"email": "g@local", "tier": "guest-long",
                                  "granted_by": "alice", "expires": dt.date(2026, 12, 1)}
    env.save()
    _, rec = env.wizard(delegator="alice", recipient="gina", sections=["agents"])
    env.clock.hours(48)
    flow.complete(env.deps, rec.id, env.inv, out=lambda _: None)
    a = env.load()["agents"]["alice-bot"]
    assert a["tier"] == "low" and a["expires"] == dt.date(2026, 12, 1)


def test_deselect_hwkeys_keeps_keys(env):
    _, rec = env.wizard(sections=["vault", "agents"])
    env.clock.hours(48)
    flow.complete(env.deps, rec.id, env.inv, out=lambda _: None)
    d = env.load()
    assert d["hardware_keys"]["yk-nathan"]["owner"] == "nathan"
    assert d["people"]["nathan"]["tier"] == "owner"


def test_new_item_above_ceiling_revoked_at_execution(env):
    _, rec = env.wizard(delegator="alice", recipient="lou", sections=["vault"])
    env.inv.items = env.inv.items + [VaultEntry("v9", "tax", data_class="private")]
    env.clock.hours(48)
    lines, ex = [], Executor()
    flow.complete(env.deps, rec.id, env.inv, ex, out=lines.append)
    assert any("new since preview: [revoke]" in x and "tax" in x for x in lines)
    assert ("revoke-from-delegator", "v9") in {(s.action, s.ref) for s in ex.applied[0]}


# ── identity refusals ───────────────────────────────────────────────────────
def test_password_only_refused(env):
    with pytest.raises(DelegationError, match="passkey is required"):
        env.wizard(delegator="alice", recipient="lou", factor=Password())


def test_typed_name_and_confirmations(env):
    w, _ = env.wizard(upto=5)
    sel = w.step6_select()
    with pytest.raises(DelegationError, match="missing: hardware keys"):
        w.step7_confirm([s for s in sel if s != "hwkeys"], "dana")
    with pytest.raises(DelegationError, match="does not match"):
        w.step7_confirm(sel, "Dana")


def test_open_delegation_and_self(env):
    env.wizard()
    w = flow.StartWizard(env.deps)
    w.done = [1, 2, 3]
    w.delegator = "nathan"
    with pytest.raises(DelegationError, match="open delegation"):
        w.step4_recipient("alice")
    with pytest.raises(DelegationError, match="same person"):
        w.step4_recipient("nathan")


def test_unregistered_key_refused(env):
    w = flow.StartWizard(env.deps)
    w.step1_cert("nathan", env.leaf["nathan"].public_bytes(yaml_pem()),
                 [env.pki.inter.public_bytes(yaml_pem())], env.pki.root.public_bytes(yaml_pem()))
    env.reader.read = lambda: KeyReading("999", True)
    with pytest.raises(DelegationError, match="not registered"):
        w.step2_factor()


def test_cli_faq_dispatch(capsys):
    assert cvc_main(["delegate", "faq"]) == 0
    assert "48 hours" in capsys.readouterr().out
