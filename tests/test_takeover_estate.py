"""Takeover additions: veto warning, primary/backup key role, estate recovery kit (D15)."""
from __future__ import annotations

import os
import stat

import pytest
from test_takeover import Elev, Env

from cvc.takeover import flow
from cvc.takeover.estate import EstateKitStore, normalize
from cvc.takeover.keys import key_role
from cvc.takeover.model import TakeoverError
from cvc.takeover.vw import EmergencyGrant


class Channel:
    def __init__(self, name):
        self.name, self.sent = name, []

    def notify(self, person, event, message):
        self.sent.append((person, event, message))


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.data["people"]["olga"] = {"email": "olga@local", "tier": "owner"}
    e.data["hardware_keys"]["yk-olga"] = {**e.data["hardware_keys"]["yk-nathan"],
                                          "owner": "olga", "serial": 444}
    e.save()
    return e


# ── veto ────────────────────────────────────────────────────────────────────
def test_veto_by_other_owner_warns_vw_view_persists(env):
    _, rec = env.wizard()
    env.reader.serial = "444"
    printed = []
    flow.veto(env.deps, rec.id, "olga", out=printed.append)
    assert env.store.get(rec.id).status == "vetoed"
    assert ("reject", "g-view") not in env.vw.calls          # cannot reject from olga's account
    assert "View access" in printed[0] and "PERSISTS" in printed[0]
    assert "only accepts a reject from the grantor" in printed[0]
    vetoed = [(p, m) for p, ev, m in env.notifier.sent if ev == "takeover-vetoed"]
    assert {p for p, _ in vetoed} == {"nathan", "dana", "olga"}
    assert all("PERSISTS" in m for _, m in vetoed)
    with pytest.raises(TakeoverError, match="already vetoed"):
        flow.complete(env.deps, rec.id, None)


def test_veto_needs_own_key_and_not_target(env):
    _, rec = env.wizard()
    env.reader.serial = "111"                                # nathan's key, claiming olga
    with pytest.raises(TakeoverError, match="olga's own YubiKey"):
        flow.veto(env.deps, rec.id, "olga", out=lambda _: None)
    env.reader.serial = "333"
    with pytest.raises(TakeoverError, match="use `cvc takeover cancel"):
        flow.veto(env.deps, rec.id, "dana", out=lambda _: None)
    with pytest.raises(TakeoverError, match="not an active owner"):
        flow.veto(env.deps, rec.id, "alice", out=lambda _: None)


# ── primary / backup ────────────────────────────────────────────────────────
def test_key_role_explicit_and_heuristic():
    assert key_role({"role": "backup", "location": "on-person"}) == "backup"
    assert key_role({"role": "primary", "location": "home-safe"}) == "primary"
    assert key_role({"location": "home-safe"}) == "backup"
    assert key_role({"location": "on-person"}) == "primary"

    class K:
        location = "offsite"
    assert key_role(K()) == "backup"


def test_takeover_records_backup_role(env):
    env.data["hardware_keys"]["yk-dana-backup"]["location"] = "home-safe"
    env.save()
    _, rec = env.wizard(target_serial="334")
    assert rec.target_key_role == "backup"
    assert "backup YubiKey yk-dana-backup" in env.notifier.sent[0][2]


def test_takeover_explicit_role_wins(env):
    env.data["hardware_keys"]["yk-dana"]["role"] = "backup"
    env.save()
    _, rec = env.wizard()
    assert rec.target_key_role == "backup"


# ── estate recovery kit ─────────────────────────────────────────────────────
def _kit(env, code=None):
    box = {}
    kit = EstateKitStore(env.store.dir, ask=lambda _: box["code"])
    return kit, box


def _estate_wizard(env, kit, target="dana"):
    w = flow.StartWizard(env.deps)
    w.step1_cert("nathan", env.pem(env.leaf), [env.pem(env.pki.inter)], env.pem(env.pki.root))
    env.reader.serial = "111"
    w.step2_initiator_key()
    w.step3_elevate(Elev())
    w.step4_target(target)
    w.step5_estate_kit(kit)
    return w.step6_start()


def test_estate_kit_generate_hash_only_0600(env):
    kit, _ = _kit(env)
    code = kit.generate("nathan", "2026-11-01")
    raw = normalize(code)
    assert len(raw) == 30 and code.count("-") == 5
    text = kit.path.read_text()
    assert raw not in text and code not in text and '"hash"' in text
    assert stat.S_IMODE(os.stat(kit.path).st_mode) == 0o600
    assert kit.generate("nathan", "2026-11-02") != code      # rotation, fresh entropy


def test_estate_kit_path_180_days_notifies_all_owners_every_channel(env):
    a, b = Channel("ha"), Channel("push")
    env.deps.notifier = flow.MultiNotifier([a, b])
    kit, box = _kit(env)
    box["code"] = kit.generate("olga", "2026-11-01").lower().replace("-", " ")  # forgiving input
    rec = _estate_wizard(env, kit)
    assert rec.path == "estate-kit" and rec.wait_days == 180 and rec.target_key is None
    assert ("initiate", "g-take180") in env.vw.calls
    for ch in (a, b):
        used = {p for p, ev, _ in ch.sent if ev == "takeover-estate-kit-used"}
        assert used == {"nathan", "dana", "olga"}
    banner = [m for p, ev, m in a.sent if ev == "takeover-banner"]
    assert banner and "estate recovery kit" in banner[0]
    env.clock.days(179)
    with pytest.raises(TakeoverError, match="day 180"):
        flow.complete(env.deps, rec.id, None)
    # single use: the kit is void, a second use is refused
    assert kit.status()["status"] == "used" and "hash" not in kit.path.read_text()
    with pytest.raises(TakeoverError, match="no active estate recovery kit"):
        kit.verify()


def test_estate_kit_any_owner_target(env):
    kit, box = _kit(env)
    box["code"] = kit.generate("nathan", "2026-11-01")
    env.vw.grants += [EmergencyGrant("o-view", "olga@local", "view", 15),
                      EmergencyGrant("o-take", "olga@local", "takeover", 180)]
    rec = _estate_wizard(env, kit, target="olga")
    assert rec.target == "olga" and rec.path == "estate-kit"


def test_estate_kit_wrong_code_and_missing(env):
    kit, box = _kit(env)
    with pytest.raises(TakeoverError, match="no active estate recovery kit"):
        _estate_wizard(env, kit)
    kit.generate("nathan", "2026-11-01")
    box["code"] = "0" * 30
    with pytest.raises(TakeoverError, match="code is wrong"):
        _estate_wizard(env, kit)
    assert kit.active()                                       # failed attempt does not burn it


def test_estate_kit_not_consumed_when_start_fails(env):
    kit, box = _kit(env)
    box["code"] = kit.generate("nathan", "2026-11-01")
    env.vw.grants = [g for g in env.vw.grants if g.wait_days != 180]
    with pytest.raises(TakeoverError, match="180-day wait"):
        _estate_wizard(env, kit)
    assert kit.active()
