"""Tests for the owner hardware-key invariant (D14): at least one active owner YubiKey."""
from __future__ import annotations

import datetime as dt

import pytest
import yaml

from cvc.access import parse_registry
from cvc.access.check import check_registry
from cvc.access.cli import main

FP = "ab" * 32
TODAY = dt.date(2026, 11, 1)


def key(owner: str, serial: int, status: str = "active") -> dict:
    return {"owner": owner, "model": "YubiKey 5C", "serial": serial,
            "uses": ["fido2-vaultwarden", "piv-device-cert", "recovery"],
            "location": "on-person", "enrolled": dt.date(2026, 10, 1), "status": status}


def base() -> dict:
    return {
        "version": 1,
        "systems": {"workers": {"kind": "http"}},
        "roles": {"home-services": {"grants": [{"system": "workers", "paths": ["/"]}]}},
        "people": {
            "alex": {"email": "alex@local", "tier": "owner"},
            "dana": {"email": "dana@local", "tier": "owner", "granted_by": "alex"},
            "alice": {"email": "alice@local", "tier": "medium", "granted_by": "alex"},
        },
        "hardware_keys": {"yk-alex": key("alex", 111),
                          "yk-alice": key("alice", 222)},
        "devices": {
            "alex-mac": {
                "owner": "alex", "kind": "laptop",
                "cert": {"storage": "yubikey-piv", "hardware_key": "yk-alex",
                         "serial": "beef", "fingerprint_sha256": FP,
                         "not_after": dt.date(2027, 1, 31), "status": "active"},
                "roles": ["home-services"],
            },
        },
    }


def write(tmp_path, data: dict):
    p = tmp_path / "registry.yaml"
    p.write_text(yaml.safe_dump(data, sort_keys=False))
    return p


@pytest.fixture
def reg(tmp_path):
    return write(tmp_path, base())


@pytest.fixture
def reg2(tmp_path):
    d = base()
    d["hardware_keys"]["yk-alex-2"] = key("alex", 333)
    return write(tmp_path, d)


def run(p, *argv) -> int:
    return main([*argv, "--registry", str(p)])


def load(p) -> dict:
    return yaml.safe_load(p.read_text())


def refused(p, capsys, *argv):
    before = p.read_text()
    assert run(p, *argv) == 1
    err = capsys.readouterr().err
    assert "zero active owner hardware keys" in err and "--force" in err
    assert p.read_text() == before


def msgs(d: dict) -> dict[str, str]:
    return {f.level + ":" + f.message: f.level
            for f in check_registry(parse_registry(d), TODAY) if f.path == "hardware_keys"}


# ── check ───────────────────────────────────────────────────────────────────
def test_check_error_when_no_owner_key():
    d = base()
    d["hardware_keys"]["yk-alex"]["status"] = "suspended"
    assert any(k.startswith("error:no active hardware key belongs to an owner") for k in msgs(d))


def test_check_error_when_only_non_owner_keys():
    d = base()
    d["people"]["alex"]["tier"] = "admin"
    d["people"]["dana"]["tier"] = "admin"
    assert any(k.startswith("error:no active") for k in msgs(d))


def test_check_warns_on_single_owner_key():
    found = msgs(base())
    assert any(k.startswith("warning:only one active owner hardware key") for k in found)
    assert not any(k.startswith("error:no active") for k in found)


def test_check_clean_with_two_owner_keys():
    d = base()
    d["hardware_keys"]["yk-dana"] = key("dana", 444)
    found = msgs(d)
    assert not any("owner hardware key" in k or "owner-tier" in k for k in found)


# ── refusals ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("reason", ["lost", "retired", "revoked"])
def test_revoke_last_owner_key_refused(reg, capsys, reason):
    refused(reg, capsys, "hwkey", "revoke", "yk-alex", "--reason", reason)


def test_suspend_last_owner_key_refused(reg, capsys):
    refused(reg, capsys, "hwkey", "suspend", "yk-alex")


def test_remove_last_owner_with_keys_refused(tmp_path, capsys):
    d = base()
    del d["people"]["dana"]
    p = write(tmp_path, d)
    refused(p, capsys, "person", "remove", "alex")


def test_demote_last_owner_refused(tmp_path, capsys):
    d = base()
    d["people"]["dana"]["tier"] = "admin"
    p = write(tmp_path, d)
    refused(p, capsys, "person", "set-tier", "alex", "--tier", "admin")


def test_transfer_to_non_owner_refused(reg2, capsys):
    assert run(reg2, "hwkey", "transfer", "yk-alex", "--to", "alice") == 1
    assert "owner-tier" in capsys.readouterr().err
    assert load(reg2)["hardware_keys"]["yk-alex"]["owner"] == "alex"


def test_transfer_last_owner_key_to_owner_without_key_ok(reg, capsys):
    # Transfer keeps the key active under an owner, so the invariant holds.
    assert run(reg, "hwkey", "transfer", "yk-alex", "--to", "dana") == 0
    k = load(reg)["hardware_keys"]["yk-alex"]
    assert k["owner"] == "dana"
    assert k["history"][-1] == {"date": k["history"][-1]["date"], "event": "transferred",
                                "from": "alex", "to": "dana"}
    out = capsys.readouterr().out
    assert "ykman fido" in out and "Vaultwarden" in out and "step ca revoke" in out
    assert "NOT executed" in out


def test_replace_with_inactive_new_refused(tmp_path, capsys):
    d = base()
    d["hardware_keys"]["yk-new"] = key("alex", 555, status="suspended")
    p = write(tmp_path, d)
    assert run(p, "hwkey", "replace", "yk-alex", "--new", "yk-new") == 1
    assert "must be active" in capsys.readouterr().err


def test_replace_with_missing_new_refused(reg, capsys):
    assert run(reg, "hwkey", "replace", "yk-alex", "--new", "yk-nope") == 1
    assert "does not exist" in capsys.readouterr().err


def test_replace_with_non_owner_new_refused(reg, capsys):
    # yk-alice is active but not an owner key: retiring yk-alex leaves zero.
    refused(reg, capsys, "hwkey", "replace", "yk-alex", "--new", "yk-alice")


def test_device_lost_cannot_drop_last_owner_key(reg, capsys):
    # Losing a device never deactivates its YubiKey by itself; it's allowed and the key stays.
    assert run(reg, "device", "lost", "alex-mac") == 0
    assert load(reg)["hardware_keys"]["yk-alex"]["status"] == "active"
    assert "hwkey revoke yk-alex" in capsys.readouterr().out


def test_dry_run_still_refused(reg, capsys):
    refused(reg, capsys, "hwkey", "revoke", "yk-alex", "--reason", "lost", "--dry-run")


# ── allowed paths ───────────────────────────────────────────────────────────
def test_revoke_with_second_owner_key_ok(reg2):
    assert run(reg2, "hwkey", "revoke", "yk-alex", "--reason", "lost") == 0
    d = load(reg2)
    assert d["hardware_keys"]["yk-alex"]["status"] == "lost"
    assert d["devices"]["alex-mac"]["cert"]["status"] == "revoked"


def test_revoke_non_owner_key_ok(reg):
    assert run(reg, "hwkey", "revoke", "yk-alice", "--reason", "retired") == 0


def test_suspend_and_resume(reg2, capsys):
    assert run(reg2, "hwkey", "suspend", "yk-alex", "--reason", "travel") == 0
    d = load(reg2)
    k = d["hardware_keys"]["yk-alex"]
    assert k["status"] == "suspended" and k["history"][-1]["event"] == "suspended"
    assert d["devices"]["alex-mac"]["cert"]["status"] == "active"  # reversible
    assert run(reg2, "hwkey", "resume", "yk-alex") == 0
    k = load(reg2)["hardware_keys"]["yk-alex"]
    assert k["status"] == "active" and k["history"][-1]["event"] == "resumed"
    # Now the other key can be suspended, but not both.
    assert run(reg2, "hwkey", "suspend", "yk-alex-2") == 0
    capsys.readouterr()
    refused(reg2, capsys, "hwkey", "suspend", "yk-alex")


def test_resume_requires_suspended(reg, capsys):
    assert run(reg, "hwkey", "resume", "yk-alex") == 1
    assert "not suspended" in capsys.readouterr().err


def test_transfer_between_owners_with_second_key(reg2):
    assert run(reg2, "hwkey", "transfer", "yk-alex-2", "--to", "dana") == 0
    assert load(reg2)["hardware_keys"]["yk-alex-2"]["owner"] == "dana"


def test_replace_enrolls_new_and_retires_old(reg, capsys):
    assert run(reg, "hwkey", "replace", "yk-alex", "--new", "yk-alex-v2",
               "--serial", "999", "--model", "YubiKey 5C NFC") == 0
    d = load(reg)
    old, new = d["hardware_keys"]["yk-alex"], d["hardware_keys"]["yk-alex-v2"]
    assert old["status"] == "retired" and old["history"][-1]["replaced_by"] == "yk-alex-v2"
    assert new["status"] == "active" and new["owner"] == "alex"
    assert new["uses"] == old["uses"]
    assert d["devices"]["alex-mac"]["cert"]["status"] == "revoked"
    out = capsys.readouterr().out
    assert "ykman fido reset" in out and "step ca revoke beef" in out
    assert "device transfer alex-mac --to-hardware-key yk-alex-v2" in out
    parse_registry(d)


def test_replace_with_existing_active_key(reg2):
    assert run(reg2, "hwkey", "replace", "yk-alex", "--new", "yk-alex-2") == 0
    assert load(reg2)["hardware_keys"]["yk-alex"]["status"] == "retired"


def test_remove_owner_when_other_owner_has_key(tmp_path):
    d = base()
    d["hardware_keys"]["yk-dana"] = key("dana", 444)
    p = write(tmp_path, d)
    assert run(p, "person", "remove", "alex") == 0
    assert "yk-alex" not in load(p)["hardware_keys"]


def test_demote_owner_when_other_owner_has_key(tmp_path):
    d = base()
    d["hardware_keys"]["yk-dana"] = key("dana", 444)
    p = write(tmp_path, d)
    assert run(p, "person", "set-tier", "alex", "--tier", "admin") == 0


def test_dry_run_writes_nothing(reg2, capsys):
    before = reg2.read_text()
    assert run(reg2, "hwkey", "suspend", "yk-alex", "--dry-run") == 0
    assert reg2.read_text() == before
    assert "dry run" in capsys.readouterr().out


def test_guard_inactive_when_registry_has_no_owner_keys(tmp_path):
    # Bootstrapping: a registry with no owner keys yet is not blocked from other edits.
    d = base()
    d["people"]["alex"]["tier"] = None
    d["people"]["dana"]["tier"] = None
    p = write(tmp_path, d)
    assert run(p, "hwkey", "revoke", "yk-alice", "--reason", "retired") == 0
