"""Tests for offboarding: `cvc-access person remove` and `cvc-access device lost`."""
from __future__ import annotations

import datetime as dt

import pytest
import yaml

from cvc.access import parse_registry
from cvc.access.cli import main

FP = "ab" * 32


def base() -> dict:
    return {
        "version": 1,
        "systems": {"workers": {"kind": "http"}},
        "roles": {"home-services": {"grants": [{"system": "workers", "paths": ["/"]}]}},
        "agents": {
            "alice-assistant": {"roles": ["home-services"], "owner": "alice",
                                "tier": "assistant"},
        },
        "people": {
            "nathan": {"email": "nathan@local"},
            "alice": {"email": "alice@local", "granted_by": "nathan"},
            "bob": {"email": "bob@local", "granted_by": "alice"},
        },
        "hardware_keys": {
            "yk-nathan": {"owner": "nathan", "model": "YubiKey 5C", "serial": 111,
                          "uses": ["piv-device-cert"], "location": "on-person",
                          "enrolled": dt.date(2026, 10, 1), "status": "active"},
            "yk-alice": {"owner": "alice", "model": "YubiKey 5C", "serial": 222,
                         "uses": ["piv-device-cert"], "location": "on-person",
                         "enrolled": dt.date(2026, 10, 1), "status": "active"},
        },
        "devices": {
            "alice-phone": {
                "owner": "alice", "kind": "phone",
                "cert": {"storage": "p12", "hardware_key": None, "serial": "0a1b",
                         "fingerprint_sha256": FP, "not_after": dt.date(2027, 1, 31),
                         "status": "active"},
                "roles": ["home-services"],
            },
            "nathan-mac": {
                "owner": "nathan", "kind": "laptop",
                "cert": {"storage": "yubikey-piv", "hardware_key": "yk-nathan",
                         "serial": "beef", "fingerprint_sha256": FP,
                         "not_after": dt.date(2027, 1, 31), "status": "active"},
                "roles": ["home-services"],
            },
        },
    }


@pytest.fixture
def reg(tmp_path):
    p = tmp_path / "registry.yaml"
    p.write_text(yaml.safe_dump(base(), sort_keys=False))
    return p


def load(p):
    return yaml.safe_load(p.read_text())


def test_person_remove(reg, capsys):
    assert main(["person", "remove", "alice", "--registry", str(reg)]) == 0
    out = capsys.readouterr().out
    d = load(reg)
    parse_registry(d)
    assert "alice" not in d["people"]
    assert "alice-phone" not in d["devices"] and "nathan-mac" in d["devices"]
    assert "yk-alice" not in d["hardware_keys"] and "yk-nathan" in d["hardware_keys"]
    assert "alice-assistant" not in d["agents"]
    assert "bob" in d["people"] and d["people"]["bob"]["granted_by"] is None
    assert "! people.bob" in out
    assert 'step ca revoke 0a1b --reason "offboard"' in out
    assert "Tailscale" in out and "Authentik" in out and "home-services" in out


def test_person_remove_unknown(reg, capsys):
    assert main(["person", "remove", "zed", "--registry", str(reg)]) == 1
    assert "unknown person" in capsys.readouterr().err


def test_person_remove_dry_run(reg, capsys):
    before = reg.read_text()
    assert main(["person", "remove", "alice", "--dry-run", "--registry", str(reg)]) == 0
    out = capsys.readouterr().out
    assert reg.read_text() == before
    assert "-  alice:" in out and "dry run" in out


def test_device_lost_yubikey(reg, capsys):
    assert main(["device", "lost", "nathan-mac", "--registry", str(reg)]) == 0
    out = capsys.readouterr().out
    dev = load(reg)["devices"]["nathan-mac"]
    parse_registry(load(reg))
    assert dev["status"] == "lost" and isinstance(dev["lost"], dt.date)
    assert dev["cert"]["status"] == "revoked"
    assert dev["history"][-1]["event"] == "lost"
    assert 'step ca revoke beef --reason "device lost"' in out
    assert "hwkey revoke yk-nathan" in out
    assert main(["device", "lost", "nathan-mac", "--registry", str(reg)]) == 1


def test_device_lost_p12_dry_run(reg, capsys):
    before = reg.read_text()
    assert main(["device", "lost", "alice-phone", "--dry-run", "--registry", str(reg)]) == 0
    out = capsys.readouterr().out
    assert reg.read_text() == before
    assert "+    status: lost" in out and "step ca revoke 0a1b" in out
    assert "YubiKey" not in out
