"""Tests for people, hardware keys and devices (D13) in the access registry."""
from __future__ import annotations

import copy
import datetime as dt
import io
from pathlib import Path

import pytest
import yaml

import cvc.access.graph  # noqa: F401  (registers builder)
from cvc.access import Device, RegistryError, parse_registry
from cvc.access.check import check_registry
from cvc.access.cli import main
from cvc.access.graph import build_graph

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "access" / "registry.example.yaml"
TODAY = dt.date(2026, 10, 31)
FP = "ab" * 32


def base() -> dict:
    return {
        "version": 1,
        "systems": {"workers": {"kind": "http"}},
        "roles": {"home-services": {"grants": [{"system": "workers", "paths": ["/"]}]}},
        "people": {"nathan": {"email": "nathan@local", "tier": "owner"}},
        "hardware_keys": {
            "yk-primary": {"owner": "nathan", "model": "YubiKey 5C NFC", "serial": 12345678,
                           "uses": ["fido2-vaultwarden", "piv-device-cert", "recovery"],
                           "location": "on-person", "enrolled": dt.date(2026, 11, 1),
                           "status": "active"},
            "yk-backup": {"owner": "nathan", "model": "YubiKey 5 NFC", "serial": 87654321,
                          "uses": ["fido2-vaultwarden", "recovery"],
                          "location": "home-safe", "enrolled": dt.date(2026, 11, 1),
                          "status": "active"},
        },
        "devices": {
            "nathan-iphone": {
                "owner": "nathan", "kind": "phone",
                "cert": {"storage": "p12", "hardware_key": None, "serial": "0a1b",
                         "fingerprint_sha256": FP, "not_after": dt.date(2027, 1, 31),
                         "status": "active"},
                "history": [{"date": dt.date(2026, 10, 1), "event": "issued",
                             "cert_serial": "0a1b"}],
                "roles": ["home-services"],
            },
            "nathan-mac": {
                "owner": "nathan", "kind": "laptop",
                "cert": {"storage": "yubikey-piv", "hardware_key": "yk-primary",
                         "status": "pending"},
                "roles": ["home-services"],
            },
        },
    }


def errors_of(d):
    with pytest.raises(RegistryError) as ei:
        parse_registry(d)
    return ei.value.errors


def test_parse_model_and_principals():
    reg = parse_registry(base())
    assert reg.people["nathan"].email == "nathan@local"
    hk = reg.hardware_keys["yk-primary"]
    assert hk.serial == "12345678" and "recovery" in hk.uses and hk.status == "active"
    dev = reg.devices["nathan-iphone"]
    assert isinstance(dev, Device) and dev.section == "devices"
    assert dev.cert.storage == "p12" and dev.cert.not_after == dt.date(2027, 1, 31)
    assert dev.history[0]["event"] == "issued"
    assert {p.id for p in reg.principals()} == {"nathan-iphone", "nathan-mac"}
    assert reg.grants_for(dev)[0][0].id == "home-services"


def test_example_file_has_devices():
    reg = parse_registry(yaml.safe_load(EXAMPLE.read_text()))
    assert reg.devices and reg.hardware_keys and reg.people
    assert not [f for f in check_registry(reg, TODAY) if f.level == "error"]


@pytest.mark.parametrize("mutate, needle", [
    (lambda d: d["devices"]["nathan-iphone"]["cert"].update(p12="base64..."),
     "cert.p12: secrets are not allowed"),
    (lambda d: d["hardware_keys"]["yk-primary"].update(pin="123456"), "yk-primary.pin"),
    (lambda d: d["hardware_keys"]["yk-primary"].update(puk="1"), "yk-primary.puk"),
    (lambda d: d["hardware_keys"]["yk-primary"].update(management_key="x"), "management_key"),
    (lambda d: d["devices"]["nathan-mac"].update(private_key="x"), "private_key"),
    (lambda d: d["hardware_keys"]["yk-backup"].update(serial=12345678), "duplicate serial"),
    (lambda d: d["devices"]["nathan-mac"]["cert"].update(hardware_key=None),
     "nathan-mac.cert.hardware_key: required"),
    (lambda d: d["devices"]["nathan-mac"]["cert"].update(hardware_key="ghost"),
     "unknown hardware key 'ghost'"),
    (lambda d: d["hardware_keys"]["yk-primary"].update(status="lost"),
     "hardware key 'yk-primary' is lost"),
    (lambda d: d["devices"]["nathan-iphone"]["cert"].update(hardware_key="yk-primary"),
     "only valid with storage yubikey-piv"),
    (lambda d: d["devices"]["nathan-iphone"]["history"].insert(
        0, {"date": dt.date(2026, 12, 1), "event": "x"}), "history: not in date order"),
    (lambda d: d["devices"]["nathan-iphone"].update(kind="toaster"), "nathan-iphone.kind"),
    (lambda d: d["devices"]["nathan-iphone"].update(owner="bob"), "unknown person 'bob'"),
    (lambda d: d["hardware_keys"]["yk-primary"].update(location="moon"), "location"),
    (lambda d: d["devices"]["nathan-iphone"]["cert"].update(fingerprint_sha256="zz"),
     "fingerprint_sha256"),
    (lambda d: d["devices"]["nathan-iphone"]["cert"].update(status="weird"), "cert.status"),
    (lambda d: d["devices"]["nathan-iphone"]["roles"].append("ghost"), "unknown role"),
])
def test_validation(mutate, needle):
    d = copy.deepcopy(base())
    mutate(d)
    errs = errors_of(d)
    assert any(needle in e for e in errs), errs


def test_revoked_cert_on_lost_key_ok():
    d = base()
    d["hardware_keys"]["yk-primary"]["status"] = "lost"
    d["devices"]["nathan-mac"]["cert"]["status"] = "revoked"
    parse_registry(d)


def test_check_device_findings():
    d = base()
    d["devices"]["nathan-iphone"]["cert"]["not_after"] = TODAY + dt.timedelta(days=10)
    d["devices"]["nathan-tablet"] = {"owner": "nathan", "kind": "tablet"}
    d["hardware_keys"]["yk-backup"]["location"] = "on-person"
    d["hardware_keys"]["yk-backup"]["uses"] = ["fido2-vaultwarden"]
    text = "\n".join(f"{f.level} {f.path} {f.message}"
                     for f in check_registry(parse_registry(d), TODAY))
    assert "devices.nathan-iphone" in text and "expires" in text
    assert "devices.nathan-tablet" in text and "no cert" in text
    assert "recovery" in text and "D11" in text
    assert "same location" in text


def test_check_clean_for_base():
    text = "\n".join(f.message for f in check_registry(parse_registry(base()), TODAY))
    assert "recovery" not in text and "same location" not in text


def test_graph_devices_no_cert_details():
    d = base()
    d["hardware_keys"]["yk-old"] = {"owner": "nathan", "model": "YubiKey 5", "serial": 1,
                                    "uses": ["recovery"], "location": "offsite",
                                    "enrolled": dt.date(2026, 1, 1), "status": "lost"}
    out = build_graph(parse_registry(d), TODAY)
    for title in ("People", "Hardware keys", "Devices"):
        assert f'"{title}"' in out
    assert FP not in out and "0a1b" not in out and "12345678" not in out
    assert "u_nathan --> p_nathan_iphone" in out
    assert "p_nathan_mac --> k_yk_primary" in out
    assert "p_nathan_iphone --> r_home_services" in out
    assert "(lost)" in out


# ── CLI ─────────────────────────────────────────────────────────────────────

def _reg(tmp_path):
    p = tmp_path / "registry.yaml"
    p.write_text(yaml.safe_dump(base(), sort_keys=False))
    return p


def _load(p):
    return yaml.safe_load(p.read_text())


def test_cli_hwkey_enroll_and_revoke(tmp_path, monkeypatch, capsys):
    p = _reg(tmp_path)
    assert main(["hwkey", "enroll", "--registry", str(p), "--id", "yk-new", "--owner", "nathan",
                 "--serial", "555", "--model", "YubiKey 5Ci", "--uses", "recovery,fido2-vaultwarden",
                 "--location", "offsite"]) == 0
    d = _load(p)
    assert d["hardware_keys"]["yk-new"]["status"] == "active"
    assert list(d)[:4] == ["version", "systems", "roles", "people"]  # order preserved
    assert main(["hwkey", "enroll", "--registry", str(p), "--id", "dup", "--owner", "nathan",
                 "--serial", "555", "--model", "x", "--uses", "recovery",
                 "--location", "offsite"]) != 0
    # revoking yk-primary revokes the mac's cert
    assert main(["device", "set-cert", "nathan-mac", "--registry", str(p), "--serial", "ff01",
                 "--fingerprint", FP, "--not-after", "2027-06-01"]) == 0
    assert main(["hwkey", "revoke", "yk-primary", "--registry", str(p), "--reason", "lost"]) == 0
    d = _load(p)
    assert d["hardware_keys"]["yk-primary"]["status"] == "lost"
    mac = d["devices"]["nathan-mac"]
    assert mac["cert"]["status"] == "revoked"
    assert mac["history"][-1]["event"] == "revoked" and "lost" in mac["history"][-1]["reason"]
    assert d["devices"]["nathan-iphone"]["cert"]["status"] == "active"


def test_cli_hwkey_enroll_from_ykman(tmp_path, monkeypatch):
    p = _reg(tmp_path)
    info = "Device type: YubiKey 5C NFC\nSerial number: 24680\nFirmware version: 5.7.1\n"
    monkeypatch.setattr("sys.stdin", io.StringIO(info))
    assert main(["hwkey", "enroll", "--registry", str(p), "--id", "yk-3", "--owner", "nathan",
                 "--from-ykman", "--uses", "recovery", "--location", "offsite"]) == 0
    hk = _load(p)["hardware_keys"]["yk-3"]
    assert hk["serial"] == 24680 and hk["model"] == "YubiKey 5C NFC"


def test_cli_device_lifecycle(tmp_path):
    p = _reg(tmp_path)
    assert main(["device", "add", "nathan-pc", "--registry", str(p), "--owner", "nathan",
                 "--kind", "desktop", "--storage", "yubikey-piv", "--hardware-key", "yk-primary",
                 "--roles", "home-services"]) == 0
    dev = _load(p)["devices"]["nathan-pc"]
    assert dev["cert"]["status"] == "pending" and dev["roles"] == ["home-services"]
    assert main(["device", "set-cert", "nathan-pc", "--registry", str(p), "--serial", "AB:CD",
                 "--fingerprint", FP.upper(), "--not-after", "2027-03-01"]) == 0
    cert = _load(p)["devices"]["nathan-pc"]["cert"]
    assert cert["status"] == "active" and cert["serial"] == "abcd"
    assert main(["device", "transfer", "nathan-pc", "--registry", str(p), "--to-p12"]) == 0
    dev = _load(p)["devices"]["nathan-pc"]
    assert dev["cert"] == {"storage": "p12", "hardware_key": None, "status": "pending"}
    events = [h["event"] for h in dev["history"]]
    assert events == ["issued", "transferred"]
    assert dev["history"][-1]["cert_serial"] == "abcd"
    assert main(["device", "transfer", "nathan-pc", "--registry", str(p),
                 "--to-hardware-key", "yk-primary"]) == 0
    assert _load(p)["devices"]["nathan-pc"]["cert"]["storage"] == "yubikey-piv"
    assert main(["device", "revoke", "nathan-iphone", "--registry", str(p)]) == 0
    iph = _load(p)["devices"]["nathan-iphone"]
    assert iph["cert"]["status"] == "revoked" and iph["history"][-1]["event"] == "revoked"


def test_cli_rejects_invalid_edit(tmp_path, capsys):
    p = _reg(tmp_path)
    before = p.read_text()
    assert main(["device", "add", "x", "--registry", str(p), "--owner", "nathan",
                 "--kind", "laptop", "--storage", "yubikey-piv"]) != 0
    assert p.read_text() == before
    assert "hardware_key" in capsys.readouterr().err
