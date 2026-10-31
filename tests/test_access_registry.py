"""Tests for the access registry model, validation, generators and CLI."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
from pathlib import Path

import pytest
import yaml

from cvc.access import (
    BUILDERS,
    RegistryError,
    load_registry,
    parse_registry,
)
from cvc.access.brokeracl import build_broker_acl
from cvc.access.check import check_registry
from cvc.access.cli import main
from cvc.access.importacl import import_broker_acl
from cvc.broker.acl import Acl

UUID1 = "11111111-2222-3333-4444-555555555555"
UUID2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TOKEN = "s3cret-token"
TOKEN_HASH = hashlib.sha256(TOKEN.encode()).hexdigest()
TODAY = dt.date(2026, 10, 31)


def base() -> dict:
    return {
        "version": 1,
        "systems": {
            "vaultwarden": {"kind": "credential-store"},
            "ha-mqtt": {"kind": "mqtt", "host": "192.168.1.208", "port": 1883},
            "workers": {"kind": "http", "hosts": ["100.73.65.49"]},
        },
        "roles": {
            "billing": {
                "description": "pay bills",
                "grants": [
                    {"system": "vaultwarden", "credential": UUID1, "purposes": ["pay-invoice"]},
                ],
            },
            "billing-audit": {
                "grants": [
                    {"system": "vaultwarden", "credential": UUID1, "purposes": ["audit"]},
                    {"system": "vaultwarden", "credential": "backup", "purposes": ["*"]},
                ],
            },
            "sensor-publish": {
                "grants": [
                    {"system": "ha-mqtt", "topics": ["sensors/{id}/#"], "access": "write"},
                ],
            },
            "worker-caller": {"grants": [{"system": "workers", "paths": ["/v1/*"]}]},
        },
        "agents": {
            "billing-agent": {
                "roles": ["billing", "billing-audit"],
                "token_sha256": TOKEN_HASH,
                "owner": "nathan",
            },
            "old-agent": {
                "roles": ["billing"],
                "token_sha256": TOKEN_HASH,
                "expires": dt.date(2026, 1, 1),
            },
        },
        "machines": {
            "garage-temp": {
                "roles": ["sensor-publish"],
                "auth": {"type": "mqtt-user", "username": "garage-temp"},
                "location": "garage",
            },
        },
    }


def errors_of(data: dict) -> list[str]:
    with pytest.raises(RegistryError) as ei:
        parse_registry(data)
    return ei.value.errors


# ── model ────────────────────────────────────────────────────────────────────

def test_parse_valid_model():
    reg = parse_registry(base())
    assert reg.systems["ha-mqtt"].kind == "mqtt"
    assert reg.systems["ha-mqtt"].enforced
    assert not reg.systems["workers"].enforced
    assert reg.systems["workers"].attrs["hosts"] == ["100.73.65.49"]
    agent = reg.agents["billing-agent"]
    assert agent.owner == "nathan" and agent.active(TODAY)
    assert not reg.agents["old-agent"].active(TODAY)
    m = reg.machines["garage-temp"]
    assert m.auth.type == "mqtt-user" and m.auth.username == "garage-temp"
    grants = reg.grants_for(m)
    assert len(grants) == 1
    role, g = grants[0]
    assert role.id == "sensor-publish"
    assert g.expand_topics(m.id) == ["sensors/garage-temp/#"]
    assert g.access == "write"
    wg = reg.roles["worker-caller"].grants[0]
    assert wg.extra == {"paths": ["/v1/*"]}
    assert {p.id for p in reg.principals()} == {"billing-agent", "old-agent", "garage-temp"}


def test_expires_as_string():
    d = base()
    d["agents"]["old-agent"]["expires"] = "2027-01-31"
    assert parse_registry(d).agents["old-agent"].expires == dt.date(2027, 1, 31)


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda d: d["roles"]["billing"]["grants"][0].update(system="nope"),
         "roles.billing.grants[0]: unknown system 'nope'"),
        (lambda d: d["agents"]["billing-agent"]["roles"].append("ghost"),
         "agents.billing-agent.roles: unknown role 'ghost'"),
        (lambda d: d["roles"]["billing"]["grants"][0].update(topics=["x"]),
         "roles.billing.grants[0]: field 'topics' not valid for kind credential-store"),
        (lambda d: d["roles"]["billing"]["grants"][0].update(credential="Acme Login"),
         "roles.billing.grants[0].credential"),
        (lambda d: d["roles"]["billing"]["grants"][0].update(purposes=[]),
         "roles.billing.grants[0].purposes"),
        (lambda d: d["roles"]["billing"]["grants"][0].pop("purposes"),
         "roles.billing.grants[0].purposes"),
        (lambda d: d["roles"]["sensor-publish"]["grants"][0].update(access="all"),
         "roles.sensor-publish.grants[0].access"),
        (lambda d: d["roles"]["sensor-publish"]["grants"][0].update(credential=UUID1),
         "field 'credential' not valid for kind mqtt"),
        (lambda d: d["machines"].update({"billing-agent": {"roles": []}}),
         "duplicate principal id 'billing-agent'"),
        (lambda d: d["agents"]["billing-agent"].update(token_sha256="zz"),
         "agents.billing-agent.token_sha256"),
        (lambda d: d["machines"]["garage-temp"]["auth"].update(password="hunter2"),
         "machines.garage-temp.auth.password: secrets are not allowed"),
        (lambda d: d["agents"]["billing-agent"].update(token="abc"),
         "agents.billing-agent.token: secrets are not allowed"),
        (lambda d: d["systems"]["ha-mqtt"].update(kind="ftp"),
         "systems.ha-mqtt.kind"),
        (lambda d: d.update(version=2), "version"),
    ],
)
def test_validation_errors(mutate, needle):
    d = copy.deepcopy(base())
    mutate(d)
    errs = errors_of(d)
    assert any(needle in e for e in errs), errs


def test_load_registry_file(tmp_path: Path):
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(base()))
    assert "garage-temp" in load_registry(p).machines


def test_example_file_is_valid():
    ex = Path(__file__).resolve().parents[1] / "access" / "registry.example.yaml"
    reg = load_registry(ex)
    assert reg.agents and reg.machines


# ── broker ACL generator ────────────────────────────────────────────────────

def test_broker_acl_round_trip(tmp_path: Path):
    out = build_broker_acl(parse_registry(base()), today=TODAY)
    assert out.startswith("# GENERATED")
    p = tmp_path / "acl.yaml"
    p.write_text(out)
    acl = Acl.load(str(p))
    assert acl.authenticate("billing-agent", TOKEN)
    assert acl.authorize("billing-agent", UUID1, "pay-invoice").allowed
    assert acl.authorize("billing-agent", UUID1, "audit").allowed  # merged purposes
    assert acl.authorize("billing-agent", "backup", "anything").allowed
    assert not acl.authorize("billing-agent", UUID2, "pay-invoice").allowed
    assert not acl.authorize("old-agent", UUID1, "pay-invoice").allowed
    data = yaml.safe_load(out)
    assert data["agents"]["old-agent"]["allow"] == []
    assert "garage-temp" not in data["agents"]  # machines aren't broker principals


def test_broker_acl_deterministic():
    d = base()
    a = build_broker_acl(parse_registry(d), today=TODAY)
    d["agents"] = dict(reversed(list(d["agents"].items())))
    d["agents"]["billing-agent"]["roles"].reverse()
    assert build_broker_acl(parse_registry(d), today=TODAY) == a


def test_builder_registry_has_broker_acl():
    assert "broker-acl" in BUILDERS


# ── import ──────────────────────────────────────────────────────────────────

def test_import_acl_round_trip(tmp_path: Path):
    acl = {
        "agents": {
            "pw": {"token_sha256": TOKEN_HASH,
                   "allow": [{"credential": UUID1, "purposes": ["login"]}]},
            "none": {"token_sha256": TOKEN_HASH, "allow": []},
        }
    }
    src = tmp_path / "acl.yaml"
    src.write_text(yaml.safe_dump(acl))
    reg_data = import_broker_acl(src)
    assert reg_data["agents"]["pw"]["roles"] == ["pw-legacy"]
    reg = parse_registry(reg_data)
    regen = yaml.safe_load(build_broker_acl(reg, today=TODAY))
    assert regen["agents"]["pw"]["allow"] == acl["agents"]["pw"]["allow"]
    assert regen["agents"]["none"]["allow"] == []


# ── check ───────────────────────────────────────────────────────────────────

def test_check_findings():
    d = base()
    d["roles"]["unused"] = {"grants": []}
    d["agents"]["soon"] = {"roles": ["billing"], "token_sha256": TOKEN_HASH,
                           "expires": TODAY + dt.timedelta(days=10)}
    d["machines"]["lonely"] = {"roles": []}
    findings = check_registry(parse_registry(d), today=TODAY)
    msgs = {(f.level, f.message.split(":")[0]) for f in findings}
    text = "\n".join(f"{f.level} {f.path} {f.message}" for f in findings)
    assert "old-agent" in text and "expired" in text
    assert "soon" in text
    assert "roles.unused" in text
    assert "machines.lonely" in text
    assert any(f.level == "info" and "unenforced" in f.message for f in findings)
    assert all(f.level != "error" for f in findings), msgs


# ── CLI ─────────────────────────────────────────────────────────────────────

def _write(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "registry.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_cli_validate(tmp_path, capsys):
    p = _write(tmp_path, base())
    assert main(["validate", "--registry", str(p)]) == 0
    bad = base()
    bad["roles"]["billing"]["grants"][0]["system"] = "nope"
    p2 = tmp_path / "bad.yaml"
    p2.write_text(yaml.safe_dump(bad))
    assert main(["validate", "--registry", str(p2)]) != 0
    assert "unknown system" in capsys.readouterr().err


def test_cli_build_and_check(tmp_path, capsys):
    p = _write(tmp_path, base())
    out = tmp_path / "deploy" / "acl.yaml"
    assert main(["build", "broker-acl", "--registry", str(p), "--out", str(out)]) == 0
    Acl.load(str(out))
    assert main(["check", "--registry", str(p)]) == 0
    assert TOKEN_HASH not in capsys.readouterr().out


def test_cli_import(tmp_path):
    src = tmp_path / "acl.yaml"
    src.write_text(yaml.safe_dump({"agents": {"pw": {"token_sha256": TOKEN_HASH, "allow": []}}}))
    out = tmp_path / "reg.yaml"
    assert main(["import-acl", str(src), "--out", str(out)]) == 0
    assert "pw" in load_registry(out).agents
    assert main(["import-acl", str(src), "--out", str(out)]) != 0  # refuses overwrite
