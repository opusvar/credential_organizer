"""Registry edits for hardware keys and devices (D13): `cvc-access hwkey|device ...`.

Each command loads the raw YAML, mutates it, re-validates the whole document with
parse_registry, and writes it back only if it is valid. Key order is preserved
(PyYAML, sort_keys=False). YAML comments are NOT preserved.
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path
from typing import Any

import yaml

from cvc.access.model import (
    CERT_STORAGE,
    DEVICE_KINDS,
    HWKEY_LOCATIONS,
    RegistryError,
    parse_registry,
)


class EditError(Exception):
    pass


def parse_ykman_info(text: str) -> dict[str, Any]:
    """Pull serial and model out of `ykman info` output."""
    out: dict[str, Any] = {}
    m = re.search(r"^\s*Serial number:\s*(\d+)", text, re.M)
    if m:
        out["serial"] = int(m.group(1))
    m = re.search(r"^\s*Device type:\s*(.+?)\s*$", text, re.M)
    if m:
        out["model"] = m.group(1)
    return out


def _csv(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def _serial(v: str) -> int | str:
    return int(v) if v.isdigit() else v


def _section(data: dict, key: str) -> dict:
    if data.get(key) is None:
        data[key] = {}
    return data[key]


def _device(data: dict, did: str) -> dict:
    dev = (data.get("devices") or {}).get(did)
    if dev is None:
        raise EditError(f"unknown device {did!r}")
    return dev


def _append(dev: dict, entry: dict) -> None:
    dev.setdefault("history", None)
    if dev["history"] is None:
        dev["history"] = []
    dev["history"].append(entry)


def _revoke_cert(dev: dict, today: dt.date, reason: str) -> bool:
    cert = dev.get("cert")
    if not cert or cert.get("status") not in ("pending", "active"):
        return False
    cert["status"] = "revoked"
    entry = {"date": today, "event": "revoked", "reason": reason}
    if cert.get("serial"):
        entry["cert_serial"] = cert["serial"]
    _append(dev, entry)
    return True


def hwkey_enroll(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    keys = _section(data, "hardware_keys")
    if a.id in keys:
        raise EditError(f"hardware key {a.id!r} already exists")
    info = parse_ykman_info(sys.stdin.read()) if a.from_ykman else {}
    serial = _serial(a.serial) if a.serial else info.get("serial")
    model = a.model or info.get("model")
    if serial is None or not model:
        raise EditError("--serial and --model are required (or pipe `ykman info` with --from-ykman)")
    keys[a.id] = {"owner": a.owner, "model": model, "serial": serial, "uses": _csv(a.uses),
                  "location": a.location, "enrolled": today, "status": "active"}
    return f"enrolled hardware key {a.id} (serial {serial})"


def hwkey_revoke(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    key = (data.get("hardware_keys") or {}).get(a.id)
    if key is None:
        raise EditError(f"unknown hardware key {a.id!r}")
    key["status"] = a.reason
    n = 0
    for dev in (data.get("devices") or {}).values():
        cert = (dev or {}).get("cert") or {}
        if cert.get("storage") == "yubikey-piv" and cert.get("hardware_key") == a.id:
            n += _revoke_cert(dev, today, f"hardware key {a.id} {a.reason}")
    return f"hardware key {a.id} marked {a.reason}; revoked {n} device cert(s)"


def device_add(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    devs = _section(data, "devices")
    if a.id in devs:
        raise EditError(f"device {a.id!r} already exists")
    devs[a.id] = {"owner": a.owner, "kind": a.kind,
                  "cert": {"storage": a.storage, "hardware_key": a.hardware_key,
                           "status": "pending"},
                  "history": [], "roles": _csv(a.roles)}
    return f"added device {a.id} (cert pending: issue via step-ca, then `device set-cert`)"


def device_set_cert(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    dev = _device(data, a.id)
    cert = dev.get("cert") or {}
    if cert.get("status") != "pending":
        raise EditError(f"device {a.id!r} has no pending cert (use `device transfer` to re-issue)")
    serial = a.serial.lower().replace(":", "")
    cert.update(serial=serial, fingerprint_sha256=a.fingerprint.lower().replace(":", ""),
                not_after=dt.date.fromisoformat(a.not_after), status="active")
    dev["cert"] = cert
    _append(dev, {"date": today, "event": "issued", "cert_serial": serial})
    return f"recorded cert for {a.id}"


def device_revoke(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    dev = _device(data, a.id)
    if not _revoke_cert(dev, today, a.reason):
        raise EditError(f"device {a.id!r} has no pending or active cert")
    return f"revoked cert of {a.id}"


def device_transfer(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    dev = _device(data, a.id)
    old = dev.get("cert") or {}
    new = ({"storage": "p12", "hardware_key": None, "status": "pending"} if a.to_p12 else
           {"storage": "yubikey-piv", "hardware_key": a.to_hardware_key, "status": "pending"})
    src = old.get("hardware_key") or old.get("storage") or "none"
    dst = new["hardware_key"] or "p12"
    entry: dict[str, Any] = {"date": today, "event": "transferred", "from": src, "to": dst}
    if old.get("serial"):
        entry["cert_serial"] = old["serial"]
    if old:
        old["status"] = "revoked"
    _append(dev, entry)
    dev["cert"] = new
    return f"transferred {a.id}: {src} -> {dst}; new cert pending"


def add_parsers(sub: argparse._SubParsersAction, reg_kw: dict) -> None:
    hw = sub.add_parser("hwkey", help="enroll or revoke hardware keys (YubiKeys)")
    hws = hw.add_subparsers(dest="action", required=True)
    e = hws.add_parser("enroll")
    e.add_argument("--id", required=True)
    e.add_argument("--owner", default="nathan")
    e.add_argument("--serial")
    e.add_argument("--model")
    e.add_argument("--uses", required=True, help="comma-separated, e.g. recovery,fido2-vaultwarden")
    e.add_argument("--location", required=True, choices=HWKEY_LOCATIONS)
    e.add_argument("--from-ykman", action="store_true",
                   help="read `ykman info` output on stdin for serial/model")
    e.set_defaults(edit=hwkey_enroll)
    r = hws.add_parser("revoke")
    r.add_argument("id")
    r.add_argument("--reason", required=True, choices=("lost", "retired", "revoked"))
    r.set_defaults(edit=hwkey_revoke)

    dv = sub.add_parser("device", help="manage human devices and their certs (D13)")
    dvs = dv.add_subparsers(dest="action", required=True)
    a = dvs.add_parser("add")
    a.add_argument("id")
    a.add_argument("--owner", default="nathan")
    a.add_argument("--kind", required=True, choices=DEVICE_KINDS)
    a.add_argument("--storage", required=True, choices=CERT_STORAGE)
    a.add_argument("--hardware-key")
    a.add_argument("--roles", help="comma-separated role ids")
    a.set_defaults(edit=device_add)
    s = dvs.add_parser("set-cert", help="record a cert issued by step-ca")
    s.add_argument("id")
    s.add_argument("--serial", required=True)
    s.add_argument("--fingerprint", required=True, help="SHA-256 of the cert (hex)")
    s.add_argument("--not-after", required=True, help="YYYY-MM-DD")
    s.set_defaults(edit=device_set_cert)
    v = dvs.add_parser("revoke")
    v.add_argument("id")
    v.add_argument("--reason", default="manual")
    v.set_defaults(edit=device_revoke)
    t = dvs.add_parser("transfer")
    t.add_argument("id")
    g = t.add_mutually_exclusive_group(required=True)
    g.add_argument("--to-hardware-key")
    g.add_argument("--to-p12", action="store_true")
    t.set_defaults(edit=device_transfer)
    for p in (e, r, a, s, v, t):
        p.add_argument("--registry", **reg_kw)


def run_edit(args: argparse.Namespace, today: dt.date | None = None) -> int:
    path = Path(args.registry)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        msg = args.edit(data, args, today or dt.date.today())
        parse_registry(data)
    except RegistryError as e:
        for err in e.errors:
            print(f"error: {err}", file=sys.stderr)
        return 1
    except (EditError, OSError, ValueError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(msg)
    return 0
