"""Registry edits for hardware keys and devices (D13): `cvc-access hwkey|device ...`.

Each command loads the raw YAML, mutates it, re-validates the whole document with
parse_registry, and writes it back only if it is valid. Key order is preserved
(PyYAML, sort_keys=False). YAML comments are NOT preserved.
"""
from __future__ import annotations

import argparse
import datetime as dt
import difflib
import re
import sys
from pathlib import Path
from typing import Any

import yaml

from cvc.access.model import (
    CERT_STORAGE,
    DEVICE_KINDS,
    HWKEY_LOCATIONS,
    PERSON_TIERS,
    RegistryError,
    parse_registry,
)


class EditError(Exception):
    pass


def parse_ykman_info(text: str) -> dict[str, Any]:
    """Pull serial and model out of `ykman info` output."""
    out: dict[str, Any] = {}
    m = re.search(r"^\s*Serial number:\s*(\d+)", text, re.MULTILINE)
    if m:
        out["serial"] = int(m.group(1))
    m = re.search(r"^\s*Device type:\s*(.+?)\s*$", text, re.MULTILINE)
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


# ── owner hardware-key invariant (D14) ──────────────────────────────────────
def active_owner_keys(data: dict) -> list[str]:
    """Ids of active hardware keys whose owner is a person with tier owner."""
    people = data.get("people") or {}
    owners = {pid for pid, p in people.items() if isinstance(p, dict) and p.get("tier") == "owner"}
    return sorted(k for k, v in (data.get("hardware_keys") or {}).items()
                  if isinstance(v, dict) and v.get("owner") in owners
                  and v.get("status", "active") == "active")


def _guard_owner_keys(before: list[str], data: dict, what: str) -> None:
    """Refuse an edit that would leave zero active owner keys. No override (D14)."""
    if before and not active_owner_keys(data):
        raise EditError(
            f"refused: {what} would leave zero active owner hardware keys "
            f"(currently active: {', '.join(before)}). The owner YubiKey is the root of "
            "recovery (D11/D14): enroll and activate a replacement first "
            "(`cvc-access hwkey enroll` / `hwkey replace`), or transfer the key to another "
            "owner (`hwkey transfer`). There is no --force for this rule.")


def _hwkey(data: dict, kid: str) -> dict:
    key = (data.get("hardware_keys") or {}).get(kid)
    if key is None:
        raise EditError(f"unknown hardware key {kid!r}")
    return key


def _key_certs(data: dict, kid: str) -> list[tuple[str, dict]]:
    return [(d, dev) for d, dev in (data.get("devices") or {}).items()
            if ((dev or {}).get("cert") or {}).get("storage") == "yubikey-piv"
            and ((dev or {}).get("cert") or {}).get("hardware_key") == kid]


def _oob(lines: list[str]) -> list[str]:
    return ["Out-of-band checklist (NOT executed):", *[f"  [ ] {x}" for x in lines]]


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
    key = _hwkey(data, a.id)
    before = active_owner_keys(data)
    key["status"] = a.reason
    _guard_owner_keys(before, data, f"hwkey revoke {a.id}")
    _append(key, {"date": today, "event": a.reason})
    n = 0
    for dev in (data.get("devices") or {}).values():
        cert = (dev or {}).get("cert") or {}
        if cert.get("storage") == "yubikey-piv" and cert.get("hardware_key") == a.id:
            n += _revoke_cert(dev, today, f"hardware key {a.id} {a.reason}")
    return f"hardware key {a.id} marked {a.reason}; revoked {n} device cert(s)"


def hwkey_suspend(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    """Lock a key out (reversible). Certs on it stay recorded but the key is not usable."""
    key = _hwkey(data, a.id)
    if key.get("status", "active") != "active":
        raise EditError(f"hardware key {a.id!r} is {key.get('status')}, not active")
    before = active_owner_keys(data)
    key["status"] = "suspended"
    _guard_owner_keys(before, data, f"hwkey suspend {a.id}")
    entry = {"date": today, "event": "suspended"}
    if a.reason:
        entry["reason"] = a.reason
    _append(key, entry)
    return "\n".join([f"suspended hardware key {a.id} (resume with `hwkey resume {a.id}`)",
                      *_oob([(f"remove/disable {a.id}'s FIDO2 credential in Vaultwarden and "
                             "Authentik while suspended"),
                             (f"device certs on {a.id} are NOT revoked; `step ca revoke` them "
                             "if the key may be compromised")])])


def hwkey_resume(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    key = _hwkey(data, a.id)
    if key.get("status") != "suspended":
        raise EditError(f"hardware key {a.id!r} is {key.get('status', 'active')}, not suspended")
    key["status"] = "active"
    _append(key, {"date": today, "event": "resumed"})
    return "\n".join([f"resumed hardware key {a.id}",
                      *_oob([(f"re-register {a.id} as a FIDO2 key in Vaultwarden/Authentik "
                             "if it was removed during the suspension")])])


def hwkey_transfer(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    key = _hwkey(data, a.id)
    target = (data.get("people") or {}).get(a.to)
    if not isinstance(target, dict):
        raise EditError(f"unknown person {a.to!r}")
    if target.get("tier") != "owner":
        raise EditError(f"refused: {a.to!r} has tier {target.get('tier')}; hardware keys may "
                        "only be transferred to an owner-tier person")
    src = key.get("owner")
    if src == a.to:
        raise EditError(f"hardware key {a.id!r} already belongs to {a.to!r}")
    before = active_owner_keys(data)
    key["owner"] = a.to
    _guard_owner_keys(before, data, f"hwkey transfer {a.id}")
    _append(key, {"date": today, "event": "transferred", "from": src, "to": a.to})
    certs = [d for d, _ in _key_certs(data, a.id)]
    lines = [(f"`ykman fido credentials list` on {a.id}; delete {src}'s passkeys "
             "(`ykman fido credentials delete <id>`)"),
             (f"re-register {a.id} as {a.to}'s FIDO2 key in Vaultwarden and Authentik; remove it "
             f"from {src}'s accounts"),
             ("change the PIV PIN/PUK and FIDO2 PIN (`ykman piv access change-pin`, "
             "`ykman fido access change-pin`)")]
    if certs:
        lines.append(f"device cert(s) on {a.id} ({', '.join(certs)}) were issued to {src}: "
                     "`step ca revoke <serial>` and `cvc-access device transfer` them")
    return "\n".join([f"transferred hardware key {a.id}: {src} -> {a.to}", *_oob(lines)])


def hwkey_replace(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    """Retire OLD in favour of NEW. NEW must exist and be active (or be enrolled here)."""
    old = _hwkey(data, a.old)
    keys = data["hardware_keys"]
    if a.new == a.old:
        raise EditError("--new must differ from the old key")
    if old.get("status", "active") not in ("active", "suspended"):
        raise EditError(f"hardware key {a.old!r} is already {old.get('status')}")
    msgs = []
    if a.new not in keys:
        if not (a.serial and a.model):
            raise EditError(f"hardware key {a.new!r} does not exist; enroll it first or pass "
                            "--serial and --model to enroll it here")
        keys[a.new] = {"owner": old.get("owner"), "model": a.model, "serial": _serial(a.serial),
                       "uses": list(old.get("uses") or []),
                       "location": a.location or old.get("location"), "enrolled": today,
                       "status": "active", "history": [{"date": today, "event": "enrolled"}]}
        msgs.append(f"enrolled hardware key {a.new}")
    new = keys[a.new]
    if new.get("status", "active") != "active":
        raise EditError(f"refused: replacement key {a.new!r} is {new.get('status')}; it must "
                        "be active before the old key is retired")
    before = active_owner_keys(data)
    old["status"] = "retired"
    _guard_owner_keys(before, data, f"hwkey replace {a.old}")
    _append(old, {"date": today, "event": "retired", "replaced_by": a.new})
    _append(new, {"date": today, "event": "replaces", "key": a.old})
    certs = _key_certs(data, a.old)
    serials = {d: (dev.get("cert") or {}).get("serial") for d, dev in certs}
    n = sum(_revoke_cert(dev, today, f"hardware key {a.old} replaced by {a.new}")
            for _, dev in certs)
    msgs.append(f"retired hardware key {a.old} (replaced by {a.new}); revoked {n} device cert(s)")
    lines = [(f"register {a.new} as a FIDO2 key in Vaultwarden and Authentik, then remove "
             f"{a.old} from both"),
             f"wipe {a.old}: `ykman fido reset` and `ykman piv reset` (destroys its keys)"]
    lines += [f"{_revoke_cmd(serials[d], 'superseded')}; then "
              f"`cvc-access device transfer {d} --to-hardware-key {a.new}`" for d, _ in certs]
    return "\n".join([*msgs, *_oob(lines)])


def person_set_tier(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    person = (data.get("people") or {}).get(a.id)
    if not isinstance(person, dict):
        raise EditError(f"unknown person {a.id!r}")
    before = active_owner_keys(data)
    old = person.get("tier")
    person["tier"] = a.tier
    _guard_owner_keys(before, data, f"demoting {a.id} from {old} to {a.tier}")
    return f"set tier of {a.id}: {old} -> {a.tier}"


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


def _revoke_cmd(serial: str | None, reason: str) -> str:
    return (f"step ca revoke {serial} --reason \"{reason}\"" if serial else
            "(no cert serial recorded; find it in the step-ca logs, then `step ca revoke`)")


def person_remove(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    """Offboard a person. Prints out-of-band steps; never runs them."""
    pid = a.id
    people = data.get("people") or {}
    if pid not in people:
        raise EditError(f"unknown person {pid!r}")
    before = active_owner_keys(data)
    del people[pid]
    devs = data.get("devices") or {}
    keys = data.get("hardware_keys") or {}
    agents = data.get("agents") or {}
    gone_devs = {d: v or {} for d, v in devs.items() if (v or {}).get("owner") == pid}
    gone_keys = {k: v or {} for k, v in keys.items() if (v or {}).get("owner") == pid}
    gone_agents = {g: v or {} for g, v in agents.items() if (v or {}).get("owner") == pid}
    for d in gone_devs:
        del devs[d]
    for k in gone_keys:
        del keys[k]
    for g in gone_agents:
        del agents[g]
    _guard_owner_keys(before, data, f"person remove {pid}")
    flagged = []
    for section in ("people", "agents"):
        for oid, raw in (data.get(section) or {}).items():
            if isinstance(raw, dict) and raw.get("granted_by") == pid:
                raw["granted_by"] = None
                flagged.append(f"{section}.{oid}")
    roles = sorted({r for v in (*gone_devs.values(), *gone_agents.values())
                    for r in (v.get("roles") or [])})

    out = [(f"removed person {pid}: {len(gone_devs)} device(s), {len(gone_keys)} hardware "
            f"key(s), {len(gone_agents)} assistant agent(s)")]
    out += [f"  - device {d}" for d in gone_devs]
    out += [f"  - hardware key {k} (serial {v.get('serial')})" for k, v in gone_keys.items()]
    out += [f"  - agent {g}" for g in gone_agents]
    if flagged:
        out.append(f"FLAGGED (granted_by {pid}; cleared, NOT removed -- re-sponsor or offboard):")
        out += [f"  ! {f}" for f in flagged]
    out.append("Out-of-band checklist (NOT executed):")
    for d, v in gone_devs.items():
        cert = v.get("cert") or {}
        if cert.get("status") in ("pending", "active") or cert.get("serial"):
            out.append(f"  [ ] revoke cert of {d}: {_revoke_cmd(cert.get('serial'), 'offboard')}")
    out.append(f"  [ ] remove {pid}'s devices from the Tailscale tailnet")
    out.append(f"  [ ] remove Authentik user {pid} and their passkeys/WebAuthn authenticators")
    if roles:
        out.append(f"  [ ] rotate shared credentials reachable via role(s): {', '.join(roles)}")
    else:
        out.append("  [ ] no roles found; confirm no shared credentials need rotation")
    return "\n".join(out)


def device_lost(data: dict, a: argparse.Namespace, today: dt.date) -> str:
    """Mark a device lost and revoke its cert in the registry. Never contacts step-ca."""
    dev = _device(data, a.id)
    before = active_owner_keys(data)
    if dev.get("status") == "lost":
        raise EditError(f"device {a.id!r} is already marked lost")
    cert = dev.get("cert") or {}
    serial = cert.get("serial")
    dev["status"] = "lost"
    dev["lost"] = today
    _revoke_cert(dev, today, "device lost")
    _append(dev, {"date": today, "event": "lost"})
    out = [f"marked {a.id} lost ({today})", "Out-of-band checklist (NOT executed):",
           f"  [ ] {_revoke_cmd(serial, 'device lost')}"]
    hk = cert.get("hardware_key") if cert.get("storage") == "yubikey-piv" else None
    if hk:
        out += [(f"  [ ] cert lived on YubiKey {hk}: if the key went missing with the device, "
                 f"run `cvc-access hwkey revoke {hk} --reason lost`"),
                (f"  [ ] if {hk} is still in hand: `ykman piv certificates delete 9a` and reset "
                 "the PIV PIN/PUK before re-issuing"),
                f"  [ ] if {hk} is lost, remove its FIDO2 passkeys from Authentik/Vaultwarden"]
    out.append(f"  [ ] remove {a.id} from the Tailscale tailnet")
    _guard_owner_keys(before, data, f"device lost {a.id}")
    return "\n".join(out)


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
    su = hws.add_parser("suspend", help="lock a key out (reversible; refused for the last "
                                        "active owner key)")
    su.add_argument("id")
    su.add_argument("--reason")
    su.set_defaults(edit=hwkey_suspend)
    rs = hws.add_parser("resume", help="re-activate a suspended key")
    rs.add_argument("id")
    rs.set_defaults(edit=hwkey_resume)
    tr = hws.add_parser("transfer", help="give a key to another owner-tier person")
    tr.add_argument("id")
    tr.add_argument("--to", required=True, help="person id (must be tier owner)")
    tr.set_defaults(edit=hwkey_transfer)
    rp = hws.add_parser("replace", help="retire OLD once NEW is active (enrolls NEW if "
                                        "--serial/--model are given)")
    rp.add_argument("old")
    rp.add_argument("--new", required=True)
    rp.add_argument("--serial")
    rp.add_argument("--model")
    rp.add_argument("--location", choices=HWKEY_LOCATIONS)
    rp.set_defaults(edit=hwkey_replace)

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
    lo = dvs.add_parser("lost", help="mark a device lost; prints step-ca revoke steps")
    lo.add_argument("id")
    lo.set_defaults(edit=device_lost)

    pe = sub.add_parser("person", help="offboard people")
    pes = pe.add_subparsers(dest="action", required=True)
    pr = pes.add_parser("remove", help="remove a person, their devices, keys and assistants")
    pr.add_argument("id")
    pr.set_defaults(edit=person_remove)
    st = pes.add_parser("set-tier", help="change a person's tier")
    st.add_argument("id")
    st.add_argument("--tier", required=True, choices=PERSON_TIERS)
    st.set_defaults(edit=person_set_tier)
    for p in (e, r, a, s, v, t, lo, pr, su, rs, tr, rp, st):
        p.add_argument("--registry", **reg_kw)
    for p in (lo, pr, r, su, rs, tr, rp, st):
        p.add_argument("--dry-run", action="store_true", help="show the diff; write nothing")


def run_edit(args: argparse.Namespace, today: dt.date | None = None) -> int:
    path = Path(args.registry)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        before = active_owner_keys(data)
        msg = args.edit(data, args, today or dt.datetime.now().astimezone().date())
        # Backstop for every edit, including ones added later (D14).
        _guard_owner_keys(before, data, f"{getattr(args, 'cmd', '')} "
                                        f"{getattr(args, 'action', '')}".strip() or "this edit")
        parse_registry(data)
    except RegistryError as e:
        for err in e.errors:
            print(f"error: {err}", file=sys.stderr)
        return 1
    except (EditError, OSError, ValueError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    new = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    if getattr(args, "dry_run", False):
        old = path.read_text(encoding="utf-8")
        sys.stdout.writelines(difflib.unified_diff(
            old.splitlines(keepends=True), new.splitlines(keepends=True),
            str(path), f"{path} (dry run)"))
        print(msg)
        print("dry run: registry not written")
        return 0
    path.write_text(new, encoding="utf-8")
    print(msg)
    return 0
