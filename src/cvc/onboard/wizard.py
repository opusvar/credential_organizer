"""The onboarding steps. Pure over (raw registry dict, spec, seams); the CLI wires real IO.

Registry mutations go through cvc.access.edit helpers where they exist (guest_add,
device_add, hwkey_enroll). Non-guest people and agents have no public add helper, so the
wizard inserts the same shape and then validates the whole document exactly like
`cvc-access` does: parse_registry + check_tiers (tier/tailnet/grant rule) +
check_classification (agents, D16 matrix). Any error finding for the new id is a refusal.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import difflib
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cvc.access.check import check_classification, check_tiers
from cvc.access.classify import classify_grant, grant_labels
from cvc.access.edit import (
    EditError,
    device_add,
    guest_add,
    hwkey_enroll,
    owner_primary_keys,
)
from cvc.access.model import (
    AGENT_TIERS,
    CERT_STORAGE,
    DEVICE_KINDS,
    GUEST_DEFAULT_DAYS,
    GUEST_TIERS,
    HA_ACCESS,
    HWKEY_LOCATIONS,
    HWKEY_ROLES,
    PASSKEY_TIERS,
    PERSON_TIERS,
    Registry,
    RegistryError,
    parse_registry,
)
from cvc.deploygen.traefik import build_tiergate_configmap
from cvc.onboard.authentik import AuthentikClient, RecordingAuthentik, tier_group
from cvc.onboard.certs import (
    TEMPLATE,
    YK_ENROLL,
    YK_ISSUE,
    cert_commands,
    expected_sans,
    provisioner_for,
)
from cvc.onboard.core import IO, OnboardError, Runner
from cvc.tailnet.policy import PolicyError, build_policy, render_hujson

HWKEY_TIERS = frozenset({"admin", "owner"})
EA_GRANTS = (("View", 15), ("Takeover", 90), ("Takeover", 180))


@dataclass
class DeviceSpec:
    id: str
    kind: str                       # DEVICE_KINDS
    storage: str = "p12"            # CERT_STORAGE
    hardware_key: str | None = None


@dataclass
class HwKeySpec:
    id: str
    role: str = "primary"           # HWKEY_ROLES
    location: str = "on-person"
    serial: str | None = None       # if serial+model known now, enroll into the registry
    model: str | None = None
    uses: str = "fido2-vaultwarden,piv-device-cert,recovery"


@dataclass
class PersonSpec:
    id: str
    name: str
    tier: str
    granted_by: str
    tailnet: str | None = None      # default derived from tier
    email: str | None = None
    expires: dt.date | None = None  # guests: default today + GUEST_DEFAULT_DAYS
    ha: str = "none"                # guests only
    devices: list[DeviceSpec] = field(default_factory=list)
    hwkeys: list[HwKeySpec] = field(default_factory=list)


@dataclass
class AgentSpec:
    id: str
    tier: str                       # AGENT_TIERS
    sponsor: str
    granted_by: str
    roles: list[str] = field(default_factory=list)
    token_sha256: str | None = None
    expires: dt.date | None = None


@dataclass
class Seams:
    io: IO
    runner: Runner | None = None                     # used only with execute
    which: Callable[[str], str | None] = shutil.which
    authentik: AuthentikClient | None = None         # live client (execute + env token)
    today: dt.date = field(default_factory=lambda: dt.datetime.now().astimezone().date())


def default_tailnet(tier: str) -> str:
    if tier in GUEST_TIERS:
        return "guests"
    return "owner" if tier == "owner" else "family"


# ── helpers ─────────────────────────────────────────────────────────────────

def _validate(data: dict, prefix: str, agents: bool = False) -> Registry:
    """parse_registry + the existing tier/grant checks; refuse on errors touching `prefix`."""
    try:
        reg = parse_registry(data)
    except RegistryError as e:
        raise OnboardError("registry would be invalid:\n  " + "\n  ".join(e.errors)) from e
    findings = check_tiers(reg) + (check_classification(reg) if agents else [])
    errs = [f"{f.path}: {f.message}" for f in findings
            if f.level == "error" and (f.path == prefix or f.path.startswith(prefix + "."))]
    if errs:
        raise OnboardError("refused by tier rules:\n  " + "\n  ".join(errs))
    return reg


def _header(io: IO, n: int | str, title: str) -> None:
    io.out("")
    io.out(f"== Step {n}: {title} ==")


class _NoAlias(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:   # shared date objects -> no &id001 anchors
        return True


def _render(data: dict) -> str:
    return yaml.dump(data, Dumper=_NoAlias, sort_keys=False, allow_unicode=True)


def _emit_file(io: IO, path: Path, text: str, dry_run: bool, what: str) -> None:
    if dry_run:
        io.out(f"  (dry run) would write {what} to {path}:")
        io.out("    " + text.rstrip().replace("\n", "\n    "))
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        io.out(f"  wrote {what} for review: {path} (NOT applied)")


def _commit(io: IO, path: Path, original: str, data: dict, confirm_word: str,
            dry_run: bool) -> bool:
    new = _render(data)
    io.out("")
    io.out("== Registry diff ==")
    io.out("".join(difflib.unified_diff(original.splitlines(keepends=True),
                                        new.splitlines(keepends=True), str(path),
                                        f"{path} (new)")).rstrip())
    if dry_run:
        io.out("dry run: registry not written")
        return False
    ans = io.ask(f"Type '{confirm_word}' to write the registry (anything else aborts): ")
    if ans.strip() != confirm_word:
        raise OnboardError("aborted: confirmation did not match; nothing written")
    path.write_text(new, encoding="utf-8")
    io.out(f"wrote {path}")
    return True


def _run(io: IO, s: Seams, cmds, execute: bool) -> None:
    """Print commands; with execute (and the tool on PATH) run them via the runner."""
    for c in cmds:
        io.out(f"    $ {c.shell()}")
    if not execute:
        return
    tool = "step"
    if s.which(tool) is None or s.runner is None:
        io.out(f"  --execute: `{tool}` not on PATH; not run. Run the commands above by hand.")
        return
    env: dict[str, str] = {}
    for c in cmds:
        argv = [env.get(a.strip('"$'), a) if a.startswith('"$') else a for a in c.argv]
        rc, outp = s.runner(argv)
        if rc != 0:
            raise OnboardError(f"command failed ({rc}): {c.shell()}")
        if c.capture:
            env[c.capture] = outp.strip()
    io.out("  executed.")


def _load(path: Path) -> tuple[str, dict]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise OnboardError(f"cannot read registry {path}: {e}") from e
    return text, yaml.safe_load(text) or {}


# ── person ──────────────────────────────────────────────────────────────────

def _step_who(io: IO, data: dict, sp: PersonSpec, today: dt.date) -> Registry:
    _header(io, 1, "Who")
    if sp.tier not in PERSON_TIERS:
        raise OnboardError(f"tier {sp.tier!r} is not a person tier ({', '.join(PERSON_TIERS)})")
    if sp.id in (data.get("people") or {}):
        raise OnboardError(f"person {sp.id!r} already exists")
    guest = sp.tier in GUEST_TIERS
    if sp.ha not in HA_ACCESS:
        raise OnboardError(f"ha must be one of {', '.join(HA_ACCESS)}")
    if not guest and sp.ha != "none":
        raise OnboardError("HA level is only for guest tiers")
    if not guest and sp.expires is not None:
        raise OnboardError("expiry is only for guest tiers")
    tailnet = sp.tailnet or default_tailnet(sp.tier)
    hist = {"date": today, "event": "added", "display_name": sp.name, "via": "cvc onboard"}
    try:
        if guest:
            guest_add(data, argparse.Namespace(
                id=sp.id, tier=sp.tier, email=sp.email, granted_by=sp.granted_by,
                expires=sp.expires.isoformat() if sp.expires else None), today)
            entry = data["people"][sp.id]
            entry["tailnet"] = tailnet          # validated below (guests must be on guests)
            if sp.ha != "none":
                entry["ha"] = sp.ha
            entry["history"] = [hist]
        else:
            entry = {"tier": sp.tier, "tailnet": tailnet, "granted_by": sp.granted_by,
                     "history": [hist]}
            if sp.email:
                entry = {"email": sp.email, **entry}
            data.setdefault("people", None)
            if data["people"] is None:
                data["people"] = {}
            data["people"][sp.id] = entry
    except EditError as e:
        raise OnboardError(str(e)) from e
    reg = _validate(data, f"people.{sp.id}")
    p = reg.people[sp.id]
    io.out(f"  id:         {sp.id}")
    io.out(f"  name:       {sp.name}")
    io.out(f"  tier:       {p.tier}")
    io.out(f"  tailnet:    {p.tailnet}")
    io.out(f"  granted_by: {p.granted_by} (grant rule checked)")
    if guest:
        default = "" if sp.expires else f" (default {GUEST_DEFAULT_DAYS} days)"
        io.out(f"  expires:    {p.expires}{default}")
        io.out(f"  HA level:   {p.ha}")
    io.out("  verify: cvc-access check   # no errors for people." + sp.id)
    return reg


def _step_hwkeys_apply(data: dict, sp: PersonSpec, today: dt.date) -> None:
    if sp.hwkeys and sp.tier not in HWKEY_TIERS:
        raise OnboardError(f"hardware keys are enrolled for owners/admins only "
                           f"(tier {sp.tier})")
    for k in sp.hwkeys:
        if k.role not in HWKEY_ROLES or k.location not in HWKEY_LOCATIONS:
            raise OnboardError(f"hardware key {k.id}: bad role/location")
        if k.serial and k.model:
            try:
                hwkey_enroll(data, argparse.Namespace(
                    id=k.id, owner=sp.id, serial=k.serial, model=k.model, uses=k.uses,
                    location=k.location, role=k.role, from_ykman=False), today)
            except EditError as e:
                raise OnboardError(str(e)) from e


def _step_devices(io: IO, data: dict, sp: PersonSpec, s: Seams, execute: bool) -> Registry:
    _header(io, 2, "Devices + device certs (step-ca)")
    if not sp.devices:
        io.out("  (no devices given; add later with `cvc-access device add`)")
    for d in sp.devices:
        if d.kind not in DEVICE_KINDS or d.storage not in CERT_STORAGE:
            raise OnboardError(f"device {d.id}: kind/storage invalid")
        try:
            device_add(data, argparse.Namespace(id=d.id, owner=sp.id, kind=d.kind,
                                                storage=d.storage,
                                                hardware_key=d.hardware_key, roles=None),
                       s.today)
        except EditError as e:
            raise OnboardError(str(e)) from e
    reg = _validate(data, f"people.{sp.id}")
    for d in sp.devices:
        prov, dur = provisioner_for(sp.tier)
        io.out(f"  device {d.id} ({d.kind}, {d.storage}) -> cert pending")
        io.out(f"    template: {TEMPLATE}; provisioner {prov}; lifetime {dur}")
        io.out("    URI SANs: " + ", ".join(expected_sans(sp.tier, sp.id, d.id)))
        if d.storage == "yubikey-piv":
            io.out(f"    (YubiKey {d.hardware_key}: ACME device-attest-01, key on slot 9a)")
        elif d.kind == "phone":
            io.out("    (phone: .p12 + .mobileconfig bundle)")
        _run(io, s, cert_commands(sp.id, d.id, sp.tier, d.kind, d.storage), execute)
        io.out(f"    verify: step certificate inspect ./out/{d.id}/{d.id}.crt | grep urn:cvc")
        io.out(f"    record: cvc-access device set-cert {d.id} --serial S --fingerprint F "
               "--not-after YYYY-MM-DD")
    return reg


def _step_hwkeys(io: IO, data: dict, sp: PersonSpec) -> None:
    _header(io, 3, "Hardware keys (YubiKey)")
    if sp.tier not in HWKEY_TIERS:
        io.out(f"  skipped: tier {sp.tier} does not enroll hardware keys")
        return
    keys = sp.hwkeys or [HwKeySpec(f"{sp.id}-yk-primary", "primary"),
                         HwKeySpec(f"{sp.id}-yk-backup", "backup", "home-safe")]
    for k in keys:
        io.out(f"  key {k.id} ({k.role}, {k.location}):")
        io.out(f"    1. on the Mac: bash {YK_ENROLL} {k.id}   # PIN/PUK/mgmt key via ykman")
        if k.serial and k.model:
            io.out(f"    2. enrolled in registry now (serial {k.serial}, {k.model})")
        else:
            io.out(f"    2. ykman info | cvc-access hwkey enroll --id {k.id} --owner {sp.id} "
                   f"--uses {k.uses} --location {k.location} --role {k.role} --from-ykman")
        io.out(f"    3. bash {YK_ISSUE} {k.id}   # PIV device cert (slot 9a)")
        io.out("    4. register it as a FIDO2 key in Vaultwarden (two-step login)")
    if sp.tier == "owner":
        prim = owner_primary_keys(data).get(sp.id, [])
        io.out(f"  owner invariant: exactly one active primary (registry now: "
               f"{', '.join(prim) or 'none yet'}) plus a backup in the safe")
    io.out("  verify: cvc-access check   # D11/D14 hardware-key findings")


def _step_tailscale(io: IO, reg: Registry, sp: PersonSpec, out_dir: Path,
                    dry_run: bool) -> None:
    _header(io, 4, "Tailscale")
    tn = reg.people[sp.id].tailnet
    who = sp.email or sp.id
    if tn == "owner":
        io.out(f"  invite {who} as a member of the owner tailnet (admin console > Users > "
               "Invite). Never via API.")
    else:
        io.out(f"  {who} joins the '{tn}' tailnet (invite there); then share node "
               f"'services-node' from the owner tailnet to {who} (Machines > Share).")
        io.out("  shared users arrive as autogroup:shared: only :443 (Traefik) and :8710.")
    owners = sorted(p.id for p in reg.people.values()
                    if p.tier == "owner" and p.status == "active")
    try:
        policy, warns = build_policy(reg, owners)
    except PolicyError as e:
        io.out(f"  owner-tailnet policy NOT regenerated: {e}")
        return
    for w in warns:
        io.out(f"  warning: {w}")
    _emit_file(io, out_dir / "tailnet-policy.hujson", render_hujson(policy), dry_run,
               "owner-tailnet policy")
    io.out("  verify: paste into the admin console policy editor; its tests must pass")


def _step_authentik(io: IO, sp: PersonSpec, s: Seams, execute: bool) -> None:
    _header(io, 5, "Authentik")
    group = tier_group(sp.tier)
    plan = RecordingAuthentik()
    live = s.authentik if execute else None
    for client in ([plan] + ([live] if live else [])):
        r1 = client.ensure_user(sp.id, sp.name, sp.email)
        r2 = client.ensure_group(group)
        r3 = client.add_to_group(sp.id, group)
        if client is live:
            io.out(f"  executed: {r1}; {r2}; {r3}")
    io.out(f"  plan: user {sp.id} ({sp.name}), group {group}, membership")
    if sp.tier in PASSKEY_TIERS:
        io.out(f"  passkey REQUIRED (tier {sp.tier}): {sp.id} enrolls a WebAuthn passkey in "
               "Authentik user settings before first login; high/admin/owner hosts route "
               "via authentik forward-auth")
    else:
        io.out("  passkey: optional for this tier")
    if execute and not live:
        io.out("  --execute: AUTHENTIK_URL/AUTHENTIK_TOKEN not set; nothing sent")
    elif not execute:
        io.out("  (plan only; nothing sent. --execute + AUTHENTIK_TOKEN to apply)")
    io.out(f"  verify: Authentik admin > Directory > Users > {sp.id} (groups: {group})")


def _step_owner(io: IO, reg: Registry, sp: PersonSpec) -> None:
    _header(io, 6, "Owners: Vaultwarden Emergency Access + recovery password")
    if sp.tier != "owner":
        io.out("  skipped: not an owner")
        return
    others = sorted(p.id for p in reg.people.values()
                    if p.tier == "owner" and p.status == "active" and p.id != sp.id)
    if not others:
        io.out("  no other owners yet: grant Emergency Access when the next owner onboards")
    for o in others:
        for kind, days in EA_GRANTS:
            io.out(f"  [ ] {sp.id} -> {o}: Emergency Access {kind}, wait {days} days")
            io.out(f"  [ ] {o} -> {sp.id}: Emergency Access {kind}, wait {days} days")
    io.out(f"  [ ] cvc takeover recovery-set {sp.id}   # sealed recovery password")
    io.out("  verify: Vaultwarden > Settings > Emergency access lists every grant as Confirmed")


def onboard_person(registry: str | Path, sp: PersonSpec, seams: Seams, *, out_dir: str | Path,
                   dry_run: bool = False, execute: bool = False) -> int:
    io = seams.io
    path, out = Path(registry), Path(out_dir)
    if dry_run and execute:
        raise OnboardError("--dry-run and --execute are mutually exclusive")
    original, raw = _load(path)
    data = copy.deepcopy(raw)
    io.out(f"Onboarding person {sp.id}" + (" (DRY RUN: nothing is written)" if dry_run else ""))
    _step_who(io, data, sp, seams.today)
    _step_hwkeys_apply(data, sp, seams.today)
    reg = _step_devices(io, data, sp, seams, execute)
    _step_hwkeys(io, data, sp)
    _step_tailscale(io, reg, sp, out, dry_run)
    _step_authentik(io, sp, seams, execute)
    _step_owner(io, reg, sp)
    _header(io, 7, "Summary + confirm")
    p = reg.people[sp.id]
    io.out(f"  {sp.id} ({sp.name}): tier {p.tier}, tailnet {p.tailnet}, granted by "
           f"{p.granted_by}, devices {', '.join(d.id for d in sp.devices) or '-'}")
    written = _commit(io, path, original, data, sp.id, dry_run)
    try:
        _emit_file(io, out / "tiergate-configmap.yaml", build_tiergate_configmap(reg), dry_run,
                   "tiergate config")
    except RegistryError as e:
        io.out(f"  tiergate config NOT regenerated: {e}")
    io.out("")
    io.out("Final checklist:")
    for line in ([f"issue + record certs for {d.id}" for d in sp.devices]
                 + (["enroll primary + backup YubiKeys"] if sp.tier in HWKEY_TIERS else [])
                 + ["apply tailnet-policy.hujson in the Tailscale console (review first)",
                    "Authentik user/group" + (" + passkey" if sp.tier in PASSKEY_TIERS else ""),
                    "kubectl apply tiergate-configmap.yaml (review first)",
                    "cvc-access check (no errors)"]
                 + (["Emergency Access grants + recovery-set"] if sp.tier == "owner" else [])):
        io.out(f"  [ ] {line}")
    if not written:
        io.out("(registry unchanged)")
    return 0


# ── agent ───────────────────────────────────────────────────────────────────

def onboard_agent(registry: str | Path, sp: AgentSpec, seams: Seams, *,
                  dry_run: bool = False) -> int:
    io = seams.io
    path = Path(registry)
    original, raw = _load(path)
    data = copy.deepcopy(raw)
    io.out(f"Onboarding agent {sp.id}" + (" (DRY RUN: nothing is written)" if dry_run else ""))
    _header(io, 1, "Agent identity")
    if sp.tier not in AGENT_TIERS:
        raise OnboardError(f"tier {sp.tier!r} is not an agent tier ({', '.join(AGENT_TIERS)})")
    taken = set(data.get("agents") or {}) | set(data.get("machines") or {}) \
        | set(data.get("devices") or {})
    if sp.id in taken:
        raise OnboardError(f"principal {sp.id!r} already exists")
    unknown = [r for r in sp.roles if r not in (data.get("roles") or {})]
    if unknown:
        raise OnboardError(f"unknown role(s): {', '.join(unknown)}")
    entry: dict[str, Any] = {"tier": sp.tier, "tailnet": "agents", "sponsor": sp.sponsor,
                             "granted_by": sp.granted_by, "roles": list(sp.roles)}
    if sp.token_sha256:
        entry["token_sha256"] = sp.token_sha256
    if sp.expires:
        entry["expires"] = sp.expires
    if data.get("agents") is None:
        data["agents"] = {}
    data["agents"][sp.id] = entry
    reg = _validate(data, f"agents.{sp.id}", agents=True)
    a = reg.agents[sp.id]
    io.out(f"  id {sp.id}, tier {a.tier}, tailnet agents, sponsor {a.sponsor}, "
           f"granted_by {a.granted_by} (grant rule checked)")
    if a.expires:
        io.out(f"  expires {a.expires}")
    _header(io, 2, "Roles vs D16 matrix")
    for rid in a.roles:
        for g in reg.roles[rid].grants:
            d, act = grant_labels(reg, g)
            res = classify_grant(reg, a, g)
            verdict = res[1] if res else "unlabeled (not classified)"
            io.out(f"  {rid} -> {g.system} [{d or '?'}/{act or '?'}]: {verdict}")
    _header(io, 3, "Session token")
    io.out("  Mint the token out-of-band (python -m cvc.broker.tokens); give it to the agent "
           "once; store ONLY token_sha256 here. Rotate with deploy/rotate-token.sh.")
    if not sp.token_sha256:
        io.out("  token_sha256 not set yet: the broker will refuse this agent until it is")
    _commit(io, path, original, data, sp.id, dry_run)
    io.out("  next: cvc-access build broker-acl (review), cvc-access check")
    return 0
