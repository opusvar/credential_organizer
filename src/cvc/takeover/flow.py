"""Takeover operations: the start wizard, view, cancel, complete, notifications (D15)."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Protocol

import yaml

from cvc.access.edit import (
    EditError,
    _append,
    _guard_owner_keys,
    _revoke_cert,
    _revoke_cmd,
    active_owner_keys,
)
from cvc.access.model import RegistryError, parse_registry
from cvc.takeover.keys import key_role
from cvc.takeover.model import (
    VIEW_WAIT_DAYS,
    Clock,
    TakeoverError,
    TakeoverRecord,
    TakeoverStore,
    new_id,
    notify_days,
    takeover_wait_days,
)
from cvc.takeover.recovery import RecoveryVerifier
from cvc.takeover.verifiers import (
    CertIdentity,
    Elevation,
    YubiKeyReader,
    check_cert_registry,
    verify_device_cert,
    verify_owner_key,
)
from cvc.takeover.vw import (
    EmergencyAccessClient,
    VaultExecutor,
    VaultInventory,
    build_plan,
    find_grants,
    format_plan,
)


class Notifier(Protocol):
    def notify(self, person: str, event: str, message: str) -> None: ...


class MultiNotifier:
    """Fan one notification out to every configured channel (webhook, push, mail ...). A failing
    channel does not stop the others; failures are re-raised together at the end."""

    def __init__(self, channels: list[Notifier]):
        self.channels = list(channels)

    def notify(self, person: str, event: str, message: str) -> None:
        errors = []
        for ch in self.channels:
            try:
                ch.notify(person, event, message)
            except Exception as e:  # noqa: BLE001 - keep notifying the other channels
                errors.append(f"{type(ch).__name__}: {e}")
        if errors:
            raise TakeoverError("notification channel(s) failed: " + "; ".join(errors))


@dataclass
class Deps:
    registry_path: Path
    store: TakeoverStore
    vw: EmergencyAccessClient
    reader: YubiKeyReader
    clock: Clock
    notifier: Notifier | None = None


def load_registry(path: Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def _owner(data: dict, pid: str) -> dict:
    p = (data.get("people") or {}).get(pid)
    if not isinstance(p, dict):
        raise TakeoverError(f"refused: unknown person {pid!r}")
    if p.get("tier") != "owner" or p.get("status", "active") != "active":
        raise TakeoverError(f"refused: {pid!r} is not an active owner-tier person "
                            f"(tier {p.get('tier')}, status {p.get('status', 'active')})")
    return p


def active_owners(data: dict) -> list[str]:
    return sorted(pid for pid, p in (data.get("people") or {}).items()
                  if isinstance(p, dict) and p.get("tier") == "owner"
                  and p.get("status", "active") == "active")


def notify_owners(deps: Deps, event: str, message: str, extra: tuple[str, ...] = ()) -> None:
    """Notify every active owner (plus ``extra``) on every channel of ``deps.notifier``."""
    if deps.notifier is None:
        return
    people = active_owners(load_registry(deps.registry_path))
    for person in dict.fromkeys([*people, *extra]):
        deps.notifier.notify(person, event, message)


def banner_message(rec: TakeoverRecord, now: datetime) -> str:
    if rec.path == "recovery-password":
        via = "target's sealed recovery password (no YubiKey)"
    elif rec.path == "estate-kit":
        via = "the household's printed estate recovery kit (no YubiKey)"
    else:
        via = f"target's {rec.target_key_role or 'primary'} YubiKey {rec.target_key}"
    left = max(0, rec.wait_days - rec.day(now))
    return (f"Takeover request in progress: {rec.initiator} started an owner takeover of "
            f"{rec.target}'s accounts on {rec.started:%Y-%m-%d} using {via}. It can complete in "
            f"{left} day(s). Cancel with your YubiKey: cvc takeover cancel {rec.id}")


# ── start wizard ────────────────────────────────────────────────────────────
@dataclass
class StartWizard:
    """Six steps; each refuses unless every earlier step passed."""
    deps: Deps
    initiator: str | None = None
    cert: CertIdentity | None = None
    initiator_key: str | None = None
    elevation: str | None = None
    target: str | None = None
    target_key: str | None = None
    path: str | None = None
    target_key_role: str | None = None
    kit: object | None = None
    done: list[int] = field(default_factory=list)

    def _need(self, step: int) -> dict:
        if self.done != list(range(1, step)):
            raise TakeoverError(f"step {step} needs steps 1..{step - 1} to pass first")
        return load_registry(self.deps.registry_path)

    def step1_cert(self, initiator: str, leaf_pem: bytes, chain_pems: list[bytes],
                   root_pem: bytes) -> str:
        data = self._need(1)
        now = self.deps.clock()
        ident = verify_device_cert(leaf_pem, chain_pems, root_pem, now)
        did = check_cert_registry(ident, data, initiator, now.date())
        self.initiator, self.cert = initiator, ident
        self.done.append(1)
        return did

    def step2_initiator_key(self) -> str:
        data = self._need(2)
        self.initiator_key = verify_owner_key(self.deps.reader.read(), data, self.initiator)
        self.done.append(2)
        return self.initiator_key

    def step3_elevate(self, elev: Elevation) -> None:
        data = self._need(3)
        email = str(_owner(data, self.initiator).get("email") or "")
        if not elev.verify(self.initiator, email):
            raise TakeoverError(f"refused: {elev.method} elevation failed for {self.initiator}")
        self.elevation = elev.method
        self.done.append(3)

    def step4_target(self, target: str) -> None:
        data = self._need(4)
        if target == self.initiator:
            raise TakeoverError("refused: initiator and target are the same person")
        _owner(data, target)
        if self.deps.store.open_for(target) or self.deps.store.open_for(self.initiator):
            raise TakeoverError(f"refused: an open takeover already involves {target} or "
                                f"{self.initiator}")
        self.target = target
        self.done.append(4)

    def step5_target_key(self) -> str:
        """Path "key": any active owner key of the target (primary or backup)."""
        data = self._need(5)
        self.target_key = verify_owner_key(self.deps.reader.read(), data, self.target)
        if self.target_key == self.initiator_key:
            raise TakeoverError("refused: the same YubiKey was presented twice")
        self.target_key_role = key_role(data["hardware_keys"][self.target_key])
        self.path = "key"
        self.done.append(5)
        return self.target_key

    def step5_recovery_password(self, verifier: RecoveryVerifier) -> None:
        """Path "recovery-password": no target key; 180-day timeline."""
        self._need(5)
        if not verifier.verify(self.target):
            raise TakeoverError(f"refused: sealed recovery password of {self.target} is wrong")
        self.target_key, self.path = None, "recovery-password"
        self.done.append(5)

    def step5_estate_kit(self, kit) -> None:
        """Path "estate-kit": the household's printed estate recovery code; 180-day timeline.
        The kit is consumed (single use) when step 6 succeeds."""
        self._need(5)
        if not kit.verify():
            raise TakeoverError("refused: estate recovery kit code is wrong")
        self.target_key, self.path, self.kit = None, "estate-kit", kit
        self.done.append(5)

    def step6_start(self) -> TakeoverRecord:
        data = self._need(6)
        now = self.deps.clock()
        email = str(_owner(data, self.target).get("email") or "")
        view_id, take_id = find_grants(self.deps.vw, email, takeover_wait_days(self.path),
                                       VIEW_WAIT_DAYS)
        rec = TakeoverRecord(
            id=new_id(now), initiator=self.initiator, target=self.target,
            initiated_at=now.isoformat(), initiator_cert_fingerprint=self.cert.fingerprint,
            initiator_key=self.initiator_key, target_key=self.target_key,
            elevation_method=self.elevation, vw_view_grant=view_id, vw_takeover_grant=take_id,
            path=self.path, target_key_role=self.target_key_role)
        self.deps.vw.initiate(view_id)
        self.deps.vw.initiate(take_id)
        detail = {"path": rec.path, "elevation": rec.elevation_method,
                  "initiator_key": rec.initiator_key, "target_key": rec.target_key,
                  "target_key_role": rec.target_key_role}
        if self.path == "estate-kit":
            detail["estate_kit"] = self.kit.consume(rec.id, now.isoformat())
        self.deps.store.save(rec, "started", self.initiator, now, detail)
        self.done.append(6)
        if self.path == "estate-kit":
            notify_owners(self.deps, "takeover-estate-kit-used",
                          f"ESTATE RECOVERY KIT USED: {rec.initiator} started a 180-day takeover "
                          f"of {rec.target} ({rec.id}). The kit is now void; generate and print "
                          f"a new one. {rec.target} can cancel: cvc takeover cancel {rec.id}; any "
                          f"other owner can veto: cvc takeover veto {rec.id}")
        tick(self.deps)
        return rec


# ── after start ─────────────────────────────────────────────────────────────
def _pending(deps: Deps, tid: str) -> TakeoverRecord:
    rec = deps.store.get(tid)
    if rec.status != "pending":
        raise TakeoverError(f"refused: takeover {tid} is already {rec.status}")
    return rec


def cancel(deps: Deps, tid: str) -> TakeoverRecord:
    rec = _pending(deps, tid)
    data = load_registry(deps.registry_path)
    reading = deps.reader.read()
    try:
        verify_owner_key(reading, data, rec.target)
    except TakeoverError as e:
        raise TakeoverError(f"refused: only {rec.target} can cancel, with their own YubiKey "
                            f"({e})") from None
    for g in (rec.vw_view_grant, rec.vw_takeover_grant):
        deps.vw.reject(g)
    now = deps.clock()
    rec.status, rec.cancelled_at = "cancelled", now.isoformat()
    deps.store.save(rec, "cancelled", rec.target, now, {"key_serial": reading.serial})
    if deps.notifier:
        deps.notifier.notify(rec.initiator, "takeover-cancelled",
                             f"{rec.target} cancelled takeover {rec.id}")
    return rec


def veto_warning(rec: TakeoverRecord) -> str:
    return (f"WARNING: takeover {rec.id} is vetoed in cvc and can no longer complete, but "
            f"{rec.initiator}'s Vaultwarden View access to {rec.target}'s vault PERSISTS until "
            f"{rec.target} rejects the emergency-access grants from their own account "
            f"(Vaultwarden only accepts a reject from the grantor). {rec.target}: run "
            f"`cvc takeover cancel {rec.id}` with your YubiKey, or reject the grants in "
            f"Vaultwarden > Settings > Emergency access.")


def veto(deps: Deps, tid: str, vetoer: str, out: Callable[[str], None] = print
         ) -> TakeoverRecord:
    """Any active owner other than the target stops a pending takeover with their own YubiKey.
    The Vaultwarden grants cannot be rejected from the vetoer's account, so a warning is printed
    and sent to the target, the initiator and every owner."""
    rec = _pending(deps, tid)
    if vetoer == rec.target:
        raise TakeoverError(f"refused: {rec.target} is the target; use `cvc takeover cancel "
                            f"{tid}`, which also rejects the Vaultwarden grants")
    data = load_registry(deps.registry_path)
    _owner(data, vetoer)
    reading = deps.reader.read()
    try:
        verify_owner_key(reading, data, vetoer)
    except TakeoverError as e:
        raise TakeoverError(f"refused: a veto needs {vetoer}'s own YubiKey ({e})") from None
    now = deps.clock()
    rec.status, rec.vetoed_by, rec.vetoed_at = "vetoed", vetoer, now.isoformat()
    warning = veto_warning(rec)
    deps.store.save(rec, "vetoed", vetoer, now,
                    {"key_serial": reading.serial, "vw_grants_still_open": True})
    out(warning)
    notify_owners(deps, "takeover-vetoed", f"{vetoer} vetoed takeover {rec.id}. {warning}",
                  extra=(rec.target, rec.initiator))
    return rec


def view(deps: Deps, tid: str) -> int:
    rec = _pending(deps, tid)
    now = deps.clock()
    if rec.phase(now) == "requested":
        raise TakeoverError(f"refused: viewer access opens on day {VIEW_WAIT_DAYS} "
                            f"(now day {rec.day(now)})")
    verify_owner_key(deps.reader.read(), load_registry(deps.registry_path), rec.initiator)
    n = deps.vw.view(rec.vw_view_grant)
    deps.store.save(rec, "viewed", rec.initiator, now, {"items": n})
    return n


def transfer_key(data: dict, kid: str, frm: str, to: str, today, reason: str) -> str:
    key = data["hardware_keys"][kid]
    key["owner"] = to
    _append(key, {"date": today, "event": "transferred", "from": frm, "to": to,
                  "reason": reason})
    return f"  - hardware key {kid} ({key_role(key)}) transferred to {to}"


def revoke_device_cert(data: dict, did: str, today, reason: str) -> tuple[str, str] | None:
    """Revoke the device cert in the registry. Returns (summary line, out-of-band command)."""
    dev = data["devices"][did]
    serial = (dev.get("cert") or {}).get("serial")
    if not _revoke_cert(dev, today, reason):
        return None
    return (f"  - device cert of {did} revoked in registry",
            f"revoke cert of {did}: {_revoke_cmd(serial, 'cessationOfOperation')}")


def apply_account_takeover(data: dict, rec: TakeoverRecord, today, rebind_agents: bool
                           ) -> list[str]:
    """Registry edit in place. Raises EditError / RegistryError on refusal."""
    tgt, ini = rec.target, rec.initiator
    reason = f"takeover {rec.id}"
    before = active_owner_keys(data)
    people = data.get("people") or {}
    out = [f"account takeover {rec.id}: {tgt} -> {ini}"]
    for kid, key in sorted((data.get("hardware_keys") or {}).items()):
        if isinstance(key, dict) and key.get("owner") == tgt:
            out.append(transfer_key(data, kid, tgt, ini, today, reason))
    cmds = []
    for did, dev in sorted((data.get("devices") or {}).items()):
        if isinstance(dev, dict) and dev.get("owner") == tgt:
            r = revoke_device_cert(data, did, today, reason)
            if r:
                out.append(r[0])
                cmds.append(r[1])
    agents = data.get("agents") or {}
    for gid in sorted(agents):
        a = agents[gid]
        if isinstance(a, dict) and a.get("owner") == tgt:
            if rebind_agents:
                a["owner"] = ini
                out.append(f"  - assistant agent {gid} rebound to {ini}")
            else:
                del agents[gid]
                out.append(f"  - assistant agent {gid} removed")
    for section in ("people", "agents"):
        for oid, raw in (data.get(section) or {}).items():
            if isinstance(raw, dict) and raw.get("granted_by") == tgt and oid != ini:
                raw["granted_by"] = ini
                out.append(f"  - {section}.{oid}.granted_by: {tgt} -> {ini}")
    people[tgt]["status"] = "taken-over"
    _guard_owner_keys(before, data, f"takeover complete {rec.id}")
    if people.get(ini, {}).get("tier") != "owner":
        raise EditError(f"refused: initiator {ini!r} is no longer owner-tier")
    parse_registry(data)
    out.append("Out-of-band checklist (NOT executed):")
    out += [f"  [ ] {c}" for c in cmds]
    out += [f"  [ ] reset PINs on transferred keys and re-register them as {ini}'s FIDO2 keys",
            f"  [ ] disable Authentik user {tgt}; remove {tgt}'s devices from the tailnet"]
    return out


def complete(deps: Deps, tid: str, inventory: VaultInventory,
             executor: VaultExecutor | None = None, rebind_agents: bool = False,
             out: Callable[[str], None] = print) -> TakeoverRecord:
    rec = _pending(deps, tid)
    now = deps.clock()
    if rec.phase(now) != "completable":
        raise TakeoverError(f"refused: takeover {tid} ({rec.path} path) can complete on day "
                            f"{rec.wait_days}; now day {rec.day(now)}")
    data = load_registry(deps.registry_path)
    verify_owner_key(deps.reader.read(), data, rec.initiator)
    try:
        lines = apply_account_takeover(data, rec, now.date(), rebind_agents)
    except RegistryError as e:
        raise TakeoverError("refused: registry invalid after takeover: " + "; ".join(e.errors))
    except EditError as e:
        raise TakeoverError(str(e)) from None
    plan = build_plan(inventory.items_for(rec.target), rec.target, rec.initiator)
    deps.vw.takeover(rec.vw_takeover_grant)
    deps.registry_path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
                                  encoding="utf-8")
    for line in lines:
        out(line)
    out(format_plan(plan))
    if executor is not None:
        executor.apply(plan, rec.target, rec.initiator)
        out("vault plan executed")
    else:
        out("vault plan: dry run (pass --execute-vault to apply)")
    rec.status, rec.completed_at = "completed", now.isoformat()
    deps.store.save(rec, "completed", rec.initiator, now,
                    {"vault_steps": len(plan), "vault_executed": executor is not None,
                     "rebind_agents": rebind_agents})
    return rec


def tick(deps: Deps) -> list[tuple[str, int]]:
    """Send due banner notifications (days 0/7/14/85, plus 170 on the recovery path)."""
    sent: list[tuple[str, int]] = []
    if deps.notifier is None:
        return sent
    now = deps.clock()
    for rec in deps.store.all().values():
        if rec.status != "pending":
            continue
        due = [d for d in notify_days(rec.path) if rec.day(now) >= d and d not in rec.notified]
        if not due:
            continue
        deps.notifier.notify(rec.target, "takeover-banner", banner_message(rec, now))
        rec.notified.extend(due)
        deps.store.save(rec, "notified", "system", now, {"days": due, "path": rec.path})
        sent += [(rec.id, d) for d in due]
    return sent
