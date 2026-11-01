"""Voluntary delegation: wizard, revoke, decline, complete (D17, docs/DELEGATION.md).

Identity reuses the takeover verifiers. Execution reuses the takeover completion machinery
(key transfer, device-cert revocation with printed ``step ca revoke``, vault plan, D14 guard).
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml

from cvc.delegate.model import (
    SECTION_TITLES,
    SECTIONS,
    DelegationError,
    DelegationRecord,
    DelegationStore,
    new_id,
    status_line,
)
from cvc.delegate.plan import (
    REVOKE,
    DelegateInventory,
    Item,
    apply_delegation,
    build_preview,
    check_guard,
    format_preview,
    need_rank_name,
    vault_plan,
)
from cvc.takeover.flow import Notifier, load_registry, notify_owners
from cvc.takeover.model import Clock, TakeoverError
from cvc.takeover.verifiers import (
    CertIdentity,
    Elevation,
    YubiKeyReader,
    check_cert_registry,
    verify_device_cert,
    verify_owner_key,
)
from cvc.takeover.vw import VaultExecutor, format_plan


@dataclass
class Deps:
    registry_path: Path
    store: DelegationStore
    reader: YubiKeyReader
    clock: Clock
    notifier: Notifier | None = None


def _person(data: dict, pid: str) -> dict:
    p = (data.get("people") or {}).get(pid)
    if not isinstance(p, dict) or p.get("status", "active") != "active":
        raise DelegationError(f"refused: {pid!r} is not an active person in the registry")
    return p


def _notify(deps: Deps, rec: DelegationRecord, event: str, message: str) -> None:
    notify_owners(deps, event, message, extra=(rec.recipient, rec.delegator))


def _prove(deps: Deps, data: dict, person: str, passkey: Elevation | None) -> str:
    """Owner: their YubiKey. Non-owner: a passkey (never a password). Returns the factor."""
    if _person(data, person).get("tier") == "owner":
        try:
            return "yubikey:" + verify_owner_key(deps.reader.read(), data, person)
        except DelegationError:
            raise
        except TakeoverError as e:
            raise DelegationError(f"{e} ({person}'s own YubiKey is required)") from None
    if passkey is None or passkey.method != "passkey":
        raise DelegationError(f"refused: {person} is not an owner, so a passkey is required "
                              "(a password alone is never enough)")
    if not passkey.verify(person, str(_person(data, person).get("email") or "")):
        raise DelegationError(f"refused: passkey check failed for {person}")
    return "passkey"


def _items(rec_or_dicts) -> list[Item]:
    return [Item(**d) for d in rec_or_dicts]


# ── wizard ──────────────────────────────────────────────────────────────────
@dataclass
class StartWizard:
    deps: Deps
    delegator: str | None = None
    cert: CertIdentity | None = None
    factor: str | None = None
    elevation: str | None = None
    recipient: str | None = None
    preview: list[Item] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    done: list[int] = field(default_factory=list)

    def _need(self, step: int) -> dict:
        if self.done != list(range(1, step)):
            raise DelegationError(f"step {step} needs steps 1..{step - 1} to pass first")
        return load_registry(self.deps.registry_path)

    def step1_cert(self, delegator: str, leaf_pem: bytes, chain_pems: list[bytes],
                   root_pem: bytes) -> str:
        data = self._need(1)
        now = self.deps.clock()
        ident = verify_device_cert(leaf_pem, chain_pems, root_pem, now)
        did = check_cert_registry(ident, data, delegator, now.date(), tier=None)
        self.delegator, self.cert = delegator, ident
        self.done.append(1)
        return did

    def step2_factor(self, passkey: Elevation | None = None) -> str:
        data = self._need(2)
        self.factor = _prove(self.deps, data, self.delegator, passkey)
        self.done.append(2)
        return self.factor

    def step3_elevate(self, elev: Elevation) -> None:
        data = self._need(3)
        if not elev.verify(self.delegator, str(_person(data, self.delegator).get("email") or "")):
            raise DelegationError(f"refused: {elev.method} elevation failed for {self.delegator}")
        self.elevation = elev.method
        self.done.append(3)

    def step4_recipient(self, recipient: str) -> str:
        data = self._need(4)
        if recipient == self.delegator:
            raise DelegationError("refused: delegator and recipient are the same person")
        p = _person(data, recipient)
        exp = p.get("expires")
        if exp is not None and str(exp) < self.deps.clock().date().isoformat():
            raise DelegationError(f"refused: {recipient} expired on {exp}")
        if self.deps.store.open_for(recipient) or self.deps.store.open_for(self.delegator):
            raise DelegationError(f"refused: an open delegation already involves {recipient} "
                                  f"or {self.delegator}")
        self.recipient = recipient
        self.done.append(4)
        return str(p.get("tier"))

    def step5_preview(self, inventory: DelegateInventory) -> str:
        data = self._need(5)
        self.preview = build_preview(data, self.delegator, self.recipient, inventory)
        self.done.append(5)
        ceiling = str(data["people"][self.recipient].get("tier"))
        return format_preview(self.preview, self.recipient, ceiling)

    def step6_select(self, sections: list[str] | None = None) -> list[str]:
        """Default = every section. Refuses here if the D14 guard would break."""
        data = self._need(6)
        sel = list(SECTIONS) if sections is None else list(sections)
        bad = [s for s in sel if s not in SECTIONS]
        if bad or not sel:
            raise DelegationError(f"refused: choose sections from {', '.join(SECTIONS)} "
                                  f"(got {', '.join(bad) or 'none'})")
        items = [i for i in self.preview if i.section in sel]
        check_guard(data, items, self.delegator, self.recipient, self.deps.clock().date())
        self.sections = [s for s in SECTIONS if s in sel]
        self.done.append(6)
        return self.sections

    def step7_confirm(self, confirmed: list[str], typed_name: str) -> None:
        self._need(7)
        missing = [SECTION_TITLES[s] for s in self.sections if s not in confirmed]
        if missing:
            raise DelegationError("refused: confirm every selected section (missing: "
                                  + ", ".join(missing) + ")")
        if typed_name != self.recipient:
            raise DelegationError(f"refused: typed name {typed_name!r} does not match the "
                                  f"recipient exactly")
        self.done.append(7)

    def step8_start(self) -> DelegationRecord:
        self._need(8)
        now = self.deps.clock()
        items = [i.to_dict() for i in self.preview if i.section in self.sections]
        rec = DelegationRecord(
            id=new_id(now), delegator=self.delegator, recipient=self.recipient,
            started_at=now.isoformat(), delegator_cert_fingerprint=self.cert.fingerprint,
            factor=self.factor, elevation_method=self.elevation, sections=self.sections,
            preview=items)
        self.deps.store.save(rec, "started", self.delegator, now,
                             {"sections": rec.sections, "factor": rec.factor,
                              "elevation": rec.elevation_method, "items": len(items),
                              "revoked_items": sum(i["action"] == REVOKE for i in items)})
        self.done.append(8)
        revoked = [i["label"] for i in items if i["action"] == REVOKE]
        _notify(self.deps, rec, "delegation-started",
                f"{rec.delegator} started delegating {', '.join(rec.sections)} to "
                f"{rec.recipient} ({rec.id}). Nothing moves until {rec.window_ends:%Y-%m-%d %H:%M}"
                f" UTC. Revoke: cvc delegate revoke {rec.id}; decline: cvc delegate decline "
                f"{rec.id}." + (f" Will be REVOKED, not transferred: {'; '.join(revoked)}"
                               if revoked else ""))
        return rec


# ── window ──────────────────────────────────────────────────────────────────
def _pending(deps: Deps, did: str) -> DelegationRecord:
    rec = deps.store.get(did)
    if rec.status != "pending":
        raise DelegationError(f"refused: delegation {did} is already {rec.status}")
    return rec


def revoke(deps: Deps, did: str, passkey: Elevation | None = None) -> DelegationRecord:
    rec = _pending(deps, did)
    now = deps.clock()
    if not rec.in_window(now):
        raise DelegationError(f"refused: the 48-hour window of {did} closed at "
                              f"{rec.window_ends:%Y-%m-%d %H:%M} UTC; it has executed or is "
                              f"executing. Undoing it needs a new delegation back.")
    factor = _prove(deps, load_registry(deps.registry_path), rec.delegator, passkey)
    rec.status, rec.revoked_at = "revoked", now.isoformat()
    deps.store.save(rec, "revoked", rec.delegator, now, {"factor": factor})
    _notify(deps, rec, "delegation-revoked",
            f"{rec.delegator} revoked delegation {rec.id} to {rec.recipient}. Nothing moved.")
    return rec


def decline(deps: Deps, did: str, proof: Elevation) -> DelegationRecord:
    rec = _pending(deps, did)
    data = load_registry(deps.registry_path)
    if not proof.verify(rec.recipient, str(_person(data, rec.recipient).get("email") or "")):
        raise DelegationError(f"refused: only {rec.recipient} can decline, with their own "
                              f"{proof.method}")
    now = deps.clock()
    rec.status, rec.declined_at = "declined", now.isoformat()
    deps.store.save(rec, "declined", rec.recipient, now, {"method": proof.method})
    _notify(deps, rec, "delegation-declined",
            f"{rec.recipient} declined delegation {rec.id} from {rec.delegator}. Nothing moved.")
    return rec


# ── execution ───────────────────────────────────────────────────────────────
def _refuse(deps: Deps, rec: DelegationRecord, now: datetime, reason: str) -> None:
    rec.status, rec.refused_reason = "refused", reason
    deps.store.save(rec, "refused", "system", now, {"reason": reason})
    _notify(deps, rec, "delegation-refused", f"delegation {rec.id} was refused: {reason}")
    raise DelegationError(reason)


def complete(deps: Deps, did: str, inventory: DelegateInventory,
             executor: VaultExecutor | None = None, out: Callable[[str], None] = print
             ) -> DelegationRecord:
    rec = _pending(deps, did)
    now = deps.clock()
    if rec.in_window(now):
        raise DelegationError(f"refused: delegation {did} can execute after "
                              f"{rec.window_ends:%Y-%m-%d %H:%M} UTC")
    data = load_registry(deps.registry_path)
    try:
        _person(data, rec.recipient)
        _person(data, rec.delegator)
    except TakeoverError as e:
        _refuse(deps, rec, now, str(e))
    # Re-check: recompute the diff now; new items above the ceiling are revoked.
    items = [i for i in build_preview(data, rec.delegator, rec.recipient, inventory)
             if i.section in rec.sections]
    seen = {(d["section"], d["ref"]) for d in rec.preview}
    for i in items:
        if (i.section, i.ref) not in seen:
            out(f"new since preview: [{i.action}] {SECTION_TITLES[i.section]}: {i.label}")
    for i in items:
        old = next((d for d in rec.preview if (d["section"], d["ref"]) == (i.section, i.ref)),
                   None)
        if old and old["action"] != i.action:
            out(f"changed since preview: {i.label}: {old['action']} -> {i.action} "
                f"(needs {need_rank_name(i.need)})")
    try:
        lines, cmds = apply_delegation(data, items, rec.delegator, rec.recipient, now.date(),
                                       rec.id)
    except DelegationError as e:
        _refuse(deps, rec, now, str(e))
    plan = vault_plan(items, rec.delegator, rec.recipient, inventory)
    deps.registry_path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
                                  encoding="utf-8")
    for line in lines:
        out(line)
    out("Out-of-band checklist (NOT executed):")
    for c in cmds:
        out(f"  [ ] {c}")
    out(format_plan(plan))
    if executor is not None:
        executor.apply(plan, rec.delegator, rec.recipient)
        out("vault plan executed")
    else:
        out("vault plan: dry run (pass --execute-vault to apply)")
    rec.status, rec.executed_at = "executed", now.isoformat()
    rec.executed_actions = [i.to_dict() for i in items]
    deps.store.save(rec, "executed", "system", now,
                    {"items": len(items), "vault_steps": len(plan),
                     "vault_executed": executor is not None})
    revoked = [i.label for i in items if i.action == REVOKE]
    _notify(deps, rec, "delegation-executed",
            f"delegation {rec.id} {rec.delegator} -> {rec.recipient} executed."
            + (f" Revoked (not transferred): {'; '.join(revoked)}" if revoked else ""))
    return rec


def status(deps: Deps, did: str) -> str:
    return status_line(deps.store.get(did), deps.clock())
