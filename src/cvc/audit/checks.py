"""Pluggable read-only audit checks.

Each check is `fn(ctx: Context) -> list[Finding]` registered with `@check("name")`. Checks only
READ: the registry file, the takeover/delegation state stores, the broker audit log, the backup
directory, `systemctl --user show`, and (optionally) vault item metadata through an existing
read-only `bw` session. No check writes anywhere; the runner persists only its own state file.
A check that cannot get its input reports a finding (or nothing) instead of raising.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cvc.access.check import check_registry
from cvc.access.model import GUEST_TIERS, Registry, RegistryError, load_registry
from cvc.audit.findings import Finding

CheckFn = Callable[["Context"], list[Finding]]
CHECKS: dict[str, CheckFn] = {}


def check(name: str) -> Callable[[CheckFn], CheckFn]:
    def deco(fn: CheckFn) -> CheckFn:
        CHECKS[name] = fn
        return fn
    return deco


Runner = Callable[[list[str]], str]


def systemctl_runner(args: list[str]) -> str:
    return subprocess.run(args, capture_output=True, text=True, timeout=20, check=False).stdout


@dataclass
class Context:
    now: dt.datetime
    registry_path: str | None = None
    takeover_dir: str | None = None
    delegate_dir: str | None = None
    backup_dir: str | None = None
    backup_unit: str = "cvc-backup.service"
    backup_max_age_days: int = 8          # weekly timer + slack
    audit_log: str | None = None
    deny_threshold: int = 10
    deny_window_hours: int = 1
    rotation_max_age_days: int = 180
    run: Runner = systemctl_runner
    vault_items: Callable[[], list[dict]] | None = None   # None -> rotation check skipped
    _registry: Any = field(default=None, repr=False)

    @property
    def today(self) -> dt.date:
        return self.now.date()

    def registry(self) -> Registry | None:
        """Loaded once; None if no path. Raises RegistryError on an invalid file."""
        if self._registry is None and self.registry_path:
            self._registry = load_registry(self.registry_path)
        return self._registry


def _reg(ctx: Context) -> Registry | None:
    try:
        return ctx.registry()
    except (RegistryError, OSError):
        return None      # reported once by registry_check


# ── registry ────────────────────────────────────────────────────────────────
@check("registry")
def registry_check(ctx: Context) -> list[Finding]:
    if not ctx.registry_path:
        return [Finding("registry", "registry", "warn", "No access registry configured",
                        suggested_fix="set CVC_REGISTRY or pass --registry")]
    try:
        reg = ctx.registry()
    except OSError as e:
        return [Finding("registry", "registry", "error", "Access registry unreadable",
                        detail=type(e).__name__, suggested_fix="check the registry path")]
    except RegistryError as e:
        return [Finding("registry", "registry", "error",
                        f"Access registry invalid ({len(e.errors)} errors)",
                        detail="; ".join(e.errors[:10]),
                        suggested_fix="run `cvc-access validate` and fix the errors")]
    sev = {"error": "error", "warning": "warn", "info": "info"}
    return [Finding("registry", f"{f.path}:{f.message}", sev[f.level], f"{f.path}: {f.message}",
                    suggested_fix="run `cvc-access check` for context")
            for f in check_registry(reg, ctx.today)]


@check("guests")
def guests_check(ctx: Context) -> list[Finding]:
    reg = _reg(ctx)
    if reg is None:
        return []
    out = []
    for pid in sorted(reg.people):
        p = reg.people[pid]
        if p.tier not in GUEST_TIERS:
            continue
        expired = p.expires is not None and p.expires < ctx.today
        if expired and p.status == "active":
            out.append(Finding("guests", f"people.{pid}:expired", "warn",
                               f"Guest {pid} past expiry but not checked out",
                               detail=f"expired {p.expires}",
                               suggested_fix=f"cvc-access guest checkout {pid}"))
        if not (expired or p.status == "checked-out"):
            continue
        devs = [d for d in sorted(reg.devices) if reg.devices[d].owner == pid
                and reg.devices[d].cert is not None and reg.devices[d].cert.status == "active"]
        agents = [a for a in sorted(reg.agents) if reg.agents[a].sponsor_id == pid
                  and reg.agents[a].roles and reg.agents[a].active(ctx.today)]
        if devs or agents:
            out.append(Finding("guests", f"people.{pid}:leftovers", "error",
                               f"Ended guest {pid} still has active devices/agents",
                               detail=f"devices: {', '.join(devs) or '-'}; "
                                      f"agents: {', '.join(agents) or '-'}",
                               suggested_fix="revoke the device certs and agents "
                                             f"(cvc-access guest checkout {pid})"))
    return out


_DEAD = ("lost", "revoked")


@check("devices")
def devices_check(ctx: Context) -> list[Finding]:
    reg = _reg(ctx)
    if reg is None:
        return []
    out = []
    for did in sorted(reg.devices):
        d = reg.devices[did]
        if d.cert is None or d.cert.status != "active":
            continue
        last = d.history[-1].get("event") if d.history else None
        key = reg.hardware_keys.get(d.cert.hardware_key or "")
        why = None
        if last in _DEAD:
            why = f"device marked {last}"
        elif key is not None and key.status in _DEAD:
            why = f"hardware key {key.id} is {key.status}"
        if why:
            out.append(Finding("devices", f"devices.{did}", "error",
                               f"Device {did}: cert still active ({why})",
                               suggested_fix=f"cvc-access device revoke {did}, then revoke the "
                                             "serial at step-ca"))
    return out


@check("owner_keys")
def owner_keys_check(ctx: Context) -> list[Finding]:
    reg = _reg(ctx)
    if reg is None or not (reg.hardware_keys or reg.devices):
        return []
    keys = [k.id for k in reg.hardware_keys.values() if k.usable
            and (p := reg.people.get(k.owner)) is not None and p.tier == "owner"
            and p.status == "active"]
    if not keys:
        return [Finding("owner_keys", "owner_keys", "error", "No active owner hardware key",
                        detail="the owner YubiKey is the root of recovery (D11/D14)",
                        suggested_fix="enroll an owner key: cvc-access hwkey enroll")]
    if len(keys) == 1:
        return [Finding("owner_keys", "owner_keys", "warn", "Only one active owner hardware key",
                        detail=keys[0], suggested_fix="enroll a second owner key (D11)")]
    return []


# ── vault rotation ─────────────────────────────────────────────────────────
def _rotated(item: dict) -> dt.datetime | None:
    # Same rule as cvc.reminders: passwordRevisionDate, else creationDate (never revisionDate).
    from cvc.reminders.__main__ import _parse_rotated
    return _parse_rotated(item)


@check("rotation")
def rotation_check(ctx: Context) -> list[Finding]:
    if ctx.vault_items is None:
        return []
    try:
        items = ctx.vault_items()
    except Exception as e:  # noqa: BLE001 - any vault failure is a finding, not a crash
        return [Finding("rotation", "rotation:source", "warn", "Vault metadata unavailable",
                        detail=type(e).__name__, suggested_fix="check BW_SERVER / BW_SESSION")]
    names = []
    for it in items:
        login = it.get("login") or {}
        if it.get("type") != 1 or not login.get("password"):
            continue
        when = _rotated(it)
        if when is not None and (ctx.now - when).days > ctx.rotation_max_age_days:
            names.append(str(it.get("name", "")))
    if not names:
        return []
    return [Finding("rotation", "rotation", "warn",
                    f"{len(names)} credentials overdue for rotation "
                    f"(> {ctx.rotation_max_age_days}d)",
                    detail="items: " + ", ".join(sorted(names)[:50]),
                    suggested_fix="rotate them; `cvc-remind` lists them")]


# ── takeovers / delegations / passwordless blocks ──────────────────────────
@check("takeovers")
def takeovers_check(ctx: Context) -> list[Finding]:
    from cvc.delegate.model import DelegationStore
    from cvc.takeover.model import TakeoverStore
    out = []
    if ctx.takeover_dir and Path(ctx.takeover_dir).expanduser().exists():
        store = TakeoverStore(ctx.takeover_dir)
        for r in store.all().values():
            if r.status != "pending":
                continue
            out.append(Finding("takeovers", f"takeover.{r.id}", "warn",
                               f"Takeover of {r.target} by {r.initiator} in progress",
                               detail=f"phase {r.phase(ctx.now)}, {r.days_left(ctx.now)} days left",
                               suggested_fix=f"if unexpected: cvc takeover cancel {r.id}"))
        if not store.verify_history():
            out.append(Finding("takeovers", "takeover:history", "error",
                               "Takeover history hash chain broken",
                               suggested_fix="investigate tampering of history.jsonl"))
    if ctx.delegate_dir and Path(ctx.delegate_dir).expanduser().exists():
        for r in DelegationStore(ctx.delegate_dir).all().values():
            if r.status != "pending":
                continue
            left = (r.window_ends - ctx.now).total_seconds() / 86400
            out.append(Finding("takeovers", f"delegation.{r.id}", "info",
                               f"Delegation {r.delegator} -> {r.recipient} in progress",
                               detail=f"phase {r.phase(ctx.now)}, {max(0, int(left))} days left",
                               suggested_fix=f"if unexpected: cvc delegate revoke {r.id}"))
    return out


PASSWORDLESS_EVENTS = ("passwordless-block", "passwordless_block")


@check("passwordless")
def passwordless_check(ctx: Context) -> list[Finding]:
    """7-day passwordless blocks recorded as person history events (skipped if none exist)."""
    reg = _reg(ctx)
    if reg is None:
        return []
    out = []
    for pid in sorted(reg.people):
        for h in reg.people[pid].history:
            if h.get("event") not in PASSWORDLESS_EVENTS:
                continue
            try:
                start = dt.date.fromisoformat(str(h.get("date")))
            except ValueError:
                continue
            left = 7 - (ctx.today - start).days
            if left > 0:
                out.append(Finding("passwordless", f"people.{pid}:{start}", "info",
                                   f"Passwordless block active for {pid}",
                                   detail=f"{left} days left"))
    return out


# ── backups ─────────────────────────────────────────────────────────────────
@check("backup")
def backup_check(ctx: Context) -> list[Finding]:
    out = []
    raw = ctx.run(["systemctl", "--user", "show", ctx.backup_unit,
                   "--property=Result,ExecMainStatus,ActiveState"])
    props = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    if not props:
        out.append(Finding("backup", "backup:unit", "warn", "Backup unit state unknown",
                           detail=f"systemctl show {ctx.backup_unit} returned nothing"))
    elif props.get("Result", "success") != "success" or props.get("ExecMainStatus", "0") != "0":
        out.append(Finding("backup", "backup:unit", "error", "Last backup run failed",
                           detail=f"Result={props.get('Result')} "
                                  f"ExecMainStatus={props.get('ExecMainStatus')}",
                           suggested_fix=f"journalctl --user -u {ctx.backup_unit}"))
    if not ctx.backup_dir:
        return out
    d = Path(ctx.backup_dir)
    files = [f for f in d.iterdir() if f.is_file()] if d.is_dir() else []
    if not files:
        out.append(Finding("backup", "backup:files", "error", "No backup files found",
                           detail=str(d), suggested_fix="run cvc-backup"))
        return out
    newest = max(f.stat().st_mtime for f in files)
    age = (ctx.now.timestamp() - newest) / 86400
    if age > ctx.backup_max_age_days:
        out.append(Finding("backup", "backup:files", "error", "Newest backup is stale",
                           detail=f"{age:.1f} days old (> {ctx.backup_max_age_days})",
                           suggested_fix="check the cvc-backup timer"))
    return out


# ── broker audit log ────────────────────────────────────────────────────────
@check("broker_audit")
def broker_audit_check(ctx: Context) -> list[Finding]:
    if not ctx.audit_log:
        return []
    from cvc.broker.audit import AuditLog
    path = Path(ctx.audit_log)
    if not path.exists():
        return []
    out = []
    if not AuditLog.verify(_ReadOnlyLog(path)):  # type: ignore[arg-type]
        out.append(Finding("broker_audit", "broker_audit:chain", "error",
                           "Broker audit log hash chain broken",
                           detail="a line was edited, deleted or corrupted",
                           suggested_fix="compare with the off-box copy; investigate"))
    since = ctx.now - dt.timedelta(hours=ctx.deny_window_hours)
    denies: dict[str, int] = {}
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
                if not str(rec.get("outcome", "")).startswith("deny"):
                    continue
                recent = dt.datetime.fromisoformat(rec["ts"]) >= since
            except (json.JSONDecodeError, KeyError, TypeError, ValueError, AttributeError):
                continue
            if recent:
                agent = str(rec.get("agent", "?"))
                denies[agent] = denies.get(agent, 0) + 1
    for agent, n in sorted(denies.items()):
        if n >= ctx.deny_threshold:
            out.append(Finding("broker_audit", f"broker_audit:deny:{agent}", "warn",
                               f"Denied-access spike for {agent}",
                               detail=f"{n} denials in the last {ctx.deny_window_hours}h "
                                      f"(threshold {ctx.deny_threshold})",
                               suggested_fix="check the agent's ACL/token; revoke if hostile"))
    return out


class _ReadOnlyLog:
    """Stand-in giving AuditLog.verify a path without AuditLog.__init__'s mkdir."""
    def __init__(self, path: Path):
        self.path = path


def run_checks(ctx: Context, names: list[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for name in names or list(CHECKS):
        try:
            out += CHECKS[name](ctx)
        except Exception as e:  # noqa: BLE001 - one broken check must not hide the rest
            out.append(Finding(name, f"{name}:crash", "error", f"Audit check {name} failed",
                               detail=type(e).__name__))
    return out


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default
