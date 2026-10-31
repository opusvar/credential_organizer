"""Typed model and validator for access/registry.yaml (see cvc.access docstring)."""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

from cvc.broker.acl import _SENTINEL_CREDENTIALS, _UUID_RE

ENFORCED_KINDS = frozenset({"credential-store", "mqtt"})
DOCUMENTED_KINDS = frozenset({"http", "cluster", "ssh", "service"})
KINDS = ENFORCED_KINDS | DOCUMENTED_KINDS
MQTT_ACCESS = ("read", "write", "readwrite")

# Allowed keys per kind; None = free-form (documented-only kinds).
_SYSTEM_KEYS: dict[str, set[str] | None] = {
    "credential-store": {"kind", "description"},
    "mqtt": {"kind", "description", "host", "port"},
}
_GRANT_KEYS: dict[str, set[str] | None] = {
    "credential-store": {"system", "credential", "purposes"},
    "mqtt": {"system", "topics", "access"},
}
_SECRET_KEYS = frozenset({"password", "passwd", "secret", "token", "api_key", "private_key"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class RegistryError(ValueError):
    """Raised with every validation problem found, each prefixed with its path."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("invalid access registry:\n  " + "\n  ".join(errors))


@dataclass(frozen=True)
class System:
    id: str
    kind: str
    attrs: dict[str, Any] = field(default_factory=dict)  # everything except `kind`

    @property
    def enforced(self) -> bool:
        return self.kind in ENFORCED_KINDS


@dataclass(frozen=True)
class Grant:
    system: str
    path: str                                   # e.g. "roles.billing.grants[0]"
    credential: str | None = None               # credential-store
    purposes: tuple[str, ...] = ()              # credential-store
    topics: tuple[str, ...] = ()                # mqtt; may contain "{id}"
    access: str | None = None                   # mqtt: read|write|readwrite
    extra: dict[str, Any] = field(default_factory=dict)  # documented-only kinds

    def expand_topics(self, principal_id: str) -> list[str]:
        return [t.replace("{id}", principal_id) for t in self.topics]


@dataclass(frozen=True)
class Role:
    id: str
    description: str
    grants: tuple[Grant, ...]


@dataclass(frozen=True)
class MachineAuth:
    type: str
    username: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Principal:
    id: str
    roles: tuple[str, ...]
    expires: dt.date | None = None

    @property
    def section(self) -> str:
        return "agents" if isinstance(self, Agent) else "machines"

    def active(self, today: dt.date | None = None) -> bool:
        today = today or dt.date.today()
        return self.expires is None or today <= self.expires


@dataclass(frozen=True)
class Agent(Principal):
    token_sha256: str | None = None
    owner: str | None = None


@dataclass(frozen=True)
class Machine(Principal):
    auth: MachineAuth | None = None
    location: str | None = None


@dataclass(frozen=True)
class Registry:
    version: int
    systems: dict[str, System]
    roles: dict[str, Role]
    agents: dict[str, Agent]
    machines: dict[str, Machine]

    def principals(self) -> Iterator[Principal]:
        yield from self.agents.values()
        yield from self.machines.values()

    def grants_for(self, principal: Principal) -> list[tuple[Role, Grant]]:
        return [(self.roles[r], g) for r in principal.roles for g in self.roles[r].grants]

    def system_of(self, grant: Grant) -> System:
        return self.systems[grant.system]


# ── parsing ─────────────────────────────────────────────────────────────────

def load_registry(path: str | Path) -> Registry:
    with open(path, encoding="utf-8") as fh:
        return parse_registry(yaml.safe_load(fh) or {})


def _scan_secrets(node: Any, path: str, errs: list[str]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}" if path else str(k)
            kl = str(k).lower()
            if kl in _SECRET_KEYS or kl.endswith(("_password", "_secret", "_token")):
                errs.append(f"{p}: secrets are not allowed in the registry "
                            "(store them in Vaultwarden; only token_sha256 is permitted)")
            _scan_secrets(v, p, errs)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _scan_secrets(v, f"{path}[{i}]", errs)


def _mapping(data: dict, key: str, errs: list[str]) -> dict:
    v = data.get(key) or {}
    if not isinstance(v, dict):
        errs.append(f"{key}: must be a mapping")
        return {}
    return v


def _str_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) and x for x in v)


def _date(v: Any, path: str, errs: list[str]) -> dt.date | None:
    if v is None:
        return None
    if isinstance(v, dt.date):
        return v
    try:
        return dt.date.fromisoformat(str(v))
    except ValueError:
        errs.append(f"{path}: expected YYYY-MM-DD, got {v!r}")
        return None


def _parse_grant(raw: Any, path: str, systems: dict[str, System], errs: list[str]) -> Grant | None:
    if not isinstance(raw, dict):
        errs.append(f"{path}: must be a mapping")
        return None
    sid = raw.get("system")
    if sid not in systems:
        errs.append(f"{path}: unknown system {sid!r}")
        return None
    kind = systems[sid].kind
    allowed = _GRANT_KEYS.get(kind)
    if allowed is not None:
        for k in raw:
            if k not in allowed:
                errs.append(f"{path}: field {k!r} not valid for kind {kind}")
    if kind == "credential-store":
        cred = raw.get("credential")
        if not isinstance(cred, str) or not (
            cred.lower() in _SENTINEL_CREDENTIALS or _UUID_RE.match(cred)
        ):
            errs.append(f"{path}.credential: {cred!r} is not a vault item UUID or a known "
                        f"sentinel ({', '.join(sorted(_SENTINEL_CREDENTIALS))})")
        purposes = raw.get("purposes")
        if not _str_list(purposes) or not purposes:
            errs.append(f"{path}.purposes: required non-empty list of strings")
            purposes = []
        return Grant(sid, path, credential=cred, purposes=tuple(purposes))
    if kind == "mqtt":
        topics = raw.get("topics")
        if not _str_list(topics) or not topics:
            errs.append(f"{path}.topics: required non-empty list of strings")
            topics = []
        access = raw.get("access")
        if access not in MQTT_ACCESS:
            errs.append(f"{path}.access: must be one of {', '.join(MQTT_ACCESS)}, got {access!r}")
        return Grant(sid, path, topics=tuple(topics), access=access)
    return Grant(sid, path, extra={k: v for k, v in raw.items() if k != "system"})


def _parse_roles_ref(raw: Any, path: str, roles: dict, errs: list[str]) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not _str_list(raw):
        errs.append(f"{path}: must be a list of role ids")
        return ()
    for r in raw:
        if r not in roles:
            errs.append(f"{path}: unknown role {r!r}")
    return tuple(raw)


def parse_registry(data: Any) -> Registry:
    """Validate a decoded registry document; raise RegistryError listing every problem."""
    errs: list[str] = []
    if not isinstance(data, dict):
        raise RegistryError(["<root>: must be a mapping"])
    _scan_secrets(data, "", errs)
    version = data.get("version")
    if version != 1:
        errs.append(f"version: expected 1, got {version!r}")
    for k in data:
        if k not in {"version", "systems", "roles", "agents", "machines"}:
            errs.append(f"{k}: unknown top-level key")

    systems: dict[str, System] = {}
    for sid, raw in _mapping(data, "systems", errs).items():
        p = f"systems.{sid}"
        if not isinstance(raw, dict):
            errs.append(f"{p}: must be a mapping")
            continue
        kind = raw.get("kind")
        if kind not in KINDS:
            errs.append(f"{p}.kind: must be one of {', '.join(sorted(KINDS))}, got {kind!r}")
            continue
        allowed = _SYSTEM_KEYS.get(kind)
        if allowed is not None:
            for k in raw:
                if k not in allowed:
                    errs.append(f"{p}: field {k!r} not valid for kind {kind}")
        systems[sid] = System(sid, kind, {k: v for k, v in raw.items() if k != "kind"})

    roles: dict[str, Role] = {}
    for rid, raw in _mapping(data, "roles", errs).items():
        p = f"roles.{rid}"
        raw = raw or {}
        if not isinstance(raw, dict):
            errs.append(f"{p}: must be a mapping")
            continue
        grants_raw = raw.get("grants") or []
        if not isinstance(grants_raw, list):
            errs.append(f"{p}.grants: must be a list")
            grants_raw = []
        grants = [_parse_grant(g, f"{p}.grants[{i}]", systems, errs)
                  for i, g in enumerate(grants_raw)]
        roles[rid] = Role(rid, str(raw.get("description") or ""),
                          tuple(g for g in grants if g is not None))

    seen: dict[str, str] = {}
    agents: dict[str, Agent] = {}
    machines: dict[str, Machine] = {}
    for section in ("agents", "machines"):
        for pid, raw in _mapping(data, section, errs).items():
            p = f"{section}.{pid}"
            if pid in seen:
                errs.append(f"{p}: duplicate principal id {pid!r} (also in {seen[pid]})")
            seen[pid] = section
            raw = raw or {}
            if not isinstance(raw, dict):
                errs.append(f"{p}: must be a mapping")
                continue
            role_ids = _parse_roles_ref(raw.get("roles"), f"{p}.roles", roles, errs)
            expires = _date(raw.get("expires"), f"{p}.expires", errs)
            if section == "agents":
                th = raw.get("token_sha256")
                if th is not None:
                    th = str(th).strip().lower()
                    if not _HEX64.match(th):
                        errs.append(f"{p}.token_sha256: must be 64 hex characters")
                agents[pid] = Agent(pid, role_ids, expires, token_sha256=th,
                                    owner=raw.get("owner"))
            else:
                auth = None
                a = raw.get("auth")
                if a is not None:
                    if not isinstance(a, dict) or not a.get("type"):
                        errs.append(f"{p}.auth: must be a mapping with a 'type'")
                    else:
                        auth = MachineAuth(str(a["type"]), a.get("username"),
                                           {k: v for k, v in a.items()
                                            if k not in ("type", "username")})
                machines[pid] = Machine(pid, role_ids, expires, auth=auth,
                                        location=raw.get("location"))

    if errs:
        raise RegistryError(errs)
    return Registry(1, systems, roles, agents, machines)
