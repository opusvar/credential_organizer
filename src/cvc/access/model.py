"""Typed model and validator for access/registry.yaml (see cvc.access docstring)."""
from __future__ import annotations

import dataclasses
import datetime as dt
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from cvc.broker.acl import _SENTINEL_CREDENTIALS, _UUID_RE

ENFORCED_KINDS = frozenset({"credential-store", "mqtt"})
DOCUMENTED_KINDS = frozenset({"http", "cluster", "ssh", "service"})
KINDS = ENFORCED_KINDS | DOCUMENTED_KINDS
MQTT_ACCESS = ("read", "write", "readwrite")

# Allowed keys per kind; None = free-form (documented-only kinds).
# D16 classification labels (docs/ACCESS-CLASSIFICATION.md).
DATA_LEVELS = ("public", "internal", "private", "secret")
ACTIONS = ("read", "relay", "write", "act", "delegate")
GRANT_VIA = ("broker-approved",)        # the only path to secret data (D16 section 3.2)
_LABEL_KEYS = {"data", "action"}
_SYSTEM_KEYS: dict[str, set[str] | None] = {
    "credential-store": {"kind", "description"} | _LABEL_KEYS,
    "mqtt": {"kind", "description", "host", "port"} | _LABEL_KEYS,
}
_GRANT_KEYS: dict[str, set[str] | None] = {
    "credential-store": {"system", "credential", "purposes", "via"} | _LABEL_KEYS,
    "mqtt": {"system", "topics", "access", "via"} | _LABEL_KEYS,
}
_SECRET_KEYS = frozenset({"password", "passwd", "secret", "token", "api_key", "private_key",
                          "p12", "pin", "puk", "management_key"})
DEVICE_KINDS = ("phone", "laptop", "desktop", "tablet")
CERT_STORAGE = ("p12", "yubikey-piv")
CERT_STATUS = ("pending", "active", "revoked", "expired")
PERSON_STATUS = ("active", "taken-over", "checked-out")  # taken-over: D15; checked-out: guest
HWKEY_ROLES = ("primary", "backup")
HWKEY_STATUS = ("active", "lost", "revoked", "retired", "suspended")
HWKEY_LOCATIONS = ("on-person", "home-safe", "offsite")
HWKEY_USES = ("fido2-vaultwarden", "piv-device-cert", "recovery")
PERSON_TIERS = ("guest-short", "guest-long", "media-only", "low", "medium", "high", "admin",
                "owner")
GUEST_TIERS = frozenset({"guest-short", "guest-long"})
AGENT_TIERS = ("scoped", "low", "medium", "high", "assistant")
TAILNETS = ("owner", "family", "guests", "agents", "machines")
_LEGACY_TAILNETS = {"long-guests": "guests", "short-guests": "guests"}
GUEST_DEFAULT_DAYS = 5
HA_ACCESS = ("none", "view", "limited-control")
RESOURCE_KINDS = ("media", "ha", "dashboard", "library", "admin")
PASSKEY_TIERS = frozenset({"high", "admin", "owner"})
_RESOURCE_KEYS = frozenset({"name", "host", "url", "kind", "min_tier", "ha_level"})
_HEX = re.compile(r"^[0-9a-f]+$")
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
    data: str | None = None          # DATA_LEVELS
    action: str | None = None        # ACTIONS: highest action the system exposes

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
    data: str | None = None                     # overrides the system's data label
    action: str | None = None                   # action granted (defaults to system's)
    via: str | None = None                      # GRANT_VIA

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
        if isinstance(self, Device):
            return "devices"
        return "agents" if isinstance(self, Agent) else "machines"

    def active(self, today: dt.date | None = None) -> bool:
        today = today or dt.datetime.now().astimezone().date()
        return self.expires is None or today <= self.expires


@dataclass(frozen=True)
class Agent(Principal):
    token_sha256: str | None = None
    owner: str | None = None
    tier: str | None = None          # AGENT_TIERS
    tailnet: str | None = None       # TAILNETS
    granted_by: str | None = None    # person id
    sponsor: str | None = None       # person id (D16 section 6); falls back to owner

    @property
    def sponsor_id(self) -> str | None:
        return self.sponsor or self.owner


@dataclass(frozen=True)
class Machine(Principal):
    auth: MachineAuth | None = None
    location: str | None = None


@dataclass(frozen=True)
class Person:
    id: str
    email: str | None = None
    tier: str | None = None          # PERSON_TIERS
    tailnet: str | None = None       # TAILNETS
    ha: str = "none"                 # HA_ACCESS (guest tiers only)
    expires: dt.date | None = None
    granted_by: str | None = None    # person id
    status: str = "active"           # PERSON_STATUS
    history: tuple[dict, ...] = ()
    name: str | None = None          # optional display name (takeover/onboard/graph)

    @property
    def display_name(self) -> str:
        return self.name or self.id

    def active(self, today: dt.date | None = None) -> bool:
        if self.status == "checked-out":
            return False
        today = today or dt.datetime.now().astimezone().date()
        return self.expires is None or today <= self.expires


@dataclass(frozen=True)
class HardwareKey:
    id: str
    owner: str
    model: str
    serial: str                  # public identifier (stringified)
    uses: tuple[str, ...]
    location: str
    enrolled: dt.date | None
    status: str
    role: str | None = None      # HWKEY_ROLES (owner keys: exactly one active primary)

    @property
    def usable(self) -> bool:
        return self.status == "active"


@dataclass(frozen=True)
class DeviceCert:
    storage: str
    status: str
    hardware_key: str | None = None
    serial: str | None = None
    fingerprint_sha256: str | None = None
    not_after: dt.date | None = None


@dataclass(frozen=True)
class Device(Principal):
    owner: str | None = None
    kind: str | None = None
    cert: DeviceCert | None = None
    history: tuple[dict, ...] = ()


@dataclass(frozen=True)
class Resource:
    """A human-facing service behind the tier gate. `min_tier` is validated by check."""
    id: str
    name: str
    host: str                        # lowercase hostname (from `host`, else from `url`)
    kind: str                        # RESOURCE_KINDS
    min_tier: str
    url: str | None = None
    ha_level: str | None = None      # HA_ACCESS minus "none"; kind ha only

    @property
    def passkey_required(self) -> bool:
        return self.min_tier in PASSKEY_TIERS


@dataclass(frozen=True)
class Registry:
    version: int
    systems: dict[str, System]
    roles: dict[str, Role]
    agents: dict[str, Agent]
    machines: dict[str, Machine]
    people: dict[str, Person] = field(default_factory=dict)
    hardware_keys: dict[str, HardwareKey] = field(default_factory=dict)
    devices: dict[str, Device] = field(default_factory=dict)
    resources: dict[str, Resource] = field(default_factory=dict)

    def principals(self) -> Iterator[Principal]:
        yield from self.agents.values()
        yield from self.machines.values()
        yield from self.devices.values()

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


def _labels(raw: dict, path: str, errs: list[str]) -> dict[str, str | None]:
    return {"data": _opt_choice(raw.get("data"), DATA_LEVELS, f"{path}.data", errs),
            "action": _opt_choice(raw.get("action"), ACTIONS, f"{path}.action", errs)}


def _parse_grant(raw: Any, path: str, systems: dict[str, System], errs: list[str]) -> Grant | None:
    g = _parse_grant_body(raw, path, systems, errs)
    if g is None:
        return None
    return dataclasses.replace(
        g, **_labels(raw, path, errs),
        via=_opt_choice(raw.get("via"), GRANT_VIA, f"{path}.via", errs),
        extra={k: v for k, v in g.extra.items() if k not in ("data", "action", "via")})


def _parse_grant_body(raw: Any, path: str, systems: dict[str, System],
                      errs: list[str]) -> Grant | None:
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
        if k not in {"version", "systems", "roles", "agents", "machines", "people",
                     "hardware_keys", "devices", "resources"}:
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
        systems[sid] = System(sid, kind, {k: v for k, v in raw.items()
                                          if k not in ("kind", "data", "action")},
                              **_labels(raw, p, errs))

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
                agents[pid] = Agent(
                    pid, role_ids, expires, token_sha256=th, owner=raw.get("owner"),
                    tier=_opt_choice(raw.get("tier"), AGENT_TIERS, f"{p}.tier", errs),
                    tailnet=_tailnet(raw.get("tailnet"), f"{p}.tailnet", errs),
                    granted_by=raw.get("granted_by"), sponsor=raw.get("sponsor"))
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

    people, hwkeys, devices = _parse_humans(data, roles, seen, errs)
    agents = _apply_sponsors(agents, people, errs)
    resources = _parse_resources(data, errs)
    if errs:
        raise RegistryError(errs)
    return Registry(1, systems, roles, agents, machines, people, hwkeys, devices, resources)


def _apply_sponsors(agents: dict[str, Agent], people: dict[str, Person],
                    errs: list[str]) -> dict[str, Agent]:
    """Validate sponsors; guest-sponsored agents expire with their guest (D16 section 6)."""
    out = {}
    for aid, a in agents.items():
        if a.sponsor is not None and a.sponsor not in people:
            errs.append(f"agents.{aid}.sponsor: unknown person {a.sponsor!r}")
        sp = people.get(a.sponsor_id or "")
        if sp is not None and sp.tier in GUEST_TIERS:
            end = sp.expires
            if sp.status == "checked-out" and end is not None:
                end = end - dt.timedelta(days=1)     # checked out: access ended that day
            if end is not None and (a.expires is None or end < a.expires):
                a = dataclasses.replace(a, expires=end)
        out[aid] = a
    return out


def _parse_resources(data: dict, errs: list[str]) -> dict[str, Resource]:
    """Structural validation only; unknown tiers and duplicate hosts are check findings."""
    out: dict[str, Resource] = {}
    for rid, raw in _mapping(data, "resources", errs).items():
        p = f"resources.{rid}"
        if not isinstance(raw, dict):
            errs.append(f"{p}: must be a mapping")
            continue
        for k in raw:
            if k not in _RESOURCE_KEYS:
                errs.append(f"{p}: unknown field {k!r}")
        kind = _choice(raw.get("kind"), RESOURCE_KINDS, f"{p}.kind", errs)
        url = raw.get("url")
        host = raw.get("host")
        if url is not None:
            url = str(url)
            parsed = urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                errs.append(f"{p}.url: must be an http(s) URL, got {url!r}")
            elif host is None:
                host = parsed.hostname
        if not host or not isinstance(host, str):
            errs.append(f"{p}: requires a host or url")
            host = ""
        host = host.strip().lower()
        if ":" in host or "/" in host:
            errs.append(f"{p}.host: hostname only (no port or path), got {host!r}")
        min_tier = raw.get("min_tier")
        if not isinstance(min_tier, str) or not min_tier:
            errs.append(f"{p}.min_tier: required")
            min_tier = ""
        ha_level = raw.get("ha_level")
        if ha_level is not None:
            ha_level = _choice(ha_level, HA_ACCESS[1:], f"{p}.ha_level", errs)
            if kind != "ha":
                errs.append(f"{p}.ha_level: only valid for kind ha")
        out[rid] = Resource(rid, str(raw.get("name") or rid), host, kind, min_tier, url,
                            ha_level)
    return out


def _choice(v: Any, allowed: tuple[str, ...], path: str, errs: list[str]) -> str:
    if v not in allowed:
        errs.append(f"{path}: must be one of {', '.join(allowed)}, got {v!r}")
    return str(v)


def _opt_choice(v: Any, allowed: tuple[str, ...], path: str, errs: list[str]) -> str | None:
    return None if v is None else _choice(v, allowed, path, errs)


def _tailnet(v: Any, path: str, errs: list[str]) -> str | None:
    if v in _LEGACY_TAILNETS:
        errs.append(f"{path}: tailnet {v!r} was merged into {_LEGACY_TAILNETS[v]!r} (D16)")
        return str(v)
    return _opt_choice(v, TAILNETS, path, errs)


def _hex(v: Any, path: str, errs: list[str], exact64: bool = False) -> str | None:
    if v is None:
        return None
    h = str(v).strip().lower().replace(":", "")
    if not _HEX.match(h) or (exact64 and len(h) != 64):
        errs.append(f"{path}: must be {'64 ' if exact64 else ''}hex characters")
    return h


def _name(v: Any, path: str, errs: list[str]) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str) or not v.strip():
        errs.append(f"{path}: must be a non-empty string")
        return None
    return v.strip()


def _parse_humans(data: dict, roles: dict, seen: dict, errs: list[str]):
    people: dict[str, Person] = {}
    for pid, raw in _mapping(data, "people", errs).items():
        raw = raw or {}
        if not isinstance(raw, dict):
            errs.append(f"people.{pid}: must be a mapping")
            continue
        p = f"people.{pid}"
        people[pid] = Person(
            pid, raw.get("email"),
            tier=_opt_choice(raw.get("tier"), PERSON_TIERS, f"{p}.tier", errs),
            tailnet=_tailnet(raw.get("tailnet"), f"{p}.tailnet", errs),
            ha=_choice(raw.get("ha", "none"), HA_ACCESS, f"{p}.ha", errs),
            expires=_date(raw.get("expires"), f"{p}.expires", errs),
            granted_by=raw.get("granted_by"),
            status=_choice(raw.get("status", "active"), PERSON_STATUS, f"{p}.status", errs),
            history=tuple(h for h in (raw.get("history") or []) if isinstance(h, dict)),
            name=_name(raw.get("name"), f"{p}.name", errs))
    for pid, person in people.items():
        if person.granted_by is not None and person.granted_by not in people:
            errs.append(f"people.{pid}.granted_by: unknown person {person.granted_by!r}")

    def owner(v: Any, path: str) -> str:
        if v not in people:
            errs.append(f"{path}: unknown person {v!r}")
        return str(v)

    hwkeys: dict[str, HardwareKey] = {}
    serials: dict[str, str] = {}
    for kid, raw in _mapping(data, "hardware_keys", errs).items():
        p = f"hardware_keys.{kid}"
        if not isinstance(raw, dict):
            errs.append(f"{p}: must be a mapping")
            continue
        serial = raw.get("serial")
        if serial is None or str(serial).strip() == "":
            errs.append(f"{p}.serial: required")
        serial = str(serial)
        if serial in serials:
            errs.append(f"{p}.serial: duplicate serial {serial} (also {serials[serial]})")
        serials[serial] = kid
        uses = raw.get("uses")
        if not _str_list(uses) or not uses:
            errs.append(f"{p}.uses: required non-empty list")
            uses = []
        for u in uses:
            if u not in HWKEY_USES:
                errs.append(f"{p}.uses: unknown use {u!r} ({', '.join(HWKEY_USES)})")
        hwkeys[kid] = HardwareKey(
            kid, owner(raw.get("owner"), f"{p}.owner"), str(raw.get("model") or ""), serial,
            tuple(uses), _choice(raw.get("location"), HWKEY_LOCATIONS, f"{p}.location", errs),
            _date(raw.get("enrolled"), f"{p}.enrolled", errs),
            _choice(raw.get("status", "active"), HWKEY_STATUS, f"{p}.status", errs),
            _opt_choice(raw.get("role"), HWKEY_ROLES, f"{p}.role", errs))

    devices: dict[str, Device] = {}
    for did, raw in _mapping(data, "devices", errs).items():
        p = f"devices.{did}"
        if did in seen:
            errs.append(f"{p}: duplicate principal id {did!r} (also in {seen[did]})")
        seen[did] = "devices"
        if not isinstance(raw, dict):
            errs.append(f"{p}: must be a mapping")
            continue
        cert = None
        c = raw.get("cert")
        if c is not None:
            cp = f"{p}.cert"
            if not isinstance(c, dict):
                errs.append(f"{cp}: must be a mapping")
            else:
                storage = _choice(c.get("storage"), CERT_STORAGE, f"{cp}.storage", errs)
                status = _choice(c.get("status", "pending"), CERT_STATUS, f"{cp}.status", errs)
                hk = c.get("hardware_key")
                if storage == "yubikey-piv":
                    if hk is None:
                        errs.append(f"{cp}.hardware_key: required when storage is yubikey-piv")
                    elif hk not in hwkeys:
                        errs.append(f"{cp}.hardware_key: unknown hardware key {hk!r}")
                    elif (status in ("pending", "active") and not hwkeys[hk].usable
                          and hwkeys[hk].status != "suspended"):
                        errs.append(f"{cp}: {status} cert but hardware key {hk!r} is "
                                    f"{hwkeys[hk].status} (revoke the cert)")
                elif hk is not None:
                    errs.append(f"{cp}.hardware_key: only valid with storage yubikey-piv")
                cert = DeviceCert(storage, status, hk, _hex(c.get("serial"), f"{cp}.serial", errs),
                                  _hex(c.get("fingerprint_sha256"),
                                       f"{cp}.fingerprint_sha256", errs, exact64=True),
                                  _date(c.get("not_after"), f"{cp}.not_after", errs))
        history = raw.get("history") or []
        if not isinstance(history, list):
            errs.append(f"{p}.history: must be a list")
            history = []
        last = None
        for i, h in enumerate(history):
            if not isinstance(h, dict) or not h.get("event"):
                errs.append(f"{p}.history[{i}]: must be a mapping with date and event")
                continue
            d = _date(h.get("date"), f"{p}.history[{i}].date", errs)
            if d is None:
                errs.append(f"{p}.history[{i}].date: required")
            elif last and d < last:
                errs.append(f"{p}.history: not in date order at [{i}] ({d} < {last})")
            else:
                last = d
        devices[did] = Device(
            did, _parse_roles_ref(raw.get("roles"), f"{p}.roles", roles, errs),
            _date(raw.get("expires"), f"{p}.expires", errs),
            owner=owner(raw.get("owner"), f"{p}.owner"),
            kind=_choice(raw.get("kind"), DEVICE_KINDS, f"{p}.kind", errs),
            cert=cert, history=tuple(h for h in history if isinstance(h, dict)))
    return people, hwkeys, devices
