"""Generate a Mosquitto `acl_file` from machine/agent MQTT grants.

Mosquitto denies everything not listed once an acl_file is active, so the generator
warns when no principal has broad read access (Home Assistant would be cut off).
Passwords are never handled here; `mqtt_usernames` lists who needs a mosquitto_passwd entry.
"""
from __future__ import annotations

import datetime as dt
import sys

from cvc.access.builders import GENERATED_HEADER, register_builder
from cvc.access.model import Machine, Registry, RegistryError

_BROAD = frozenset({"#", "homeassistant/#"})
_WARN = "applying this ACL may cut off Home Assistant"


def _username(p) -> str | None:
    if isinstance(p, Machine) and p.auth and p.auth.type == "mqtt-user":
        return p.auth.username or None
    return None


def _check_topic(topic: str, path: str, errs: list[str]) -> None:
    levels = topic.split("/")
    for i, lv in enumerate(levels):
        if lv == "#":
            if i != len(levels) - 1:
                errs.append(f"{path}: '#' must be the last level in {topic!r}")
        elif lv == "+":
            pass
        elif "#" in lv or "+" in lv:
            errs.append(f"{path}: wildcard must occupy a whole level in {topic!r}")


def _collect(registry: Registry, today: dt.date, system: str | None):
    """-> (user -> {(topic, access)}, errors, any_broad_read)."""
    acl: dict[str, set[tuple[str, str]]] = {}
    errs: list[str] = []
    broad = False
    for p in registry.principals():
        if not p.active(today):
            continue
        grants = [g for _r, g in registry.grants_for(p)
                  if registry.system_of(g).kind == "mqtt" and (system is None or g.system == system)]
        if not grants:
            continue
        user = _username(p)
        if user is None:
            errs.append(f"{p.section}.{p.id}: has mqtt grants but no auth with "
                        "type 'mqtt-user' and a username")
            continue
        for g in grants:
            for t in g.expand_topics(p.id):
                _check_topic(t, g.path, errs)
                acl.setdefault(user, set()).add((t, g.access))
                if g.access in ("read", "readwrite") and t in _BROAD:
                    broad = True
    return acl, errs, broad


def build_mosquitto(registry: Registry, today: dt.date | None = None,
                    system: str | None = None) -> str:
    """Build the acl_file. `system` limits output to one mqtt system's grants."""
    today = today or dt.datetime.now().astimezone().date()
    if system is not None and (system not in registry.systems
                               or registry.systems[system].kind != "mqtt"):
        raise RegistryError([f"system {system!r} is not an mqtt system"])
    acl, errs, broad = _collect(registry, today, system)
    if errs:
        raise RegistryError(errs)
    out = GENERATED_HEADER.format(name="mosquitto")
    if not broad:
        out += ("# WARNING: no principal has broad read access (# or homeassistant/#);\n"
                f"# {_WARN}.\n")
        print(f"warning: {_WARN}", file=sys.stderr)
    for user in sorted(acl):
        out += f"\nuser {user}\n"
        for t, a in sorted(acl[user]):
            out += f"topic {a} {t}\n"
    return out


@register_builder("mosquitto")
def _builder(registry: Registry, today: dt.date | None = None) -> str:
    return build_mosquitto(registry, today)


def mqtt_usernames(registry: Registry, today: dt.date | None = None,
                   system: str | None = None) -> list[str]:
    """Sorted usernames needing a `mosquitto_passwd` entry (no passwords handled)."""
    acl, errs, _ = _collect(registry, today or dt.datetime.now().astimezone().date(), system)
    if errs:
        raise RegistryError(errs)
    return sorted(acl)
