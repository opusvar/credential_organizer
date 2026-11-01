"""Resource catalog: tier-gate config generator and per-person reachability."""
from __future__ import annotations

import datetime as dt

import yaml

from cvc.access.builders import GENERATED_HEADER, register_builder
from cvc.access.check import check_resources
from cvc.access.model import PERSON_TIERS, Person, Registry, RegistryError, Resource
from cvc.site import GENERIC

_RANK = {t: i for i, t in enumerate(PERSON_TIERS)}


def can_reach(person: Person, resource: Resource, today: dt.date | None = None) -> bool:
    """Mirror of the tiergate decision: an active person whose tier >= resource min_tier."""
    today = today or dt.datetime.now().astimezone().date()
    if person.tier is None or resource.min_tier not in _RANK:
        return False
    if not person.active(today):     # expired, or a checked-out guest
        return False
    return _RANK[person.tier] >= _RANK[resource.min_tier]


def reachable(registry: Registry, person: Person,
              today: dt.date | None = None) -> list[Resource]:
    return [registry.resources[r] for r in sorted(registry.resources)
            if can_reach(person, registry.resources[r], today)]


DEFAULT_BASE_DOMAIN = GENERIC.base_domain   # library default; CLIs use the loaded site


def resource_hosts(registry: Registry, base_domain: str = DEFAULT_BASE_DOMAIN,
                   host_overrides: dict[str, str] | None = None,
                   registry_hosts: bool = False) -> dict[str, str]:
    """resource id -> route hostname (override > registry host if requested > id.base).

    Canonical host resolution shared by `cvc-access build tiergate` and `cvc-deploygen`.
    """
    overrides = host_overrides or {}
    unknown = sorted(set(overrides) - set(registry.resources))
    if unknown:
        raise RegistryError([f"host override for unknown resource: {r}" for r in unknown])
    base = base_domain.strip().strip(".").lower()
    out = {}
    for rid in sorted(registry.resources):
        if rid in overrides:
            out[rid] = overrides[rid].strip().lower()
        elif registry_hosts:
            out[rid] = registry.resources[rid].host
        else:
            out[rid] = f"{rid}.{base}"
    dupes = sorted({h for h in out.values() if list(out.values()).count(h) > 1})
    if dupes:
        raise RegistryError([f"duplicate route host: {h}" for h in dupes])
    return out


def tiergate_hosts(registry: Registry, base_domain: str = DEFAULT_BASE_DOMAIN,
                   host_overrides: dict[str, str] | None = None,
                   registry_hosts: bool = False) -> dict[str, str]:
    """Canonical tier-gate `hosts:` map (route host -> min tier), sorted by host."""
    errors = [f"{f.path}: {f.message}" for f in check_resources(registry)
              if f.level == "error"]
    if errors:
        raise RegistryError(errors)
    hosts = resource_hosts(registry, base_domain, host_overrides, registry_hosts)
    return {hosts[r]: registry.resources[r].min_tier
            for r in sorted(hosts, key=lambda r: hosts[r])}


def tiergate_config(registry: Registry, base_domain: str = DEFAULT_BASE_DOMAIN,
                    host_overrides: dict[str, str] | None = None,
                    registry_hosts: bool = False) -> str:
    """The cvc.tiergate config.yaml body (comments + `hosts:`). Unlisted hosts are denied."""
    hosts = tiergate_hosts(registry, base_domain, host_overrides, registry_hosts)
    by_host = {h: rid for rid, h in
               resource_hosts(registry, base_domain, host_overrides, registry_hosts).items()}
    passkey = sorted(h for h, rid in by_host.items()
                     if registry.resources[rid].passkey_required)
    head = ("# Tier order: " + " < ".join(PERSON_TIERS) + "\n"
            "# Hosts with min tier high/admin/owner also need Authentik passkey proof"
            + (f": {', '.join(passkey)}" if passkey else "") + ".\n"
            "# default_min_tier is unset: hosts not listed are denied.\n")
    return head + yaml.safe_dump({"hosts": hosts}, sort_keys=False)


@register_builder("tiergate")
def build_tiergate(registry: Registry, today: dt.date | None = None, *,
                   base_domain: str = DEFAULT_BASE_DOMAIN,
                   host_overrides: dict[str, str] | None = None,
                   registry_hosts: bool = False) -> str:
    """Emit the cvc.tiergate config. Hosts default to `<resource-id>.<base-domain>`,
    identical to the routes `cvc-deploygen traefik` generates."""
    return (GENERATED_HEADER.format(name="tiergate")
            + tiergate_config(registry, base_domain, host_overrides, registry_hosts))
