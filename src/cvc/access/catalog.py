"""Resource catalog: tier-gate config generator and per-person reachability."""
from __future__ import annotations

import datetime as dt

import yaml

from cvc.access.builders import GENERATED_HEADER, register_builder
from cvc.access.check import check_resources
from cvc.access.model import PERSON_TIERS, Person, Registry, RegistryError, Resource

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


@register_builder("tiergate")
def build_tiergate(registry: Registry, today: dt.date | None = None) -> str:
    """Emit the cvc.tiergate config (`hosts:` host -> min tier). Unlisted hosts are denied."""
    errors = [f"{f.path}: {f.message}" for f in check_resources(registry)
              if f.level == "error"]
    if errors:
        raise RegistryError(errors)
    hosts = {registry.resources[r].host: registry.resources[r].min_tier
             for r in sorted(registry.resources, key=lambda r: registry.resources[r].host)}
    passkey = sorted(r.host for r in registry.resources.values() if r.passkey_required)
    head = GENERATED_HEADER.format(name="tiergate")
    head += ("# Tier order: " + " < ".join(PERSON_TIERS) + "\n"
             "# Hosts with min tier high/admin/owner also need Authentik passkey proof"
             + (f": {', '.join(passkey)}" if passkey else "") + ".\n"
             "# default_min_tier is unset: hosts not listed are denied.\n")
    return head + yaml.safe_dump({"hosts": hosts}, sort_keys=False)
