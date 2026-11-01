"""Access registry: one source of truth for who may access what.

`access/registry.yaml` (example: access/registry.example.yaml) declares systems, roles
(lists of grants), AI agents and machines (sensors/devices). Generators derive deployable
config from it; v1 enforces kinds `credential-store` (broker ACL) and `mqtt`. Kinds
`http`, `cluster`, `ssh`, `service` are carried in the model but documented only.

Model API for generators (all frozen dataclasses):
    load_registry(path) / parse_registry(dict) -> Registry   (raise RegistryError)
    Registry.systems/roles/agents/machines: dict[id, System|Role|Agent|Machine]
    Registry.people/hardware_keys/devices: Person|HardwareKey|Device (D13)
    Registry.principals()            agents, machines, then devices
    Device: .owner/.kind/.cert (DeviceCert: storage, hardware_key, status, not_after)/.history
    Registry.grants_for(principal)   [(Role, Grant), ...]
    Registry.system_of(grant)        System (.kind, .attrs, .enforced)
    Grant: .credential/.purposes (credential-store), .topics/.access (mqtt),
           .extra (other kinds), .expand_topics(principal_id), .path
    Principal.active(today)          False once `expires` has passed
    Machine.auth: MachineAuth(type, username)

New artifacts: decorate `fn(registry, today) -> str` with `@register_builder("name")` and
import the module in cvc.access.cli; `cvc-access build name` then works.
"""
from cvc.access.builders import BUILDERS, register_builder
from cvc.access.model import (
    ENFORCED_KINDS,
    KINDS,
    Agent,
    Device,
    DeviceCert,
    HardwareKey,
    Person,
    Grant,
    Machine,
    MachineAuth,
    Principal,
    Registry,
    RegistryError,
    Role,
    System,
    load_registry,
    parse_registry,
)
from cvc.access import brokeracl as _brokeracl  # noqa: F401,E402  (registers builder)

__all__ = [
    "BUILDERS", "ENFORCED_KINDS", "KINDS", "Agent", "Device", "DeviceCert",
    "HardwareKey", "Person", "Grant", "Machine", "MachineAuth",
    "Principal", "Registry", "RegistryError", "Role", "System", "load_registry",
    "parse_registry", "register_builder",
]
