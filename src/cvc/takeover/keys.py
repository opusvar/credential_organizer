"""Primary vs backup hardware key (D11/D15).

The access registry may carry an explicit ``role: primary|backup`` on a hardware key; it always
wins. Older registries do not, so the role falls back to a heuristic:
1. if the caller knows whether the key backs one of the owner's device certs (``on_cert``), a
   key on a cert is the primary and any other key a backup (the takeover factor rule);
2. otherwise by location: ``on-person`` (or unset) = primary, ``home-safe``/``offsite`` = backup.
Works on raw registry dicts and on parsed ``HardwareKey`` objects (read via getattr, so it works
before and after the access model gains the field).
"""
from __future__ import annotations

from typing import Any

ROLES = ("primary", "backup")


def key_role(key: Any, on_cert: bool | None = None) -> str:
    get = key.get if isinstance(key, dict) else (lambda k, d=None: getattr(key, k, d))
    role = get("role", None)
    if role in ROLES:
        return role
    if on_cert is not None:
        return "primary" if on_cert else "backup"
    return "primary" if get("location", None) in (None, "on-person") else "backup"


def key_factor(key: Any, on_cert: bool | None = None) -> str:
    """Takeover ``factor`` for a presented target key: ``key`` or ``backup-key``."""
    return "key" if key_role(key, on_cert) == "primary" else "backup-key"
