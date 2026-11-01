"""Primary vs backup hardware key (D11/D15).

The access registry may carry an explicit ``role: primary|backup`` on a hardware key. Older
registries do not, so the role falls back to a location heuristic: a key kept ``on-person`` is
the primary; one in the ``home-safe`` or ``offsite`` is a backup. Works on raw registry dicts
and on parsed ``HardwareKey`` objects (read via getattr, so it works before and after the
access model gains the field).
"""
from __future__ import annotations

from typing import Any

ROLES = ("primary", "backup")


def key_role(key: Any) -> str:
    get = key.get if isinstance(key, dict) else (lambda k, d=None: getattr(key, k, d))
    role = get("role", None)
    if role in ROLES:
        return role
    return "primary" if get("location", None) in (None, "on-person") else "backup"
