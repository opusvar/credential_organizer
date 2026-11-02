"""Hooks other flows call so bridges end automatically (D27).

- `cvc-access device set-cert` (a permanent device's cert is recorded = enrolled) -> promote.
- `cvc-access person remove` (offboarding) -> revoke all of the person's bridges.
Both run only after the registry is written, and only when the bridge state dir exists.
"""
from __future__ import annotations

import argparse

from cvc.access.model import load_registry

from .certs import revoke_command
from .model import is_temp_device
from .service import BridgeError, BridgeService, BridgeStore, state_dir


def _service(registry_path: str, state: str | None = None) -> BridgeService | None:
    d = state_dir(state)
    if not (d / "bridges.json").exists():
        return None
    return BridgeService(load_registry(registry_path), BridgeStore(d))


def after_set_cert(args: argparse.Namespace, state: str | None = None) -> str:
    if is_temp_device(args.id):
        return ""
    svc = _service(args.registry, state)
    if svc is None:
        return ""
    dev = svc.reg.devices.get(args.id)
    if dev is None or not dev.owner:
        return ""
    try:
        b = svc.promote(dev.owner, args.id, "cvc-access")
    except BridgeError as e:
        return f"temp device not promoted: {e}"
    if b is None:
        return ""
    return f"promoted {args.id}: bridge {b.id} revoked\n  [ ] {revoke_command(b)}"


def after_person_remove(args: argparse.Namespace, state: str | None = None) -> str:
    d = state_dir(state)
    if not (d / "bridges.json").exists():
        return ""
    store = BridgeStore(d)
    # The person is gone from the registry now, so revoke directly from the store.
    from cvc.access.model import Registry
    svc = BridgeService(Registry(1, {}, {}, {}, {}), store)
    gone = svc.revoke_all(args.id, "offboard", "offboard")
    return "\n".join(f"offboard: bridge {b.id} revoked\n  [ ] {revoke_command(b)}"
                     for b in gone)
