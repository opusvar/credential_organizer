"""`cvc-backup` CLI — authenticate to Vaultwarden, export (password-protected, personal + orgs),
sync off-host, prune old exports.

Run as a systemd user timer (see deploy/cvc-backup.service) or directly, alongside
cvc-remind. Requires the same vault auth env vars as cvc-import.
"""
from __future__ import annotations

import os
import sys

from ..config import load
from ..vault.client import BwClient, VaultError
from .exporter import copy_to_onedrive, export_encrypted, prune


def main(argv: list[str] | None = None) -> int:
    cfg = load()
    if not cfg.bw_server:
        print("ERROR: BW_SERVER not configured", file=sys.stderr)
        return 1

    client = BwClient(server=cfg.bw_server)
    try:
        client.configure()
        client.login_apikey()
        session = client.unlock()
    except VaultError as exc:
        print(f"ERROR: vault auth failed — {exc}", file=sys.stderr)
        return 1

    os.environ["BW_SESSION"] = session

    try:
        paths = export_encrypted(cfg.backup_dir)
    except VaultError as exc:
        print(f"ERROR: export failed — {exc}", file=sys.stderr)
        return 1
    for path in paths:
        print(f"backup: exported to {path}")

    # F8: a failed off-host copy/sync is fatal to the exit code (a backup that never
    # leaves the host is not a backup), but retention still runs on the good local export.
    rc = 0
    try:
        copy_to_onedrive(
            paths, cfg.onedrive_dest_dir, cfg.onedrive_bin, cfg.onedrive_config_dir
        )
        print("backup: synced to OneDrive")
    except RuntimeError as exc:
        print(f"ERROR: OneDrive sync failed — {exc}", file=sys.stderr)
        rc = 1

    # Pruning is best-effort: a retention failure must not fail the backup itself.
    try:
        removed = prune(cfg.backup_dir, cfg.backup_retention_days)
    except OSError as exc:
        print(f"WARNING: prune failed — {exc}", file=sys.stderr)
        return rc

    print(f"backup: pruned {removed} export(s) older than {cfg.backup_retention_days}d")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
