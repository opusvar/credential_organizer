"""`cvc-backup` CLI — authenticate to Vaultwarden, export encrypted, prune old exports.

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
        path = export_encrypted(cfg.backup_dir)
        print(f"backup: exported to {path}")
    except VaultError as exc:
        print(f"ERROR: export failed — {exc}", file=sys.stderr)
        return 1

    # Non-fatal: PVC export already succeeded; sync outage must not fail the job (D9).
    try:
        copy_to_onedrive(
            path, cfg.onedrive_dest_dir, cfg.onedrive_bin, cfg.onedrive_config_dir
        )
        print("backup: synced to OneDrive")
    except RuntimeError as exc:
        print(f"WARNING: OneDrive sync failed — {exc}", file=sys.stderr)

    # Pruning is best-effort: the export above already succeeded, so a retention failure
    # (read-only volume, races with another job) must not fail the backup itself.
    try:
        removed = prune(cfg.backup_dir, cfg.backup_retention_days)
    except OSError as exc:
        print(f"WARNING: prune failed — {exc}", file=sys.stderr)
        return 0

    print(f"backup: pruned {removed} export(s) older than {cfg.backup_retention_days}d")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
