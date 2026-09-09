"""Encrypted vault export + retention (D4: encrypted_json primary recovery path).

Export uses `bw export --format encrypted_json` which encrypts with the vault master password —
no separate passphrase to manage, and the file is useless without the master password.

Recovery runbook: docs/RUNBOOK-recovery.md
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ..vault.client import VaultError

_FILENAME_FMT = "vault-backup-{ts}.json"


def export_encrypted(dest_dir: str) -> Path:
    """Write a dated encrypted vault export to dest_dir. Returns the export path.

    Requires BW_SESSION set in env (vault already unlocked by the caller).
    Never writes a plaintext export — encrypted_json format only.
    """
    session = os.environ.get("BW_SESSION")
    if not session:
        raise VaultError("BW_SESSION not set — unlock the vault before exporting")

    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = dest / _FILENAME_FMT.format(ts=ts)

    env = os.environ.copy()
    env["BW_SESSION"] = session

    result = subprocess.run(
        ["bw", "export", "--format", "encrypted_json", "--output", str(out_path)],
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        raise VaultError(f"bw export failed (exit {result.returncode}): {result.stderr.strip()}")

    return out_path


def prune(dest_dir: str, retention_days: int) -> int:
    """Delete exports older than retention_days. Returns count removed."""
    dest = Path(dest_dir)
    if not dest.exists():
        return 0

    cutoff = datetime.now(timezone.utc).timestamp() - retention_days * 86400
    removed = 0
    for f in dest.glob("vault-backup-*.json"):
        if f.stat().st_mtime < cutoff:
            f.unlink()
            removed += 1
    return removed
