"""Encrypted vault export + retention. Recovery paths are documented in docs/RUNBOOK-recovery.md.

SCAFFOLD: export uses `bw export --format encrypted_json`; the recovery flows depend on D4
(which recovery model) and are runbook-driven, not automated here.
"""
from __future__ import annotations

from pathlib import Path


def export_encrypted(dest_dir: str) -> Path:
    """Write a dated, encrypted vault export to dest_dir. Never writes a plaintext export."""
    Path(dest_dir).mkdir(parents=True, exist_ok=True)
    raise NotImplementedError(
        "TODO(Phase 3): `bw export --format encrypted_json` with a dedicated export passphrase"
    )


def prune(dest_dir: str, retention_days: int) -> int:
    """Delete exports older than retention_days; return count removed."""
    raise NotImplementedError("TODO(Phase 3): prune by mtime, mirror pg-backup-all semantics")
