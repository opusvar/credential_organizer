"""Encrypted vault export + retention (D4: encrypted_json primary recovery path).

Export uses `bw export --format encrypted_json` which encrypts with the vault master password —
no separate passphrase to manage, and the file is useless without the master password.

Recovery runbook: docs/RUNBOOK-recovery.md
"""
from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ..vault.client import _BW, VaultError

_FILENAME_FMT = "vault-backup-{ts}.json"

# D9: the OneDrive folder the export is pushed to, relative to the client's configured
# sync_dir (/mnt/data/onedrive). Passed to --single-directory so a sync touches only this
# folder and not the whole 26-directory OneDrive tree.
_ONEDRIVE_SINGLE_DIR = "dan_ai_tool_dock/cvc-backups"

# A sync of one small JSON file should take a second or two. The timeout exists only so a
# network hang (or an interactive reauth prompt) cannot wedge the CronJob pod forever.
_ONEDRIVE_SYNC_TIMEOUT = 120

# A full vault export is one short-lived `bw` (Node) invocation. Phase 4 measured a single
# credential fetch at ~15s on this ARM64 host under a 200m CPU limit, so an export of the
# whole vault needs far more headroom than vault.client._run()'s 30s. 300s is a deliberate
# over-estimate: the point is only that a wedged bw cannot hang the CronJob pod forever.
_EXPORT_TIMEOUT = 300


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

    # NOTE: unlike vault.client._run(), this passes the full process environment rather than
    # an allowlist. Deliberate: export is a one-shot operation run by the backup CronJob (whose
    # env contains only the cvc-vault secret), not a request-serving security boundary. It also
    # means BITWARDENCLI_APPDATA_DIR flows through without being enumerated here.
    env = os.environ.copy()
    env["BW_SESSION"] = session

    try:
        # check=False: the returncode is inspected below so the error can be raised as a
        # VaultError carrying bw's stderr, rather than a bare CalledProcessError.
        result = subprocess.run(  # noqa: PLW1510
            [_BW, "export", "--format", "encrypted_json", "--output", str(out_path)],
            capture_output=True,
            text=True,
            env=env,
            timeout=_EXPORT_TIMEOUT,
        )
    except FileNotFoundError as exc:
        raise VaultError(f"bw CLI not found at {_BW} — install Bitwarden CLI") from exc
    except subprocess.TimeoutExpired as exc:
        raise VaultError(f"bw export timed out after {_EXPORT_TIMEOUT}s") from exc

    if result.returncode != 0:
        raise VaultError(f"bw export failed (exit {result.returncode}): {result.stderr.strip()}")

    # Defensive: a zero-byte or absent "backup" that reports success is worse than a loud
    # failure, because prune() would then age out good exports behind an empty one. Not a
    # bug observed in the wild — an assertion that the deliverable actually exists.
    if not out_path.exists() or out_path.stat().st_size == 0:
        raise VaultError(f"bw export reported success but produced no data at {out_path}")

    return out_path


def copy_to_onedrive(
    src_path: Path,
    onedrive_dest_dir: str,
    onedrive_bin: str,
    config_dir: str,
) -> None:
    """Stage an export in the OneDrive sync dir and trigger a one-shot sync (D9).

    The PVC copy written by export_encrypted() is primary; this is the durable off-host
    copy. Every failure mode raises RuntimeError and the CALLER decides severity —
    backup/__main__.py treats them all as non-fatal, because a sync outage must not
    invalidate an export that already landed on the PVC.

    The staging copy and the sync are deliberately ordered copy-then-sync: if the sync
    leg fails the file is still on the NVMe, so a later host-side `onedrive --sync`
    picks it up with no re-export.

    The export is already encrypted with the vault master password (D4), so uploading it
    as-is is safe — there is no separate passphrase to manage or leak.
    """
    src = Path(src_path)
    dest = Path(onedrive_dest_dir)

    try:
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest / src.name)
    except OSError as exc:
        # Covers a missing source, an unmounted/read-only hostPath, and EACCES when the
        # host directory is not owned by uid 1000 (see deploy/setup-phase23.sh).
        raise RuntimeError(f"copy to {dest} failed: {exc}") from exc

    if not Path(onedrive_bin).exists():
        raise RuntimeError(f"onedrive not found at {onedrive_bin}")

    # NOTE — flag names are version-sensitive. The installed client is abraunegg v2.5.11,
    # which REMOVED `--synchronize` (now `--sync`) and has never accepted `--config-dir`
    # (it is `--confdir`). Both wrong spellings exit non-zero with "Unrecognized option",
    # and because sync failures are non-fatal by design that would degrade silently to
    # "off-host backup never happens" — the exact failure D9 exists to prevent.
    # --confdir is required so the client finds the refresh token from the mounted config.
    argv = [
        onedrive_bin,
        "--sync",
        "--single-directory",
        _ONEDRIVE_SINGLE_DIR,
        "--confdir",
        config_dir,
    ]

    try:
        # check=False: the returncode is inspected below so stderr can be carried on the
        # RuntimeError rather than a bare CalledProcessError.
        result = subprocess.run(  # noqa: PLW1510
            argv,
            capture_output=True,
            text=True,
            timeout=_ONEDRIVE_SYNC_TIMEOUT,
        )
    except FileNotFoundError as exc:
        # Racing the exists() check above, or onedrive_bin is a dangling symlink.
        raise RuntimeError(f"onedrive not found at {onedrive_bin}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"onedrive sync timed out after {_ONEDRIVE_SYNC_TIMEOUT}s"
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"onedrive sync failed (exit {result.returncode}): "
            f"{(result.stderr or '').strip()}"
        )


def prune(dest_dir: str, retention_days: int) -> int:
    """Delete exports older than retention_days. Returns count removed."""
    dest = Path(dest_dir)
    if not dest.exists():
        return 0

    cutoff = datetime.now(timezone.utc).timestamp() - retention_days * 86400
    removed = 0
    for f in dest.glob("vault-backup-*.json"):
        if not f.is_file():  # a directory matching the glob would make unlink() raise
            continue
        if f.stat().st_mtime < cutoff:
            f.unlink()
            removed += 1
    return removed
