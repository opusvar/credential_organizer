"""Password-protected vault export + retention (D4: encrypted export is the primary recovery path).

Each run writes one `bw export --format encrypted_json --password <passphrase>` file for the
personal vault plus one per Vaultwarden organization (F9: `bw export` without
--organizationid covers ONLY the personal vault). The passphrase comes from
BACKUP_EXPORT_PASSWORD (F10). Without --password, bw encrypts with the *account* key, so a
key rotation or a lost account would make every backup unreadable; there is deliberately no
fallback to that mode. Restoring needs only the file + the passphrase, not the account.

Recovery runbook: docs/RUNBOOK-recovery.md
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from ..vault.client import _BW, VaultError

_FILENAME_FMT = "vault-backup-{ts}-{scope}.json"
_PASSWORD_ENV = "BACKUP_EXPORT_PASSWORD"
_SAFE_ORG_ID = re.compile(r"^[A-Za-z0-9-]+$")

# D9: the OneDrive folder the export is pushed to, relative to the client's configured
# sync_dir (/mnt/data/onedrive). Passed to --single-directory so a sync touches only this
# folder and not the whole 26-directory OneDrive tree.
_ONEDRIVE_SINGLE_DIR = "dan_ai_tool_dock/cvc-backups"

# A sync of a few small JSON files should take seconds. The timeout exists only so a
# network hang (or an interactive reauth prompt) cannot wedge the job forever.
_ONEDRIVE_SYNC_TIMEOUT = 120

# A full vault export is one short-lived `bw` (Node) invocation. Phase 4 measured a single
# credential fetch at ~15s on this ARM64 host under a 200m CPU limit, so an export of the
# whole vault needs far more headroom than vault.client._run()'s 30s. 300s is a deliberate
# over-estimate: the point is only that a wedged bw cannot hang the job forever.
_EXPORT_TIMEOUT = 300


def _bw(args: list[str], env: dict[str, str], password: str) -> str:
    """Run one bw subcommand; return stdout. Never lets the passphrase into an error."""
    try:
        # check=False: returncode inspected below so the error carries bw's stderr.
        result = subprocess.run(  # noqa: PLW1510
            [_BW, *args], capture_output=True, text=True, env=env, timeout=_EXPORT_TIMEOUT,
        )
    except FileNotFoundError as exc:
        raise VaultError(f"bw CLI not found at {_BW} — install Bitwarden CLI") from exc
    except subprocess.TimeoutExpired as exc:
        raise VaultError(f"bw {args[0]} timed out after {_EXPORT_TIMEOUT}s") from exc
    if result.returncode != 0:
        err = (result.stderr or "").strip().replace(password, "***")
        raise VaultError(f"bw {args[0]} failed (exit {result.returncode}): {err}")
    return result.stdout or ""


def _count(args: list[str], env: dict[str, str], password: str) -> int:
    try:
        return len(json.loads(_bw(args, env, password)))
    except (ValueError, TypeError) as exc:
        raise VaultError(f"bw {' '.join(args[:2])} returned unparseable output") from exc


def export_encrypted(dest_dir: str) -> list[Path]:
    """Write dated password-protected exports (personal + one per org) to dest_dir.

    Returns the export paths. Requires BW_SESSION (vault unlocked by the caller) and
    BACKUP_EXPORT_PASSWORD. Never writes a plaintext or account-restricted export.
    Raises VaultError if the per-scope item counts do not add up to `bw list items`.
    """
    session = os.environ.get("BW_SESSION")
    if not session:
        raise VaultError("BW_SESSION not set — unlock the vault before exporting")
    password = os.environ.get(_PASSWORD_ENV)
    if not password:
        raise VaultError(
            f"{_PASSWORD_ENV} not set — refusing to write an account-restricted export; "
            "add it to ~/.config/cvc/backup.env"
        )

    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    # NOTE: unlike vault.client._run(), this passes the full process environment rather than
    # an allowlist. Deliberate: export is a one-shot operation run by the backup job (whose
    # env holds only backup.env), not a request-serving security boundary. It also means
    # BITWARDENCLI_APPDATA_DIR flows through without being enumerated here. The passphrase
    # is passed via argv because `bw export --password` accepts no env/file form; it is
    # stripped from the child env so it is not inherited twice.
    env = os.environ.copy()
    env.pop(_PASSWORD_ENV, None)
    env["BW_SESSION"] = session

    try:
        orgs = json.loads(_bw(["list", "organizations", "--raw"], env, password))
    except (ValueError, TypeError) as exc:
        raise VaultError("bw list organizations returned unparseable output") from exc

    scopes: list[tuple[str, str | None]] = [("personal", None)]
    for org in orgs:
        oid = str(org.get("id", ""))
        if not _SAFE_ORG_ID.fullmatch(oid):
            raise VaultError("bw returned an organization id with unexpected characters")
        scopes.append((f"org-{oid}", oid))

    # F9 sanity check: every item must belong to exactly one exported scope.
    total = _count(["list", "items", "--raw"], env, password)
    covered = 0
    for _, oid in scopes:
        covered += _count(
            ["list", "items", "--organizationid", oid or "null", "--raw"], env, password
        )
    if covered != total:
        raise VaultError(
            f"item count mismatch: exported scopes cover {covered} item(s) "
            f"but the vault lists {total}"
        )

    paths: list[Path] = []
    for scope, oid in scopes:
        out_path = dest / _FILENAME_FMT.format(ts=ts, scope=scope)
        args = ["export", "--format", "encrypted_json", "--password", password,
                "--output", str(out_path)]
        if oid:
            args += ["--organizationid", oid]
        _bw(args, env, password)

        # A zero-byte or absent "backup" that reports success is worse than a loud
        # failure, because prune() would then age out good exports behind it.
        if not out_path.exists() or out_path.stat().st_size == 0:
            raise VaultError(f"bw export reported success but produced no data at {out_path}")
        try:
            protected = json.loads(out_path.read_text()).get("passwordProtected") is True
        except (ValueError, AttributeError):
            protected = False
        if not protected:
            out_path.unlink(missing_ok=True)
            raise VaultError(f"export {out_path.name} is not password-protected — refusing it")
        paths.append(out_path)

    return paths


def copy_to_onedrive(
    src_paths: Path | Sequence[Path],
    onedrive_dest_dir: str,
    onedrive_bin: str,
    config_dir: str,
) -> None:
    """Stage exports in the OneDrive sync dir and trigger ONE one-shot sync (D9).

    The local copy written by export_encrypted() is primary; this is the durable off-host
    copy. Every failure mode raises RuntimeError; backup/__main__.py turns that into a
    non-zero exit (F8) after still running retention on the good local export.

    Copy-then-sync: if the sync leg fails the files are still staged, so a later host-side
    `onedrive --sync` picks them up with no re-export. If a source already IS the staging
    file (BACKUP_DIR == ONEDRIVE_DEST_DIR), the copy is skipped but the sync still runs —
    previously SameFileError skipped the sync and nothing ever left the host.

    The exports are password-protected (BACKUP_EXPORT_PASSWORD, D4), so uploading them
    as-is is safe; the passphrase is never uploaded.
    """
    srcs = [Path(src_paths)] if isinstance(src_paths, (str, Path)) else [Path(p) for p in src_paths]
    dest = Path(onedrive_dest_dir)

    try:
        dest.mkdir(parents=True, exist_ok=True)
        for src in srcs:
            target = dest / src.name
            if target.exists() and os.path.samefile(src, target):
                continue
            shutil.copy2(src, target)
    except OSError as exc:
        # Covers a missing source, an unmounted/read-only dir, and EACCES.
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

    cutoff = datetime.now(UTC).timestamp() - retention_days * 86400
    removed = 0
    for f in dest.glob("vault-backup-*.json"):
        if not f.is_file():  # a directory matching the glob would make unlink() raise
            continue
        if f.stat().st_mtime < cutoff:
            f.unlink()
            removed += 1
    return removed
