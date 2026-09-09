"""`cvc-import` CLI — parse + dedup an export and push unique items to Vaultwarden.

Safety rules:
- Requires an explicit --file path; no auto-discovery.
- Dry-run by default; --commit is required to write to the vault.
- Unless --keep is given, reminds the user to shred the plaintext export after use.
  (Automated shredding is deferred: shred(1) / srm vary by OS; file may be on SSD.)

Vault auth (D1 resolved): `bw login --apikey` via BW_CLIENTID + BW_CLIENTSECRET in env.
Unlock: BW_PASSWORD in env → BW_SESSION injected into the process for the run.
"""
from __future__ import annotations

import argparse
import os
import sys

from .chrome import ChromeImporter
from .keychain import KeychainImporter
from .normalize import dedup

IMPORTERS = {"chrome": ChromeImporter, "keychain": KeychainImporter}

# D3: single-user vault, folders by source. Override with --folder.
DEFAULT_FOLDERS = {"chrome": "imported-chrome", "keychain": "imported-keychain"}


def _vault_push(items, folder: str | None, dry_run: bool) -> int:
    """Configure, login, unlock, and push items to Vaultwarden. Returns exit code."""
    from ..config import load
    from ..vault.client import BwClient, VaultError

    cfg = load()
    if not cfg.bw_server:
        print("ERROR: BW_SERVER not set", file=sys.stderr)
        return 1

    client = BwClient(server=cfg.bw_server)
    try:
        client.configure()
        client.login_apikey()
        session = client.unlock()
    except VaultError as exc:
        print(f"ERROR: vault auth failed — {exc}", file=sys.stderr)
        return 1

    # Inject session for this process so all subsequent client calls pick it up.
    os.environ["BW_SESSION"] = session

    try:
        client.sync()
    except VaultError as exc:
        print(f"WARNING: sync failed (continuing) — {exc}", file=sys.stderr)

    folder_id: str | None = None
    if folder:
        try:
            folder_id = client.get_or_create_folder(folder)
        except VaultError as exc:
            print(f"ERROR: could not create folder '{folder}' — {exc}", file=sys.stderr)
            return 1

    created = skipped = errors = 0
    for item in items:
        if dry_run:
            print(f"  [dry-run] would create: {item.name!r} ({item.username})")
            continue
        try:
            client.create_login(
                name=item.name,
                username=item.username,
                password=item.password,
                uri=item.uri or None,
                folder_id=folder_id,
            )
            created += 1
        except VaultError as exc:
            print(f"  ERROR creating {item.name!r}: {exc}", file=sys.stderr)
            errors += 1

    if not dry_run:
        print(f"vault: created={created} skipped={skipped} errors={errors}")
    return 0 if errors == 0 else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cvc-import")
    p.add_argument("--source", required=True, choices=sorted(IMPORTERS))
    p.add_argument("--file", required=True, help="path to the plaintext export file")
    p.add_argument("--commit", action="store_true",
                   help="write unique items to Vaultwarden (default: dry-run)")
    p.add_argument("--folder", default=None,
                   help="vault folder name to import into (default: imported-<source>)")
    p.add_argument("--keep", action="store_true",
                   help="do not remind about shredding the plaintext export")
    args = p.parse_args(argv)

    items = IMPORTERS[args.source]().parse(args.file)
    result = dedup(items)
    print(f"{args.source}: parsed {len(items)}, "
          f"unique {len(result.unique)}, duplicates {len(result.duplicates)}")

    folder = args.folder or DEFAULT_FOLDERS.get(args.source)
    rc = _vault_push(result.unique, folder=folder, dry_run=not args.commit)

    if not args.keep:
        print(
            f"\nReminder: {args.file!r} is plaintext — shred it when done:\n"
            f"  shred -u {args.file!r}   # Linux\n"
            f"  srm -sz {args.file!r}    # macOS"
        )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
