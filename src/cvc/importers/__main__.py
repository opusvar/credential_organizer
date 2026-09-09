"""`cvc-import` CLI — parse + dedup an export, and (once implemented) push to the vault.

Safety: requires an explicit --file; refuses to push to the vault without --commit; and, unless
--keep is given, offers to shred the plaintext export afterward (the import file is a cleartext
dump of your passwords).

SCAFFOLD: parse + dedup are live; --commit (vault write) and shredding are stubbed.
"""
from __future__ import annotations

import argparse
import sys

from .chrome import ChromeImporter
from .keychain import KeychainImporter
from .normalize import dedup

IMPORTERS = {"chrome": ChromeImporter, "keychain": KeychainImporter}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cvc-import")
    p.add_argument("--source", required=True, choices=sorted(IMPORTERS))
    p.add_argument("--file", required=True, help="explicit path to the export file")
    p.add_argument("--commit", action="store_true", help="write to the vault (not yet implemented)")
    p.add_argument("--keep", action="store_true", help="do NOT shred the plaintext export after")
    args = p.parse_args(argv)

    items = IMPORTERS[args.source]().parse(args.file)
    result = dedup(items)
    print(f"{args.source}: parsed {len(items)}, unique {len(result.unique)}, "
          f"duplicates {len(result.duplicates)}")

    if args.commit:
        print("--commit: TODO(Phase 1) push result.unique via cvc.vault.client", file=sys.stderr)
        return 2
    if not args.keep:
        print("NOTE: re-run with a shred step once Phase 1 lands — the export is plaintext.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
