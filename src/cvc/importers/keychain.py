"""Apple Keychain importer (macOS only).

D2 resolved 2026-09-09: path (a) — macOS Passwords app CSV export.
  Settings → Passwords → ··· → Export
  Columns: Title,URL,Username,Password,Notes,OTPAuth
  Invoke: cvc-import --source keychain --file ~/passwords.csv
"""
from __future__ import annotations

import csv

from .base import Importer
from .normalize import Item


class KeychainImporter(Importer):
    source = "keychain"

    def parse(self, path: str) -> list[Item]:
        items: list[Item] = []
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                row = {k.strip().lower(): (v or "").strip() for k, v in row.items()}
                items.append(Item(
                    name=row.get("title") or row.get("name") or row.get("url") or "",
                    username=row.get("username") or "",
                    password=row.get("password") or "",
                    uri=row.get("url") or "",
                    note=row.get("notes") or "",
                    source=self.source,
                ))
        return items
