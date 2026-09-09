"""Chrome / Chromium password CSV importer.

Chrome exports (chrome://password-manager/passwords → Export) a CSV with columns:
    name,url,username,password,note
This parser is implemented (it's the Phase-1 vertical slice); it does no network or vault I/O.
"""
from __future__ import annotations

import csv

from .base import Importer
from .normalize import Item


class ChromeImporter(Importer):
    source = "chrome"

    def parse(self, path: str) -> list[Item]:
        items: list[Item] = []
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                # Chrome uses these header names; tolerate missing optional columns.
                items.append(Item(
                    name=(row.get("name") or row.get("url") or "").strip(),
                    username=(row.get("username") or "").strip(),
                    password=row.get("password") or "",
                    uri=(row.get("url") or "").strip(),
                    note=(row.get("note") or "").strip(),
                    source=self.source,
                ))
        return items
