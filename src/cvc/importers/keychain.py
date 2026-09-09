"""Apple Keychain importer (macOS only).

Keychain has no clean bulk export. Two candidate paths (decision D2):
  (a) macOS Passwords app / Safari → export CSV, then reuse a CSV parser.
  (b) `security` CLI (`security dump-keychain`) — messy, partial, prompts per item.
Left as a stub until D2 picks the path.
"""
from __future__ import annotations

from .base import Importer
from .normalize import Item


class KeychainImporter(Importer):
    source = "keychain"

    def parse(self, path: str) -> list[Item]:
        raise NotImplementedError(
            "TODO(D2): choose Keychain export path (Passwords-app CSV vs `security` CLI)"
        )
