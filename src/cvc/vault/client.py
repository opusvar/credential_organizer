"""Thin wrapper over the Bitwarden CLI (`bw`) against Vaultwarden.

Design rules:
- The unlock session key is passed per-call via the BW_SESSION env, never stored on an object
  and never logged.
- No method logs secret material. Errors are raised without echoing item contents.

SCAFFOLD: methods are stubs. Implement once decision D1 (Authentik↔Vaultwarden auth model) is
settled — it determines how we authenticate the CLI. See docs/DECISIONS.md.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


class VaultError(RuntimeError):
    pass


@dataclass
class BwClient:
    server: str

    def _session(self) -> str:
        session = os.environ.get("BW_SESSION")
        if not session:
            raise VaultError("BW_SESSION not set — unlock the vault and export the session key")
        return session

    # --- read ---------------------------------------------------------------
    def list_items(self) -> list[dict]:
        """Return all vault items (decrypted by the CLI in-process)."""
        raise NotImplementedError("TODO(D1): implement `bw list items` wrapper")

    def get_item(self, item_id: str) -> dict:
        raise NotImplementedError("TODO(D1): implement `bw get item <id>` wrapper")

    # --- write --------------------------------------------------------------
    def create_login(self, name: str, username: str, password: str, uri: str | None = None,
                     folder_id: str | None = None) -> str:
        """Create a login item; returns the new item id. Used by importers (Phase 1)."""
        raise NotImplementedError("TODO(Phase 1): implement `bw create item` wrapper")
