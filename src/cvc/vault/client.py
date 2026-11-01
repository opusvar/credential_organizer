"""Thin wrapper over the Bitwarden CLI (`bw`) against Vaultwarden.

Auth model (D1 resolved 2026-09-09):
- Human web login: Authentik OIDC SSO
- Headless/scripted: Vaultwarden API key (BW_CLIENTID + BW_CLIENTSECRET)
  Login flow: bw config server → bw login --apikey → bw unlock → BW_SESSION

Design rules:
- The unlock session key is read from BW_SESSION per-call; never stored on an object.
- No method logs secret material. Errors are raised without echoing item contents.
- All subprocess calls use a list argv (no shell=True) to prevent injection.
"""
from __future__ import annotations

import json
import logging as _logging
import os
import subprocess
import time as _time
from dataclasses import dataclass


class VaultError(RuntimeError):
    pass


def _session() -> str:
    val = os.environ.get("BW_SESSION")
    if not val:
        raise VaultError("BW_SESSION not set — run `bw unlock` and export the session key")
    return val


_BW = "/usr/local/bin/bw"
_ENV_BASE = {"HOME", "USER", "TMPDIR", "LANG", "LC_ALL", "PATH", "BITWARDENCLI_APPDATA_DIR"}
_vault_log = _logging.getLogger(__name__)


def _run(*args: str, session: str | None = None,
         extra_env: set[str] | None = None) -> str:
    """Run a bw subcommand and return stdout. Raises VaultError on non-zero exit."""
    allowed = _ENV_BASE | (extra_env or set())
    env: dict[str, str] = {k: v for k, v in os.environ.items() if k in allowed}
    if session:
        env["BW_SESSION"] = session
    t0 = _time.monotonic()
    try:
        result = subprocess.run(
            [_BW, *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            check=False,
        )
    except FileNotFoundError as exc:
        raise VaultError("bw CLI not found — install Bitwarden CLI") from exc
    except subprocess.TimeoutExpired as exc:
        raise VaultError("bw command timed out") from exc
    elapsed_ms = round((_time.monotonic() - t0) * 1000)
    if result.returncode != 0:
        _vault_log.error(
            "bw_failed",
            extra={
                "subcommand": args[0],
                "exit_code": result.returncode,
                "elapsed_ms": elapsed_ms,
            },
        )
        raise VaultError("vault command failed")
    _vault_log.debug(
        "bw_ok",
        extra={"subcommand": args[0], "elapsed_ms": elapsed_ms},
    )
    return result.stdout.strip()


@dataclass
class BwClient:
    server: str  # e.g. https://cvc.example.ts.net:8443/vault (site vault_url)

    def _status(self) -> dict:
        """Return parsed output of `bw status`. Never raises."""
        try:
            import json as _json
            raw = _run("status")
            return _json.loads(raw)
        except Exception:  # noqa: BLE001 - status probe falls back to {}
            return {}

    def configure(self) -> None:
        """Point bw at this Vaultwarden instance. Idempotent.

        bw refuses `config server` when already logged in, so skip it if the
        server URL is already correct (the common case on the second+ run).
        """
        st = self._status()
        if st.get("serverUrl", "").rstrip("/") == self.server.rstrip("/"):
            return
        _run("config", "server", self.server)

    def login_apikey(self) -> None:
        """Log in using BW_CLIENTID + BW_CLIENTSECRET from the environment.

        Skips the login call when bw reports it is already authenticated, so the
        service can call this unconditionally on every run without re-logging in.
        """
        if not os.environ.get("BW_CLIENTID") or not os.environ.get("BW_CLIENTSECRET"):
            raise VaultError("BW_CLIENTID and BW_CLIENTSECRET must be set for API key login")
        st = self._status()
        if st.get("status") in ("locked", "unlocked"):
            return  # already logged in
        _run("login", "--apikey", extra_env={"BW_CLIENTID", "BW_CLIENTSECRET"})

    def unlock(self) -> str:
        """Unlock the vault with BW_PASSWORD and return the session key.

        The caller is responsible for exporting the returned value as BW_SESSION
        for the lifetime of the process (or passing it explicitly to each call).
        The value is never logged here.
        """
        if not os.environ.get("BW_PASSWORD"):
            raise VaultError("BW_PASSWORD must be set to unlock the vault")
        raw = _run("unlock", "--passwordenv", "BW_PASSWORD", "--raw",
                   extra_env={"BW_PASSWORD"})
        return raw

    def sync(self) -> None:
        """Pull latest vault state from the server."""
        _run("sync", session=_session())

    # --- read -----------------------------------------------------------------

    def list_items(self) -> list[dict]:
        """Return all vault items (decrypted by the CLI in-process)."""
        raw = _run("list", "items", "--raw", session=_session())
        return json.loads(raw)

    def get_item(self, item_id: str) -> dict:
        """Return a single item by UUID."""
        raw = _run("get", "item", item_id, session=_session())
        return json.loads(raw)

    def list_folders(self) -> list[dict]:
        raw = _run("list", "folders", "--raw", session=_session())
        return json.loads(raw)

    def get_or_create_folder(self, name: str) -> str:
        """Return folder id for *name*, creating it if absent."""
        folders = self.list_folders()
        for f in folders:
            if f.get("name") == name:
                return f["id"]
        raw = _run("create", "folder", json.dumps({"name": name}), session=_session())
        return json.loads(raw)["id"]

    # --- write ----------------------------------------------------------------

    def create_login(
        self,
        name: str,
        username: str,
        password: str,
        uri: str | None = None,
        folder_id: str | None = None,
    ) -> str:
        """Create a login item and return the new item UUID."""
        item: dict = {
            "type": 1,  # Login
            "name": name,
            "login": {
                "username": username,
                "password": password,
                "uris": [{"match": None, "uri": uri}] if uri else [],
            },
        }
        if folder_id:
            item["folderId"] = folder_id
        encoded = _encode(json.dumps(item))
        raw = _run("create", "item", encoded, session=_session())
        return json.loads(raw)["id"]


def _encode(payload: str) -> str:
    """Base64-encode a JSON payload the way `bw encode` does (no subprocess)."""
    import base64
    return base64.b64encode(payload.encode()).decode()
