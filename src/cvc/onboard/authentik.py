"""Authentik seam: a tiny client interface, a recording fake, and an httpx implementation.

The live client is only built with --execute AND AUTHENTIK_URL + AUTHENTIK_TOKEN set.
Passkey enforcement is not an API call here: it is the tier group's authentication flow /
the Traefik chain (authentik forward-auth on high/admin/owner hosts); the wizard prints it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Protocol

import httpx


def tier_group(tier: str) -> str:
    return f"cvc-tier-{tier}"


class AuthentikClient(Protocol):
    def ensure_user(self, username: str, name: str, email: str | None) -> str: ...
    def ensure_group(self, name: str) -> str: ...
    def add_to_group(self, username: str, group: str) -> str: ...


@dataclass
class RecordingAuthentik:
    """Fake/plan client: records calls, contacts nothing."""
    calls: list[tuple] = field(default_factory=list)

    def ensure_user(self, username: str, name: str, email: str | None) -> str:
        self.calls.append(("ensure_user", username, name, email))
        return f"user {username}"

    def ensure_group(self, name: str) -> str:
        self.calls.append(("ensure_group", name))
        return f"group {name}"

    def add_to_group(self, username: str, group: str) -> str:
        self.calls.append(("add_to_group", username, group))
        return f"{username} in {group}"


class HttpAuthentik:
    """Authentik API v3 (core/users, core/groups). Idempotent: looks up before creating."""

    def __init__(self, base_url: str, token: str, client: httpx.Client | None = None):
        self._c = client or httpx.Client(base_url=base_url.rstrip("/") + "/api/v3",
                                         headers={"Authorization": f"Bearer {token}"},
                                         timeout=15)

    def _find(self, path: str, **params: str) -> dict | None:
        r = self._c.get(path, params=params)
        r.raise_for_status()
        res = r.json().get("results") or []
        return res[0] if res else None

    def ensure_user(self, username: str, name: str, email: str | None) -> str:
        if self._find("/core/users/", username=username):
            return f"user {username} exists"
        body = {"username": username, "name": name, "is_active": True}
        if email:
            body["email"] = email
        self._c.post("/core/users/", json=body).raise_for_status()
        return f"created user {username}"

    def ensure_group(self, name: str) -> str:
        if self._find("/core/groups/", name=name):
            return f"group {name} exists"
        self._c.post("/core/groups/", json={"name": name}).raise_for_status()
        return f"created group {name}"

    def add_to_group(self, username: str, group: str) -> str:
        user = self._find("/core/users/", username=username)
        grp = self._find("/core/groups/", name=group)
        if not user or not grp:
            raise RuntimeError(f"missing user {username!r} or group {group!r}")
        self._c.post(f"/core/groups/{grp['pk']}/add_user/",
                     json={"pk": user["pk"]}).raise_for_status()
        return f"added {username} to {group}"


def client_from_env() -> HttpAuthentik | None:
    url, token = os.environ.get("AUTHENTIK_URL"), os.environ.get("AUTHENTIK_TOKEN")
    return HttpAuthentik(url, token) if url and token else None
