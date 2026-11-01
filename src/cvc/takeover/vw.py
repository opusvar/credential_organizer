"""Vaultwarden Emergency Access client interface + vault merge plan (D15).

Emergency Access in Vaultwarden is configured by the *grantor* (the owner being taken over)
ahead of time: they invite the grantee with a type (0 View, 1 Takeover) and a wait time. The
takeover flow only *initiates* recovery on existing grants, so grants must be pre-provisioned.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Protocol

import httpx

from cvc.takeover.model import TakeoverError

VW_TYPES = {0: "view", 1: "takeover"}


@dataclass(frozen=True)
class EmergencyGrant:
    id: str
    grantor_email: str
    type: str          # "view" | "takeover"
    wait_days: int


class EmergencyAccessClient(Protocol):
    def granted(self) -> list[EmergencyGrant]: ...
    def initiate(self, grant_id: str) -> None: ...
    def reject(self, grant_id: str) -> None: ...
    def view(self, grant_id: str) -> int: ...       # number of ciphers visible
    def takeover(self, grant_id: str) -> None: ...


class HttpEmergencyAccessClient:
    """Real client. ``token`` is a bearer token for the acting account (grantee for
    granted/initiate/view/takeover; grantor for reject)."""

    def __init__(self, base_url: str, token: str, http: httpx.Client | None = None):
        self.http = http or httpx.Client(base_url=base_url.rstrip("/"), timeout=15,
                                         headers={"Authorization": f"Bearer {token}"})

    def _post(self, path: str) -> httpx.Response:
        r = self.http.post(f"/api/emergency-access/{path}")
        r.raise_for_status()
        return r

    def granted(self) -> list[EmergencyGrant]:
        r = self.http.get("/api/emergency-access/granted")
        r.raise_for_status()
        return [EmergencyGrant(str(g["id"]), str(g.get("email", "")).lower(),
                               VW_TYPES.get(g.get("type"), "unknown"), int(g.get("waitTimeDays", 0)))
                for g in r.json().get("data", [])]

    def initiate(self, grant_id: str) -> None:
        self._post(f"{grant_id}/initiate")

    def reject(self, grant_id: str) -> None:
        self._post(f"{grant_id}/reject")

    def view(self, grant_id: str) -> int:
        return len(self._post(f"{grant_id}/view").json().get("ciphers", []))

    def takeover(self, grant_id: str) -> None:
        self._post(f"{grant_id}/takeover")


def find_grants(client: EmergencyAccessClient, grantor_email: str,
                takeover_wait: int, view_wait: int = 15) -> tuple[str, str]:
    email = grantor_email.lower()
    mine = [g for g in client.granted() if g.grantor_email == email]
    out = {}
    for kind, wait in (("view", view_wait), ("takeover", takeover_wait)):
        g = next((g for g in mine if g.type == kind and g.wait_days == wait), None)
        if g is None:
            have = ", ".join(f"{x.type}/{x.wait_days}d" for x in mine) or "none"
            raise TakeoverError(
                f"refused: no Vaultwarden {kind} emergency-access grant with a {wait}-day wait "
                f"from {email} (found: {have}). The owner must pre-provision it (D15).")
        out[kind] = g.id
    return out["view"], out["takeover"]


# ── vault merge / transfer plan ─────────────────────────────────────────────
@dataclass(frozen=True)
class VaultItem:
    id: str
    name: str
    organization_id: str | None = None


@dataclass(frozen=True)
class PlanStep:
    action: str        # "copy-to-initiator" | "transfer-org-ownership"
    ref: str           # item id or organization id
    detail: str


class VaultInventory(Protocol):
    def items_for(self, person: str) -> list[VaultItem]: ...


class VaultExecutor(Protocol):
    def apply(self, steps: list[PlanStep], target: str, initiator: str) -> None: ...


def build_plan(items: list[VaultItem], target: str, initiator: str) -> list[PlanStep]:
    steps = [PlanStep("copy-to-initiator", i.id, f"{i.name}: re-encrypt into {initiator}'s vault")
             for i in items if i.organization_id is None]
    orgs: dict[str, int] = defaultdict(int)
    for i in items:
        if i.organization_id:
            orgs[i.organization_id] += 1
    steps += [PlanStep("transfer-org-ownership", o,
                       f"make {initiator} owner of org {o} ({n} item(s) stay in place); "
                       f"then remove {target}'s membership")
              for o, n in sorted(orgs.items())]
    return steps


def format_plan(steps: list[PlanStep]) -> str:
    if not steps:
        return "vault plan: nothing to move"
    return "\n".join(["vault plan:", *[f"  - {s.action} {s.ref}: {s.detail}" for s in steps]])
