"""Itemised delegation preview and its execution against the registry (D17, D16 ceilings).

Every item carries the minimum recipient rank needed to hold it. Items at or below the
recipient's ceiling are ``transfer``; anything above is ``revoke`` ("cannot transfer — will be
revoked"): it is taken from the delegator at execution and never given to the recipient.

Ranks (person tiers): guests/media-only 0, low 1, medium 2, high 3, admin 4, owner 5.
Requirements: vault item by data class (public/internal 1, private 2, secret 5); org membership
2 (owner/admin role in the org: 4); an owner's hardware key 5 (others 1); device 1 (its cert
is always revoked and re-issued for the recipient); a grant the delegator gave = the grantee's
rank (one cannot sponsor above one's own tier); agents always transfer with their tier capped
at min(agent tier, recipient's agent ceiling) (D16 §3); the delegator's tier = its own rank
(it is relinquished either way: the delegator drops to ``low``).
"""
from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from typing import Protocol

from cvc.access.edit import EditError, _append, _guard_owner_keys, active_owner_keys
from cvc.access.model import RegistryError, parse_registry
from cvc.delegate.model import SECTION_TITLES, SECTIONS, DelegationError
from cvc.takeover.flow import revoke_device_cert, transfer_key
from cvc.takeover.keys import key_role
from cvc.takeover.vw import PlanStep

PERSON_RANK = {"guest-short": 0, "guest-long": 0, "media-only": 0, "low": 1, "medium": 2,
               "high": 3, "admin": 4, "owner": 5}
AGENT_RANK = {"scoped": 0, "low": 1, "medium": 2, "assistant": 2, "high": 3}
DATA_RANK = {"public": 1, "internal": 1, "private": 2, "secret": 5}
RANK_NAME = {0: "guest", 1: "low", 2: "medium", 3: "high", 4: "admin", 5: "owner"}
TRANSFER, REVOKE = "transfer", "revoke"
REVOKE_TEXT = "cannot transfer — will be revoked"


def agent_ceiling(person_rank: int) -> str:
    return "low" if person_rank <= 1 else "medium" if person_rank == 2 else "high"


# ── inventory (vault side; no secrets) ──────────────────────────────────────
@dataclass(frozen=True)
class VaultEntry:
    id: str
    name: str
    organization_id: str | None = None
    folder: str | None = None
    data_class: str = "private"


@dataclass(frozen=True)
class OrgMembership:
    id: str
    name: str
    role: str = "user"


class DelegateInventory(Protocol):
    def items_for(self, person: str) -> list[VaultEntry]: ...
    def orgs_for(self, person: str) -> list[OrgMembership]: ...


class EmptyInventory:
    def items_for(self, person: str) -> list[VaultEntry]:
        return []

    def orgs_for(self, person: str) -> list[OrgMembership]:
        return []


@dataclass(frozen=True)
class Item:
    section: str
    ref: str
    label: str
    need: int
    action: str
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _rank(data: dict, pid: str) -> int:
    p = (data.get("people") or {}).get(pid) or {}
    return PERSON_RANK.get(p.get("tier"), 0)


def build_preview(data: dict, delegator: str, recipient: str,
                  inventory: DelegateInventory) -> list[Item]:
    ceiling = _rank(data, recipient)
    people = data.get("people") or {}
    out: list[Item] = []

    def add(section, ref, label, need, note=""):
        out.append(Item(section, ref, label, need, TRANSFER if need <= ceiling else REVOKE, note))

    for v in inventory.items_for(delegator):
        if v.organization_id is None:
            where = f"folder {v.folder}" if v.folder else "no folder"
            add("vault", v.id, f"{v.name} ({where}, {v.data_class})",
                DATA_RANK.get(v.data_class, 2))
    for o in inventory.orgs_for(delegator):
        add("orgs", o.id, f"{o.name} (role {o.role})", 4 if o.role in ("owner", "admin") else 2)
    d_owner = (people.get(delegator) or {}).get("tier") == "owner"
    for kid, k in sorted((data.get("hardware_keys") or {}).items()):
        if isinstance(k, dict) and k.get("owner") == delegator \
                and k.get("status", "active") == "active":
            add("hwkeys", kid, f"{kid} ({key_role(k)}, serial {k.get('serial')})",
                5 if d_owner else 1)
    for did, dev in sorted((data.get("devices") or {}).items()):
        if isinstance(dev, dict) and dev.get("owner") == delegator:
            add("devices", did, f"{did} ({dev.get('kind')})", 1,
                "device cert revoked; re-issue for the recipient")
    for section, ranks, tier_of in (("people", PERSON_RANK, "tier"),
                                    ("agents", AGENT_RANK, "tier")):
        for oid, raw in sorted((data.get(section) or {}).items()):
            if isinstance(raw, dict) and raw.get("granted_by") == delegator and oid != recipient:
                add("grants", f"{section}.{oid}", f"{section}.{oid} (tier {raw.get(tier_of)})",
                    ranks.get(raw.get(tier_of), 0))
    cap = agent_ceiling(ceiling)
    for gid, a in sorted((data.get("agents") or {}).items()):
        if isinstance(a, dict) and a.get("owner") == delegator:
            tier = a.get("tier") or "low"
            eff = tier if tier == "assistant" or AGENT_RANK.get(tier, 0) <= AGENT_RANK[cap] \
                else cap
            add("agents", gid, f"{gid} (tier {tier})", 0,
                f"new sponsor {recipient}; effective tier {eff}")
    tier = (people.get(delegator) or {}).get("tier")
    add("roles", f"tier:{tier}", f"{delegator}'s tier {tier}", PERSON_RANK.get(tier, 0),
        f"{delegator} drops to low")
    return out


def format_preview(items: list[Item], recipient: str, ceiling: str) -> str:
    lines = [f"Delegation preview (recipient {recipient}, ceiling {ceiling}):"]
    for s in SECTIONS:
        sec = [i for i in items if i.section == s]
        lines.append(f"  {SECTION_TITLES[s]}:" + ("" if sec else " (none)"))
        for i in sec:
            tag = "transfer" if i.action == TRANSFER else REVOKE_TEXT
            lines.append(f"    - [{tag}] {i.label}" + (f" ({i.note})" if i.note else ""))
    return "\n".join(lines)


# ── execution ───────────────────────────────────────────────────────────────
def apply_delegation(data: dict, items: list[Item], delegator: str, recipient: str, today,
                     reason: str) -> tuple[list[str], list[str]]:
    """Edit ``data`` in place for ``items``. Returns (summary lines, out-of-band commands).
    Raises DelegationError if the D14 guard or registry validation refuses."""
    before = active_owner_keys(data)
    people = data.get("people") or {}
    agents = data.get("agents") or {}
    r_rank = _rank(data, recipient)
    out, cmds = [f"delegation {reason}: {delegator} -> {recipient}"], []
    for i in items:
        if i.section == "hwkeys":
            if i.action == TRANSFER:
                out.append(transfer_key(data, i.ref, delegator, recipient, today, reason))
            else:
                k = data["hardware_keys"][i.ref]
                k["status"] = "revoked"
                _append(k, {"date": today, "event": "revoked", "reason": f"{reason}: above "
                            f"{recipient}'s ceiling"})
                out.append(f"  - hardware key {i.ref} REVOKED (above {recipient}'s ceiling)")
                cmds.append(f"wipe/reset hardware key {i.ref}; remove it from Vaultwarden 2FA")
        elif i.section == "devices":
            dev = data["devices"][i.ref]
            r = revoke_device_cert(data, i.ref, today, reason)
            if r:
                out.append(r[0])
                cmds.append(r[1])
            if i.action == TRANSFER:
                dev["owner"] = recipient
                out.append(f"  - device {i.ref} transferred to {recipient}")
                cmds.append(f"issue a new device cert for {i.ref} as {recipient}")
            else:
                out.append(f"  - device {i.ref} REVOKED for delegation (cert revoked only)")
        elif i.section == "grants":
            section, oid = i.ref.split(".", 1)
            raw = data[section][oid]
            if i.action == TRANSFER:
                raw["granted_by"] = recipient
                out.append(f"  - {i.ref}.granted_by: {delegator} -> {recipient}")
            else:
                raw["expires"] = today
                out.append(f"  - {i.ref} REVOKED: expires {today} (above {recipient}'s ceiling)")
        elif i.section == "agents":
            a = agents[i.ref]
            a["owner"] = recipient
            tier = a.get("tier")
            cap = agent_ceiling(r_rank)
            if tier and tier != "assistant" and AGENT_RANK.get(tier, 0) > AGENT_RANK[cap]:
                a["tier"] = cap
                out.append(f"  - agent {i.ref}: sponsor {recipient}; tier {tier} -> {cap}")
            else:
                out.append(f"  - agent {i.ref}: sponsor {recipient}")
            rexp = (people.get(recipient) or {}).get("expires")
            if rexp is not None and (a.get("expires") is None or str(a["expires"]) > str(rexp)):
                a["expires"] = rexp
                out.append(f"  - agent {i.ref}: expires with {recipient} on {rexp}")
        elif i.section == "roles":
            p = people[delegator]
            if PERSON_RANK.get(p.get("tier"), 0) > 1:
                out.append(f"  - {delegator}: tier {p.get('tier')} -> low"
                           + ("" if i.action == TRANSFER else " (not transferred: above ceiling)"))
                p["tier"] = "low"
    try:
        _guard_owner_keys(before, data, f"delegation {reason}")
        parse_registry(data)
    except EditError as e:
        raise DelegationError(str(e)) from None
    except RegistryError as e:
        raise DelegationError("refused: registry invalid after delegation: "
                              + "; ".join(e.errors)) from None
    return out, cmds


def check_guard(data: dict, items: list[Item], delegator: str, recipient: str, today) -> None:
    """Dry-run the registry edit on a copy (D14 guard + validation)."""
    apply_delegation(copy.deepcopy(data), items, delegator, recipient, today, "preview")


def vault_plan(items: list[Item], delegator: str, recipient: str,
               inventory: DelegateInventory) -> list[PlanStep]:
    names = {v.id: v.name for v in inventory.items_for(delegator)}
    steps = []
    for i in items:
        if i.section == "vault":
            steps.append(PlanStep("copy-to-recipient", i.ref,
                                  f"{names.get(i.ref, i.label)}: re-encrypt into {recipient}'s "
                                  f"vault; then delete {delegator}'s copy")
                         if i.action == TRANSFER else
                         PlanStep("revoke-from-delegator", i.ref,
                                  f"{names.get(i.ref, i.label)}: above {recipient}'s ceiling; "
                                  f"remove {delegator}'s access; NOT transferred"))
        elif i.section == "orgs":
            steps.append(PlanStep("transfer-org-membership", i.ref,
                                  f"add {recipient} to org {i.label}; then remove {delegator}")
                         if i.action == TRANSFER else
                         PlanStep("remove-org-membership", i.ref,
                                  f"remove {delegator} from org {i.label}; NOT transferred"))
    return steps


def need_rank_name(n: int) -> str:
    return RANK_NAME.get(n, str(n))
