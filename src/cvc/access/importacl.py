"""Bootstrap a registry document from an existing broker ACL (one `<agent>-legacy` role each)."""
from __future__ import annotations

from pathlib import Path

import yaml


def import_broker_acl(path: str | Path, system: str = "vaultwarden") -> dict:
    with open(path, encoding="utf-8") as fh:
        acl = yaml.safe_load(fh) or {}
    roles: dict = {}
    agents: dict = {}
    for aid in sorted(acl.get("agents") or {}):
        a = acl["agents"][aid] or {}
        role = f"{aid}-legacy"
        roles[role] = {
            "description": f"Imported from broker ACL for agent {aid}",
            "grants": [{"system": system, "credential": e.get("credential"),
                        "purposes": list(e.get("purposes") or [])}
                       for e in (a.get("allow") or [])],
        }
        entry: dict = {"roles": [role]}
        if a.get("token_sha256"):
            entry["token_sha256"] = str(a["token_sha256"])
        agents[aid] = entry
    return {"version": 1, "systems": {system: {"kind": "credential-store"}},
            "roles": roles, "agents": agents, "machines": {}}
