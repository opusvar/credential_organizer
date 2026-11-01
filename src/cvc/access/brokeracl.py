"""Generate the broker ACL (cvc.broker.acl shape) from agent roles."""
from __future__ import annotations

import datetime as dt

import yaml

from cvc.access.builders import GENERATED_HEADER, register_builder
from cvc.access.model import Registry


@register_builder("broker-acl")
def build_broker_acl(registry: Registry, today: dt.date | None = None) -> str:
    today = today or dt.datetime.now().astimezone().date()
    agents: dict = {}
    for aid in sorted(registry.agents):
        agent = registry.agents[aid]
        merged: dict[str, set[str]] = {}
        if agent.active(today):
            for _role, g in registry.grants_for(agent):
                if registry.system_of(g).kind == "credential-store":
                    merged.setdefault(g.credential.lower(), set()).update(g.purposes)
        allow = []
        for cred in sorted(merged):
            p = merged[cred]
            allow.append({"credential": cred, "purposes": ["*"] if "*" in p else sorted(p)})
        entry: dict = {}
        if agent.token_sha256:
            entry["token_sha256"] = agent.token_sha256
        entry["allow"] = allow
        agents[aid] = entry
    body = yaml.safe_dump({"agents": agents}, sort_keys=False, default_flow_style=False)
    return GENERATED_HEADER.format(name="broker-acl") + body
