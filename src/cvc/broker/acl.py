"""Default-deny access control for agent credential requests.

ACL file (YAML) shape:

    agents:
      playwright-billing:
        token_sha256: "<hex sha256 of the agent's service token>"
        allow:
          - credential: "acme-portal-login"    # vault item name or id
            purposes: ["pay-invoice"]          # optional; [] or omitted = any purpose
      playwright-signup:
        token_sha256: "..."
        allow: []                              # explicitly nothing

Rules enforced:
- Unknown agent  -> deny.
- Agent with no matching allow entry for the credential -> deny.
- Purpose list present and request purpose not in it -> deny.
Nothing is allowed implicitly.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import uuid as _uuid_mod
from dataclasses import dataclass

import yaml

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class Denied(Exception):
    """Raised when a request is not explicitly permitted."""


@dataclass
class Decision:
    allowed: bool
    reason: str


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class Acl:
    def __init__(self, data: dict):
        self._agents: dict = (data or {}).get("agents", {}) or {}

    @classmethod
    def load(cls, path: str) -> "Acl":
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        for agent_id, agent in (data.get("agents") or {}).items():
            for entry in agent.get("allow", []) or []:
                cred = entry.get("credential", "")
                if not _UUID_RE.match(cred):
                    raise ValueError(
                        f"ACL agent '{agent_id}': credential '{cred}' is not a UUID"
                    )
        return cls(data)

    def authenticate(self, agent_id: str, token: str) -> bool:
        """Constant-time token check against the stored sha256 for this agent."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        expected = agent.get("token_sha256", "")
        got = _sha256(token)
        return hmac.compare_digest(expected, got)

    def authorize(self, agent_id: str, credential: str, purpose: str) -> Decision:
        agent = self._agents.get(agent_id)
        if not agent:
            return Decision(False, "unknown agent")
        for entry in agent.get("allow", []) or []:
            if entry.get("credential") != credential:
                continue
            purposes = entry.get("purposes") or []
            if "*" in purposes or purpose in purposes:
                return Decision(True, "explicit allow")
            return Decision(False, f"purpose '{purpose}' not permitted for {credential}")
        return Decision(False, f"no allow entry for credential '{credential}'")
