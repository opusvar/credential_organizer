"""Default-deny access control for agent credential requests.

ACL file (YAML) shape:

    agents:
      playwright-billing:
        token_sha256: "<hex sha256 of the agent's service token>"
        allow:
          - credential: "acme-portal-login"    # vault item name or id
            purposes: ["pay-invoice"]          # required; [] or omitted = DENY ALL; ["*"] = any purpose
      playwright-signup:
        token_sha256: "..."
        allow: []                              # explicitly nothing

`credential:` is normally a Vaultwarden item UUID (enforced by Acl.load()). The sole
exception is the capability sentinels in _SENTINEL_CREDENTIALS — e.g. "backup", which gates
POST /v1/backup/trigger. A sentinel names an operation, not a vault item, so no UUID exists
for it. Authorization treats sentinels exactly like any other credential: default-deny,
purpose-bound, audited.

Rules enforced:
- Unknown agent  -> deny.
- Agent with no matching allow entry for the credential -> deny.
- `purposes` empty/None/missing -> deny all.
- `purposes: ["*"]` -> any purpose allowed.
- Purpose list present and request purpose not in it -> deny.
Nothing is allowed implicitly.

Agent-tier fields (optional, see tiers.py):
    tier: scoped | low | medium | high | assistant   # absent/unknown -> scoped
    require_session_token: true         # optional; also allowed at top level, or env
                                        # CVC_REQUIRE_SESSION_TOKEN=1 (global). When on, the
                                        # long-lived service token may only mint session
                                        # tokens; fetch/backup reject it.
    on_behalf_of: "nathan"              # required for tier assistant (dual attribution)
    allow entries may set `physical: true` — for tier high such requests need human approval.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass

import yaml

from .tiers import normalize_tier

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Non-UUID `credential:` values that name a broker CAPABILITY rather than a vault item.
# The UUID rule exists to catch a real mistake — writing an item's human name where its id
# belongs, which silently denies at runtime. A capability has no vault id at all, so the
# rule cannot apply to it; a closed allowlist keeps the typo protection for everything else
# instead of dropping the check (or minting a fake UUID that no `bw get item` would resolve
# and that nobody reading the ACL could interpret).
#
# Every sentinel must be lowercase: authorize() lowercases the requested credential.
_SENTINEL_CREDENTIALS = frozenset({
    "backup",   # POST /v1/backup/trigger — runs the export pipeline, returns no secret
})


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
        self._require_session_token = bool((data or {}).get("require_session_token"))

    @classmethod
    def load(cls, path: str) -> Acl:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        for agent_id, agent in (data.get("agents") or {}).items():
            for entry in agent.get("allow", []) or []:
                cred = entry.get("credential", "")
                if cred.lower() in _SENTINEL_CREDENTIALS:
                    continue
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
        expected = str(agent.get("token_sha256") or "").strip().lower()
        got = _sha256(token).lower()
        return hmac.compare_digest(expected, got)

    def authorize(self, agent_id: str, credential: str, purpose: str) -> Decision:
        agent = self._agents.get(agent_id)
        if not agent:
            return Decision(False, "unknown agent")
        credential = credential.lower()
        for entry in agent.get("allow", []) or []:
            if (entry.get("credential") or "").lower() != credential:
                continue
            purposes = entry.get("purposes") or []
            if "*" in purposes or purpose in purposes:
                return Decision(True, "explicit allow")
            return Decision(False, f"purpose '{purpose}' not permitted for {credential}")
        return Decision(False, f"no allow entry for credential '{credential}'")

    def tier(self, agent_id: str) -> str:
        """Agent tier from the ACL; absent or unrecognised -> 'scoped'."""
        agent = self._agents.get(agent_id) or {}
        return normalize_tier(agent.get("tier"))

    def requires_session_token(self, agent_id: str) -> bool:
        """True if this agent must use a session token (not its service token) for
        fetch/backup. Opt-in: per-agent flag, ACL top-level flag, or
        CVC_REQUIRE_SESSION_TOKEN=1. Default off."""
        if os.environ.get("CVC_REQUIRE_SESSION_TOKEN", "").strip().lower() in (
                "1", "true", "yes", "on"):
            return True
        if self._require_session_token:
            return True
        agent = self._agents.get(agent_id) or {}
        return bool(agent.get("require_session_token"))

    def on_behalf_of(self, agent_id: str) -> str | None:
        agent = self._agents.get(agent_id) or {}
        v = str(agent.get("on_behalf_of") or "").strip()
        return v or None

    def is_physical(self, agent_id: str, credential: str) -> bool:
        agent = self._agents.get(agent_id) or {}
        credential = credential.lower()
        for entry in agent.get("allow", []) or []:
            if (entry.get("credential") or "").lower() == credential:
                return bool(entry.get("physical"))
        return False

    def allowed_credentials(self, agent_id: str) -> set[str]:
        agent = self._agents.get(agent_id) or {}
        return {(e.get("credential") or "").lower() for e in agent.get("allow", []) or []}
