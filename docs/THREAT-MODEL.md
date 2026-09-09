# Threat model (draft — complete during Phase 0)

Credential infrastructure. Fill this in before building anything that touches real secrets.

## Assets
- The master vault (all personal credentials) — highest value.
- Agent-accessible credential subset (Phase 4) — smaller, but reachable by automation.
- Vault master key / unlock session.
- Backups & recovery material.
- The audit log (integrity matters — it's the record of who accessed what).

## Trust boundaries
- Source stores (Keychain/Chrome) → import host → Vaultwarden.
- Personal clients (browser/mobile) ↔ Vaultwarden.
- **Playwright agents ↔ broker ↔ vault** — the new, highest-risk boundary. Agents are semi-trusted
  at best; treat a compromised agent as an assumed condition.

## Adversaries / scenarios (seed list — expand)
- Plaintext export files left on disk / synced to cloud during migration (Phase 1).
- A compromised or misbehaving Playwright agent attempting to read credentials outside its grant.
- Broker used as a confused deputy (agent requests a secret for a false "purpose").
- Audit-log tampering to hide an access.
- Loss of the master password with no working recovery path.
- Secrets leaking into logs / process listings / error messages.

## Controls (map each adversary → control during Phase 0)
- Encrypted staging + `shred` for exports; never sync.
- Default-deny ACL, per-credential grants, agent-cred isolation (separate collection/instance — D5).
- Purpose binding + append-only, off-box-shipped audit log; optional human approval for sensitive items.
- 2FA on the vault; short-lived/just-in-time secret return from the broker.
- Prearranged recovery (D4) tested via the recovery runbook.
- No secrets in logs; redaction enforced in code review.

## Review gate
Phase 4 (broker) must pass an **Opus security review** before it ships.
