# credential-vault-consolidation (cvc)

Consolidate passwords from Apple Keychain, Chrome, and other stores into the self-hosted
**Vaultwarden** (running on the OPi k3s auth stack), then layer on rotation reminders, Home
Assistant surfacing, backup/emergency recovery, and a least-privilege **broker** that lets
Playwright automations fetch specific credentials for a stated purpose — with a tamper-evident
access log.

> **Status: planning / scaffold.** No credential-handling logic is implemented yet. Phase 0
> decisions (see `docs/DECISIONS.md`) must be resolved and the threat model written before any
> component that touches real secrets is built. The Playwright broker (Phase 4) additionally
> requires an Opus security review before it ships.

Project state tracker (checkpoint): `~/projectTracking/ai/credential-vault-consolidation/checkpoint.md`
Depends on: the OPi auth stack (Vaultwarden on k3s).

## Layout

```
src/cvc/
  vault/       Vaultwarden access (Bitwarden `bw` CLI wrapper)
  importers/   Phase 1 — Keychain/Chrome/… → normalized items → vault
  reminders/   Phase 2 — rotation/reuse/breach policy → MQTT → Home Assistant
  backup/      Phase 3 — encrypted export + emergency/break-glass recovery
  broker/      Phase 4 — Playwright credential broker: ACL + purpose + audit
deploy/        k8s manifests + systemd timers (stubs)
docs/          ARCHITECTURE, THREAT-MODEL, DECISIONS (Phase 0), RUNBOOK-recovery
tests/
```

## Safety rules (enforced by scaffold conventions)
- **No secrets in git** — `.gitignore` blocks `.env`, exports, sessions, keys, backups, audit logs.
- **No hardcoded config** — everything reads from env (`.env.example` documents the keys).
- **Importers never auto-run** — they require explicit input paths and shred plaintext temp files.
- **Broker is default-deny** — an agent may fetch only credentials on an explicit allowlist, and
  every access is written to an append-only audit log before the secret is returned.

## Getting started (scaffold only)
```bash
python -m venv .venv && . .venv/bin/activate      # or your env manager
pip install -e '.[dev]'
cp .env.example .env                              # fill in; never commit
make test
```

See `docs/DECISIONS.md` for the open Phase-0 questions that block real implementation.
