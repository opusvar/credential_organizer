# credential-vault-consolidation (cvc)

Consolidate passwords from Apple Keychain, Chrome, and other stores into the self-hosted
**Vaultwarden** (running on the OPi k3s auth stack), then layer on rotation reminders, Home
Assistant surfacing, backup/emergency recovery, and a least-privilege **broker** that lets
Playwright automations fetch specific credentials for a stated purpose — with a tamper-evident
access log.

> **Status: Phases 0-4 implemented and deployed** (import, reminders, backup, broker), plus the
> access registry (`cvc-access`). Phase-0 decisions are recorded in `docs/DECISIONS.md`. The
> step-ca and YubiKey material under `deploy/` is scaffold/runbook only (not applied). The
> threat model in `docs/THREAT-MODEL.md` is still a draft. A few operator steps remain (see the
> project checkpoint).

Project state tracker (checkpoint): `~/projectTracking/ai/credential-vault-consolidation/checkpoint.md`
Depends on: the OPi auth stack (Vaultwarden on k3s).

## Layout

```
src/cvc/
  vault/       Vaultwarden access (Bitwarden `bw` CLI wrapper)
  importers/   Phase 1 — Keychain/Chrome/… → normalized items → vault
  reminders/   Phase 2 — rotation/reuse/breach policy → MQTT → Home Assistant
  backup/      Phase 3 — password-protected export (personal vault + each org) + OneDrive sync
  broker/      Phase 4 — Playwright credential broker: ACL + purpose + audit
  access/      access registry (roles, machines): broker ACL, Mosquitto ACL and Mermaid graph builders (`cvc-access`)
deploy/        broker k8s manifests, systemd user timers (remind/backup), step-ca + YubiKey scaffolds
docs/          ARCHITECTURE, THREAT-MODEL, DECISIONS (Phase 0), RUNBOOK-recovery
tests/
```

## Safety rules (enforced by scaffold conventions)
- **No secrets in git** — `.gitignore` blocks `.env`, exports, sessions, keys, backups, audit logs.
- **No hardcoded config** — everything reads from env (`.env.example` documents the keys).
- **Importers never auto-run** — they require explicit input paths and shred plaintext temp files.
- **Broker is default-deny** — an agent may fetch only credentials on an explicit allowlist, and
  every access is written to an append-only audit log before the secret is returned.

## Getting started
```bash
python -m venv .venv && . .venv/bin/activate      # or your env manager
pip install -e '.[dev]'
cp .env.example .env                              # fill in; never commit
make test
```

See `docs/DECISIONS.md` for the decisions (D1-D12) behind the design. After merging changes to
`src/cvc/broker/` the broker image must be rebuilt (`deploy/rebuild.sh --restart`); the broker runs
in k3s from a built image, not from this checkout. `remind` and `backup` run as host systemd user
timers (D10) and pick up code via the editable install.
