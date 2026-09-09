# Architecture

Target vault: **Vaultwarden** (Bitwarden-compatible), on the OPi k3s auth stack. All vault
access goes through the Bitwarden CLI (`bw`) or the Vaultwarden API; no component stores the
master key — an unlock session (`BW_SESSION`) is injected at runtime.

```
Sources (Keychain / Chrome / …)
        │ export (CSV/JSON)  — plaintext, staged encrypted, shredded after
        ▼
[ importers ] → normalized items → dedup → [ vault.client (bw) ] → Vaultwarden
                                                                      │
     ┌────────────────────────────────────────────────────────────────┼─────────────────┐
     ▼                              ▼                          ▼                          ▼
[ reminders ]                 [ backup ]                 [ broker ]                personal
 policy: age/reuse/weak/      encrypted export +         FastAPI, default-deny     clients
 breach → MQTT discovery      emergency access +         ACL + purpose binding +   (browser/
 → Home Assistant             break-glass secret         append-only audit log     mobile)
                                                              │
                                                              ▼
                                                       Playwright agents
```

## Modules (`src/cvc/`)
- **vault/client.py** — thin, testable wrapper over `bw` (login/unlock/list/get/create). Never logs secrets.
- **importers/** — `base.Importer` ABC; `chrome`, `keychain`, … each yield `normalize.Item`s; `normalize`
  handles the canonical item model + dedup. Importers require explicit input paths and shred temp files.
- **reminders/** — `policy` computes rotation/reuse/weak/breach flags; `hibp` does k-anonymity lookups;
  `mqtt_publish` emits HA MQTT-discovery sensors + notifications.
- **backup/** — `exporter` produces encrypted exports and drives the recovery runbook.
- **broker/** — `app` (FastAPI) + `acl` (default-deny per-credential allowlist) + `audit` (append-only).
  The agent-access surface; isolated from the personal vault per decision D5.

## Deployment (`deploy/`)
- `k8s/` — manifests for the broker + reminder CronJob (target: OPi k3s, per D6).
- `systemd/` — timer alternative for host-run reminder/backup jobs.

Design specifics depend on the Phase-0 decisions in `DECISIONS.md`; sections marked TODO in code
point back to the blocking decision.
