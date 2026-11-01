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
 policy: age/reuse/weak/      password-protected         FastAPI, default-deny     clients
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
- **backup/** — `exporter` produces one password-protected export per scope (personal vault plus each
  organization; passphrase `BACKUP_EXPORT_PASSWORD`, required), `__main__` (`cvc-backup`) copies them
  to the OneDrive staging dir and syncs. Local `BACKUP_DIR` and `ONEDRIVE_DEST_DIR` are separate.
  A failed export, copy or sync exits non-zero (retention still runs).
- **broker/** — `app` (FastAPI) + `acl` (default-deny per-credential allowlist) + `audit` (append-only).
  The agent-access surface; isolated from the personal vault per decision D5. `POST /v1/backup/trigger`
  is single-flight (409 when one is running), request bodies are capped at 8 KB (413), and child
  stderr is redacted before it reaches the broker log.
- **access/** — access registry (`cvc-access`, D12): `model` (roles, machines, principals, grants),
  `brokeracl` / `mosquitto` / `graph` builders (broker ACL, Mosquitto `acl_file`, Mermaid auth graph),
  `check`, `importacl`, `cli`. Source of truth is `access/registry.yaml` (example in `access/`).

## Deployment (`deploy/`)
- `broker-deployment.yaml`, `namespace.yaml`, `broker-acl.yaml` — the broker in OPi k3s (Tailscale-only,
  hostPort 8710). Rebuild the image after code changes with `deploy/rebuild.sh --restart`.
- `cvc-{remind,backup}.{service,timer}` + `setup-timers.sh` — host systemd user timers (D10). The
  `*-cronjob.yaml` files are reference only; the old k3s CronJobs are superseded.
- `step-ca/`, `yubikey/` — home CA scaffold (not applied) and YubiKey enrollment runbook.

Design specifics are recorded in `DECISIONS.md`.
