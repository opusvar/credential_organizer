# API documentation (OpenAPI)

The credential broker (`cvc.broker.app`) is a FastAPI service, so it is **OpenAPI-native**:

OpenAPI docs (`/docs`, `/redoc`, `/openapi.json`) are **disabled** on the live broker
(security: a credential broker must not advertise its contract). The static spec at
[`openapi.yaml`](openapi.yaml) is the reviewable contract. Regenerate after endpoint changes:

```bash
# Run locally (not from the deployed pod) to regenerate:
python -c "import yaml, json; from cvc.broker.app import app; print(yaml.dump(json.loads(app.openapi())))" > docs/openapi.yaml
```

## Endpoints
- `GET /healthz` — liveness (no auth required).
- `GET /readyz` — readiness (no auth required). 200 `{"status": "ready", "vault": "unlocked"}`
  when the vault session is unlocked; 503 `{"status": "not ready", "vault": "<detail>"}`
  otherwise (`locked`, `unauthenticated`, `session-missing`, `vault-unreachable`,
  `status-unparseable`, or `probe-failed`). Backed by a `bw status` check cached for ~25s so
  repeated probing doesn't shell out every request.
- `GET /v1/audit/verify` — audit hash-chain integrity (`intact: bool`). Requires auth.
- `POST /v1/credentials/fetch` — default-deny, purpose-bound, audited credential fetch.
  Auth via `X-Agent-Id` + `Authorization: Bearer <token>`. Returns 401 (auth), 403 (ACL deny),
  502 (vault error), or 200 with `{"credential": "<uuid>", "field": "<field>", "value": "<val>"}`.
- `POST /v1/backup/trigger` — run the password-protected backup pipeline now (the on-demand
  equivalent of the weekly `cvc-backup` systemd user timer; D9, D10). Auth via
  `X-Agent-Id` + `Authorization: Bearer <token>`. Body: `{"purpose": "manual-trigger"}`.

  Note that the broker still runs in k3s (D10), so a trigger through this endpoint
  executes `cvc-backup` **in the broker pod**, not on the host. The pod has no access to
  the host's `onedrive` client, so the off-host sync step is expected to fail (and, since F8,
  to make `exit_code` non-zero even though the local export succeeded) — that is the sync gap D10
  closes for the *scheduled* run. Use `systemctl --user start cvc-backup.service` on the host for a manual run that
  also reaches OneDrive.

  **⚠ BLOCKING — takes MINUTES.** A full `bw export` on this ARM64 host under a 200m CPU
  limit runs for minutes, and the response is returned only after the pipeline finishes.
  Set a client timeout of **600s or more**; do not poll it (each call holds a FastAPI
  threadpool worker for its whole duration).

  Authorized against the ACL credential sentinel `"backup"` — a *capability*, not a vault
  item, so it is exempt from the UUID rule that applies to every other `credential:` entry
  (see `acl._SENTINEL_CREDENTIALS`). Permitted purposes come from `deploy/broker-acl.yaml`
  (`manual-trigger`, `scheduled`). The grant is audited before the vault is touched, with
  `credential: "backup"`.

  | Status | Meaning |
  |--------|---------|
  | 200 | The **trigger** succeeded. Check `exit_code` for whether the **backup** did. |
  | 401 | Authentication failed. |
  | 403 | ACL deny — agent lacks the `backup` capability, or the purpose is not permitted. |
  | 409 | A backup is already running (single-flight; the refusal is audited as `deny:busy`). |
  | 413 | Request body over the 8 KB limit (applies to every endpoint). |
  | 503 | The subprocess could not be started at all. |
  | 504 | The backup exceeded the internal 600s cap and was killed. |

  200 body: `{"triggered": true, "exit_code": 0, "log": "<last 2000 chars of stdout>",
  "note": "..."}`. `exit_code: 0` means the password-protected exports landed in the pod's
  `BACKUP_DIR`.
  A non-zero `exit_code` means the backup failed — read `log`. Since PR #3 (F8) a failed
  OneDrive copy/sync also makes `cvc-backup` exit non-zero (the local export is kept and
  retention still runs); a missing `BACKUP_EXPORT_PASSWORD` fails the run too. stderr is not
  returned: a redacted tail (secret-looking lines dropped) goes to the broker log.

  The broker runs from a built image: after merging changes to `src/cvc/broker/` or
  `src/cvc/backup/`, run `deploy/rebuild.sh --restart` or the live pod keeps the old behaviour.
  The broker listens on 8710 (hostPort on the Tailscale IP `100.106.97.34`).

The other components (importers, reminders, backup) are CLIs/jobs, not HTTP services, so they
have no OpenAPI surface; their contracts live in `ARCHITECTURE.md` and their `--help`.

## CLI deployment surface

`cvc-remind` and `cvc-backup` are deployed as **systemd user timers on the host**, not as
k3s CronJobs (D10). Their contract is the process environment plus the unit files:

| | `cvc-remind` | `cvc-backup` |
|---|---|---|
| Unit | `deploy/cvc-remind.service` | `deploy/cvc-backup.service` |
| Timer | `deploy/cvc-remind.timer` — daily 07:00 UTC | `deploy/cvc-backup.timer` — Sun 02:00 UTC |
| Env file | `~/.config/cvc/remind.env` (mode 600) | `~/.config/cvc/backup.env` (mode 600) |
| Template | `deploy/remind.env.example` | `deploy/backup.env.example` |
| Install | `deploy/setup-timers.sh` | `deploy/setup-timers.sh` |
| Logs | `journalctl --user -u cvc-remind` | `journalctl --user -u cvc-backup` |
| Run now | `systemctl --user start cvc-remind.service` | `systemctl --user start cvc-backup.service` |

Exit codes (both): `0` success, `1` a fatal step failed (vault auth, vault read, export,
MQTT publish). The OneDrive sync and the retention prune are non-fatal by design (D9) — they
log `WARNING:` and leave the exit code at `0`, so a `0` does **not** prove the off-host copy
happened. `journalctl` is the only place that distinction is visible.
