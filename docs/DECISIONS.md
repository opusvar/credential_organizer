# Phase 0 decisions (ADR-lite)

These block real implementation. Each has a status: **OPEN** (needs Nathan) / DECIDED / DEFERRED.
Record the decision + date inline as they resolve.

## D1 — Authentik ↔ Vaultwarden relationship  **[DECIDED 2026-09-09]**
**Decision:** Option (a) — standalone Vaultwarden auth (email + master password + API key for headless).
Authentik handles human SSO; Vaultwarden uses its own auth. Broker authenticates headless via
`BW_CLIENTID`/`BW_CLIENTSECRET` (API key, no interactive login required).

## D2 — Sources & export methods  **[DECIDED 2026-09-09]**
**Decision:** Apple Keychain via macOS Passwords app CSV export; Chrome via `chrome://password-manager` CSV.
Two importers built: `importers/keychain.py`, `importers/chrome.py`.

## D3 — Single-user vault  **[DECIDED 2026-09-09, revised by D5]**
**Decision:** Single personal vault; per-source folders for import layout.
**Revised by D5:** personal creds stay in personal account; agent-accessible creds go in a dedicated
agent Vaultwarden account (separate login, separate vault).

## D4 — Recovery model  **[DECIDED 2026-09-09]**
**Decision:** Encrypted export primary (Phase 3 `cvc-backup`) + Vaultwarden Emergency Access secondary.

**CORRECTION [2026-10-31]:** the export was originally `bw export --format encrypted_json`
*without* `--password`, which encrypts with the **account** key, not "the master password":
rotating the account key or losing the account makes every such backup unreadable. It also
omitted `--organizationid`, so only the personal vault (1 of 587 items) was exported.
`cvc-backup` now writes one **password-protected** export per scope
(`vault-backup-<ts>-personal.json`, `vault-backup-<ts>-org-<id>.json`) using the passphrase in
`BACKUP_EXPORT_PASSWORD` (required; no account-restricted fallback), and fails if the
per-scope item counts do not sum to `bw list items`. Restore needs only file + passphrase;
keep the passphrase outside the vault.

## D5 — Agent-access scope & isolation  **[DECIDED 2026-09-09]**  ✅
**Decision:** Option (b) variant — dedicated **Vaultwarden user account** for the broker (not a separate
instance, but a separate login with its own vault). Personal vault is unreachable from the broker.
**Rationale (Opus security review 2026-09-09):** Option (a) (single collection) rejected because a
compromised broker holds `BW_SESSION` and can call `bw` directly, bypassing ACL entirely — blast
radius would be the entire personal vault. A separate account limits blast radius to only the
credentials explicitly provisioned in the agent account.
**Manual step required:** create the agent Vaultwarden account and provision its API keys into k8s
secret `cvc-broker-vault` before deploying the broker. See broker-deployment.yaml prerequisites.

## D6 — Where services run  **[DECIDED 2026-09-09]**
**Decision:** k3s on OPi 6 Plus (`100.106.97.34`). Broker as k3s Deployment with `hostPort: 8710`
bound to Tailscale IP only. nerdctl Compose rejected (CNI flakiness on routable bridges).
Caddy rejected from broker path — see D8.

## D7 — Reminder policy  **[DECIDED 2026-09-09]**
**Decision:** `ROTATION_MAX_AGE_DAYS=180`, `HIBP_ENABLED=true`.

## D9 — Off-host backup destination  **[DECIDED 2026-09-13]**
**Decision:** Write encrypted vault exports locally to `/mnt/data/cvc-backups/`, copy them to
`/mnt/data/onedrive/dan_ai_tool_dock/cvc-backups/` on the OPi NVMe, then trigger `onedrive --sync` (abraunegg client, already installed at
`/usr/local/bin/onedrive`) to push to cloud OneDrive.

**CORRECTION [2026-09-13, implementation]:** this decision was originally written against the
flags `--synchronize` and `--config-dir`. Neither exists in the installed client (abraunegg
**v2.5.11**): `--synchronize` was removed in favour of `--sync`, and the config-dir flag has
always been `--confdir`. Both wrong spellings exit non-zero with `Unrecognized option`. Since
sync failures were non-fatal at the time, that would have degraded silently to "the off-host backup
never happens" — the exact outcome this decision exists to prevent. The implementation and
the commands below use the real flags.

**Why this path:**
- `onedrive` client is already installed, configured, and has a valid refresh token at
  `/home/admin/.config/onedrive/`. Sync dir is `/mnt/data/onedrive/`. No new OAuth setup required.
- `dan_ai_tool_dock/` is the established namespace for AI-adjacent tool data on this OneDrive.
- The export files are password-protected (`bw export --format encrypted_json --password`,
  passphrase from `BACKUP_EXPORT_PASSWORD`; see D4 correction), so cloud storage of the raw
  files is safe.

**CORRECTION [2026-10-31, F8]:** the unit had BACKUP_DIR equal to the staging dir, so the copy
raised SameFileError and the sync was skipped — nothing ever left the host, while the job
exited 0. Now the copy is skipped for same-file sources but the sync always runs, the unit's
BACKUP_DIR is the separate `/mnt/data/cvc-backups`, and a copy/sync failure exits non-zero.
- Alternatives rejected: rclone (would require OAuth setup from scratch); rsync to mesh node
  (off-node but not off-site; Windows/Mac nodes are not always-on storage); leaving data only on
  the PVC (single-disk failure = data loss, violates D4 intent). (PVC text is historical: the PVC
  went away with the CronJob, see D10.)

**Mechanism (current, since PR #3 and D10):**
- `backup/__main__.py` calls `export_encrypted()` → writes to the local staging dir
  `/mnt/data/cvc-backups/` (`BACKUP_DIR`, set in `deploy/cvc-backup.service`) → copies the file
  to the OneDrive sync dir `/mnt/data/onedrive/dan_ai_tool_dock/cvc-backups/`
  (`ONEDRIVE_DEST_DIR`) → runs
  `onedrive --sync --single-directory dan_ai_tool_dock/cvc-backups --confdir <ONEDRIVE_CONFIG_DIR>`.
- The local staging copy is the primary (fast, always available); OneDrive is the durable
  off-host copy.
- Copy and sync failures are fatal to the exit code: the error goes to stderr and the job exits
  non-zero (PR #3, F8). Retention pruning still runs on the good local export, and a pruning
  failure alone does not fail the job.
- On-demand trigger: `POST /v1/backup/trigger` on the broker (ACL-gated, purpose `"backup"`).
  Runs the same pipeline as the timer.

**Constraint (current):** `cvc-backup` runs as a host systemd user timer as `admin` (D10), so it
calls the host `onedrive` directly with the host's own `~/.config/onedrive/`; no bind-mounts are
involved.

### Historical: CronJob design (superseded by D10, kept for context)
*The text below describes the original k3s CronJob deployment. It no longer applies.*

The CronJob exported to a PVC (`/backups/`) and ran `onedrive --sync` as a subprocess with
`/home/admin/.config/onedrive/` bind-mounted read-only (refresh token) and the sync-dir mounted
read-write. `uid 1000` (cvc) had to write to `/mnt/data/onedrive/dan_ai_tool_dock/cvc-backups/`
(host `admin` is already uid 1000; `fsGroup: 1000` does NOT apply to hostPath volumes, only to
the PVC, asserted in `deploy/setup-phase23.sh`).

**OPEN GAP [2026-09-13], closed by D10:** the in-pod sync leg did not work: `onedrive` was not in
`cvc:latest` and the host binary could not be bind-mounted (glibc 2.39 host vs 2.36 in
`python:3.11-slim`); mounting the confdir read-only conflicted with the client writing
`items.sqlite3`; and no `onedrive` service ran on the host. With non-fatal failures the sync leg
logged a warning and exited 0. Running on the host as a systemd user timer (option (c) of the
original analysis) removed all of this.

## D10 — remind/backup deployment model  **[DECIDED 2026-09-13]**
**Decision:** Run `cvc-remind` and `cvc-backup` as host systemd user timers on the OPi, not as
k3s CronJobs.

**Rationale:**
- The OneDrive sync gap (D9) closes for free: timers run as `admin`, where `onedrive` is already
  installed, configured, and authenticated. No glibc mismatch, no bind-mount gymnastics.
- MQTT host targeting is trivial: the OPi is on the LAN; `MQTT_HOST=<LAN IP>` works directly,
  no hostAliases or Tailscale DNS workarounds needed.
- Single-node k3s provides no scheduling benefit for these jobs. CronJob retry/history machinery
  is pure overhead; `journalctl --user -u cvc-remind` is simpler than `kubectl -n cvc get jobs`.
- Source changes take effect via `pip install -e .` without a full image rebuild + k3s import cycle.
- Backup pipeline has no PVC: export to the local staging dir `/mnt/data/cvc-backups`
  (`BACKUP_DIR`), copy to the OneDrive sync dir, run `onedrive --sync` (see D9).

**What's given up:**
- CPU/memory limits enforced by the kernel (mitigate with `CPUQuota=` and `MemoryMax=` in the
  unit file — see deploy/remind.service, deploy/backup.service).
- Unified `kubectl -n cvc get all` view — broker stays in k3s; jobs are in journald.
- If remind/backup ever need to move to another node, systemd timers are host-tied (k3s manifests
  would be node-portable). On a single always-on node this portability is not needed today.

**Broker (Phase 4) stays in k3s:** it earns the overhead — hostPort isolation, PVC audit log,
Recreate strategy for the port mutex, resource limits on the bw subprocess.

**deploy/remind-cronjob.yaml and deploy/backup-cronjob.yaml are kept** as historical reference
and fallback but are not applied; the k3s CronJobs are superseded by the systemd user timers
(`deploy/cvc-remind.*`, `deploy/cvc-backup.*`).

## D11 — Hardware recovery keys  **[RESOLVED 2026-10-31]** (decided 2026-09-13)
**Decision:** YubiKeys will serve as hardware recovery keys for the vault.

**Context:** D4 established encrypted export (primary) + Vaultwarden Emergency Access (secondary)
as the recovery model. YubiKeys add a third, hardware-bound layer.

**Role:** A YubiKey stores a static credential (HMAC-SHA1 challenge-response or a FIDO2
passkey) that can unlock the vault master password or serve as a second factor for Vaultwarden
login. In a break-glass scenario where the OPi is unreachable and Emergency Access is unavailable,
the YubiKey provides offline, hardware-bound access to the master password.

**Resolution (2026-10-31):**
- **Mode:** FIDO2 is used for Vaultwarden 2FA, with 2 keys registered: primary on-person, backup
  in the home safe.
- **Master password:** NOT stored on the key. Static-password slots can be read by anything that
  can type. The master password, `BACKUP_EXPORT_PASSWORD` and the Vaultwarden recovery code are
  kept on paper in the safe, plus one offsite copy.
- **Emergency Access:** unchanged.
- **PIV:** slot 9a holds the per-device cert key (see D13).
- **Test restore:** `bw import` of the password-protected export (PR #3) with the passphrase.
- **Procedures:** `deploy/yubikey/RUNBOOK-yubikey.md` (PR #11). The registry's `hardware_keys`
  section tracks keys, and `cvc-access check` warns when fewer than 2 active keys carry the `recovery` use.

**Effect on cvc-backup:** the encrypted export (D9) is already encrypted with the vault master
password. YubiKey integration does not change the export format — it changes how the master
password itself is protected and recovered. The mode is chosen (see Resolution); the YubiKey
procedures live in `deploy/yubikey/RUNBOOK-yubikey.md`.

## D8 — mTLS / Caddy in broker path  **[DECIDED 2026-09-12]**
**Considered:** Using short-lived client certificates (mTLS) so bearer tokens are only exchanged at
a `/auth` endpoint to mint a cert; subsequent `/v1/fetch` calls use the cert, not the token.
This would allow Caddy in TCP-passthrough mode (Caddy never sees application-layer headers, so
bearer tokens can't appear in logs).
**Decision:** Skip. Tailscale ACL already provides mutual network-layer authentication between
nodes (both sides hold Tailscale-issued certs; ACL restricts port 8710 to worker IPs
`100.73.65.49` and `100.127.180.96` only). Adding a custom CA and cert lifecycle management is
engineering overhead with marginal security gain in a single-user home setup on a Tailnet.
Current posture: direct hostPort binding to Tailscale IP + bearer token auth. No Caddy in path.

## D12 — Access registry: roles for agents and machines  **[DECIDED 2026-10-31]**
**Problem:** grants were scattered (broker ACL per agent, MQTT users by hand, worker access
undocumented), so "who may access what" had no single answer.
**Decision:** `access/registry.yaml` (gitignored; `access/registry.example.yaml` committed) is
the source of truth: systems, roles (lists of grants), AI agents and machines. `cvc-access`
validates it and generates artifacts. `deploy/broker-acl.yaml` becomes generated output
(`cvc-access build broker-acl`); `import-acl` bootstraps a registry from the current ACL.
- v1 enforces kinds `credential-store` (broker) and `mqtt`. `http`, `cluster`, `ssh` and
  `service` are valid in the schema and in the model, but documented only; `check` flags their grants as "unenforced".
- Sensors get per-device MQTT identities (one user each, topics scoped via `{id}`).
- No secrets in the registry: only `token_sha256`. Machine passwords stay in Vaultwarden.
- Expired agents generate `allow: []`. Generators register through `@register_builder`, so the
  Mosquitto ACL and Mermaid graph arrive as new modules without changing the CLI dispatch.

**Tier model (decided 2026-10-31, not yet implemented):**
- Human tiers, lowest to highest: guest-short < guest-long < media-only < low < medium < high <
  admin < owner.
- Agent tiers: scoped < low < medium < high < assistant.
- Authentication: guest through medium = Tailscale + device cert; high = passkey for sensitive
  actions; admin = passkey always; owner = YubiKey only.
- Guest Home Assistant access is configurable per guest: `none` | `view` | `limited-control`.
- The grantor must be at least 2 tiers above the tier being granted.
- Separate tailnets (owner, family, long-guests, short-guests, agents, machines) are network
  walls only; authorization lives in certs and tokens, not in tailnet membership.
- The tier rides in the cert URI SAN `urn:cvc:tier:<tier>`, enforced by Traefik and a tier-gate
  forwardAuth (opusvar/opi_base_config#3).

## D13 — Per-device certificates from a home CA (supersedes D8 for human devices)  **[DECIDED 2026-10-31]**
**Problem:** human devices (phone, laptops, desktop) reached home services with shared or
bearer credentials. Losing a device meant rotating everything, and the registry had no record of
which device held which credential.
**Decision:** every human device gets its own client certificate from a home CA (Smallstep
step-ca, `deploy/step-ca`). All the certs sit under one human identity (`people.nathan`).
- Phones get a `.p12`. Mac and Windows certs live on YubiKeys: PIV slot 9a, key generated on
  the key, with attestation. YubiKeys are also the Vaultwarden FIDO2 2FA and recovery keys (D11).
- The registry gains `people`, `hardware_keys` and `devices`. Devices are principals and hold
  roles. Only public metadata is stored (serials, fingerprints, dates). Keys named `p12`, `pin`,
  `puk`, `management_key` and `private_key` are rejected.
- Lifecycle runs through `cvc-access hwkey enroll|revoke` and `cvc-access device
  add|set-cert|transfer|revoke`. Each device keeps an append-only `history`. Revoking (losing) a
  YubiKey revokes every cert stored on it. Issuance itself is done by step-ca.
- `check` warns about certs expiring within 30 days, devices with no cert, fewer than 2 recovery keys
  and all active keys in one location.
- **D8 still stands for agent→broker auth** (bearer token over Tailscale). D13 covers human
  devices only.
