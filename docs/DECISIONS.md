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
sync failures are non-fatal here, that would have degraded silently to "the off-host backup
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
  the PVC (single-disk failure = data loss, violates D4 intent).

**Mechanism:**
- `backup/__main__.py` calls `export_encrypted()` → writes to PVC (`/backups/`) → copies the file
  to `/mnt/data/onedrive/dan_ai_tool_dock/cvc-backups/` → runs
  `onedrive --sync --single-directory dan_ai_tool_dock/cvc-backups --confdir <ONEDRIVE_CONFIG_DIR>`.
- The PVC copy is the primary (fast, always available); OneDrive is the durable off-host copy.
- Copy and sync failures are non-fatal: logged, exit 0, so a sync outage doesn't break the
  backup job or leave the PVC export invalid.
- On-demand trigger: `POST /v1/backup/trigger` on the broker (ACL-gated, purpose `"backup"`).
  Runs the same pipeline as the CronJob.

**Constraint:** The `onedrive` service is user-scoped (`systemctl --user`). The k3s pod cannot
call it directly — the CronJob runs `onedrive --sync` as a subprocess with
`/home/admin/.config/onedrive/` bind-mounted read-only (refresh token) and the sync-dir mounted
read-write. `uid 1000` (cvc) must be able to write to `/mnt/data/onedrive/dan_ai_tool_dock/cvc-backups/`
(host `admin` is already uid 1000, so this lines up by default; `fsGroup: 1000` does NOT apply
to hostPath volumes, only to the PVC — asserted in `deploy/setup-phase23.sh`).

**OPEN GAP [2026-09-13]:** the in-pod sync leg does not work yet, and the staging copy is
currently the whole benefit:
1. `onedrive` is **not in `cvc:latest`** (the Dockerfile installs only nodejs/npm + `bw`), and
   the host binary cannot be bind-mounted in: it is dynamically linked against the host's
   glibc 2.39 (Ubuntu 24.04) plus the LDC D runtime, and the image is `python:3.11-slim`
   (Debian bookworm, glibc 2.36).
2. Mounting the confdir read-only conflicts with the client needing to write `items.sqlite3`
   and its hash files there, so shipping the binary is necessary but not sufficient.
3. No `onedrive` service is running on the host (`systemctl --user is-active onedrive` →
   `inactive`), so nothing picks the staged file up automatically today.

Because copy/sync failures are non-fatal, today's behaviour is: export lands on the PVC, a copy
lands on the NVMe staging dir, and the sync leg logs
`WARNING: OneDrive sync failed — onedrive not found at /usr/local/bin/onedrive` and exits 0.
To close it, pick one: (a) add `onedrive` to the image **and** give it a writable confdir
(copy the config in an init container, or mount only `refresh_token` read-only), (b) a host
systemd path-unit/timer that syncs when the staging dir changes, or (c) run `cvc-backup` on
the host rather than in k3s. (b) is the least invasive and keeps the pod's confdir read-only.

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
- Backup pipeline collapses to two steps: export directly to the OneDrive staging dir, run
  `onedrive --sync`. No PVC, no intermediate NVMe copy.

**What's given up:**
- CPU/memory limits enforced by the kernel (mitigate with `CPUQuota=` and `MemoryMax=` in the
  unit file — see deploy/remind.service, deploy/backup.service).
- Unified `kubectl -n cvc get all` view — broker stays in k3s; jobs are in journald.
- If remind/backup ever need to move to another node, systemd timers are host-tied (k3s manifests
  would be node-portable). On a single always-on node this portability is not needed today.

**Broker (Phase 4) stays in k3s:** it earns the overhead — hostPort isolation, PVC audit log,
Recreate strategy for the port mutex, resource limits on the bw subprocess.

**deploy/remind-cronjob.yaml and deploy/backup-cronjob.yaml are kept** as reference and fallback
but are not applied. The active deployment is the systemd units in deploy/.

## D11 — Hardware recovery keys  **[DECIDED 2026-09-13]**
**Decision:** YubiKeys will serve as hardware recovery keys for the vault.

**Context:** D4 established encrypted export (primary) + Vaultwarden Emergency Access (secondary)
as the recovery model. YubiKeys add a third, hardware-bound layer.

**Role:** A YubiKey stores a static credential (HMAC-SHA1 challenge-response or a FIDO2
passkey) that can unlock the vault master password or serve as a second factor for Vaultwarden
login. In a break-glass scenario where the OPi is unreachable and Emergency Access is unavailable,
the YubiKey provides offline, hardware-bound access to the master password.

**Open questions (to resolve before implementation):**
- Which YubiKey mode: HMAC-SHA1 (slot 2, works offline, derives a key from a challenge) vs
  FIDO2/WebAuthn (requires a browser/relying party, online)?
- Where is the master password stored relative to the YubiKey — on the YubiKey itself (static
  password slot 1), derived via HMAC (slot 2 + a stored challenge), or as a FIDO2 passkey for
  Vaultwarden?
- How many YubiKeys and where are they kept (on-person, offsite, safety deposit)?
- Does the backup export (D9) need a separate decryption step, or is the vault master password
  alone sufficient for `bw import --format encrypted_json`?

**Effect on cvc-backup:** the encrypted export (D9) is already encrypted with the vault master
password. YubiKey integration does not change the export format — it changes how the master
password itself is protected and recovered. `docs/RUNBOOK-recovery.md` will need a YubiKey
section once the mode is chosen.

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
