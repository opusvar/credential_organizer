# Phase 0 decisions (ADR-lite)

These block real implementation. Each has a status: **OPEN** (needs the owner) / DECIDED / DEFERRED.
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
**Decision:** k3s on OPi 6 Plus (`<node_ip>`). Broker as k3s Deployment with `hostPort: 8710`
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
  *(Note 2026-11-01: long-guests and short-guests were merged into one `guests` tailnet. The
  tailnets are now owner, family, guests, agents, machines; see `cvc.tailnet.policy.TAILNETS`.)*
- The tier rides in the cert URI SAN `urn:cvc:tier:<tier>`, enforced by Traefik and a tier-gate
  forwardAuth (opusvar/opi_base_config#3).

## D13 — Per-device certificates from a home CA (supersedes D8 for human devices)  **[DECIDED 2026-10-31]**
**Problem:** human devices (phone, laptops, desktop) reached home services with shared or
bearer credentials. Losing a device meant rotating everything, and the registry had no record of
which device held which credential.
**Decision:** every human device gets its own client certificate from a home CA (Smallstep
step-ca, `deploy/step-ca`). All the certs sit under one human identity (`people.alex`).
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

## D14 — Always at least one active owner hardware key  **[DECIDED 2026-11-01]**
**Problem:** the owner YubiKey is the root of recovery (D11): Vaultwarden FIDO2 2FA, owner-tier
auth (D12) and PIV device certs (D13) all hang off it. A single `hwkey revoke`, `person remove`
or tier change could leave the registry with no usable owner key, i.e. no way back in.
**Decision:** the registry must always hold at least 1 active hardware key owned by an
owner-tier person.
- `cvc-access check` reports an error at zero and a warning at exactly one (D11 wants 2+).
- Every `cvc-access` edit is refused if it would take the count from >=1 to 0: `hwkey revoke`,
  `hwkey suspend`, `hwkey replace`, `person remove`, `person set-tier`, `device lost`, and a
  backstop in `run_edit` for any future command. `--dry-run` is refused too. There is **no
  `--force`**: to drop the last key, first enroll a replacement.
- Allowed instead: `hwkey suspend|resume` (reversible lockout; certs stay recorded),
  `hwkey transfer --to <owner-tier person>` and `hwkey replace OLD --new NEW` (NEW must be active,
  or is enrolled in the same edit; then OLD is retired and its certs revoked). Each writes a
  `history` entry on the key and prints the ykman / Vaultwarden / `step ca revoke` steps. It
  never runs them.
- Hardware key status gains `suspended`. Certs on a suspended key stay valid in the registry.

## D15 — Owner takeover on death or incapacity  **[DECIDED 2026-11-01]**
**Problem:** if an owner dies or is incapacitated, another owner must be able to take over their
vault and cvc account. No single stolen factor should give that power, and a living but absent
owner needs time to object.
**Decision:** `cvc takeover start` runs a six-step wizard. Each step is verified before the next:
1. The initiator's step-ca device cert must chain to the configured root and carry
   `urn:cvc:tier:owner` and `urn:cvc:person:<initiator>`. Its fingerprint must be an active,
   unexpired cert on a device the registry says the initiator owns.
2. The initiator's YubiKey: PIV 9a attestation (signed by the key's f9 intermediate, same
   serial) and an active owner key registered to the initiator.
3. Elevation: an Authentik passkey (OAuth device flow) or the Vaultwarden master password
   (prelogin + password grant). The secret is prompted for, used, and dropped. It is never
   logged or stored.
4. Target: a different active owner-tier person with no open takeover.
5. Possession of the target's factor, one of:
   - **path `key`**: any active owner key registered to the target, primary or backup (D11).
     Completion is allowed from day 90.
   - **path `recovery-password`**: the target's sealed recovery password, set in advance with
     `cvc takeover recovery-set <owner>`, which needs that owner's YubiKey. Only a scrypt hash
     is stored (`recovery.json`, mode 0600). Completion is allowed from day 180.
6. Start: initiate the target's pre-provisioned Vaultwarden Emergency Access grants to the
   initiator: View (15 d) and Takeover (90 d, or 180 d on the recovery path). If they are
   missing or the wait time is wrong, the start is refused. Grants must be set up ahead of time.

Timeline from initiation:
- Day 0: the target sees a banner (`GET /v1/takeover/banner`). Notifications go out on days
  0/7/14/85, plus day 170 on the recovery path. Each one says which path was used.
- Day 15+: read-only View access on both paths. It is reversible, because a cancel rejects the
  grants. View is read-only, so the longer recovery wait protects only the irreversible step.
- Day 90+ (or 180+): `cvc takeover complete`, which needs the initiator's key again. It runs
  Vaultwarden takeover plus a registry edit:
  - the target's keys transfer to the initiator, with history
  - the target's device certs are revoked; `step ca revoke` is printed, never run
  - assistant agents are removed, or rebound with `--rebind-agents`
  - `granted_by` passes to the initiator
  - the person's status becomes `taken-over`
  Then it prints a vault plan: personal items are copied, org items change ownership and are
  not copied. The executor sits behind an interface and is dry-run by default. The D14 guard
  is enforced, and taken-over people no longer count as owners.
- Cancel: only the target, with any of their own active owner keys, until completion.

State lives in `~/.local/state/cvc/takeover/`: `takeovers.json` plus an append-only,
hash-chained `history.jsonl` (`cvc takeover verify-history`).

**D15 addendum: misuse protections and initiator UX** (approved by the owner 2026-11-01):
- **Alerts.** The target is alerted on every channel through `MultiNotifier`
  (`CVC_TAKEOVER_WEBHOOKS`: email relay, push, Home Assistant).
  - Key path: days 0/7/14/85.
  - Recovery path: those days, then every 30 days until completion, plus day 170.
  - On start, every other active owner is notified too.
- **Veto.** The target, or any other active owner, can cancel with their own YubiKey. The
  initiator cannot. `vetoed_by` is recorded, and the history event is `cancelled` (target) or
  `vetoed` (another owner).
- **No counter-takeovers.**
  - Someone who is the target of an active takeover cannot start one.
  - A person can be the target of at most one active takeover; the first one started wins.
- **Voiding.** If the initiator is removed, taken over or demoted below owner, the takeover is
  voided automatically on the next `tick`, `view`, `cancel`, `reconcile` or `complete`. The
  Vaultwarden requests are rejected, and a different owner must restart.
- **Suspended keys.** A suspended target key is accepted at step 5, because suspension is a
  lockout, not a recovery block. Lost or revoked keys are still refused. The record notes
  whether the target's primary key (one holding a device cert) or a backup key was used:
  `factor` is key, backup-key or recovery-password.
- **Reconcile.** The cvc record is the source of truth. `cvc takeover reconcile <id>`
  re-initiates Vaultwarden requests that are missing or were reset, and adopts a re-created
  grant that matches. The original `initiated_at` and deadline are kept. If Vaultwarden's own
  timer restarted, completion is still gated on the cvc deadline, and the Vaultwarden takeover
  call may also wait for Vaultwarden's own timer.
- **Backup.** `~/.local/state/cvc/takeover/` (`takeovers.json`, `history.jsonl`,
  `recovery.json`) **must be included in the identity backup**. That is
  `opi_base_config/scripts/backup-identity.sh`, in another repo; add the path there.
- **Wizard.** Before confirming, the wizard prints:
  - the target's name, factor and path
  - the view and completion days, with real dates
  - who is notified
  - the veto rule
  - what completion does
  The initiator must type the target's display name (`people.<id>.name`, or the id if there is
  no name). The FAQ ships as `cvc/takeover/faq.md`; it is printed at wizard start, by
  `cvc takeover faq`, and at `GET /v1/takeover/faq`.
- **Initiator status.** `GET /v1/takeover/status?initiator=<id>` and
  `cvc takeover status --initiator <id>` return an `icon` (`hourglass`, or `check` when
  eligible) and the text "You are taking over <Target Name>'s account. <N> days left" (or
  "Ready to complete"), plus the FAQ link. Like the banner, the API is unauthenticated and must
  sit behind the tier gate.

**D15 addendum 2: veto warning, key role, estate recovery kit** (2026-11-01):
- **Veto warning.** Vaultwarden only accepts a grant reject from the grantor's (target's)
  account. A veto by another owner therefore still tries the reject, best effort, but it cannot
  close View access. It prints a warning and sends it to the target, the initiator and every
  owner: View access persists until the target rejects the grants (`cvc takeover cancel` with
  their key, or in Vaultwarden). `cvc takeover veto <id>` is an alias of `cancel`.
- **Primary vs backup.** An explicit hardware-key `role: primary|backup` (from the access
  registry, when present) decides `factor` (`key` or `backup-key`). Without it, the rule above
  applies: a key holding one of the target's device certs is the primary. Where there is no
  cert context, the location decides: `on-person` is primary; `home-safe` or `offsite` is a
  backup.
- **Estate recovery kit.** `cvc takeover estate-kit generate --owner <id>` needs that owner's
  YubiKey. It prints a 150-bit code (30 Crockford base32 symbols) once, to be printed on paper
  and kept in a safety deposit box. Only a scrypt hash is stored (`estate_kit.json`, 0600).
  - It is a step-5 alternative (`start --estate-kit`; path and factor `estate-kit`). The
    initiator still passes steps 1-4.
  - It starts the 180-day path, with the recovery-path alert schedule, against any owner
    target.
  - It notifies every owner on every channel (`CVC_TAKEOVER_WEBHOOKS`; the older
    `CVC_TAKEOVER_WEBHOOK` is merged in).
  - It is single use. When the start succeeds, the hash is destroyed and the kit is marked
    used, and a new kit must be generated and printed. A failed attempt does not use it up.
  - It is never auto-replaced, so whoever used it does not get a fresh code.
  - `estate_kit.json` belongs in the identity backup too.
  - **Printable sheet.** `generate` writes a one-page PDF with mode 0600 (`--out`; the default
    is the current dir, and the state dir is refused). With `--terminal` it shows a text QR
    instead. The sheet carries a QR code of `cvc-estate:v1:<code>`, the code in 6 groups of 5,
    and plain-language instructions for whoever opens the box, plus the generated date and the
    kit id. The kit id is a prefix of the scrypt hash, not the code.
  - Everything is made offline: `segno`, from the optional extra `cvc[estate]`, plus a
    built-in minimal PDF writer. If `segno` is missing, the command stops with an install hint
    before any kit is created. After writing the file it prints a reminder to print it and
    then `shred -u` it.
  - `start --estate-kit` accepts the typed code or the scanned URI.

## D16 — Access classification matrix  **[DECIDED 2026-11-01]**
Two axes (data public/internal/private/secret × action read/relay/write/act/delegate), tier ceilings (scoped/low/medium/high/assistant), effective = min(agent, sponsor) ∩ role grants, secret only via broker single-use approved fetch; guest/family are sponsors, not tiers. See [ACCESS-CLASSIFICATION.md](ACCESS-CLASSIFICATION.md).
Sponsored guest and family agents are not separate tiers: they use the agent tier ladder plus a `sponsor` (human) attribute (approved by the owner).

## D17 — Voluntary delegation  **[DECIDED 2026-11-01]**
`cvc delegate start` wizard: strong identity, itemised preview (items above the recipient ceiling are revoked, never escalated), 48h revoke window, then execution via the takeover-completion machinery with the D14 owner-key guard. See [DELEGATION.md](DELEGATION.md).

**ADDENDUM [2026-11-01] — implementation (`src/cvc/delegate/`):** `cvc delegate
start|revoke|decline|status|complete|faq|verify-history` (also `cvc-delegate`). Ceilings use a
person-tier rank (guest/media-only 0, low 1, medium 2, high 3, admin 4, owner 5). Requirements
per item: vault item by data class (public/internal low, private medium, secret owner); org
membership medium (owner/admin role in the org: admin); an owner's hardware key owner;
device low (its cert is always revoked and re-issued); a grant the delegator gave = the
grantee's tier. Agents always transfer, capped at min(agent tier, recipient agent ceiling:
low/medium/high), and expire with a guest recipient. Selecting "roles" drops the delegator to
`low`; it is never raised on the recipient. Above-ceiling hardware keys are set `revoked`,
grants get `expires` = execution date, and vault/org items get a revoke step in the plan. The D14
guard is dry-run at section selection and enforced again at execution. A failure there sets
status `refused`. `complete` needs no extra factor (it was authorised at start and had the
48 h window), but it recomputes the diff. State is in `~/.local/state/cvc/delegate/`, with the
same hash-chained history as takeover.

## D18 — Approvals via MQTT → Home Assistant → dashboard  **[DECIDED 2026-11-01]**
cvc publishes approval requests as retained MQTT messages on `cvc/approvals/<id>` (schema `cvc.approval.v1`), surfaced by Home Assistant on the personal-dashboard Agents page (Approvals section). Timeout always means deny. No secrets in payloads. Decisions go over HTTPS to the broker behind the tier gate (passkey for act/physical), never via MQTT; status updates are re-published. Approver must be ≥ request level; assistant requests go to their person and escalate to the owner. See [APPROVALS.md](APPROVALS.md).

## D19 — Credential rotation  **[DECIDED 2026-11-01]**
Reminders by default. Opt-in auto-rotate only when every consumer in the dependency map has an update hook and a verify check. Flow: dry run → overlap → cut over → retire old after all consumers verify. Failure rolls back and alerts. Auth-chain/permission changes get graph-diff dry runs.

## D20 — Home Assistant proxy  **[DECIDED 2026-11-01]**
A tier-gated proxy filters HA API calls using registry-generated per-tier/per-guest entity allowlists. `view` = read-only; `limited-control` = allowlisted entities only. Locks, garage, cameras and alarm need high + passkey; agents reach them only via broker approval (D18). Only owners hold HA admin.

## D21 — Vault by tier  **[DECIDED 2026-11-01]**
One Household org in Vaultwarden. Collections are labelled with D16 data levels; membership is generated from the registry. Personal vaults stay private (reachable only via takeover D15 / delegation D17). Guests get no VW account (expiring Sends or a Wi-Fi QR page). Agents never get VW accounts.

## D22 — Tailscale accounts  **[DECIDED 2026-11-01]**
The owner tailnet is the owner's. Each other tailnet (family, guests, agents, machines) is owned by a separate admin account whose credentials live in the vault behind YubiKey; each has its own free-plan limits. Family = users; guests = invites with device expiry; agents/machines = tagged devices with auth keys.

## D23 — Lost device self-report  **[DECIDED 2026-11-01]**
A user reports a lost device with their password. Its cert is revoked immediately; passwordless (cert) access is blocked for 7 days while password + passkey still work. Owners/admins are notified; an owner can lift the block early with a YubiKey. Runs the device-lost flow.

## D24 — Audits  **[DECIDED 2026-11-01]**
A read-only admin system process (not an LLM) runs scheduled checks and publishes findings to `cvc/audits/<id>` (schema `cvc.audit.v1`) and `cvc/audits/summary`, shown to owners only on the dashboard. Fixes are owner actions. See [AUDITS.md](AUDITS.md).

## D25 — Google / Microsoft integrations  **[DECIDED 2026-11-01]**
OAuth scopes are registry systems labelled per D16; the broker holds refresh tokens and mints down-scoped short-lived access tokens per agent tier; `cvc integrate google|microsoft` consent wizard. Pending owner decision: personal vs Workspace/M365, and which first (recommend Google). See [INTEGRATIONS.md](INTEGRATIONS.md).

## D26 — Agent gateway ("Clear for agents")  **[DECIDED 2026-11-01]**
Enroll once, fast lane via brokered short-lived scoped tokens, screening still applies, per-task boarding pass, full dual-attribution audit; exposed as MCP server and HTTP credential proxy. See [AGENT-GATEWAY.md](AGENT-GATEWAY.md).

## D27 — Temporary (bridge) devices  **[DECIDED 2026-11-01]**
**Problem:** a person sometimes needs access from a device that is not (yet) theirs: a new or
borrowed phone, a loaner laptop, a replacement for a lost or broken device, travel. D13 only
knows permanent per-device certs, and D23 blocks passwordless access for 7 days after a lost
report, so the person had no path back to cert-based access in that window.
**Decision:** a *bridge*: a short-lived step-ca device cert, managed by `cvc-tempdevice
request|approve|deny|extend|promote|revoke|list|sweep` (`src/cvc/tempdevice/`). See
[TEMP-DEVICE.md](TEMP-DEVICE.md).
- **SANs:** `urn:cvc:person:<p>`, `urn:cvc:device:<p>-temp-<n>`, `urn:cvc:tier:<capped>` and
  the temp flag `urn:cvc:temp:<expires_at>`. `device-leaf.tpl` renders the flag from a `temp`
  claim and refuses a temp cert above medium.
- **Tier cap:** effective tier = min(person tier, medium). tier-gate caps any cert with the temp
  flag *or* a `-temp-<n>` device id at medium, denies an expired/unparseable flag, and passes
  `X-Cvc-Temp` / `X-Cvc-Temp-Expires`. The broker re-applies the cap on `/v1/whoami` and
  `/decide`. High/admin/owner actions never run from a bridge. Owner actions still need the
  physical YubiKey (its own PIV cert + FIDO2), which is the second factor and works when
  plugged in; a bridge can never become an owner key, host a key, or be added as a permanent
  device (`cvc-access device add` refuses `-temp-` ids).
- **Lifetime:** 72 h by default, extendable to 14 days in total; every extension needs a new
  approval. Pending requests/extensions expire (deny) after 24 h.
- **Issuing:** the person proves password + passkey, or a YubiKey. An approver at least 2 tiers
  above the *capped* tier (the D12 grant rule; owners always) approves with a passkey. Requests
  go through the approvals pipeline (card + ntfy) and card decisions are re-checked against
  these rules. Owners/admins may self-issue with a YubiKey. During a D23 lost-device block the
  bridge still works but always needs someone else's approval (no self-issue, no
  self-approval).
- **Limits:** one open (pending or active) bridge per person. Guests never. Agents and machines
  never.
- **Ending:** `cvc-access device set-cert` on a permanent device of the person (the normal
  onboard/enroll flow) promotes it and revokes the bridge; `cvc-tempdevice promote` does the
  same by hand. Bridges auto-expire (`sweep`). The person, an admin or an owner can revoke at any time
  (admins added 2026-11-01: revoking only reduces access; refusals and revokes are audited
  with the actor).
  `cvc-access person remove` revokes all of the person's bridges. step-ca revoke commands are
  printed, never run.
- **Visibility:** `/v1/whoami` returns `temp`, `temp_expires_at`, `temp_hours_left` for the
  dashboard banner "Temporary device: N hours left". The `tempdevice` audit check (D24) flags
  bridges older than 7 days and people with 3+ bridges in 90 days. Every state change and every
  refused approval/revoke goes to a hash-chained audit log.
