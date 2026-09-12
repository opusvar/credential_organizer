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
