# Phase 0 decisions (ADR-lite)

These block real implementation. Each has a status: **OPEN** (needs Nathan) / DECIDED / DEFERRED.
Record the decision + date inline as they resolve.

## D1 — Authentik ↔ Vaultwarden relationship  **[OPEN]**
Vaultwarden (OSS) has no native SSO. Options:
- **(a)** Standalone Vaultwarden auth (email + master password + 2FA); Authentik unrelated.
- **(b)** Front Vaultwarden with Authentik via a forward-auth / OIDC proxy (extra layer; Vaultwarden
  still has its own vault unlock underneath).
Impact: shapes user model, the import target, and how the broker authenticates. **Blocks Phase 1.**

## D2 — Sources & export methods  **[OPEN]**
Confirm the exact set and each export path:
- Apple Keychain → macOS Passwords app CSV export, or `security` CLI?
- Chrome → `chrome://password-manager` CSV.
- Others? (1Password / LastPass / Firefox / …)
Impact: which importers to build. Blocks Phase 1 breadth.

## D3 — Single-user vs multi-user  **[OPEN]**
One personal vault, or orgs/collections for multiple people? Impact: import layout, ACL model.

## D4 — Recovery model risk appetite  **[OPEN]**
Vaultwarden is E2E; a forgotten master password = unrecoverable without prearranged recovery.
Choose one or more: Emergency Access (trusted contact, time-delayed) · offline encrypted export ·
Shamir-split break-glass secret in a safe. Impact: Phase 3 design.

## D5 — Agent-access scope & isolation  **[OPEN]**  ⚠ security-critical
Which credentials may EVER be Playwright-accessible? Expect a **tiny allowlist**. Decide isolation:
- **(a)** Separate Vaultwarden **collection/org** for agent creds, or
- **(b)** a **separate Vaultwarden instance** entirely (strongest blast-radius containment).
Impact: the entire Phase 4 broker design. **Opus security review required before build.**

## D6 — Where services run  **[OPEN]**
Broker + reminder service on the OPi k3s cluster, or another host? Impact: deploy/ manifests.

## D7 — Reminder policy  **[OPEN]**
Rotation cadence (`ROTATION_MAX_AGE_DAYS`), and whether HIBP breach checks are enabled. Impact: Phase 2.
