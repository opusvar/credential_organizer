# Recovery runbook (draft — rehearse a restore, then remove this label)

Vaultwarden is end-to-end encrypted: **a forgotten master password cannot be recovered by the
server admin.** Recovery depends entirely on material prepared in advance (decision D4). This
runbook must be written AND rehearsed before it's relied on.

## Prepared recovery material (choose per D4)
- [ ] **Emergency Access** — trusted contact granted time-delayed takeover in Vaultwarden.
- [ ] **Password-protected export** — `cvc-backup` runs `bw export --format encrypted_json --password`
      with `BACKUP_EXPORT_PASSWORD` (not the account key, not the master password), one file per
      scope (`vault-backup-<ts>-personal.json`, `...-org-<id>.json`), kept in `/mnt/data/cvc-backups`
      and synced to OneDrive. Restore needs only the file + that passphrase; keep the passphrase
      outside the vault.
- [ ] **Break-glass secret** — master password (+ 2FA recovery code) sealed in a safe, or split via
      Shamir across N holders.

## Scenario: forgotten master password
1. TODO(D4): if Emergency Access is configured, initiate takeover from the trusted contact and wait
   out the delay window.
2. TODO(D4): else restore the latest password-protected export (all scopes) into a fresh vault using
   `BACKUP_EXPORT_PASSWORD` as the file passphrase. No restore has been rehearsed yet (TODO).
3. TODO(D4): else assemble the break-glass secret from the safe / Shamir shares.
4. Rotate everything afterward — the old master and any exposed material are now suspect.

## Scenario: vault data loss (DB/hostPath)
- Restore from the OPi backup job (see OPi ENH-001) — Postgres/Authentik + Vaultwarden data dir.

## Test schedule
- [ ] Dry-run each configured recovery path at least once, and after any change to the vault or
      backup pipeline. Record the date of the last successful test here.
