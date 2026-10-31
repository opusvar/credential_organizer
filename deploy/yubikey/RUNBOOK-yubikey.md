# YubiKey Runbook

Scripts here were written without hardware and have NOT been run. Items marked (uncertain) need checking.

## 1. Enrollment (2 keys)

Primary lives on your person; backup lives in the home safe. Enroll both before relying on either.

1. On the Mac: `brew install ykman`, attach ONE key, run `./enroll-mac.sh primary`. Repeat with the other key: `./enroll-mac.sh backup`.
2. Change PIV PIN, PUK and management key when prompted; store them in Vaultwarden.
3. In Vaultwarden (https://orangepi6.humpback-krait.ts.net:8443/vault): Account settings > Security > Two-step login > FIDO2 WebAuthn. Register BOTH keys.
4. Run the printed `cvc-access hwkey enroll ...` on the OPi for each key (location: `on-person` / `home-safe`).
5. Get device certs with `issue-device-cert.sh <key-id>` (placeholder; see deploy/step-ca/README.md).
6. Put the backup key in the safe. Test that each key alone can log in to Vaultwarden.

## 2. Lost or stolen key

1. Vaultwarden: remove that key's FIDO2 credential (log in with the other key).
2. OPi: `cvc-access hwkey revoke --id <key-id>` (exact flags: check CLI help).
3. step-ca: revoke the key's device certs (see deploy/step-ca/README.md; revocation method uncertain, step-ca passive revocation vs short-lived certs).
4. Enroll a replacement with `enroll-mac.sh <new-id>` and repeat the registration steps.
5. If the lost key had a known PIN, rotate anything its certs unlocked.

## 3. Recovery (resolves D11)

Recommendation:

- Use FIDO2 for Vaultwarden 2FA (two registered keys).
- Do NOT store the master password on the key (OTP static-password slot). Anything that can type or read the slot gets it, and the key is a second factor, not a vault.
- Keep the master password and BACKUP_EXPORT_PASSWORD on paper in the home safe, plus a copy offsite.
- Vaultwarden Emergency Access stays as configured.
- Losing both keys is recoverable via the paper master password plus the Vaultwarden recovery code (store that on paper too; save it when 2FA is enabled).

### Test-restore checklist (do after setup, then yearly)

- [ ] Locate the latest password-protected export from the backup job (PR #3).
- [ ] On a scratch machine, `bw import bitwardenjson <file>` (format/option name: uncertain, check `bw import --help`) and enter BACKUP_EXPORT_PASSWORD as the passphrase.
- [ ] Spot-check several items, including one with TOTP.
- [ ] Log in with the backup key alone; confirm FIDO2 works.
- [ ] Confirm the paper copies match the current passwords.
- [ ] Delete the scratch vault/import afterwards.
