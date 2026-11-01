# step-ca — home certificate authority (SCAFFOLD, not applied)

## Architecture

```
 offline root (encrypted USB / YubiKey)  --signs once-->  intermediate (RSA-3072)
                                                               |
                         /mnt/data/pki (hostPath, mode 700) ---+--> step-ca pod (ns pki)
                                                                    hostPort 9000 on <node_ip> only
 Provisioners:
   authentik      OIDC  -> human sign-in via Authentik (k3s ns auth); used by issue-p12.sh
   yubikey-attest ACME device-attest-01, format "step" -> Mac/Windows, YubiKey PIV 9a key generated on-key
   apple-attest   ACME device-attest-01, format "apple" -> managed Apple devices (needs MDM; optional)
   ios-scep       SCEP  -> iOS profiles that enroll on-device (key never leaves phone)
 Lifetimes: per tier, see Tier issuance. Tier-bearing certs are not renewable (re-issue by an admin).
 Revocation: passive + CRL at /1.0/crl. No OCSP (commercial only).
```

- Phones: admin runs `issue-p12.sh --person P --device D --tier T` (see Tier issuance; `.p12` -> `.mobileconfig`).
  Preferable long term: a `.mobileconfig` with a `com.apple.security.scep` payload
  pointing at `/scep/ios-scep`, so the key is generated on the phone.
- Mac/Windows: generate a key in PIV slot 9a on the YubiKey, then e.g.
  `step ca certificate <device-id> --kms 'yubikey:' --attestation-uri 'yubikey:slot-id=9a' --provisioner yubikey-attest`
  (exact flags: assumed, verify against `step ca certificate --help` for the installed version).
  step-ca verifies the Yubico attestation chain before issuing.
- Secrets: the OIDC client secret and SCEP challenge live only in k8s secret
  `pki/step-ca-secrets`; an initContainer renders `ca.json.tmpl` -> `ca.json` on the PV.

## Docs check (smallstep.com/docs, read 2026-10-31)

| Feature | Status |
|---|---|
| ACME `device-attest-01` with `attestationFormats` `apple`/`step`/`tpm` | Confirmed. Disabled by default; must be listed in `challenges` (inferred from "disabled by default"). |
| `step` format covers YubiKey PIV, trusts Yubico root | Confirmed. Docs warn: restrict the provisioner (anyone with a YubiKey passes attestation). |
| TPM attestation end-to-end | Commercial only — not used. |
| SCEP in open source | Confirmed (static challenge). Requires RSA intermediate. Dynamic SCEP is commercial. |
| OIDC provisioner fields (`clientID`, `clientSecret`, `configurationEndpoint`, `admins`, `domains`, `listenAddress`) | Confirmed. clientSecret from env/file: NOT documented -> render step. Secret is visible on `/provisioners` by design (public client). |
| Claims (`defaultTLSCertDuration`, `maxTLSCertDuration`, `disableRenewal`, `allowRenewalAfterExpiry`) | Confirmed. |
| CRL (`crl.enabled`, `generateOnRevoke`, `cacheDuration`, `idpURL`) | Confirmed, marked experimental. |
| OCSP | Confirmed NOT in open source. |
| `/health` endpoint | Assumed (exists in step-ca source; not found on doc pages read). |
| Image `smallstep/step-ca:0.30.2` with linux/arm64 | Confirmed on Docker Hub (a newer tag may exist). |
| `step certificate p12 ... --ca --legacy` | Confirmed. |
| YubiKey `step ca certificate --kms/--attestation-uri` flags | Assumed. |

## Apply (manual, by the owner)

1. Register port **9000/tcp (step-ca, Tailscale only)** in `opi_base_config/containers/PORT-REGISTRY.md`.
2. Run `init.sh` on an offline machine; move root key offline (see below); copy cert/intermediate files as it prints.
3. In Authentik: create OAuth2 provider + app `step-ca`, public-ish client, redirect `http://127.0.0.1:10000`; replace `AUTHENTIK_HOST` in `ca.json.tmpl`.
4. Create secret + configmap (commands in `deployment.yaml` header), then
   `kubectl apply -f deploy/step-ca/namespace.yaml -f deploy/step-ca/pv.yaml -f deploy/step-ca/deployment.yaml`.
5. `step ca bootstrap --ca-url <ca_url> --fingerprint <root fp>`; `curl --cacert root_ca.crt <ca_url>/health`.
6. Issue per device; record with `cvc-access device set-cert`.

## Root-CA safety

- Root key is created offline and never touches the OPi. Keep two encrypted copies
  (LUKS USB in a safe + YubiKey or second USB); shred the working copy.
- Root is needed only to re-sign the intermediate (5y) or revoke it.
- If the OPi is compromised: revoke trust by issuing a new intermediate from the root, rotate
  `step-ca-secrets`, re-issue devices. The root stays valid.

## Client trust of the root

- **macOS:** `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root_ca.crt` (or `step certificate install root_ca.crt`).
- **iOS:** install the `.mobileconfig` (contains the root payload), then Settings > General > About > Certificate Trust Settings > enable full trust.
- **Windows:** `certutil -addstore -f Root root_ca.crt` (admin) or `step certificate install root_ca.crt`.

## Rollback

`kubectl delete -f deploy/step-ca/deployment.yaml` (stops issuance; existing certs stay valid until not_after).
Full removal: `kubectl delete ns pki && kubectl delete pv pki-step-ca`. `/mnt/data/pki` is retained (PV `Retain`) — delete it only deliberately. Remove the root from clients to fully untrust.

## Tier issuance (urn:cvc:tier SAN)

Every device cert carries `urn:cvc:person:<id>`, `urn:cvc:device:<id>`, `urn:cvc:tier:<tier>`
as URI SANs, rendered by `templates/device-leaf.tpl` solely from signed token claims
(`.Token.person/device/tier`). The template never reads `.SANs`, `.Insecure.CR` or `.Insecure.User`.

**Mechanism chosen: admin-held JWK "issuer" provisioners.** The JWK private key is stored
encrypted (`ISSUER_JWK_ENCRYPTED`); only admins know the password, so only an admin can mint a
token with `--set tier=...`. A user cannot self-assign a tier because no user-reachable
provisioner can emit one: `authentik` (OIDC), `yubikey-attest`, `apple-attest`, `ios-scep` all use
`templates/no-tier.tpl`, which emits only the subject and no URI SANs, so a CSR carrying
`urn:cvc:tier:owner` is ignored. Relying parties must treat a cert with no tier SAN as no access.

| Tier | Provisioner | Lifetime (default = max) |
|---|---|---|
| guest-short | issuer-guest-short | 48h |
| guest-long | issuer-guest-long | 720h (30d) |
| media-only, low, medium, high | issuer-family | 8760h (365d, phones; Tailscale still required) |
| admin, owner | issuer-admin | 2160h (90d) |

Lifetimes are enforced by per-provisioner `claims` (max), and each provisioner's `templateData.AllowedTiers`
is checked in the template, so a token from `issuer-guest-short` cannot yield `owner`. The global max is 8760h.

Tradeoffs vs alternatives:
- OIDC `templateData` per issuance: templateData is static config in `ca.json` (needs a CA restart per change) and OIDC identity proves the person, not the admin's intent. Rejected.
- "Admin issues on behalf" via OIDC: step-ca has no impersonation; would need a custom service. More code, same trust root.
- JWK token: signed, one-time-ish, short-lived, no extra service. Cost: admin password handling; a stolen password plus the encrypted key lets an attacker mint any tier in its class (rotate `ISSUER_JWK_*`, which also appears in the k8s secret).

## Template/doc verification (smallstep.com/docs/step-ca/templates, read 2026-10-31)

- Confirmed: `uris` and `sans` with `type: uri`; `.Token.<claim>` exposes token claims; `.Insecure.User` and `.Insecure.CR` are unauthenticated; wrap values in `toJson`; `templateFile` + `templateData` under provisioner `options.x509`; templateFile may be an absolute path.
- Assumed (not on pages read): `step ca token --set k=v` placing claims where `.Token.k` reads them; `fail`/`has` available in the template func map (sprig); `JWK` provisioner fields `key`/`encryptedKey` and that `key` is a JSON object (hence the init container substitutes the quoted placeholder); `--not-after` on `step ca token`. Dry-run against a throwaway step-ca before applying.
