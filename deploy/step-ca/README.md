# step-ca — home certificate authority (SCAFFOLD, not applied)

## Architecture

```
 offline root (encrypted USB / YubiKey)  --signs once-->  intermediate (RSA-3072)
                                                               |
                         /mnt/data/pki (hostPath, mode 700) ---+--> step-ca pod (ns pki)
                                                                    hostPort 9000 on 100.106.97.34 only
 Provisioners:
   authentik      OIDC  -> human sign-in via Authentik (k3s ns auth); used by issue-p12.sh
   yubikey-attest ACME device-attest-01, format "step" -> Mac/Windows, YubiKey PIV 9a key generated on-key
   apple-attest   ACME device-attest-01, format "apple" -> managed Apple devices (needs MDM; optional)
   ios-scep       SCEP  -> iOS profiles that enroll on-device (key never leaves phone)
 Lifetimes: default = max = 90d (2160h), renewal allowed, no renewal after expiry.
 Revocation: passive + CRL at /1.0/crl. No OCSP (commercial only).
```

- Phones: `issue-p12.sh <device-id>` (OIDC sign-in -> cert -> `.p12` -> `.mobileconfig`).
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

## Apply (manual, by Nathan)

1. Register port **9000/tcp (step-ca, Tailscale only)** in `opi_base_config/containers/PORT-REGISTRY.md`.
2. Run `init.sh` on an offline machine; move root key offline (see below); copy cert/intermediate files as it prints.
3. In Authentik: create OAuth2 provider + app `step-ca`, public-ish client, redirect `http://127.0.0.1:10000`; replace `AUTHENTIK_HOST` in `ca.json.tmpl`.
4. Create secret + configmap (commands in `deployment.yaml` header), then
   `kubectl apply -f deploy/step-ca/namespace.yaml -f deploy/step-ca/pv.yaml -f deploy/step-ca/deployment.yaml`.
5. `step ca bootstrap --ca-url https://100.106.97.34:9000 --fingerprint <root fp>`; `curl --cacert root_ca.crt https://100.106.97.34:9000/health`.
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
