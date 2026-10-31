#!/usr/bin/env bash
# PLACEHOLDER: request a device cert for the slot 9a key from step-ca via ACME device-attest-01.
# Every step command below is TODO-verify against Smallstep docs (device-attest-01, --kms,
# provisioner name). CA URL, root fingerprint and provisioner: see deploy/step-ca/README.md.
set -euo pipefail

KEY_ID="${1:-}"
[[ -n "$KEY_ID" ]] || { echo "usage: $0 <key-id>" >&2; exit 2; }
command -v step >/dev/null 2>&1 || { echo "step not found: brew install step" >&2; exit 1; }

CA_URL="${CA_URL:?set CA_URL (see deploy/step-ca/README.md)}"
FINGERPRINT="${CA_FINGERPRINT:?set CA_FINGERPRINT (root fingerprint)}"
PROVISIONER="${PROVISIONER:-yubikey-attest}"   # TODO-verify against step-ca config
SERIAL="$(ykman list --serials | head -n1)"
OUT="${OUT_DIR:-$HOME/yubikey-enroll/$KEY_ID}"

# TODO-verify: exact flags for ACME device-attest-01 with a YubiKey KMS key.
step ca certificate "$SERIAL" "$OUT/device.crt" \
  --provisioner "$PROVISIONER" \
  --ca-url "$CA_URL" --root-fingerprint "$FINGERPRINT" \
  --kms "yubikey:" \
  --key "yubikey:slot-id=9a" \
  --attestation-uri "yubikey:slot-id=9a" || {
    echo "TODO-verify: step flags may differ; see deploy/step-ca/README.md." >&2
    exit 1
  }
echo "Certificate: $OUT/device.crt"
