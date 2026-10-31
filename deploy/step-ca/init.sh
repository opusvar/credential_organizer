#!/usr/bin/env bash
# One-time OFFLINE creation of the home root CA + intermediate.
# Run on an air-gapped or at least offline machine with `step` CLI installed.
# Passwords are always prompted (never hard-coded, never on argv).
#
# Output (in $OUT, default ./pki-init):
#   root_ca.crt            -> public; distribute to clients
#   root_ca_key            -> MOVE OFFLINE (encrypted USB / YubiKey) then shred here
#   intermediate_ca.crt    -> copy to /mnt/data/pki/certs/
#   intermediate_ca_key    -> copy to /mnt/data/pki/secrets/ (encrypted with its password)
#
# The intermediate is RSA-3072 because step-ca's SCEP provisioner requires an
# RSA decrypter (docs: step-ca/provisioners#scep). The root is ECDSA P-384.
set -euo pipefail
umask 077

OUT="${OUT:-./pki-init}"
NAME="${CA_NAME:-Smuckler Home}"
mkdir -p "$OUT"
cd "$OUT"

if [[ -e root_ca_key ]]; then
  echo "refusing: $OUT/root_ca_key already exists" >&2; exit 1
fi

echo "== Root CA ($NAME Root CA, 10y). You will be prompted for the ROOT key password."
step certificate create "$NAME Root CA" root_ca.crt root_ca_key \
  --profile root-ca --kty EC --curve P-384 --not-after 87600h

echo "== Intermediate CA (5y, RSA-3072). Prompts: root password, then NEW intermediate password."
step certificate create "$NAME Intermediate CA" intermediate_ca.crt intermediate_ca_key \
  --profile intermediate-ca --kty RSA --size 3072 --not-after 43800h \
  --ca root_ca.crt --ca-key root_ca_key

step certificate inspect root_ca.crt --short
step certificate inspect intermediate_ca.crt --short
echo "Root fingerprint (pin this in clients / record it):"
step certificate fingerprint root_ca.crt

cat <<EOF

NEXT (manual):
  1. Copy root_ca_key to TWO encrypted offline media (LUKS USB / YubiKey
     slot via 'step kms' or ykman). Verify both copies, then:
       shred -u $OUT/root_ca_key
  2. On the OPi:
       sudo install -d -m 700 -o 1000 -g 1000 /mnt/data/pki/{certs,secrets,db,config}
       sudo install -m 644 -o 1000 root_ca.crt intermediate_ca.crt /mnt/data/pki/certs/
       sudo install -m 600 -o 1000 intermediate_ca_key /mnt/data/pki/secrets/
  3. Put the intermediate password into the k8s secret 'step-ca-secrets' (key 'password').
EOF
