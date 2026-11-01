#!/usr/bin/env bash
# issue-p12.sh <device-id>
# Gets a device cert via the Authentik OIDC provisioner (browser sign-in),
# bundles it as .p12 and wraps it in an iOS .mobileconfig.
# Prints serial / SHA-256 fingerprint / not_after for:
#   cvc-access device set-cert <device-id> --serial ... --sha256 ... --not-after ...
set -euo pipefail
umask 077

DEV="${1:?usage: issue-p12.sh <device-id>}"
[[ "$DEV" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "bad device-id" >&2; exit 2; }
CA_URL="${CA_URL:-https://100.106.97.34:9000}"
ROOT="${ROOT:-$HOME/.step/certs/root_ca.crt}"
OUT="${OUT:-./out/$DEV}"
mkdir -p "$OUT"

# 1. Sign in through Authentik and get a 90-day cert.
step ca certificate "$DEV" "$OUT/$DEV.crt" "$OUT/$DEV.key" \
  --provisioner authentik --ca-url "$CA_URL" --root "$ROOT" --not-after 2160h

# 2. Bundle. Prompts for the export password (iOS asks for it on install).
#    --legacy: iOS/macOS reject modern PBES2 p12 encryption in some versions.
step certificate p12 "$OUT/$DEV.p12" "$OUT/$DEV.crt" "$OUT/$DEV.key" \
  --ca "$ROOT" --legacy
shred -u "$OUT/$DEV.key" 2>/dev/null || rm -f "$OUT/$DEV.key"

# 3. iOS profile: root CA payload + PKCS#12 identity payload.
P12_B64=$(base64 < "$OUT/$DEV.p12" | tr -d '\n')
ROOT_B64=$(step certificate format "$ROOT" --format der | base64 | tr -d '\n')
U1=$(uuidgen); U2=$(uuidgen); U3=$(uuidgen)
cat > "$OUT/$DEV.mobileconfig" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadIdentifier</key><string>home.pki.root.$U1</string>
      <key>PayloadUUID</key><string>$U1</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>Home Root CA</string>
      <key>PayloadContent</key><data>$ROOT_B64</data>
    </dict>
    <dict>
      <key>PayloadType</key><string>com.apple.security.pkcs12</string>
      <key>PayloadIdentifier</key><string>home.pki.device.$U2</string>
      <key>PayloadUUID</key><string>$U2</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>$DEV device certificate</string>
      <key>PayloadCertificateFileName</key><string>$DEV.p12</string>
      <key>PayloadContent</key><data>$P12_B64</data>
    </dict>
  </array>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadIdentifier</key><string>home.pki.$DEV</string>
  <key>PayloadUUID</key><string>$U3</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadDisplayName</key><string>Home PKI: $DEV</string>
</dict>
</plist>
EOF

SERIAL=$(step certificate inspect "$OUT/$DEV.crt" --format json | python3 -c 'import json,sys;print(json.load(sys.stdin)["serial_number"])')
NOT_AFTER=$(step certificate inspect "$OUT/$DEV.crt" --format json | python3 -c 'import json,sys;print(json.load(sys.stdin)["validity"]["end"])')
FPR=$(step certificate fingerprint "$OUT/$DEV.crt")

echo "device:    $DEV"
echo "serial:    $SERIAL"
echo "sha256:    $FPR"
echo "not_after: $NOT_AFTER"
echo "files:     $OUT/$DEV.p12 $OUT/$DEV.mobileconfig (AirDrop/email the .mobileconfig, then delete)"
echo "record:    cvc-access device set-cert $DEV --serial $SERIAL --sha256 $FPR --not-after $NOT_AFTER"
