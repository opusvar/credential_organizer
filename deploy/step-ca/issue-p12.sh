# issue-p12.sh --person <id> --device <id> --tier <tier>
# ADMIN-RUN ONLY. Issues a device cert via an issuer-* JWK provisioner; the
# person/device/tier URI SANs come from the signed token (--set), not the CSR.
# The JWK password (prompted by `step ca token`) is held only by admins.
# Bundles .p12 + iOS .mobileconfig and prints the `cvc-access device set-cert` command.
set -euo pipefail
umask 077

usage() { echo "usage: issue-p12.sh --person <id> --device <id> --tier <tier>" >&2; exit 2; }
PERSON=""; DEV=""; TIER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --person) PERSON="${2:?}"; shift 2 ;;
    --device) DEV="${2:?}"; shift 2 ;;
    --tier) TIER="${2:?}"; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$PERSON" && -n "$DEV" && -n "$TIER" ]] || usage
[[ "$PERSON" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "bad person id" >&2; exit 2; }
[[ "$DEV" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "bad device id" >&2; exit 2; }

# tier -> provisioner + lifetime (keep in sync with ca.json.tmpl; tests check it)
case "$TIER" in
  guest-short) PROV=issuer-guest-short; DUR=48h ;;
  guest-long) PROV=issuer-guest-long; DUR=720h ;;
  media-only|low|medium|high) PROV=issuer-family; DUR=8760h ;;
  admin|owner) PROV=issuer-admin; DUR=2160h ;;
  *) echo "unknown tier: $TIER" >&2; exit 2 ;;
esac

CA_URL="${CA_URL:-https://100.106.97.34:9000}"
ROOT="${ROOT:-$HOME/.step/certs/root_ca.crt}"
OUT="${OUT:-./out/$DEV}"
mkdir -p "$OUT"

# 1. Admin token carrying the identity claims, then the cert.
#    NOTE: `step ca token --set` is assumed (not on the docs pages read); verify with `step ca token --help`.
TOKEN=$(step ca token "$DEV" --provisioner "$PROV" --ca-url "$CA_URL" --root "$ROOT" \
  --set "person=$PERSON" --set "device=$DEV" --set "tier=$TIER" --not-after "$DUR")
step ca certificate "$DEV" "$OUT/$DEV.crt" "$OUT/$DEV.key" \
  --token "$TOKEN" --ca-url "$CA_URL" --root "$ROOT" --not-after "$DUR"

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

NA_DATE="${NOT_AFTER%%T*}"
echo "person:    $PERSON"
echo "device:    $DEV"
echo "tier:      $TIER"
step certificate inspect "$OUT/$DEV.crt" --format text | grep -A6 "Subject Alternative Name" || true
echo "serial:    $SERIAL"
echo "sha256:    $FPR"
echo "not_after: $NOT_AFTER"
echo "files:     $OUT/$DEV.p12 $OUT/$DEV.mobileconfig (AirDrop/email the .mobileconfig, then delete)"
echo "record:    cvc-access device set-cert $DEV --serial $SERIAL --fingerprint $FPR --not-after $NA_DATE"
