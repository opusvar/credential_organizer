#!/usr/bin/env bash
# Enroll a YubiKey on the Mac: harden PIV credentials, generate a slot 9a key, export attestation.
# Usage: enroll-mac.sh <key-id>     (e.g. primary, backup)
# Secrets (PIN/PUK/management key) are only ever typed into ykman's own hidden prompts;
# this script never reads, echoes, logs or stores them.
# NOT YET RUN on real hardware: verify ykman flags against your version (ykman piv --help).
set -euo pipefail

KEY_ID="${1:-}"
[[ -n "$KEY_ID" ]] || { echo "usage: $0 <key-id>" >&2; exit 2; }
[[ "$KEY_ID" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "key-id must match [A-Za-z0-9._-]+" >&2; exit 2; }

command -v ykman >/dev/null 2>&1 || { echo "ykman not found. Install: brew install ykman" >&2; exit 1; }

OUT_DIR="${OUT_DIR:-$HOME/yubikey-enroll/$KEY_ID}"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

confirm() { local a; read -r -p "$1 [y/N] " a; [[ "$a" == "y" || "$a" == "Y" ]]; }

if [[ "$(ykman list --serials | wc -l | tr -d ' ')" != "1" ]]; then
  echo "Attach exactly one YubiKey and retry." >&2
  exit 1
fi

echo "== Device info =="
INFO_TXT="$(ykman info)"
SERIAL="$(ykman list --serials | head -n1)"
MODEL="$(sed -n 's/^Device type:[[:space:]]*//p' <<<"$INFO_TXT" | head -n1)"
FW="$(sed -n 's/^Firmware version:[[:space:]]*//p' <<<"$INFO_TXT" | head -n1)"
# TODO-verify: the "Applications" table layout differs between ykman versions.
APPS_JSON="$(awk '/^Applications/{f=1;next} f && NF && /Enabled/ {print $1}' <<<"$INFO_TXT" \
  | sed 's/.*/"&"/' | paste -sd, -)"
printf '{"serial": %s, "model": "%s", "firmware": "%s", "enabled_apps": [%s]}\n' \
  "${SERIAL:-0}" "${MODEL//\"/}" "${FW//\"/}" "$APPS_JSON" | tee "$OUT_DIR/ykman-info.json"

echo
echo "== PIV credentials =="
echo "Factory defaults: PIN 123456, PUK 12345678, management key 010203040506070801020304050607080102030405060708."
echo "Pick new values and store them in Vaultwarden. ykman prompts (hidden); nothing is saved here."
if confirm "Change PIV PIN now?"; then ykman piv access change-pin; fi
if confirm "Change PIV PUK now?"; then ykman piv access change-puk; fi
if confirm "Change management key now (random key, PIN-protected on the device)?"; then
  # TODO-verify flags: --generate --protect
  ykman piv access change-management-key --generate --protect
fi

echo
echo "== Optional destructive PIV reset (default: NO) =="
echo "This ERASES all PIV keys/certs on the key (FIDO2/OTP unaffected)."
if confirm "Reset the PIV application?"; then
  read -r -p "Type the serial ($SERIAL) to confirm: " typed
  if [[ "$typed" == "$SERIAL" ]]; then ykman piv reset --force; else echo "Serial mismatch; reset skipped."; fi
fi

echo
echo "== Generate key in slot 9a =="
# TODO-verify: the "Slot 9A" text in `ykman piv info` varies by version.
if ykman piv info 2>/dev/null | grep -qi 'slot 9a' && ! confirm "Slot 9a already has content. Overwrite?"; then
  echo "Keeping existing slot 9a; skipping generation."
else
  ykman piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy CACHED 9a "$OUT_DIR/9a-public.pem"
fi

echo
echo "== Export attestation =="
ykman piv keys attest 9a "$OUT_DIR/9a-attestation.pem"
ykman piv certificates export f9 "$OUT_DIR/f9-intermediate.pem"
echo "Wrote public material only to $OUT_DIR"

cat <<MSG

== Next steps ==
1. Browser: Vaultwarden -> Account settings -> Security -> Two-step login -> FIDO2 WebAuthn
   https://orangepi6.humpback-krait.ts.net:8443/vault   (register this key, name it "$KEY_ID")
2. On the OPi, register the key (it also accepts ykman info JSON on stdin):

   cvc-access hwkey enroll --id "$KEY_ID" --serial "$SERIAL" --model "$MODEL" \\
       --uses fido2,piv --location "<on-person|home-safe>"

3. Device cert: see issue-device-cert.sh and deploy/step-ca/README.md.
MSG
