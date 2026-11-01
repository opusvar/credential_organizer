#!/usr/bin/env bash
# setup-personal-account.sh — create the personal Vaultwarden vault account headlessly.
#
# No browser required. Flow:
#   1. Admin invite (creates user record, sets emailVerified=true, no password/keys yet)
#   2. POST /api/accounts/register with KDF hash + encrypted symmetric key (what the browser does)
#      This works even with SIGNUPS_ALLOWED=false because the user is pre-invited.
# SMTP is not configured on this instance, so invite emails are never sent.
#
# Usage:
#   bash deploy/setup-personal-account.sh [email]
#   bash deploy/setup-personal-account.sh alex@local
#
# After this script completes:
#   1. Log in with bw CLI:    bw login <email>
#   2. Get API key:           bw unlock && export BW_SESSION="..." && bw get api-key
#   3. Put API key + password into ~/.config/cvc/remind.env and ~/.config/cvc/backup.env

set -euo pipefail

EMAIL="${1:-alex@local}"

VW_BASE="${SITE_VAULT_URL}"
COOKIE_FILE="$(mktemp /tmp/vw-admin-XXXXXX.cookie)"
cleanup() { rm -f "$COOKIE_FILE"; }
trap cleanup EXIT

ADMIN_TOKEN="$(grep VAULTWARDEN_ADMIN_TOKEN /home/admin/containers/compose/auth/.env \
  | cut -d= -f2- | tr -d '[:space:]')"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; exit 1; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }

echo "Creating personal Vaultwarden account: $EMAIL"
echo

# ── 1. Admin login ────────────────────────────────────────────────────────────
echo "── 1. Admin login"
ENCODED_TOKEN=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote('$ADMIN_TOKEN', safe=''))")
HTTP=$(curl -sf -c "$COOKIE_FILE" -X POST "$VW_BASE/admin/" \
  -d "token=$ENCODED_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -o /dev/null -w "%{http_code}" 2>/dev/null) || true
[[ "$HTTP" == "200" ]] || fail "Admin login failed (HTTP $HTTP) — check VAULTWARDEN_ADMIN_TOKEN"
ok "Admin session established"

# ── 2. Check if account already exists ───────────────────────────────────────
echo "── 2. Checking for existing account"
USERS_JSON=$(curl -sf "$VW_BASE/admin/users" -b "$COOKIE_FILE" 2>/dev/null || echo "[]")
EXISTING_ID=$(echo "$USERS_JSON" | python3 -c "
import sys, json
users = json.load(sys.stdin)
for u in users:
    em = u.get('email') or u.get('Email') or ''
    if em.lower() == '$EMAIL'.lower():
        print(u.get('id') or u.get('Id',''))
        break
" 2>/dev/null || true)

# Check whether existing account is invited-only (key='') vs fully initialized
if [[ -n "$EXISTING_ID" ]]; then
    EXISTING_KEY=$(echo "$USERS_JSON" | python3 -c "
import sys, json
users = json.load(sys.stdin)
for u in users:
    if (u.get('id') or u.get('Id','')) == '$EXISTING_ID':
        print(u.get('key') or u.get('Key') or '')
        break
" 2>/dev/null || true)

    if [[ -z "$EXISTING_KEY" ]]; then
        warn "Account $EMAIL exists but is uninitialised (invited, no key). Proceeding to register it."
        USER_ID="$EXISTING_ID"
    else
        warn "Account $EMAIL already exists and is fully initialised (id: $EXISTING_ID)"
        warn "Use setup-agent-account.sh to reset it, or choose a different email."
        exit 0
    fi
else
    ok "No existing account — proceeding"

    # ── 3. Invite ───────────────────────────────────────────────────────────────
    echo "── 3. Sending invite (no email sent — SMTP not configured)"
    INVITE_RESP=$(curl -sf -X POST "$VW_BASE/admin/invite" \
      -b "$COOKIE_FILE" \
      -H "Content-Type: application/json" \
      -d "{\"email\": \"$EMAIL\"}" 2>/dev/null) || fail "Invite failed"

    USER_ID=$(echo "$INVITE_RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('id') or d.get('Id',''))
" 2>/dev/null) || fail "Could not parse user id from invite response: $INVITE_RESP"
    [[ -n "$USER_ID" ]] || fail "Empty user id from invite response: $INVITE_RESP"
    ok "Invited $EMAIL (id: $USER_ID)"
fi

# ── 4. Generate master password ───────────────────────────────────────────────
echo "── 4. Generating master password"
MASTER_PASS=$(openssl rand -hex 20)

# ── 5. Compute KDF keys + encrypted symmetric key via Node.js ─────────────────
# Bitwarden crypto spec (PBKDF2 / KDF type 0):
#   master_key   = PBKDF2-SHA256(password, email, 600000, 32)
#   mph          = PBKDF2-SHA256(master_key, password, 1, 32) → base64  (sent to server)
#   enc_key      = HKDF-Expand(master_key, "enc", 32)          (stretches master key)
#   mac_key      = HKDF-Expand(master_key, "mac", 32)
#   sym_key      = random 64 bytes (vault symmetric key)
#   vault_key    = EncType2: AES-256-CBC(enc_key, IV, sym_key) + HMAC-SHA256(mac_key, IV+ct)
#                  format: "2.<iv_b64>|<ct_b64>|<mac_b64>"
# Node.js crypto is stdlib — no npm install needed.
echo "── 5. Computing KDF hash + encrypted vault key (Node.js crypto)"
CRYPTO_OUT=$(node - "$MASTER_PASS" "$EMAIL" <<'JSEOF'
const crypto = require('crypto');
const password = process.argv[2];
const email    = process.argv[3].toLowerCase();

const masterKey = crypto.pbkdf2Sync(password, email, 600000, 32, 'sha256');
const mph       = crypto.pbkdf2Sync(masterKey, password, 1, 32, 'sha256').toString('base64');

// Bitwarden Rust SDK uses Hkdf::from_prk — treats masterKey as already-extracted PRK,
// expand only: T(1) = HMAC-SHA256(masterKey, info || 0x01). Do NOT use hkdfSync here;
// that does a full extract-then-expand which produces a different result.
function hkdfExpand(prk, info, len) {
  const h = crypto.createHmac('sha256', prk);
  h.update(Buffer.from(info, 'utf8'));
  h.update(Buffer.from([1]));
  return h.digest().slice(0, len);
}
const encK = hkdfExpand(masterKey, 'enc', 32);
const macK = hkdfExpand(masterKey, 'mac', 32);

// ── Encrypt a buffer with the stretched master key (EncType2) ──────────────
function encryptWithMasterKey(plaintext) {
  const iv  = crypto.randomBytes(16);
  const c   = crypto.createCipheriv('aes-256-cbc', encK, iv);
  const ct  = Buffer.concat([c.update(plaintext), c.final()]);
  const h   = crypto.createHmac('sha256', macK);
  h.update(iv); h.update(ct);
  return `2.${iv.toString('base64')}|${ct.toString('base64')}|${h.digest().toString('base64')}`;
}

// ── Encrypt a buffer with the random symmetric key (EncType2) ────────────
function encryptWithSymKey(plaintext, symEncK, symMacK) {
  const iv  = crypto.randomBytes(16);
  const c   = crypto.createCipheriv('aes-256-cbc', symEncK, iv);
  const ct  = Buffer.concat([c.update(plaintext), c.final()]);
  const h   = crypto.createHmac('sha256', symMacK);
  h.update(iv); h.update(ct);
  return `2.${iv.toString('base64')}|${ct.toString('base64')}|${h.digest().toString('base64')}`;
}

// ── Random 64-byte symmetric vault key ────────────────────────────────────
const symKey   = crypto.randomBytes(64);
const symEncK  = symKey.slice(0, 32);
const symMacK  = symKey.slice(32, 64);
const vaultKey = encryptWithMasterKey(symKey);

// ── RSA-2048 key pair (required by bw CLI 2024+) ──────────────────────────
const { publicKey: rsaPub, privateKey: rsaPriv } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding:  { type: 'spki',  format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'der' },
});
const publicKeyB64        = rsaPub.toString('base64');
const encryptedPrivateKey = encryptWithSymKey(rsaPriv, symEncK, symMacK);

process.stdout.write(JSON.stringify({ mph, key: vaultKey, publicKey: publicKeyB64, encryptedPrivateKey }));
JSEOF
) || fail "Crypto key generation failed"

MASTER_HASH=$(echo "$CRYPTO_OUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['mph'])")
VAULT_KEY=$(echo   "$CRYPTO_OUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")
PUBLIC_KEY=$(echo  "$CRYPTO_OUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['publicKey'])")
ENC_PRIV=$(echo    "$CRYPTO_OUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['encryptedPrivateKey'])")
ok "KDF hash + vault key ready"

# ── 6. Get email verification token ───────────────────────────────────────────
# Vaultwarden 1.32+ requires an emailVerificationToken for registration/finish even
# when SIGNUPS_ALLOWED=false. The token is returned DIRECTLY in the response body
# of /identity/accounts/register/send-verification-email — no SMTP needed.
# (The token is a short-lived JWT signed by Vaultwarden's private key.)
echo "── 6. Getting email verification token"
VERIFY_TOKEN=$(curl -sf -X POST "$VW_BASE/identity/accounts/register/send-verification-email" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"name\":\"$EMAIL\"}" 2>/dev/null) \
  || fail "Could not get verification token (is this email already registered?)"
[[ -n "$VERIFY_TOKEN" ]] || fail "Empty verification token"
ok "Verification token obtained (${#VERIFY_TOKEN} chars)"

# ── 7. Register via /identity/accounts/register/finish (Vaultwarden 1.32+) ─────
echo "── 7. Registering account"
REG_PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({
  'email': '$EMAIL',
  'masterPasswordHash': '$MASTER_HASH',
  'masterPasswordHint': '',
  'key': '$VAULT_KEY',
  'keys': {
    'publicKey': '$PUBLIC_KEY',
    'encryptedPrivateKey': '$ENC_PRIV',
  },
  'kdfType': 0,
  'kdfIterations': 600000,
  'emailVerificationToken': '$VERIFY_TOKEN'
}))
")
REG_RESP=$(curl -s -X POST "$VW_BASE/identity/accounts/register/finish" \
  -H "Content-Type: application/json" \
  -d "$REG_PAYLOAD" \
  -w "\n%{http_code}" 2>/dev/null) || fail "Registration request failed"

REG_HTTP=$(echo "$REG_RESP" | tail -1)
REG_BODY=$(echo "$REG_RESP" | head -n -1)
[[ "$REG_HTTP" == "200" ]] || fail "Registration failed (HTTP $REG_HTTP): $REG_BODY"
ok "Account registered — encryption keys initialized"

# ── 8. Verify account is ready ────────────────────────────────────────────────
echo "── 8. Verifying account"
VERIFIED=$(curl -sf "$VW_BASE/admin/users" -b "$COOKIE_FILE" 2>/dev/null \
  | python3 -c "
import sys, json
users = json.load(sys.stdin)
for u in users:
    if (u.get('id') or u.get('Id','')) == '$USER_ID':
        ev = u.get('emailVerified') or u.get('EmailVerified')
        print(str(ev))
        break
" 2>/dev/null || echo "unknown")
# Vaultwarden marks email verified after admin password set
[[ "$VERIFIED" == "True" ]] && ok "Email verified" || warn "Email verification status: $VERIFIED (may still work)"

# ── 8. Output ─────────────────────────────────────────────────────────────────
echo
echo "  ╔══════════════════════════════════════════════════════════════════╗"
echo "  ║  PERSONAL VAULT ACCOUNT — SAVE THESE CREDENTIALS               ║"
echo "  ║                                                                 ║"
printf "  ║  Email:    %-51s ║\n" "$EMAIL"
printf "  ║  Password: %-51s ║\n" "$MASTER_PASS"
echo "  ║                                                                 ║"
echo "  ║  40-char hex — no special characters, terminal-safe            ║"
echo "  ╚══════════════════════════════════════════════════════════════════╝"
echo

echo "── Next steps ───────────────────────────────────────────────────────────"
echo
echo "  1. Log in with the bw CLI:"
echo "       bw config server $VW_BASE"
echo "       bw login $EMAIL"
echo "       (paste the password above)"
echo
echo "  2. Unlock and get your API key:"
echo "       bw unlock"
echo "       export BW_SESSION=\"<key from unlock output>\""
echo "       bw get api-key --nointeraction"
echo
echo "  3. Add to ~/.config/cvc/remind.env and ~/.config/cvc/backup.env:"
echo "       BW_SERVER=$VW_BASE"
echo "       BW_CLIENTID=<client_id from step 2>"
echo "       BW_CLIENTSECRET=<client_secret from step 2>"
echo "       BW_PASSWORD=$MASTER_PASS"
echo
echo "  4. Import your credentials:"
echo "       cvc-import --source chrome  --file ~/chrome-passwords.csv"
echo "       cvc-import --source keychain --file ~/keychain-passwords.csv"
echo
