#!/usr/bin/env bash
# setup-agent-account.sh — provision or reset the dedicated Vaultwarden agent account
#                           for the cvc credential broker (Fix 5 / D5=B).
#
# Run this script:
#   • FIRST TIME: to create the cvc-agent@local account before deploying the broker
#   • RESET: to recover from a lost master password or corrupt account state
#
# Prerequisites:
#   - Vaultwarden running on the OPi k3s auth stack (sudo kubectl -n auth get pods)
#   - VAULTWARDEN_ADMIN_TOKEN in containers/compose/auth/.env
#   - bw CLI installed: npm install -g @bitwarden/cli  (ARM64: use npm, not the binary)
#
# After this script:
#   1. Open the registration URL it prints in a browser (hostname, not IP — see note below)
#   2. Register with the email + password it prints
#   3. Run: bw login cvc-agent@local  (paste the printed password)
#   4. Run: bw unlock && export BW_SESSION="<key>"
#   5. Run: bw get api-key --nointeraction  → copy client_id + client_secret
#   6. Load into k8s: kubectl -n cvc create secret generic cvc-broker-vault \
#        --from-literal=BW_SERVER=${SITE_VAULT_URL} \
#        --from-literal=BW_CLIENTID=<client_id> \
#        --from-literal=BW_CLIENTSECRET=<client_secret> \
#        --from-literal=BW_PASSWORD=<printed password>
#
# Password design (see docs/DECISIONS.md D5, VAULTWARDEN-API.md):
#   Uses openssl rand -hex 20 (40-char hex, purely [0-9a-f]).
#   base64 contains +/= which terminals and browsers silently mangle → login failures.
#   Hex eliminates that failure class. Min length is 12 chars (enforced since VW ~2023.5.0).
#   Sources: https://github.com/dani-garcia/vaultwarden/discussions/3635
#            https://vaultwarden.discourse.group/t/master-password-length/2587
#
# Registration URL note:
#   MUST use the hostname URL, not the IP. Vaultwarden validates registration against DOMAIN;
#   using the IP causes a silent domain mismatch that breaks the crypto.
#
# D5=B rationale: dedicated account, not a collection. A compromised broker holding BW_SESSION
#   can call bw directly and bypass ACL — if that's the personal vault, full exposure results.
#   A separate account limits blast radius to only what is explicitly provisioned there.

set -euo pipefail

EMAIL="${1:-cvc-agent@local}"

# ── Config (edit if your environment differs) ─────────────────────────────────
VW_DB="/home/admin/data/auth/vaultwarden/db.sqlite3"
ADMIN_TOKEN="$(grep VAULTWARDEN_ADMIN_TOKEN /home/admin/containers/compose/auth/.env \
  | cut -d= -f2- | tr -d '[:space:]')"
VW_BASE="${SITE_VAULT_URL}"
COOKIE_FILE="/tmp/vw-admin.cookie"
KUBECTL="sudo kubectl"

echo "── 1. Scaling down Vaultwarden ──────────────────────────────────────────"
$KUBECTL -n auth scale deployment/vaultwarden --replicas=0
echo -n "Waiting for pod to terminate"
for _ in $(seq 1 30); do
  count=$($KUBECTL -n auth get pods -l app=vaultwarden --no-headers 2>/dev/null | grep -c "Running" || true)
  [[ "$count" -eq 0 ]] && echo " done." && break
  echo -n "."
  sleep 2
done
echo -n "Waiting 30s for SQLite WAL lock to release"
sleep 30
echo " done."

echo "── 2. Deleting user + invitation from DB ────────────────────────────────"
sudo python3 - <<PYEOF
import sqlite3
conn = sqlite3.connect("$VW_DB")
conn.execute("DELETE FROM users WHERE email='$EMAIL'")
conn.execute("DELETE FROM invitations WHERE email='$EMAIL'")
conn.commit()
remaining = conn.execute("SELECT COUNT(*) FROM users WHERE email='$EMAIL'").fetchone()[0]
print(f"  Deleted. Users remaining for $EMAIL: {remaining}")
PYEOF

echo "── 3. Scaling Vaultwarden back up ───────────────────────────────────────"
$KUBECTL -n auth scale deployment/vaultwarden --replicas=1
echo -n "Waiting for pod to be Ready"
for _ in $(seq 1 30); do
  ready=$($KUBECTL -n auth get pods -l app=vaultwarden --no-headers 2>/dev/null | grep -c "1/1" || true)
  [[ "$ready" -eq 1 ]] && echo " done." && break
  echo -n "."
  sleep 3
done

echo "── 4. Refreshing admin session cookie ───────────────────────────────────"
ENCODED_TOKEN=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$ADMIN_TOKEN', safe=''))")
HTTP_CODE=$(curl -s -c "$COOKIE_FILE" -X POST \
  "$VW_BASE/admin/" \
  -d "token=$ENCODED_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -o /dev/null -w "%{http_code}")
echo "  Admin login HTTP $HTTP_CODE"
[[ "$HTTP_CODE" != "200" ]] && echo "ERROR: admin login failed" && exit 1

echo "── 5. Re-inviting $EMAIL ────────────────────────────────────────────────"
curl -s -X POST \
  "$VW_BASE/admin/invite" \
  -b "$COOKIE_FILE" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$EMAIL\"}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(f'  Invited: {d.get(\"email\", \"?\")} (id: {d.get(\"id\", \"?\")})')
except:
    print('  ' + sys.stdin.read())
" 2>/dev/null

echo "── 6. Generating master password ────────────────────────────────────────"
MASTER_PASS=$(openssl rand -hex 20)
echo ""
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║  MASTER PASSWORD — SAVE IN YOUR PERSONAL VAULT NOW      ║"
echo "  ║                                                          ║"
echo "  ║  Email:    $EMAIL"
echo "  ║  Password: $MASTER_PASS"
echo "  ║                                                          ║"
echo "  ║  40-char hex — no special characters                     ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo ""

echo "── 7. Next steps ────────────────────────────────────────────────────────"
echo ""
echo "  a) Open in browser (HOSTNAME URL — not the IP):"
echo "     $VW_BASE/#/register"
echo ""
echo "  b) Enter:"
echo "     Email:    $EMAIL"
echo "     Password: $MASTER_PASS"
echo ""
echo "  c) Once registered, run on the OPi:"
echo "     bw login $EMAIL"
echo "     (paste the password above when prompted)"
echo ""
echo "  d) Get the API key:"
echo "     bw unlock"
echo "     export BW_SESSION=\"<session key from unlock output>\""
echo "     bw get api-key --nointeraction"
echo ""
echo "  e) Load into k8s:"
echo "     sudo kubectl -n cvc create secret generic cvc-broker-vault \\"
echo "       --from-literal=BW_SERVER=$VW_BASE \\"
echo "       --from-literal=BW_CLIENTID=<client_id> \\"
echo "       --from-literal=BW_CLIENTSECRET=<client_secret> \\"
echo "       --from-literal=BW_PASSWORD=$MASTER_PASS"
echo ""
