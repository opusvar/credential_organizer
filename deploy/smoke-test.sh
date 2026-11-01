#!/usr/bin/env bash
# smoke-test.sh — live end-to-end integration test against the running cvc credential broker.
#
# Purpose:
#   Exercises the real broker at $BROKER_URL (default: ${SITE_BROKER_URL}) with a
#   real agent token, and asserts:
#     1. /healthz responds and reports "ok"
#     2. POST /v1/credentials/fetch returns HTTP 200 for a known-good agent/credential/purpose
#     3. the response body's "credential" and "field" match what was requested
#     4. the response body's "value" matches the expected fixture password exactly
#
# Token supply (never hardcode a real token in this file or pass it on the command line):
#   1. export CVC_SMOKE_TOKEN=<token>            (highest precedence)
#   2. otherwise the first line of ${CVC_TOKEN_FILE:-$HOME/.config/cvc/smoke-token}
#      (create that file with `chmod 600`)
#
# Usage:
#   deploy/smoke-test.sh [--verbose|-v] [--help|-h]
#
# Exit codes:
#   0 = all assertions passed
#   1 = an assertion, connectivity, or configuration failure (including missing token)
#   2 = usage error (bad flag)

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }
section() { echo; echo "── $* ──────────────────────────────────────────────────"; }

VERBOSE=0

usage() {
    cat <<'EOF'
Usage: deploy/smoke-test.sh [--verbose|-v] [--help|-h]

Live end-to-end smoke test of the cvc credential broker's
POST /v1/credentials/fetch endpoint (and GET /healthz).

Token resolution (never pass a token as a CLI argument):
  1. $CVC_SMOKE_TOKEN environment variable, if non-empty.
  2. First line of ${CVC_TOKEN_FILE:-$HOME/.config/cvc/smoke-token}, if present
     and non-empty. This file should be chmod 600.

Other overridable parameters (env vars):
  CVC_BROKER_URL         broker base URL      (default: ${SITE_BROKER_URL})
  CVC_SMOKE_AGENT        X-Agent-Id           (default: playwright-example)
  CVC_SMOKE_CREDENTIAL   credential UUID      (default: 72c393aa-6bc7-4323-a9e7-e2d7459aa777)
  CVC_SMOKE_PURPOSE      purpose string       (default: smoke-test)
  CVC_SMOKE_EXPECT       expected value       (default: testpass123, a disposable test fixture)
  CVC_SMOKE_TIMEOUT      fetch timeout (secs) (default: 45; bw is slow under CPU pressure)

Options:
  -v, --verbose   print extra diagnostic detail (never the token or credential value)
  -h, --help      show this help and exit 0

Exit codes:
  0 = all assertions passed
  1 = assertion / connectivity / configuration failure
  2 = usage error
EOF
}

for arg in "$@"; do
    case "$arg" in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=1
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            echo "Run with --help for usage." >&2
            exit 2
            ;;
    esac
done

BROKER_URL="${CVC_BROKER_URL:-${SITE_BROKER_URL}}"
AGENT_ID="${CVC_SMOKE_AGENT:-playwright-example}"
CREDENTIAL="${CVC_SMOKE_CREDENTIAL:-72c393aa-6bc7-4323-a9e7-e2d7459aa777}"
PURPOSE="${CVC_SMOKE_PURPOSE:-smoke-test}"
# EXPECT: this is a deliberately disposable test-fixture password for a throwaway vault item
# (the "test-credential" entry in deploy/broker-acl.yaml), which is why it is safe to default
# in-repo. Any real credential's expected value must be supplied via CVC_SMOKE_EXPECT instead
# of being hardcoded here.
EXPECT="${CVC_SMOKE_EXPECT:-testpass123}"
# A fetch shells out to the Bitwarden CLI (a Node process) inside the pod, under a 200m CPU
# limit on ARM64. Measured latency is ~2s idle but ~15s when the host is busy, and
# cvc.vault.client._run gives bw a 30s timeout of its own — so the client timeout must sit
# comfortably above that or a healthy-but-slow broker reads as "unreachable" (HTTP 000).
FETCH_TIMEOUT="${CVC_SMOKE_TIMEOUT:-45}"

if ! command -v jq >/dev/null 2>&1; then
    warn "jq not found — falling back to raw (non-redacted-safe) body handling where possible"
    HAVE_JQ=0
else
    HAVE_JQ=1
fi

# ── resolve token ─────────────────────────────────────────────────────────────
TOKEN=""
TOKEN_SOURCE=""

if [[ -n "${CVC_SMOKE_TOKEN:-}" ]]; then
    TOKEN="$CVC_SMOKE_TOKEN"
    TOKEN_SOURCE="env (CVC_SMOKE_TOKEN)"
else
    TOKEN_FILE="${CVC_TOKEN_FILE:-$HOME/.config/cvc/smoke-token}"
    if [[ -s "$TOKEN_FILE" ]]; then
        TOKEN="$(head -n1 "$TOKEN_FILE" | tr -d '\r\n')"
        TOKEN_SOURCE="file ($TOKEN_FILE)"
        MODE="$(stat -c '%a' "$TOKEN_FILE" 2>/dev/null || echo '???')"
        if [[ "$MODE" != "600" ]]; then
            warn "token file $TOKEN_FILE has mode $MODE — recommend chmod 600"
        fi
    fi
fi

if [[ -z "$TOKEN" ]]; then
    fail "No smoke-test token available."
    echo "  Either: export CVC_SMOKE_TOKEN=<token>"
    echo "  Or:     create \${CVC_TOKEN_FILE:-\$HOME/.config/cvc/smoke-token} (chmod 600) with the token as its first line"
    exit 1
fi

if [[ "$VERBOSE" -eq 1 ]]; then
    section "Configuration"
    echo "  Broker URL:  $BROKER_URL"
    echo "  Agent ID:    $AGENT_ID"
    echo "  Credential:  $CREDENTIAL"
    echo "  Purpose:     $PURPOSE"
    echo "  Token from:  $TOKEN_SOURCE (length: ${#TOKEN})"
fi

# ── redaction helper ──────────────────────────────────────────────────────────
redact_body() {
    local body="$1"
    if [[ "$HAVE_JQ" -eq 1 ]]; then
        if echo "$body" | jq -c 'if type=="object" and has("value") then .value="<redacted>" else . end' 2>/dev/null; then
            return 0
        fi
    fi
    # jq missing or body not valid JSON — print as-is (no "value" field to redact reliably,
    # but also nothing we can safely parse to find one).
    echo "$body"
}

# ── Step 1: liveness ──────────────────────────────────────────────────────────
section "1. Broker liveness (/healthz)"
HEALTH="$(curl -sf --max-time 5 "$BROKER_URL/healthz" 2>/dev/null || true)"
if [[ "$HEALTH" == *'"ok"'* ]]; then
    ok "/healthz → $HEALTH"
else
    fail "/healthz did not report ok (got: ${HEALTH:-<no response>})"
    echo "  Run deploy/diag.sh for a full diagnostic."
    exit 1
fi

# ── Step 2: fetch ─────────────────────────────────────────────────────────────
section "2. POST /v1/credentials/fetch"

umask 077
BODY="$(mktemp)"
cleanup() { rm -f "$BODY"; }
trap cleanup EXIT

REQUEST_JSON=$(printf '{"credential": "%s", "purpose": "%s"}' "$CREDENTIAL" "$PURPOSE")

HTTP_STATUS="$(curl -s --max-time "$FETCH_TIMEOUT" \
    -o "$BODY" -w '%{http_code}' \
    -X POST "$BROKER_URL/v1/credentials/fetch" \
    -H "X-Agent-Id: $AGENT_ID" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$REQUEST_JSON" 2>/dev/null || true)"

RESPONSE_BODY="$(cat "$BODY" 2>/dev/null || true)"

if [[ "$VERBOSE" -eq 1 ]]; then
    echo "  HTTP status: ${HTTP_STATUS:-<none>}"
    echo "  Response body (redacted): $(redact_body "$RESPONSE_BODY")"
fi

verdict_fail() {
    section "Result"
    fail "SMOKE TEST FAILED"
    echo "  Broker:     $BROKER_URL"
    echo "  Agent:      $AGENT_ID"
    echo "  Credential: $CREDENTIAL"
    exit 1
}

if [[ -z "$HTTP_STATUS" || "$HTTP_STATUS" == "000" ]]; then
    fail "Could not connect to broker at $BROKER_URL (empty/000 status)"
    echo "  Broker unreachable on that IP/port — check the service is running and reachable."
    echo "  Note: /healthz passed above, so the broker process is up. A timeout here means the"
    echo "  vault path is slow (bw under CPU pressure) — retry with CVC_SMOKE_TIMEOUT=90."
    verdict_fail
fi

if [[ "$HTTP_STATUS" != "200" ]]; then
    fail "Fetch returned HTTP $HTTP_STATUS (expected 200)"
    echo "  Response: $(redact_body "$RESPONSE_BODY")"
    case "$HTTP_STATUS" in
        401)
            echo "  Hint: token rotated or wrong agent id — check deploy/rotate-token.sh"
            ;;
        403)
            echo "  Hint: ACL does not permit this credential+purpose — check deploy/broker-acl.yaml"
            ;;
        502)
            echo "  Hint: the pod's vault session is dead — kubectl -n cvc rollout restart deploy/cvc-broker"
            ;;
        *)
            echo "  Hint: unexpected status — check deploy/diag.sh for broader diagnostics"
            ;;
    esac
    verdict_fail
fi
ok "HTTP 200"

# ── Step 3: assert response shape ─────────────────────────────────────────────
GOT_CREDENTIAL=""
GOT_FIELD=""
GOT_VALUE=""
if [[ "$HAVE_JQ" -eq 1 ]]; then
    GOT_CREDENTIAL="$(echo "$RESPONSE_BODY" | jq -r '.credential // empty' 2>/dev/null || true)"
    GOT_FIELD="$(echo "$RESPONSE_BODY" | jq -r '.field // empty' 2>/dev/null || true)"
    GOT_VALUE="$(echo "$RESPONSE_BODY" | jq -r '.value // empty' 2>/dev/null || true)"
else
    fail "jq is required to safely parse and assert on the response — install jq"
    verdict_fail
fi

if [[ "$GOT_CREDENTIAL" == "$CREDENTIAL" ]]; then
    ok "response \"credential\" matches ($CREDENTIAL)"
else
    fail "response \"credential\" mismatch (expected $CREDENTIAL, got ${GOT_CREDENTIAL:-<empty>})"
    verdict_fail
fi

if [[ "$GOT_FIELD" == "password" ]]; then
    ok "response \"field\" == password"
else
    fail "response \"field\" mismatch (expected password, got ${GOT_FIELD:-<empty>})"
    verdict_fail
fi

# ── Step 4: assert value (never print either value) ───────────────────────────
if [[ "$GOT_VALUE" == "$EXPECT" ]]; then
    ok "vault value matches expected fixture (length ${#EXPECT})"
else
    fail "vault value does NOT match expected fixture"
    echo "  Expected length: ${#EXPECT}, received length: ${#GOT_VALUE}"
    echo "  The vault item's password does not match the expected fixture."
    verdict_fail
fi

# ── verdict ────────────────────────────────────────────────────────────────────
section "Result"
ok "SMOKE TEST PASSED"
echo "  Broker:     $BROKER_URL"
echo "  Agent:      $AGENT_ID"
echo "  Credential: $CREDENTIAL"
exit 0
