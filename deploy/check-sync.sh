#!/usr/bin/env bash
# check-sync.sh — verify key constants are consistent between credential_organizer
# and opi_base_config. Run after editing either repo.
#
# Usage:
#   bash deploy/check-sync.sh
#   bash deploy/check-sync.sh --opi /path/to/opi_base_config   # non-default path

set -uo pipefail

OPI="${1:-}"
if [[ "$OPI" == --opi ]]; then shift; OPI="${1:-}"; shift; fi
OPI="${OPI:-/home/admin/opi_base_config}"

CVC="$(cd "$(dirname "$0")/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; FAILURES=$((FAILURES + 1)); }
warn() { echo -e "${YELLOW}  !${NC} $*"; }

FAILURES=0

if [[ ! -d "$OPI" ]]; then
    echo "opi_base_config not found at $OPI — pass --opi /path/to/repo"
    exit 1
fi

echo "CVC:  $CVC"
echo "OPI:  $OPI"
echo

# Constants defined in cvc (sources of truth)
TAILSCALE_IP="100.106.97.34"
TAILSCALE_HOST="orangepi6.humpback-krait.ts.net"
VW_URL="https://${TAILSCALE_HOST}:8443/vault"
BROKER_PORT="8710"

check_contains() {
    local label="$1" file="$2" pattern="$3"
    if [[ ! -f "$file" ]]; then
        warn "$label — file missing: $file"
        return
    fi
    if grep -qF "$pattern" "$file" 2>/dev/null; then
        ok "$label"
    else
        fail "$label — '$pattern' not found in $file"
    fi
}

echo "── Tailscale IP ($TAILSCALE_IP) ─────────────────────────────────────────"
check_contains "broker-deployment.yaml hostAliases"  "$CVC/deploy/broker-deployment.yaml"     "$TAILSCALE_IP"
check_contains "broker-deployment.yaml hostIP"       "$CVC/deploy/broker-deployment.yaml"     "hostIP: \"$TAILSCALE_IP\""
check_contains "diag.sh BROKER_IP"                   "$CVC/deploy/diag.sh"                   "BROKER_IP=\"$TAILSCALE_IP\""
check_contains "smoke-test.sh broker IP"              "$CVC/deploy/smoke-test.sh"             "$TAILSCALE_IP"
check_contains "opi AI-AGENT-K8S-GUIDE tailscale IP" "$OPI/containers/k8s/AI-AGENT-K8S-GUIDE.md" "$TAILSCALE_IP"
check_contains "opi hostAliases template"            "$OPI/containers/k8s/templates/hostAliases-tailscale.yaml" "$TAILSCALE_IP"

echo
echo "── Tailscale hostname ($TAILSCALE_HOST) ─────────────────────────────────"
check_contains "broker-deployment.yaml hostAliases hostname"  "$CVC/deploy/broker-deployment.yaml"  "$TAILSCALE_HOST"
check_contains "remind-cronjob.yaml hostAliases"             "$CVC/deploy/remind-cronjob.yaml"     "$TAILSCALE_HOST"
check_contains "backup-cronjob.yaml hostAliases"             "$CVC/deploy/backup-cronjob.yaml"     "$TAILSCALE_HOST"
check_contains "opi LESSONS-LEARNED hostname"                "$OPI/LESSONS-LEARNED.md"            "$TAILSCALE_HOST"

echo
echo "── Vaultwarden URL ($VW_URL) ────────────────────────────────────────────"
check_contains "broker-deployment.yaml BW_SERVER comment"    "$CVC/deploy/broker-deployment.yaml"   "$VW_URL"
check_contains "diag.sh VW_URL"                              "$CVC/deploy/diag.sh"                  "VW_URL"
check_contains "opi VAULTWARDEN-API.md URL"                  "$OPI/containers/k8s/auth/VAULTWARDEN-API.md" "8443/vault"
check_contains "opi AI-AGENT-K8S-GUIDE VW URL"              "$OPI/containers/k8s/AI-AGENT-K8S-GUIDE.md" "8443/vault"

echo
echo "── Broker port ($BROKER_PORT) ───────────────────────────────────────────"
check_contains "broker-deployment.yaml containerPort"  "$CVC/deploy/broker-deployment.yaml"   "containerPort: $BROKER_PORT"
check_contains "broker-deployment.yaml hostPort"       "$CVC/deploy/broker-deployment.yaml"   "hostPort: $BROKER_PORT"
check_contains "diag.sh BROKER_PORT"                   "$CVC/deploy/diag.sh"                  "BROKER_PORT=\"$BROKER_PORT\""
check_contains "opi AI-AGENT-K8S-GUIDE port"           "$OPI/containers/k8s/AI-AGENT-K8S-GUIDE.md" "$BROKER_PORT"

echo
echo "── Deployment patterns (cross-repo consistency) ─────────────────────────"
# Every pod spec that connects to Vaultwarden must have hostAliases.
for f in "$CVC/deploy/broker-deployment.yaml" "$CVC/deploy/remind-cronjob.yaml" "$CVC/deploy/backup-cronjob.yaml"; do
    name=$(basename "$f")
    if grep -q "hostAliases" "$f" 2>/dev/null; then
        ok "$name has hostAliases"
    else
        fail "$name missing hostAliases — Tailscale MagicDNS won't resolve in pod"
    fi
done

# strategy: Recreate must be on the broker deployment (hostPort).
if grep -q "type: Recreate" "$CVC/deploy/broker-deployment.yaml" 2>/dev/null; then
    ok "broker-deployment.yaml strategy: Recreate"
else
    fail "broker-deployment.yaml missing strategy: Recreate — hostPort scheduling deadlock risk"
fi

# BROKER_BIND must be 0.0.0.0, not the Tailscale IP.
# The value sits on the line after the name: key, so grep for the value alone.
if grep -q '"0\.0\.0\.0"' "$CVC/deploy/broker-deployment.yaml" 2>/dev/null; then
    ok "BROKER_BIND=0.0.0.0 (correct — Tailscale IP not in pod netns)"
else
    fail "BROKER_BIND is not 0.0.0.0 — broker will fail with EADDRNOTAVAIL"
fi

# BITWARDENCLI_APPDATA_DIR must appear on BOTH init and main containers.
COUNT=$(grep -c "BITWARDENCLI_APPDATA_DIR" "$CVC/deploy/broker-deployment.yaml" 2>/dev/null || true)
if [[ "$COUNT" -ge 2 ]]; then
    ok "BITWARDENCLI_APPDATA_DIR present on both containers ($COUNT occurrences)"
else
    fail "BITWARDENCLI_APPDATA_DIR only on $COUNT container(s) — bw app-data won't be shared between init and main"
fi

echo
echo "── Templates in sync with GUIDE ─────────────────────────────────────────"
GUIDE="$OPI/containers/k8s/AI-AGENT-K8S-GUIDE.md"
for tpl in hostAliases-tailscale.yaml strategy-recreate-hostport.yaml init-appdata-pattern.yaml diag-template.sh rebuild-template.sh; do
    if grep -q "$tpl" "$GUIDE" 2>/dev/null; then
        ok "GUIDE references $tpl"
    else
        fail "GUIDE missing reference to templates/$tpl"
    fi
    if [[ -f "$OPI/containers/k8s/templates/$tpl" ]]; then
        ok "templates/$tpl exists"
    else
        fail "templates/$tpl MISSING"
    fi
done

echo
if [[ "$FAILURES" -eq 0 ]]; then
    echo -e "${GREEN}All checks passed.${NC}"
    exit 0
else
    echo -e "${RED}$FAILURES check(s) failed — fix the inconsistencies above.${NC}"
    exit 1
fi
