#!/usr/bin/env bash
# diag.sh — cvc-broker health and troubleshooting diagnostic
#
# Run this any time the broker is misbehaving or after a deployment change.
# Requires: KUBECONFIG set, or run with sudo kubectl.
#
# Usage:
#   export KUBECONFIG=/home/admin/.kube/config
#   bash deploy/diag.sh

set -uo pipefail

BROKER_IP="${SITE_NODE_IP}"
BROKER_PORT="8710"
NAMESPACE="cvc"
VW_URL="${SITE_VAULT_URL}"
KUBECTL="${KUBECTL:-kubectl}"
AGENT_ID="${CVC_SMOKE_AGENT:-playwright-example}"
TOKEN_FILE="${CVC_TOKEN_FILE:-$HOME/.config/cvc/smoke-token}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }
section() { echo; echo "── $* ──────────────────────────────────────────────────"; }

# ── 1. k3s image ──────────────────────────────────────────────────────────────
section "1. k3s image (cvc:latest)"
if sudo k3s ctr -n k8s.io images ls 2>/dev/null | grep -q "cvc:latest"; then
    DIGEST=$(sudo k3s ctr -n k8s.io images ls 2>/dev/null | grep "cvc:latest" | awk '{print $3}')
    ok "cvc:latest present in k3s containerd ($DIGEST)"
else
    fail "cvc:latest NOT found in k3s containerd"
    echo "    Fix: sudo nerdctl build -t cvc:latest . && sudo nerdctl save cvc:latest -o /tmp/cvc.tar && sudo k3s ctr -n k8s.io images import /tmp/cvc.tar"
fi

# ── 2. namespace + secrets ────────────────────────────────────────────────────
section "2. Namespace and secrets"
if $KUBECTL get ns "$NAMESPACE" &>/dev/null; then
    ok "namespace/$NAMESPACE exists"
else
    fail "namespace/$NAMESPACE missing"
    echo "    Fix: kubectl apply -f deploy/namespace.yaml"
fi

for secret in cvc-broker-vault cvc-broker-acl; do
    if $KUBECTL -n "$NAMESPACE" get secret "$secret" &>/dev/null; then
        KEYS=$($KUBECTL -n "$NAMESPACE" get secret "$secret" -o jsonpath='{.data}' | python3 -c "import sys,json; print(', '.join(json.load(sys.stdin).keys()))")
        ok "secret/$secret exists (keys: $KEYS)"
    else
        fail "secret/$secret MISSING"
        case "$secret" in
            cvc-broker-vault) echo "    Fix: see setup-agent-account.sh step e" ;;
            cvc-broker-acl)   echo "    Fix: kubectl -n cvc create secret generic cvc-broker-acl --from-file=broker-acl.yaml=deploy/broker-acl.yaml" ;;
        esac
    fi
done

# ── 3. pod status ─────────────────────────────────────────────────────────────
section "3. Pod status"
PODS=$($KUBECTL -n "$NAMESPACE" get pods -l app=cvc-broker --no-headers 2>/dev/null)
if [ -z "$PODS" ]; then
    fail "No cvc-broker pods found"
    echo "    Fix: kubectl apply -f deploy/broker-deployment.yaml"
else
    echo "$PODS"
    POD=$($KUBECTL -n "$NAMESPACE" get pods -l app=cvc-broker --no-headers 2>/dev/null | awk '{print $1}' | head -1)
    STATUS=$($KUBECTL -n "$NAMESPACE" get pod "$POD" --no-headers 2>/dev/null | awk '{print $3}')
    READY=$($KUBECTL -n "$NAMESPACE" get pod "$POD" --no-headers 2>/dev/null | awk '{print $2}')
    RESTARTS=$($KUBECTL -n "$NAMESPACE" get pod "$POD" --no-headers 2>/dev/null | awk '{print $4}')

    [[ "$READY" == "1/1" ]] && ok "pod $POD ready ($READY)" || fail "pod $POD NOT ready ($READY, status: $STATUS)"
    [[ "$RESTARTS" -gt 3 ]] && warn "pod $POD has $RESTARTS restarts — check logs below"

    # ── 4. pod spec checks ────────────────────────────────────────────────────
    section "4. Pod spec checks"
    SPEC=$($KUBECTL -n "$NAMESPACE" get pod "$POD" -o json 2>/dev/null)

    # hostAliases
    if echo "$SPEC" | python3 -c "import sys,json; s=json.load(sys.stdin); aliases=[h for a in s['spec'].get('hostAliases',[]) for h in a.get('hostnames',[])] if 'hostAliases' in s['spec'] else []; exit(0 if '${SITE_BASE_DOMAIN}' in aliases else 1)" 2>/dev/null; then
        ok "hostAliases: ${SITE_BASE_DOMAIN} present"
    else
        fail "hostAliases missing — Tailscale MagicDNS won't resolve inside pod"
        echo "    Fix: add hostAliases to broker-deployment.yaml and re-apply"
    fi

    # BROKER_BIND
    BIND=$(echo "$SPEC" | python3 -c "import sys,json; s=json.load(sys.stdin); envs={e['name']:e.get('value','') for c in s['spec']['containers'] for e in c.get('env',[])}; print(envs.get('BROKER_BIND','MISSING'))" 2>/dev/null)
    [[ "$BIND" == "0.0.0.0" ]] && ok "BROKER_BIND=0.0.0.0 (correct)" || fail "BROKER_BIND=$BIND — should be 0.0.0.0 (not the Tailscale IP)"

    # strategy
    STRATEGY=$($KUBECTL -n "$NAMESPACE" get deploy cvc-broker -o jsonpath='{.spec.strategy.type}' 2>/dev/null)
    [[ "$STRATEGY" == "Recreate" ]] && ok "strategy: Recreate (correct)" || warn "strategy: $STRATEGY — should be Recreate for hostPort deployments"

    # ── 5. logs ───────────────────────────────────────────────────────────────
    section "5. Init container logs (bw-unlock)"
    $KUBECTL -n "$NAMESPACE" logs "$POD" -c bw-unlock 2>/dev/null || \
        $KUBECTL -n "$NAMESPACE" logs "$POD" -c bw-unlock --previous 2>/dev/null || \
        warn "No init container logs available"

    section "6. Main container logs (last 30 lines)"
    $KUBECTL -n "$NAMESPACE" logs "$POD" --tail=30 2>/dev/null || warn "No main container logs available"
fi

# ── 7. healthz probe ──────────────────────────────────────────────────────────
section "7. Broker /healthz"
HEALTH=$(curl -sf --max-time 5 "http://${BROKER_IP}:${BROKER_PORT}/healthz" 2>/dev/null)
if [[ "$HEALTH" == *'"ok"'* ]]; then
    ok "/healthz → $HEALTH"
else
    fail "/healthz unreachable or unhealthy (got: ${HEALTH:-<no response>})"
    echo "    Check: is port 8710 bound on the Tailscale interface?"
    echo "    Check: ss -tlnp | grep 8710"
fi

# ── 8. Vaultwarden reachability ───────────────────────────────────────────────
section "8. Vaultwarden /alive (from host)"
VW_ALIVE=$(curl -sf --max-time 5 "${VW_URL}/alive" 2>/dev/null)
if [[ "$VW_ALIVE" == *"alive"* ]] || [[ -n "$VW_ALIVE" ]]; then
    ok "Vaultwarden alive: $VW_ALIVE"
else
    fail "Vaultwarden unreachable at ${VW_URL}/alive"
    echo "    Check: sudo kubectl -n auth get pods"
fi

# ── 9. PVC ────────────────────────────────────────────────────────────────────
section "9. PersistentVolumeClaim"
PVC=$($KUBECTL -n "$NAMESPACE" get pvc cvc-broker-audit-log --no-headers 2>/dev/null)
if [ -n "$PVC" ]; then
    PVC_STATUS=$(echo "$PVC" | awk '{print $2}')
    [[ "$PVC_STATUS" == "Bound" ]] && ok "cvc-broker-audit-log PVC: Bound" || fail "cvc-broker-audit-log PVC: $PVC_STATUS"
else
    fail "cvc-broker-audit-log PVC missing"
fi

# ── 10. audit log integrity ───────────────────────────────────────────────────
section "10. Audit log integrity"
TOKEN=""
if [ -n "${CVC_SMOKE_TOKEN:-}" ]; then
    TOKEN="$CVC_SMOKE_TOKEN"
elif [ -s "$TOKEN_FILE" ]; then
    TOKEN=$(head -n1 "$TOKEN_FILE" | sed -e 's/[[:space:]]*$//')
fi

if [ -z "$TOKEN" ]; then
    warn "audit log check skipped — no token available"
    echo "    Enable: export CVC_SMOKE_TOKEN=<agent-token>"
    echo "    Or:     write the agent token to $TOKEN_FILE (mode 600)"
else
    AUDIT_BODY=$(umask 077 && mktemp)
    if [ -z "$AUDIT_BODY" ]; then
        warn "could not create temp file for audit check — skipping"
    else
        AUDIT_STATUS=$(curl -s --max-time 10 \
            -H "X-Agent-Id: $AGENT_ID" \
            -H "Authorization: Bearer $TOKEN" \
            -o "$AUDIT_BODY" -w '%{http_code}' \
            "http://${BROKER_IP}:${BROKER_PORT}/v1/audit/verify" 2>/dev/null) || true
        AUDIT_RESP=$(cat "$AUDIT_BODY" 2>/dev/null)
        rm -f "$AUDIT_BODY"

        case "$AUDIT_STATUS" in
            200)
                if command -v jq &>/dev/null; then
                    INTACT=$(echo "$AUDIT_RESP" | jq -r '.intact // empty' 2>/dev/null)
                elif echo "$AUDIT_RESP" | grep -q '"intact":true'; then
                    INTACT="true"
                else
                    INTACT="false"
                fi

                if [ -z "$INTACT" ]; then
                    # Distinguish "could not parse" from "chain is broken" — reporting a
                    # tampered audit log because jq choked would be a false alarm.
                    fail "could not parse the /v1/audit/verify response (no 'intact' field)"
                    echo "    Response: $AUDIT_RESP"
                elif [[ "$INTACT" == "true" ]]; then
                    ok "audit log intact (hash chain verifies)"

                    # Cheap emptiness check — best-effort, never fatal. Re-derive the
                    # pod name into its own var; the section-3 POD var may be unset here.
                    AUDIT_POD=$($KUBECTL -n "$NAMESPACE" get pods -l app=cvc-broker --no-headers 2>/dev/null | awk '{print $1}' | head -1)
                    if [ -n "$AUDIT_POD" ]; then
                        AUDIT_LINES=$($KUBECTL -n "$NAMESPACE" exec "$AUDIT_POD" -- sh -c 'wc -l < /var/log/cvc/access.jsonl 2>/dev/null || echo 0' 2>/dev/null)
                        if [[ "$AUDIT_LINES" =~ ^[0-9]+$ ]] && [ "$AUDIT_LINES" -eq 0 ]; then
                            warn "intact:true is vacuous — audit log has no records yet"
                        fi
                    fi
                else
                    fail "AUDIT LOG NOT INTACT — the hash chain does not recompute; the log was altered or truncated"
                    echo "    See: docs/RUNBOOK-recovery.md"
                    echo "    Check: the audit PVC must not be an emptyDir"
                fi
                ;;
            401)
                fail "audit token rejected (rotated token, or agent id not in ACL)"
                echo "    Fix: deploy/rotate-token.sh"
                echo "    Check: deploy/broker-acl.yaml"
                ;;
            400)
                fail "malformed Authorization header sent to /v1/audit/verify"
                ;;
            ""|000)
                fail "broker unreachable"
                echo "    See: section 7 above (Broker /healthz)"
                ;;
            *)
                fail "unexpected status $AUDIT_STATUS from /v1/audit/verify: $AUDIT_RESP"
                ;;
        esac
    fi
fi

# ── summary ───────────────────────────────────────────────────────────────────
section "Done"
echo "Easiest end-to-end check:  deploy/smoke-test.sh"
echo
echo "For a manual test credential fetch:"
# NOTE: do NOT mint a token here with 'python3 -m cvc.broker.tokens' — a freshly minted
# token is not in the ACL and will just return 401. Use the agent's existing token.
echo "  TOKEN=\$(cat $TOKEN_FILE)   # or: export CVC_SMOKE_TOKEN=<agent-token>"
echo "  curl -s -X POST http://${BROKER_IP}:${BROKER_PORT}/v1/credentials/fetch \\"
echo "    -H 'X-Agent-Id: playwright-example' \\"
echo "    -H \"Authorization: Bearer \$TOKEN\" \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"credential\": \"<uuid>\", \"purpose\": \"smoke-test\"}'"
echo
echo "For a manual audit log integrity check:"
echo "  curl -s http://${BROKER_IP}:${BROKER_PORT}/v1/audit/verify \\"
echo "    -H 'X-Agent-Id: playwright-example' \\"
echo "    -H \"Authorization: Bearer \$TOKEN\""
echo
