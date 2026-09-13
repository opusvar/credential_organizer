#!/usr/bin/env bash
# rotate-token.sh — rotate the bearer service token for one agent in the cvc
#                   credential broker's ACL, and push the new sha256 live.
#
# What it does:
#   1. Validates the agent already has a real entry in deploy/broker-acl.yaml
#      (this script rotates existing agents; it does not create new ones).
#   2. Mints a brand new random token + sha256 (python3 -m cvc.broker.tokens).
#   3. Backs up the ACL file, then surgically replaces only that agent's
#      token_sha256 line — every comment, every other agent, and all
#      surrounding formatting is left byte-identical.
#   4. Re-validates the patched file with the project's own ACL loader.
#   5. Pushes the updated file into the live cvc-broker-acl secret (no
#      delete-then-create window) and, unless --no-restart, restarts the
#      broker deployment so it picks up the change.
#   6. Prints the new token to stdout ONCE.
#
# IMPORTANT: the token is shown exactly one time, right here, and is
# unrecoverable afterward — only its sha256 is ever stored in the ACL or the
# secret. Copy it into the agent's own configuration / a password manager
# immediately. Until you do, that agent's requests to the broker will start
# failing with 401 Unauthorized, because the old token no longer matches the
# sha256 on file.
#
# Usage:
#   deploy/rotate-token.sh <agent-id> [--acl PATH] [--no-restart] [--help]

set -euo pipefail

# ── colors (match deploy/diag.sh) ─────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }
section() { echo; echo "── $* ──────────────────────────────────────────────────"; }

usage() {
    cat <<'EOF'
Usage: deploy/rotate-token.sh <agent-id> [--acl PATH] [--no-restart] [--help]

Rotate the bearer service token for one existing agent in the cvc credential
broker's ACL (deploy/broker-acl.yaml, e.g. agent id "playwright-example"),
and push the new token's sha256 to the live cvc-broker-acl secret.

Arguments:
  <agent-id>     Agent id that must already have an entry in the ACL. This
                 script rotates existing agents; it does not provision new
                 ones (use deploy/setup-agent-account.sh for that).

Options:
  --acl PATH     Path to the ACL file (default: deploy/broker-acl.yaml
                 resolved from this script's own location, not your cwd).
  --no-restart   Update the secret but skip restarting deploy/cvc-broker.
  --help, -h     Show this help and exit.

The new bearer token is printed to stdout exactly once, at the very end, and
cannot be recovered afterward — only its sha256 is kept in the ACL. Store it
in the agent's configuration or a password manager immediately: until you
do, that agent's requests will start failing with 401 Unauthorized.
EOF
}

# ── 0. argument parsing ───────────────────────────────────────────────────────
AGENT_ID=""
ACL_FILE_OVERRIDE=""
NO_RESTART=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --acl)
            if [[ $# -lt 2 ]]; then
                echo "error: --acl requires a PATH argument" >&2
                exit 2
            fi
            ACL_FILE_OVERRIDE="$2"
            shift 2
            ;;
        --no-restart)
            NO_RESTART=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --*)
            echo "error: unknown flag: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [[ -n "$AGENT_ID" ]]; then
                echo "error: unexpected extra argument: $1" >&2
                usage >&2
                exit 2
            fi
            AGENT_ID="$1"
            shift
            ;;
    esac
done

if [[ -z "$AGENT_ID" ]]; then
    echo "error: missing required <agent-id>" >&2
    usage >&2
    exit 2
fi

# ── 1. config ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -n "$ACL_FILE_OVERRIDE" ]]; then
    ACL_FILE="$(realpath -m "$ACL_FILE_OVERRIDE")"
else
    ACL_FILE="${REPO_ROOT}/deploy/broker-acl.yaml"
fi

NAMESPACE="${CVC_NAMESPACE:-cvc}"
DEPLOYMENT="${CVC_DEPLOYMENT:-cvc-broker}"
SECRET="${CVC_ACL_SECRET:-cvc-broker-acl}"
export KUBECONFIG="${KUBECONFIG:-/home/admin/.kube/config}"

# ── 2. preflight ───────────────────────────────────────────────────────────────
section "Preflight"

for bin in kubectl python3; do
    if command -v "$bin" >/dev/null 2>&1; then
        ok "$bin is on PATH"
    else
        fail "$bin is not on PATH — install it or fix your PATH before rotating tokens"
        exit 1
    fi
done

if [[ -f "$ACL_FILE" && -w "$ACL_FILE" ]]; then
    ok "ACL file exists and is writable: $ACL_FILE"
else
    fail "ACL file missing or not writable: $ACL_FILE"
    echo "    Fix: check the path (--acl PATH) or file permissions." >&2
    exit 1
fi

if kubectl -n "$NAMESPACE" get secret "$SECRET" &>/dev/null; then
    ok "secret/$SECRET exists in namespace $NAMESPACE"
else
    fail "secret/$SECRET not found in namespace $NAMESPACE — nothing live to rotate against"
    echo "    Fix: kubectl -n $NAMESPACE create secret generic $SECRET --from-file=broker-acl.yaml=$ACL_FILE" >&2
    exit 1
fi

if AGENT_ID="$AGENT_ID" ACL_FILE="$ACL_FILE" python3 - <<'PYEOF'
import os
import re
import sys

import yaml

acl_file = os.environ["ACL_FILE"]
agent_id = os.environ["AGENT_ID"]

with open(acl_file, encoding="utf-8") as fh:
    data = yaml.safe_load(fh) or {}

agents = data.get("agents")
if not isinstance(agents, dict):
    print("ACL file has no top-level 'agents' mapping", file=sys.stderr)
    sys.exit(1)

if agent_id not in agents:
    present = ", ".join(sorted(agents.keys())) or "(none)"
    print(
        f"Agent '{agent_id}' has no entry in the ACL. Rotation requires an "
        f"existing entry — it does not create new agents.",
        file=sys.stderr,
    )
    print(f"Agents present in {acl_file}: {present}", file=sys.stderr)
    sys.exit(1)

entry = agents.get(agent_id) or {}
token_sha256 = entry.get("token_sha256")
if not isinstance(token_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", token_sha256):
    print(
        f"Agent '{agent_id}' exists but has no valid 64-char hex token_sha256 "
        f"— refusing to rotate a malformed entry.",
        file=sys.stderr,
    )
    sys.exit(1)

sys.exit(0)
PYEOF
then
    ok "agent '$AGENT_ID' has an existing, well-formed entry in the ACL"
else
    exit 1
fi

# ── 3. mint the new token ─────────────────────────────────────────────────────
section "Minting new token"

TOKEN_OUTPUT="$(cd "$REPO_ROOT" && python3 -m cvc.broker.tokens)"
NEW_TOKEN="$(printf '%s\n' "$TOKEN_OUTPUT" | awk '/^token:/{print $2}')"
NEW_SHA256="$(printf '%s\n' "$TOKEN_OUTPUT" | awk '/^sha256:/{print $2}')"

if [[ -z "$NEW_TOKEN" ]]; then
    fail "Failed to parse a token from 'python3 -m cvc.broker.tokens' output"
    exit 1
fi
if [[ ! "$NEW_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
    fail "Failed to parse a valid 64-hex-char sha256 from the token minter output"
    exit 1
fi
ok "new token minted (sha256: ${NEW_SHA256:0:8}...)"

# ── 4. backup ──────────────────────────────────────────────────────────────────
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_FILE="${ACL_FILE}.bak-${TS}"
cp -p -- "$ACL_FILE" "$BACKUP_FILE"
echo "Backup written to: $BACKUP_FILE"

# ── 5. surgically patch only this agent's token_sha256 line ──────────────────
section "Patching ACL"

if ! AGENT_ID="$AGENT_ID" NEW_SHA256="$NEW_SHA256" ACL_FILE="$ACL_FILE" python3 - <<'PYEOF'
import os
import re
import sys
import tempfile

acl_file = os.environ["ACL_FILE"]
agent_id = os.environ["AGENT_ID"]
new_sha256 = os.environ["NEW_SHA256"]


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


with open(acl_file, encoding="utf-8") as fh:
    lines = fh.readlines()

# Find the top-level "agents:" line.
agents_idx = None
for i, line in enumerate(lines):
    if line.rstrip("\n") == "agents:":
        agents_idx = i
        break
if agents_idx is None:
    print("Could not find a top-level 'agents:' key in the ACL file", file=sys.stderr)
    sys.exit(1)
agents_indent = indent_of(lines[agents_idx])

# Find the line whose stripped form is "<agent-id>:" at a deeper indentation.
target_key = f"{agent_id}:"
agent_idx = None
agent_indent = None
for i in range(agents_idx + 1, len(lines)):
    line = lines[i]
    stripped = line.strip()
    ind = indent_of(line)
    if stripped == target_key and ind > agents_indent:
        agent_idx = i
        agent_indent = ind
        break
if agent_idx is None:
    print(f"Could not locate the ACL block for agent '{agent_id}'", file=sys.stderr)
    sys.exit(1)

# Within that agent's block (until a line at the same/lesser indentation as
# the agent key), replace the first token_sha256 line.
pattern = re.compile(r"^(\s*)token_sha256:.*$")
match_count = 0
for i in range(agent_idx + 1, len(lines)):
    line = lines[i]
    if line.strip() != "" and indent_of(line) <= agent_indent:
        break
    m = pattern.match(line.rstrip("\n"))
    if m:
        lines[i] = f'{m.group(1)}token_sha256: "{new_sha256}"\n'
        match_count += 1
        break

if match_count != 1:
    print(
        f"Expected exactly 1 token_sha256 substitution for '{agent_id}', made {match_count}",
        file=sys.stderr,
    )
    sys.exit(1)

dir_name = os.path.dirname(os.path.abspath(acl_file)) or "."
fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".broker-acl.", suffix=".tmp")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    os.replace(tmp_path, acl_file)
except BaseException:
    if os.path.exists(tmp_path):
        os.remove(tmp_path)
    raise
PYEOF
then
    fail "ACL patch failed — original file untouched, backup at $BACKUP_FILE"
    exit 1
fi
ok "patched token_sha256 for '$AGENT_ID' in $ACL_FILE"

# ── 6. re-validate through the project's own parser ───────────────────────────
if (cd "$REPO_ROOT" && python3 -c 'import sys; from cvc.broker.acl import Acl; Acl.load(sys.argv[1])' "$ACL_FILE"); then
    ok "patched ACL file re-validated with cvc.broker.acl.Acl.load()"
else
    fail "Patched ACL failed validation — restoring backup"
    cp -p -- "$BACKUP_FILE" "$ACL_FILE"
    exit 1
fi

# ── 7. push to the live secret (no delete-then-create window) ────────────────
section "Updating live secret"

if ! SECRET_YAML="$(kubectl -n "$NAMESPACE" create secret generic "$SECRET" \
        --from-file=broker-acl.yaml="$ACL_FILE" --dry-run=client -o yaml 2>&1)"; then
    fail "Failed to render manifest for secret/$SECRET — restoring ACL backup"
    echo "$SECRET_YAML" >&2
    cp -p -- "$BACKUP_FILE" "$ACL_FILE"
    exit 1
fi

if printf '%s\n' "$SECRET_YAML" | kubectl apply -f - >/dev/null; then
    ok "secret/$SECRET updated in namespace $NAMESPACE"
else
    fail "kubectl apply of secret/$SECRET failed — restoring ACL backup"
    cp -p -- "$BACKUP_FILE" "$ACL_FILE"
    exit 1
fi

# ── 8. restart so the broker picks up the change ──────────────────────────────
DEGRADED=0
if [[ "$NO_RESTART" -eq 0 ]]; then
    section "Restarting deploy/$DEPLOYMENT"
    # Why restart at all: the broker calls Acl.load() on the mounted file per
    # request (see the _acl() dependency in src/cvc/broker/app.py), so it WILL
    # pick up the new sha256 on its own — but only after the kubelet refreshes
    # the projected secret volume, which can take ~60s. The restart makes the
    # rotation effective immediately instead of eventually.
    #
    # Everything below is deliberately non-fatal. The new sha256 is already live
    # in the secret at this point, so the old token is on its way out; if this
    # script died here without printing the new token, the agent would be locked
    # out with no way to recover it. Degraded outcomes are reported via DEGRADED
    # and the token is still printed at the end.
    if kubectl -n "$NAMESPACE" rollout restart "deploy/${DEPLOYMENT}"; then
        if kubectl -n "$NAMESPACE" rollout status "deploy/${DEPLOYMENT}" --timeout=180s; then
            ok "deploy/$DEPLOYMENT rolled out successfully"
        else
            warn "deploy/$DEPLOYMENT did not become ready within the timeout"
            warn "The new sha256 IS already live in secret/$SECRET, but the pod may still serve the old ACL."
            warn "Run deploy/diag.sh to investigate before relying on the new token."
            DEGRADED=1
        fi
    else
        warn "rollout restart of deploy/$DEPLOYMENT failed"
        warn "The new sha256 IS already live in secret/$SECRET — the running pod will pick it up"
        warn "within ~60s when the kubelet refreshes the mounted secret, or restart it manually:"
        warn "  kubectl -n $NAMESPACE rollout restart deploy/${DEPLOYMENT}"
        DEGRADED=1
    fi
else
    warn "--no-restart passed: secret/$SECRET is updated. The running pod re-reads the ACL"
    warn "per request, so it will pick up the new sha256 once the kubelet refreshes the"
    warn "mounted secret volume (~60s). Restart deploy/$DEPLOYMENT to make it immediate."
fi

# ── 9. print the token — exactly once, exactly here ───────────────────────────
section "New token"
echo ""
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║  NEW SERVICE TOKEN — SHOWN ONLY ONCE                     ║"
echo "  ║                                                           ║"
echo "  ║  Agent:  $AGENT_ID"
echo "  ║  Token:  $NEW_TOKEN"
echo "  ║                                                           ║"
echo "  ║  This is the ONLY time this token is displayed. It cannot ║"
echo "  ║  be recovered from the broker or the ACL afterward — only ║"
echo "  ║  its sha256 is stored there. Save it in the agent's own   ║"
echo "  ║  configuration or a password manager right now.           ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Until the agent's own configuration is updated with this token, its"
echo "requests to the broker will start failing with 401 Unauthorized."
echo ""
echo "Follow-up:"
echo "  - If '$AGENT_ID' is the smoke-test agent, update ~/.config/cvc/smoke-token"
echo "    with the token above."
echo "  - Then run: deploy/smoke-test.sh"

if [[ "$DEGRADED" -eq 1 ]]; then
    exit 1
fi
