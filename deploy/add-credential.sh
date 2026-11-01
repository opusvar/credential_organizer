#!/usr/bin/env bash
# add-credential.sh — add a login item to the dedicated Vaultwarden AGENT account
#                     (cvc-agent@local) used by the cvc credential broker.
#
# What it does:
#   1. Reads the agent account's bw credentials (BW_SERVER/BW_CLIENTID/BW_CLIENTSECRET/
#      BW_PASSWORD) from the k8s secret cvc-broker-vault (namespace cvc).
#   2. Logs into Vaultwarden as cvc-agent@local, in an isolated throwaway bw profile.
#   3. Creates a login item (name/username/password/uri) and prints its new UUID.
#
# UUID -> ACL workflow:
#   The broker is default-deny (src/cvc/broker/acl.py): an agent can only fetch a
#   credential whose UUID is explicitly listed under that agent in
#   deploy/broker-acl.yaml, for one of the listed purposes. So the UUID this script
#   prints is not useful on its own — it must be pasted (or, with --grant, is
#   automatically appended) into that agent's `allow:` list before anything can
#   fetch it through the broker.
#
# Profile isolation:
#   the owner's own `bw` login state may already exist on this host. To avoid clobbering
#   it, every `bw` call in this script runs against a private, throwaway app-data dir
#   created with mktemp -d and pointed to via BITWARDENCLI_APPDATA_DIR. That variable
#   is what actually isolates the CLI's session/profile state — HOME is left
#   unchanged (bw does not use it for profile storage) — so this script's bw calls
#   always start from a fresh, logged-out profile, and the throwaway dir plus any
#   login session are destroyed on exit (see the EXIT trap below).
#
# The sync caveat (see also the printed warning after item creation):
#   The running cvc-broker pod holds its own long-lived bw profile in an in-memory
#   emptyDir, populated once by its init container at pod start. The broker does NOT
#   re-sync that profile on its own. A brand-new item created by this script will
#   therefore make the broker return HTTP 502 "vault retrieval failed" for that
#   credential until the pod is restarted (its init container logs in and syncs
#   fresh). Run `kubectl -n cvc rollout restart deploy/cvc-broker` afterwards, or
#   pass --restart-broker to this script to have it do that for you.
#
# Usage:
#   deploy/add-credential.sh <name> <username> <password|-> [uri]
#                             [--grant AGENT:PURPOSE] [--restart-broker] [--help]
#
# See --help for full details.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." &>/dev/null && pwd)"

NAMESPACE="cvc"
SECRET_NAME="cvc-broker-vault"
DEPLOY_NAME="cvc-broker"
ACL_FILE="$REPO_ROOT/deploy/broker-acl.yaml"

# ── house style (see diag.sh) ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*" >&2; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }
section() { echo; echo "── $* ──────────────────────────────────────────────────"; }
die() { fail "$*"; exit 1; }

usage() {
  cat <<'EOF'
Usage: add-credential.sh <name> <username> <password|-> [uri]
                          [--grant AGENT:PURPOSE] [--restart-broker] [--help]

Adds a login item to the dedicated Vaultwarden agent account (cvc-agent@local)
used by the cvc credential broker, and prints the new item's UUID — the value
that goes into deploy/broker-acl.yaml under an agent's `allow:` list.

Positional arguments (name, username, password are required):
  name       Vault item name.
  username   Login username.
  password   Login password, OR "-" to read it from stdin (recommended — a
             password given directly on the command line is visible to any
             other user of this host via `ps`). $CVC_NEW_PASSWORD, if set,
             takes precedence over this argument (and over "-").
  uri        Optional login URI. Omit for no URI.

Options:
  --grant AGENT:PURPOSE   After creating the item, append an allow entry for
                          its new UUID to deploy/broker-acl.yaml under AGENT,
                          with purposes: ["PURPOSE"], and push the updated
                          file into the cvc-broker-acl secret. Refuses (without
                          undoing the already-created item) if AGENT is not in
                          the file, if its allow: list is written inline as
                          `allow: []`, or if the UUID is already listed.
  --restart-broker        After a successful create (and --grant, if given),
                          run `kubectl -n cvc rollout restart deploy/cvc-broker`
                          and wait for it to finish. Needed for the broker to
                          see the new item and/or ACL grant — see the sync
                          caveat below.
  -h, --help               Show this help and exit.

Recommended safe invocation (password never touches argv or a shell history file):
  CVC_NEW_PASSWORD=... deploy/add-credential.sh myitem myuser -
  # or, interactively:
  deploy/add-credential.sh myitem myuser -
  <paste password, press Enter>

Sync caveat:
  The running broker pod caches its own bw profile in memory and does not
  re-sync on its own. A newly created item 502s ("vault retrieval failed")
  through the broker until the pod restarts. Use --restart-broker or run
  `kubectl -n cvc rollout restart deploy/cvc-broker` yourself afterwards.
EOF
}

# ── arg parsing ────────────────────────────────────────────────────────────────
POSITIONAL=()
GRANT=""
RESTART_BROKER=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --grant)
      [[ $# -ge 2 ]] || { echo "add-credential.sh: --grant requires an AGENT:PURPOSE argument" >&2; usage >&2; exit 2; }
      GRANT="$2"
      shift 2
      ;;
    --restart-broker)
      RESTART_BROKER=1
      shift
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do POSITIONAL+=("$1"); shift; done
      ;;
    -)
      # bare "-" is the stdin-password marker, not a flag
      POSITIONAL+=("$1")
      shift
      ;;
    -*)
      echo "add-credential.sh: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL[@]} -lt 3 || ${#POSITIONAL[@]} -gt 4 ]]; then
  echo "add-credential.sh: expected 3 or 4 positional arguments (name, username, password, [uri]), got ${#POSITIONAL[@]}" >&2
  usage >&2
  exit 2
fi

NAME="${POSITIONAL[0]}"
USERNAME="${POSITIONAL[1]}"
PASSWORD_ARG="${POSITIONAL[2]}"
URI="${POSITIONAL[3]:-}"

GRANT_AGENT=""
GRANT_PURPOSE=""
if [[ -n "$GRANT" ]]; then
  if [[ "$GRANT" != *:* || "${GRANT%%:*}" == "" || "${GRANT#*:}" == "" ]]; then
    echo "add-credential.sh: --grant expects AGENT:PURPOSE (both non-empty), got: $GRANT" >&2
    usage >&2
    exit 2
  fi
  GRANT_AGENT="${GRANT%%:*}"
  GRANT_PURPOSE="${GRANT#*:}"
fi

# Resolve the password: $CVC_NEW_PASSWORD > "-" (stdin) > positional argument.
if [[ -n "${CVC_NEW_PASSWORD:-}" ]]; then
  PASSWORD="$CVC_NEW_PASSWORD"
elif [[ "$PASSWORD_ARG" == "-" ]]; then
  IFS= read -r PASSWORD
else
  PASSWORD="$PASSWORD_ARG"
fi
unset PASSWORD_ARG CVC_NEW_PASSWORD

# ── preflight ──────────────────────────────────────────────────────────────────
section "Preflight"

command -v kubectl >/dev/null 2>&1 || die "kubectl not found on PATH"
ok "kubectl found"

BW="${BW_BIN:-$(command -v bw || true)}"
if [[ -z "$BW" ]]; then
  die "bw CLI not found on PATH. On this host it is mise-managed (not /usr/local/bin/bw); install it (e.g. \`mise use -g node@lts && npm install -g @bitwarden/cli\`) or set BW_BIN=/path/to/bw"
fi
ok "bw resolved: $BW"

command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"
ok "python3 found"

command -v jq >/dev/null 2>&1 || die "jq not found on PATH"
ok "jq found"

if ! kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" >/dev/null 2>&1; then
  die "secret $NAMESPACE/$SECRET_NAME not found — run deploy/setup-agent-account.sh first"
fi

declare -A SECRET_VALS
for key in BW_SERVER BW_CLIENTID BW_CLIENTSECRET BW_PASSWORD; do
  val="$(kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" -o jsonpath="{.data.$key}" 2>/dev/null | base64 -d 2>/dev/null || true)"
  if [[ -z "$val" ]]; then
    die "secret $NAMESPACE/$SECRET_NAME is missing or has an empty key '$key' — run deploy/setup-agent-account.sh"
  fi
  SECRET_VALS["$key"]="$val"
done
ok "secret $NAMESPACE/$SECRET_NAME has all four required keys"

# ── load agent credentials (never printed) ────────────────────────────────────
export BW_SERVER="${SECRET_VALS[BW_SERVER]}"
export BW_CLIENTID="${SECRET_VALS[BW_CLIENTID]}"
export BW_CLIENTSECRET="${SECRET_VALS[BW_CLIENTSECRET]}"
export BW_PASSWORD="${SECRET_VALS[BW_PASSWORD]}"
unset SECRET_VALS

# ── isolated bw profile (never touches the owner's own bw login state) ──────────
umask 077
TMPDIR_BW="$(mktemp -d)"
# HOME is left unchanged on purpose; BITWARDENCLI_APPDATA_DIR is what actually
# isolates the bw CLI's profile/session state to this throwaway directory.
export BITWARDENCLI_APPDATA_DIR="$TMPDIR_BW"

GRANT_APPLIED=0
GRANT_BACKUP=""

cleanup() {
  "$BW" logout >/dev/null 2>&1 || true
  rm -rf "$TMPDIR_BW"
}
trap cleanup EXIT

# ── vault session ─────────────────────────────────────────────────────────────
section "Vault session"

"$BW" config server "$BW_SERVER" >/dev/null
ok "server configured"

LOGIN_OUT="$("$BW" login --apikey 2>&1)" && LOGIN_RC=0 || LOGIN_RC=$?
if [[ $LOGIN_RC -ne 0 ]]; then
  if echo "$LOGIN_OUT" | grep -qi "already logged in"; then
    warn "bw reported already logged in (unexpected for a fresh profile) — continuing"
  else
    echo "$LOGIN_OUT" >&2
    die "bw login --apikey failed"
  fi
fi
ok "logged in as cvc-agent@local"

SESSION="$("$BW" unlock --passwordenv BW_PASSWORD --raw)"
[[ -n "$SESSION" ]] || die "bw unlock returned an empty session key"
export BW_SESSION="$SESSION"
unset SESSION
ok "vault unlocked"

"$BW" sync >/dev/null
ok "synced latest vault state"

# ── build the item JSON + base64 payload (values only ever cross via env) ────
export CVC_ITEM_NAME="$NAME"
export CVC_ITEM_USERNAME="$USERNAME"
export CVC_ITEM_PASSWORD="$PASSWORD"
export CVC_ITEM_URI="$URI"

ENCODED="$(python3 -c '
import base64, json, os

name = os.environ["CVC_ITEM_NAME"]
username = os.environ["CVC_ITEM_USERNAME"]
password = os.environ["CVC_ITEM_PASSWORD"]
uri = os.environ.get("CVC_ITEM_URI", "")

item = {
    "type": 1,
    "name": name,
    "login": {
        "username": username,
        "password": password,
        "uris": [{"match": None, "uri": uri}] if uri else [],
    },
}
print(base64.b64encode(json.dumps(item).encode()).decode())
')"
unset CVC_ITEM_PASSWORD

# ── create the item (payload on stdin, never on argv) ────────────────────────
section "Creating item"

CREATE_OUT="$(printf '%s' "$ENCODED" | "$BW" create item)"
unset ENCODED
UUID="$(printf '%s' "$CREATE_OUT" | jq -r '.id // empty')"
UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
if [[ -z "$UUID" ]] || ! [[ "$UUID" =~ $UUID_RE ]]; then
  die "bw create item did not return a valid UUID (got: '${UUID:-<empty>}')"
fi
ok "item created"

# ── result ─────────────────────────────────────────────────────────────────────
section "Result"
echo "  Item name : $NAME"
echo "  Username  : $USERNAME"
echo "  URI       : ${URI:-<none>}"
echo "  UUID      : $UUID"
echo
echo "Paste this into deploy/broker-acl.yaml under the agent that should get access:"
echo
echo "    - credential: \"$UUID\""
echo "      purposes: [\"${GRANT_PURPOSE:-<your-purpose>}\"]"
echo
warn "The running cvc-broker pod holds its own bw profile in an in-memory emptyDir and"
warn "does NOT re-sync on its own. This item will 502 (\"vault retrieval failed\") through"
warn "the broker until the pod restarts (its init container logs in + syncs fresh)."
warn "Run: kubectl -n cvc rollout restart deploy/$DEPLOY_NAME   (or pass --restart-broker)"

# ── --grant: append allow entry to broker-acl.yaml ────────────────────────────
if [[ -n "$GRANT_AGENT" ]]; then
  section "Granting $GRANT_AGENT:$GRANT_PURPOSE"

  if [[ ! -f "$ACL_FILE" ]]; then
    fail "ACL file not found at $ACL_FILE — item $UUID was still created; add the grant manually"
    exit 1
  fi

  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  GRANT_BACKUP="${ACL_FILE}.bak-${TS}"
  cp "$ACL_FILE" "$GRANT_BACKUP"
  echo "  Backup: $GRANT_BACKUP"

  export CVC_ACL_FILE="$ACL_FILE"
  export CVC_GRANT_AGENT="$GRANT_AGENT"
  export CVC_GRANT_PURPOSE="$GRANT_PURPOSE"
  export CVC_GRANT_UUID="$UUID"

  set +e
  EDIT_ERR="$(python3 - <<'PYEOF' 2>&1
import os, re, sys

acl_file = os.environ["CVC_ACL_FILE"]
agent = os.environ["CVC_GRANT_AGENT"]
purpose = os.environ["CVC_GRANT_PURPOSE"]
uuid = os.environ["CVC_GRANT_UUID"]

with open(acl_file, encoding="utf-8") as fh:
    lines = fh.readlines()


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def refuse(msg):
    print(f"REFUSE: {msg}", file=sys.stderr)
    sys.exit(1)


agents_idx = None
for i, line in enumerate(lines):
    if line.rstrip("\n") == "agents:":
        agents_idx = i
        break
if agents_idx is None:
    refuse("no top-level 'agents:' key found in ACL file")

agents_indent = indent_of(lines[agents_idx])
agent_entry_indent = agents_indent + 2

# Collect top-level agent entries under agents:
entries = []  # (line_idx, name)
end_of_agents = len(lines)
i = agents_idx + 1
while i < len(lines):
    line = lines[i]
    bare = line.rstrip("\n").strip()
    if bare == "" or bare.startswith("#"):
        i += 1
        continue
    cur_indent = indent_of(line)
    if cur_indent < agent_entry_indent:
        end_of_agents = i
        break
    if cur_indent == agent_entry_indent:
        m = re.match(r'^([^:#\s][^:]*):\s*(#.*)?$', bare)
        if m:
            entries.append((i, m.group(1)))
    i += 1

target = next(((idx, nm) for idx, nm in entries if nm == agent), None)
if target is None:
    refuse(f"agent '{agent}' not found under agents: in {acl_file}")

target_idx = target[0]
following = [idx for idx, _ in entries if idx > target_idx]
agent_block_end = min(following) if following else end_of_agents

# Find this agent's allow: line
allow_idx = None
allow_indent = None
allow_trailing = ""
for j in range(target_idx + 1, agent_block_end):
    line = lines[j]
    bare = line.rstrip("\n").strip()
    if bare == "" or bare.startswith("#"):
        continue
    cur_indent = indent_of(line)
    if cur_indent == agent_entry_indent + 2:
        m = re.match(r'^allow:(.*)$', bare)
        if m:
            allow_idx = j
            allow_indent = cur_indent
            allow_trailing = m.group(1)
            break

if allow_idx is None:
    refuse(f"no 'allow:' key found for agent '{agent}'")

trailing_nocomment = allow_trailing.split("#")[0].strip()
if trailing_nocomment == "[]":
    refuse("allow: is written inline as 'allow: []' — convert it to block-list form manually first")

# Walk the existing allow list (if any) to find its extent, entry indentation,
# and any already-listed credentials.
entry_indent = None
credentials = []
last_list_line = allow_idx
j = allow_idx + 1
while j < agent_block_end:
    line = lines[j]
    bare = line.rstrip("\n").strip()
    if bare == "" or bare.startswith("#"):
        j += 1
        continue
    cur_indent = indent_of(line)
    if cur_indent <= allow_indent:
        break
    m = re.match(r'^-\s*credential:\s*"?([0-9a-fA-F-]+)"?\s*(#.*)?$', bare)
    if m:
        if entry_indent is None:
            entry_indent = cur_indent
        credentials.append(m.group(1))
    last_list_line = j
    j += 1

if any(c.lower() == uuid.lower() for c in credentials):
    refuse(f"credential '{uuid}' is already listed for agent '{agent}'")

cred_indent = entry_indent if entry_indent is not None else allow_indent + 2
purposes_indent = cred_indent + 2

new_lines = [
    " " * cred_indent + f'- credential: "{uuid}"\n',
    " " * purposes_indent + f'purposes: ["{purpose}"]\n',
]

insert_at = last_list_line + 1
new_content = lines[:insert_at] + new_lines + lines[insert_at:]

with open(acl_file, "w", encoding="utf-8") as fh:
    fh.writelines(new_content)

print("OK")
PYEOF
)"
  EDIT_RC=$?
  set -e

  if [[ $EDIT_RC -ne 0 ]]; then
    fail "grant refused — deploy/broker-acl.yaml was NOT modified: $EDIT_ERR"
    fail "the credential item itself was still created successfully (UUID: $UUID) — add the allow entry by hand"
    exit 1
  fi
  ok "appended allow entry"

  if ! ( cd "$REPO_ROOT" && python3 -c 'import sys; from cvc.broker.acl import Acl; Acl.load(sys.argv[1])' "$ACL_FILE" ); then
    fail "edited ACL file failed to reload via Acl.load() — restoring backup"
    cp "$GRANT_BACKUP" "$ACL_FILE"
    fail "deploy/broker-acl.yaml restored from backup; item $UUID was still created — add the grant by hand"
    exit 1
  fi
  ok "ACL file re-validated with Acl.load()"

  kubectl -n "$NAMESPACE" create secret generic cvc-broker-acl \
    --from-file=broker-acl.yaml="$ACL_FILE" --dry-run=client -o yaml | kubectl apply -f -
  ok "cvc-broker-acl secret updated"
  GRANT_APPLIED=1
  warn "the grant takes effect only after the broker pod restarts — see --restart-broker below"
fi

# ── --restart-broker ───────────────────────────────────────────────────────────
if [[ "$RESTART_BROKER" -eq 1 ]]; then
  section "Restarting broker"
  kubectl -n "$NAMESPACE" rollout restart "deploy/$DEPLOY_NAME"
  kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY_NAME" --timeout=180s
  ok "broker restarted"
fi

exit 0
