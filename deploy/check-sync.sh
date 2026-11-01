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
TAILSCALE_IP="${SITE_NODE_IP}"
TAILSCALE_HOST="${SITE_BASE_DOMAIN}"
VW_URL="https://${TAILSCALE_HOST}:8443/vault"
BROKER_PORT="8710"
# Phase 2/3 timer constants (D10 — host systemd user timers, not k3s CronJobs).
# These are the sources of truth for the schedules documented in docs/ARCHITECTURE.md,
# docs/DECISIONS.md, and the setup scripts' summaries. A drifted schedule is silent:
# the job just runs at the wrong time.
REMIND_ONCALENDAR="07:00:00"     # daily 07:00 UTC
BACKUP_ONCALENDAR="02:00:00"     # weekly Sunday 02:00 UTC
CVC_IMAGE="cvc:latest"           # still used by the Phase 4 broker deployment
# Backup paths. BACKUP_DIR is the LOCAL primary copy; ONEDRIVE_DEST_DIR is the onedrive
# client's sync_dir staging path (D9 + D10). They must differ: copy_to_onedrive() copies
# from the former into the latter, then runs `onedrive --sync`.
LOCAL_BACKUP_PATH="/mnt/data/cvc-backups"
ONEDRIVE_DEST_PATH="/mnt/data/onedrive/dan_ai_tool_dock/cvc-backups"

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
# The remind/backup CronJobs needed hostAliases because Tailscale MagicDNS does not
# resolve inside a pod netns. As host timers (D10) they use the host resolver, so the
# hostname only has to be correct in the env templates' BW_SERVER.
check_contains "remind.env.example BW_SERVER hostname"       "$CVC/deploy/remind.env.example"     "$TAILSCALE_HOST"
check_contains "backup.env.example BW_SERVER hostname"       "$CVC/deploy/backup.env.example"     "$TAILSCALE_HOST"
check_contains "opi LESSONS-LEARNED hostname"                "$OPI/LESSONS-LEARNED.md"            "$TAILSCALE_HOST"

echo
echo "── Vaultwarden URL ($VW_URL) ────────────────────────────────────────────"
check_contains "broker-deployment.yaml BW_SERVER comment"    "$CVC/deploy/broker-deployment.yaml"   "$VW_URL"
check_contains "diag.sh VW_URL"                              "$CVC/deploy/diag.sh"                  "VW_URL"
check_contains "remind.env.example BW_SERVER"                "$CVC/deploy/remind.env.example"       "BW_SERVER=$VW_URL"
check_contains "backup.env.example BW_SERVER"                "$CVC/deploy/backup.env.example"       "BW_SERVER=$VW_URL"
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
# Every pod spec that connects to Vaultwarden must have hostAliases. After D10 the
# broker is the only cvc workload left in k3s; remind/backup are host timers.
for f in "$CVC/deploy/broker-deployment.yaml"; do
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
echo "── Phase 2/3 systemd timers (D10) ───────────────────────────────────────"
# cvc-remind and cvc-backup run as HOST systemd USER timers, not k3s CronJobs (D10).
# deploy/remind-cronjob.yaml and deploy/backup-cronjob.yaml are kept as reference and
# fallback but are not applied by anything, so they are deliberately NOT checked here.

for u in cvc-remind.service cvc-remind.timer cvc-backup.service cvc-backup.timer; do
    if [[ -f "$CVC/deploy/$u" ]]; then
        ok "deploy/$u exists"
    else
        fail "deploy/$u MISSING — setup-timers.sh cannot install it"
    fi
done

# Schedules. OnCalendar drift is silent: the job just runs at the wrong time. These
# values are also quoted in docs/ARCHITECTURE.md and both setup scripts' summaries.
check_contains "cvc-remind.timer OnCalendar (daily $REMIND_ONCALENDAR UTC)" \
    "$CVC/deploy/cvc-remind.timer" "OnCalendar=*-*-* $REMIND_ONCALENDAR UTC"
check_contains "cvc-backup.timer OnCalendar (Sundays $BACKUP_ONCALENDAR UTC)" \
    "$CVC/deploy/cvc-backup.timer" "OnCalendar=Sun *-*-* $BACKUP_ONCALENDAR UTC"

# Exactly one OnCalendar per timer — a second line would add a run at a time nothing
# else here (docs, setup scripts, this file) knows about.
for f in cvc-remind.timer cvc-backup.timer; do
    COUNT=$(grep -c '^OnCalendar=' "$CVC/deploy/$f" 2>/dev/null || echo 0)
    if [[ "$COUNT" -eq 1 ]]; then
        ok "$f declares exactly one OnCalendar"
    else
        fail "$f declares $COUNT OnCalendar line(s) — expected exactly 1"
    fi
done

# Persistent=true: a run missed while the host was off fires on the next start rather
# than being silently skipped until the following week (matters most for the backup).
# Matched as a bare line, which also catches the trailing-comment bug below.
for f in cvc-remind.timer cvc-backup.timer; do
    if grep -qE '^Persistent=true[[:space:]]*$' "$CVC/deploy/$f" 2>/dev/null; then
        ok "$f sets Persistent=true (missed runs are caught up)"
    else
        fail "$f has no bare 'Persistent=true' — a missed run would be skipped"
    fi
done

# Each .timer must point at its own .service, and pull it in via Requires=.
for pair in "cvc-remind:cvc-remind.service" "cvc-backup:cvc-backup.service"; do
    name="${pair%%:*}"; svc="${pair##*:}"
    check_contains "$name.timer Unit=$svc"     "$CVC/deploy/$name.timer" "Unit=$svc"
    check_contains "$name.timer Requires=$svc" "$CVC/deploy/$name.timer" "Requires=$svc"
done

echo
echo "── Timer unit-file correctness ──────────────────────────────────────────"
# systemd does NOT support a trailing `# comment` on the same line as a directive: the
# whole remainder becomes part of the value, so `Persistent=true  # note` is an invalid
# boolean and `TimeoutStartSec=600  # note` an invalid timespan. The unit still loads and
# the bad directive is dropped with only a journal warning — exactly the kind of silent
# misconfiguration this file exists to catch.
for f in cvc-remind.service cvc-remind.timer cvc-backup.service cvc-backup.timer; do
    if BAD=$(grep -nE '^[A-Za-z][A-Za-z0-9]*=.*[^%]#' "$CVC/deploy/$f" 2>/dev/null); then
        fail "$f has a trailing '#' comment on a directive line — systemd parses it as part of the value:"
        echo "$BAD" | sed 's/^/        /'
    else
        ok "$f has no trailing-comment directives"
    fi
done

# TimeoutStartSec is a [Service] directive. In [Unit] it is ignored (the [Unit]-level
# equivalent is JobTimeoutSec=, which times the *job* not the start), so a vault hang
# would never be cut short.
for f in cvc-remind.service cvc-backup.service; do
    if sed -n '/^\[Unit\]/,/^\[Service\]/p' "$CVC/deploy/$f" 2>/dev/null \
            | grep -q '^TimeoutStartSec='; then
        fail "$f puts TimeoutStartSec in [Unit] — it only takes effect in [Service]"
    elif grep -q '^TimeoutStartSec=' "$CVC/deploy/$f" 2>/dev/null; then
        ok "$f sets TimeoutStartSec in [Service]"
    else
        fail "$f has no TimeoutStartSec — an unreachable vault would hang the unit indefinitely"
    fi
done

for pair in "cvc-remind:remind" "cvc-backup:backup"; do
    name="${pair%%:*}"; env="${pair##*:}"
    f="$CVC/deploy/$name.service"

    check_contains "$name.service Type=oneshot"  "$f" "Type=oneshot"
    # Secrets reach the unit through the env file, never the command line (ps output).
    check_contains "$name.service EnvironmentFile=%h/.config/cvc/$env.env" \
        "$f" "EnvironmentFile=%h/.config/cvc/$env.env"
    # Phase 4 lesson: without BITWARDENCLI_APPDATA_DIR, bw cannot find the login state
    # it just wrote and every vault call fails with "You are not logged in."
    check_contains "$name.service sets BITWARDENCLI_APPDATA_DIR" \
        "$f" "Environment=BITWARDENCLI_APPDATA_DIR="
    check_contains "$name.service ExecStart=%h/.local/bin/$name" \
        "$f" "ExecStart=%h/.local/bin/$name"
    # `bw` is a '#!/usr/bin/env node' script and node lives only under mise, which is
    # not on a user unit's default PATH. cvc.vault.client forwards PATH (and little
    # else) into the bw subprocess, so this is the PATH bw actually sees.
    if grep -q '^Environment=PATH=.*mise' "$f" 2>/dev/null; then
        ok "$name.service PATH includes the mise toolchain dirs (node for bw)"
    else
        fail "$name.service PATH does not include mise — bw fails with 'env: node: No such file or directory'"
    fi
    # D10 gave up kernel-enforced limits unless these are set (they replace the k8s
    # cpu 200m / memory 128Mi limits).
    check_contains "$name.service CPUQuota"  "$f" "CPUQuota="
    check_contains "$name.service MemoryMax" "$f" "MemoryMax="
    # A user unit must NOT carry User= — it already runs as the session's user, and
    # User= makes the unit fail to load entirely.
    if grep -q '^User=' "$f" 2>/dev/null; then
        fail "$name.service sets User= — invalid in a user unit; it will fail to load"
    else
        ok "$name.service has no User= (correct for a user unit)"
    fi
done

echo
echo "── Env file templates ───────────────────────────────────────────────────"
for e in remind.env.example backup.env.example; do
    if [[ -f "$CVC/deploy/$e" ]]; then
        ok "deploy/$e exists"
    else
        fail "deploy/$e MISSING — setup-timers.sh has nothing to copy from"
    fi
done

# The examples are committed. A real credential pasted into one would be published to
# git history, so every secret key must still hold a <placeholder>.
for pair in "remind.env.example:BW_CLIENTID BW_CLIENTSECRET BW_PASSWORD MQTT_PASSWORD MQTT_USERNAME MQTT_HOST" \
            "backup.env.example:BW_CLIENTID BW_CLIENTSECRET BW_PASSWORD"; do
    e="${pair%%:*}"; keys="${pair##*:}"
    [[ -f "$CVC/deploy/$e" ]] || continue
    LEAKED=""
    for k in $keys; do
        VAL=$(grep -m1 "^$k=" "$CVC/deploy/$e" 2>/dev/null | cut -d= -f2-)
        # A placeholder looks like <...>; anything else is a real value.
        if [[ -n "$VAL" && "$VAL" != *"<"*">"* ]]; then
            LEAKED+=" $k"
        fi
    done
    if [[ -z "$LEAKED" ]]; then
        ok "$e holds only <placeholder> secrets"
    else
        fail "$e appears to contain REAL value(s) for:$LEAKED — scrub before committing"
    fi
done

echo
echo "── Phase 3 backup destination (D9 + D10) ────────────────────────────────"
# The export is written to the local BACKUP_DIR, then copied into the staging dir inside
# the onedrive client's sync_dir — no PVC and no hostPath any more, because the timer runs as admin on the
# host. Every failure in the sync path is non-fatal by design (the job still exits 0),
# so a misconfiguration is invisible in the unit status and these checks are the only
# thing that catches it.
check_contains "backup.env.example BACKUP_DIR ($LOCAL_BACKUP_PATH)" \
    "$CVC/deploy/backup.env.example" "BACKUP_DIR=$LOCAL_BACKUP_PATH"
check_contains "backup.env.example ONEDRIVE_DEST_DIR ($ONEDRIVE_DEST_PATH)" \
    "$CVC/deploy/backup.env.example" "ONEDRIVE_DEST_DIR=$ONEDRIVE_DEST_PATH"
check_contains "backup.env.example ONEDRIVE_BIN" \
    "$CVC/deploy/backup.env.example" "ONEDRIVE_BIN=/usr/local/bin/onedrive"
check_contains "backup.env.example ONEDRIVE_CONFIG_DIR" \
    "$CVC/deploy/backup.env.example" "ONEDRIVE_CONFIG_DIR=/home/admin/.config/onedrive"
check_contains "cvc-backup.service Environment=BACKUP_DIR ($LOCAL_BACKUP_PATH)" \
    "$CVC/deploy/cvc-backup.service" "Environment=BACKUP_DIR=$LOCAL_BACKUP_PATH"

# BACKUP_DIR and ONEDRIVE_DEST_DIR must be different directories (local vs OneDrive).
ENV_DEST_DIR=$(grep -m1 '^ONEDRIVE_DEST_DIR=' "$CVC/deploy/backup.env.example" \
    2>/dev/null | cut -d= -f2-)
if [[ -n "$ENV_DEST_DIR" && "$ENV_DEST_DIR" != "$LOCAL_BACKUP_PATH" ]]; then
    ok "ONEDRIVE_DEST_DIR differs from the local BACKUP_DIR"
else
    fail "ONEDRIVE_DEST_DIR is unset or equals the local BACKUP_DIR — the OneDrive copy would be a no-op"
fi

# BACKUP_EXPORT_PASSWORD is REQUIRED (password-protected exports, F10).
check_contains "backup.env.example documents BACKUP_EXPORT_PASSWORD" \
    "$CVC/deploy/backup.env.example" "BACKUP_EXPORT_PASSWORD=<"
check_contains ".env.example documents BACKUP_EXPORT_PASSWORD" \
    "$CVC/.env.example" "BACKUP_EXPORT_PASSWORD"
check_contains "cvc-backup.service mentions BACKUP_EXPORT_PASSWORD" \
    "$CVC/deploy/cvc-backup.service" "BACKUP_EXPORT_PASSWORD"

# cvc-backup.service's Environment=BACKUP_DIR overrides the EnvironmentFile (later
# directives win), so a disagreement means the env file is quietly ignored and exports
# land somewhere nobody is looking.
UNIT_BACKUP_DIR=$(grep -m1 '^Environment=BACKUP_DIR=' "$CVC/deploy/cvc-backup.service" \
    2>/dev/null | cut -d= -f3-)
ENV_BACKUP_DIR=$(grep -m1 '^BACKUP_DIR=' "$CVC/deploy/backup.env.example" \
    2>/dev/null | cut -d= -f2-)
if [[ -n "$UNIT_BACKUP_DIR" && "$UNIT_BACKUP_DIR" == "$ENV_BACKUP_DIR" ]]; then
    ok "BACKUP_DIR agrees between cvc-backup.service and backup.env.example"
else
    fail "BACKUP_DIR mismatch: unit '${UNIT_BACKUP_DIR:-<none>}' != example '${ENV_BACKUP_DIR:-<none>}' — the unit's Environment= wins and the env file is ignored"
fi

# %h expands to /home/admin only; it cannot address /mnt/data. `%h/../..` "works" as a
# path but is unreadable and breaks if $HOME ever moves.
if grep -q '^Environment=BACKUP_DIR=%h' "$CVC/deploy/cvc-backup.service" 2>/dev/null; then
    fail "cvc-backup.service reaches /mnt/data via %h — use the absolute path instead"
else
    ok "cvc-backup.service uses an absolute BACKUP_DIR (not %h-relative)"
fi

# setup-timers.sh must create both dirs: a missing directory is a hard export failure,
# and there is no DirectoryOrCreate safety net now that there is no hostPath.
check_contains "setup-timers.sh creates the local BACKUP_DIR" \
    "$CVC/deploy/setup-timers.sh" "$LOCAL_BACKUP_PATH"
check_contains "setup-timers.sh creates the OneDrive staging dir" \
    "$CVC/deploy/setup-timers.sh" "$ONEDRIVE_DEST_PATH"

# The broker's on-demand trigger must be in the reviewable API contract — /docs is disabled
# on the live broker, so docs/API.md is the only place a caller can discover it.
check_contains "docs/API.md documents POST /v1/backup/trigger" \
    "$CVC/docs/API.md" "POST /v1/backup/trigger"

# The endpoint is ACL-gated on the non-UUID "backup" sentinel; if the ACL template loses the
# entry, every trigger returns 403 with no other symptom.
check_contains "broker-acl.yaml has the backup sentinel entry" \
    "$CVC/deploy/broker-acl.yaml" 'credential: "backup"'

echo
echo "── Phase 2/3 deployment scripts ─────────────────────────────────────────"
# setup-timers.sh is the live installer (D10); setup-phase23.sh is now a reporting /
# redirect script, and smoke-phase23.sh still drives one-off runs.
for s in setup-timers.sh setup-phase23.sh smoke-phase23.sh; do
    if [[ -f "$CVC/deploy/$s" ]]; then
        if [[ -x "$CVC/deploy/$s" ]]; then
            ok "deploy/$s exists and is executable"
        else
            fail "deploy/$s exists but is not executable (chmod +x)"
        fi
    else
        fail "deploy/$s MISSING"
    fi
done

# setup-phase23.sh must not still apply the retired CronJob/PVC manifests: if both it
# and setup-timers.sh run, the job is installed twice and fires twice.
# The leading [^#[:space:]] skips comment lines: the retired commands are KEPT in the
# script as commented-out history, which must not trip this check.
if LIVE=$(grep -nE '^[[:space:]]*[^#[:space:]].*kubectl apply -f.*(cronjob|backup-pvc)' \
        "$CVC/deploy/setup-phase23.sh" 2>/dev/null); then
    fail "setup-phase23.sh still applies a retired CronJob/PVC manifest — remove or comment it out (D10):"
    echo "$LIVE" | sed 's/^/        /'
else
    ok "setup-phase23.sh no longer applies the CronJob/PVC manifests"
fi
check_contains "setup-phase23.sh points at setup-timers.sh" \
    "$CVC/deploy/setup-phase23.sh" "setup-timers.sh"

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
