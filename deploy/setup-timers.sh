#!/usr/bin/env bash
#
# setup-timers.sh — install cvc-remind and cvc-backup as systemd USER timers (D10).
#
# Run once as admin on the OPi. This replaces the k3s CronJob deployment: the jobs now
# run on the host, where the `onedrive` client is already installed and authenticated
# and the HA MQTT broker is reachable on the LAN.
#
# What it does:
#   0. Preflight: the cvc console scripts and `bw` are actually reachable from a
#      systemd user unit's minimal environment. This is the step that catches the two
#      ways this deployment silently fails (see NOTES at the bottom).
#   1. Installs deploy/cvc-{remind,backup}.{service,timer} into ~/.config/systemd/user/
#   2. systemctl --user daemon-reload
#   3. Creates ~/.config/cvc (700) and ~/.local/share/cvc/bw (700)
#   4. Creates the OneDrive staging dir (plain NVMe path — just mkdir -p)
#   5. Prints the commands to create remind.env / backup.env. It NEVER creates them —
#      they hold real credentials.
#   6. Enables and starts both timers, then shows the schedule
#
# Idempotent: re-running re-copies the units, re-reloads, and re-checks the same state.
# Re-run it after a `pip install -e .` or a mise python/node upgrade — that is what
# repairs the ~/.local/bin symlinks.
#
# Deliberately NOT done here:
#   - Creating the env files (real credentials — see the printed instructions).
#   - Running the jobs (use: systemctl --user start cvc-remind.service).
#   - Anything requiring sudo. Where a root step is needed it is printed, not run.
#
# Usage:
#   deploy/setup-timers.sh                 # full install
#   deploy/setup-timers.sh --dry-run       # report only, change nothing
#   deploy/setup-timers.sh --no-enable     # install units but do not enable/start
#   deploy/setup-timers.sh --help
#
# Exit codes:
#   0 = install complete (missing env files are reported, not fatal)
#   1 = a preflight or install failure
#   2 = usage error

set -uo pipefail

DEPLOY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEPLOY/.." && pwd)"

UNIT_DIR="$HOME/.config/systemd/user"
CONFIG_DIR="$HOME/.config/cvc"
BW_DATA_DIR="$HOME/.local/share/cvc/bw"
BIN_DIR="$HOME/.local/bin"
BACKUP_DIR="/mnt/data/onedrive/dan_ai_tool_dock/cvc-backups"
ONEDRIVE_CONF="$HOME/.config/onedrive"

UNITS=(cvc-remind.service cvc-remind.timer cvc-backup.service cvc-backup.timer)
TIMERS=(cvc-remind.timer cvc-backup.timer)

DRY_RUN=0
NO_ENABLE=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; FAILURES=$((FAILURES + 1)); }
warn() { echo -e "${YELLOW}  !${NC} $*"; }
section() { echo; echo "── $* ──────────────────────────────────────────────────"; }

FAILURES=0

usage() {
    cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [--dry-run] [--no-enable] [--help]

Install cvc-remind and cvc-backup as systemd user timers on this host (D10).

Options:
  --dry-run     Report what would change and make no changes.
  --no-enable   Install and validate the units but do not enable/start the timers.
  -h, --help    Show this help and exit 0.

Next steps after this script:
  install -m 600 deploy/remind.env.example ~/.config/cvc/remind.env   # then edit
  install -m 600 deploy/backup.env.example ~/.config/cvc/backup.env   # then edit
  systemctl --user restart cvc-remind.timer cvc-backup.timer
  systemctl --user start cvc-remind.service     # one-off run, watch the journal
  journalctl --user -u cvc-remind -f
EOF
}

for arg in "$@"; do
    case "$arg" in
        --dry-run)   DRY_RUN=1 ;;
        --no-enable) NO_ENABLE=1 ;;
        -h|--help)   usage; exit 0 ;;
        *)
            echo "Unknown argument: $arg" >&2
            echo "Run with --help for usage." >&2
            exit 2
            ;;
    esac
done

# ── 0. preflight ──────────────────────────────────────────────────────────────
section "0. Preflight"

if ! systemctl --user show-environment >/dev/null 2>&1; then
    fail "no systemd user session — cannot manage user units"
    echo "  If this is an SSH session without a login seat, enable lingering first:"
    echo "    sudo loginctl enable-linger $(id -un)"
    echo "  (lingering is also required for the timers to fire when nobody is logged in)"
    exit 1
fi
ok "systemd user session reachable"

if loginctl show-user "$(id -u)" -p Linger 2>/dev/null | grep -q 'Linger=yes'; then
    ok "lingering enabled — timers fire without an active login session"
else
    warn "lingering is NOT enabled: the user manager (and these timers) stop when the"
    warn "  last session ends, so a 07:00 run with nobody logged in will never happen."
    warn "  Fix (one-time, needs root):  sudo loginctl enable-linger $(id -un)"
fi

for u in "${UNITS[@]}"; do
    if [[ -f "$DEPLOY/$u" ]]; then
        ok "deploy/$u present"
    else
        fail "deploy/$u MISSING — cannot continue"
    fi
done
for e in remind.env.example backup.env.example; do
    if [[ -f "$DEPLOY/$e" ]]; then
        ok "deploy/$e present"
    else
        fail "deploy/$e MISSING"
    fi
done
if [[ "$FAILURES" -gt 0 ]]; then
    exit 1
fi

# ── 0b. console scripts on ~/.local/bin ───────────────────────────────────────
# The units use ExecStart=%h/.local/bin/cvc-{remind,backup}, but `pip install -e .`
# puts the console scripts in whichever python is active — here the mise-managed
# interpreter (~/.local/share/mise/installs/python/3.12/bin), NOT ~/.local/bin. A
# missing script shows up only as status=203/EXEC in the journal, so link it here.
section "0b. cvc console scripts"

PY_BIN_DIR="$(python -c 'import sysconfig; print(sysconfig.get_path("scripts"))' 2>/dev/null || true)"
[[ -n "$PY_BIN_DIR" ]] && ok "active python scripts dir: $PY_BIN_DIR"

if [[ "$DRY_RUN" -eq 0 ]]; then
    mkdir -p "$BIN_DIR"
fi

for cmd in cvc-remind cvc-backup; do
    # Resolve the real console script, ignoring anything already in ~/.local/bin so a
    # stale/broken symlink there cannot satisfy its own check.
    TARGET=""
    if [[ -n "$PY_BIN_DIR" && -x "$PY_BIN_DIR/$cmd" ]]; then
        TARGET="$PY_BIN_DIR/$cmd"
    else
        RESOLVED="$(command -v "$cmd" 2>/dev/null || true)"
        # command -v may return the ~/.local/bin symlink or a mise shim; follow it.
        [[ -n "$RESOLVED" ]] && RESOLVED="$(readlink -f "$RESOLVED" 2>/dev/null || true)"
        [[ -n "$RESOLVED" && -x "$RESOLVED" ]] && TARGET="$RESOLVED"
    fi

    if [[ -z "$TARGET" ]]; then
        fail "$cmd is not installed anywhere — the unit would fail with status=203/EXEC"
        echo "      Install the package (the entry points come from [project.scripts]):"
        echo "        cd $REPO_ROOT && pip install -e ."
        echo "      then re-run this script."
        continue
    fi

    if [[ -x "$BIN_DIR/$cmd" && "$(readlink -f "$BIN_DIR/$cmd")" == "$(readlink -f "$TARGET")" ]]; then
        ok "$BIN_DIR/$cmd → $TARGET"
    elif [[ "$DRY_RUN" -eq 1 ]]; then
        warn "dry-run — would link $BIN_DIR/$cmd → $TARGET"
    elif ln -sfn "$TARGET" "$BIN_DIR/$cmd"; then
        ok "linked $BIN_DIR/$cmd → $TARGET"
    else
        fail "could not link $BIN_DIR/$cmd → $TARGET"
    fi
done

# ── 0c. bw CLI at the hardcoded path ─────────────────────────────────────────
# src/cvc/vault/client.py has _BW = "/usr/local/bin/bw" as an absolute path — PATH is
# not consulted for it. In the container image that path existed; on this host the
# Bitwarden CLI comes from mise (node), so /usr/local/bin/bw must be created by hand.
# Symptom if missing: VaultError "bw CLI not found — install Bitwarden CLI".
section "0c. bw CLI (/usr/local/bin/bw — hardcoded in cvc.vault.client)"

BW_HARDCODED="/usr/local/bin/bw"
BW_ON_PATH="$(command -v bw 2>/dev/null || true)"

if [[ -x "$BW_HARDCODED" ]]; then
    ok "$BW_HARDCODED exists"
    if BW_VER="$(env -i PATH="/usr/local/bin:/usr/bin:/bin" HOME="$HOME" \
            "$BW_HARDCODED" --version 2>&1)"; then
        ok "bw runs from a minimal environment (version $BW_VER)"
    else
        # bw is a #!/usr/bin/env node script; node lives in mise, not /usr/bin.
        warn "bw exists but fails from a minimal PATH:"
        warn "  ${BW_VER:-<no output>}"
        warn "  The units set PATH to include the mise node bin dir, which covers this."
        warn "  To make it independent of PATH, replace $BW_HARDCODED with a wrapper"
        warn "  that invokes node by absolute path (see NOTES in this script)."
    fi
elif [[ -n "$BW_ON_PATH" ]]; then
    BW_REAL="$(readlink -f "$BW_ON_PATH")"
    NODE_BIN="$(readlink -f "$(command -v node 2>/dev/null || true)" 2>/dev/null || true)"
    fail "bw is installed at $BW_ON_PATH but NOT at $BW_HARDCODED"
    echo "      cvc.vault.client calls $BW_HARDCODED by absolute path, so every vault"
    echo "      call will fail with: VaultError: bw CLI not found — install Bitwarden CLI"
    echo
    echo "      One-time fix (needs root). A wrapper, not a symlink: bw is a"
    echo "      '#!/usr/bin/env node' script and node is only in mise, so a bare symlink"
    echo "      breaks the moment PATH lacks the mise node dir."
    echo
    echo "        sudo tee $BW_HARDCODED >/dev/null <<'WRAP'"
    echo "        #!/bin/sh"
    echo "        exec ${NODE_BIN:-<path to node>} $BW_REAL \"\$@\""
    echo "        WRAP"
    echo "        sudo chmod 0755 $BW_HARDCODED"
    echo
else
    fail "bw CLI not found anywhere — install the Bitwarden CLI first"
    echo "      e.g.  mise exec node -- npm install -g @bitwarden/cli"
fi

if [[ -x "/usr/local/bin/onedrive" ]]; then
    ok "onedrive client present: /usr/local/bin/onedrive"
else
    fail "/usr/local/bin/onedrive MISSING — cvc-backup's off-host sync cannot run"
fi

if [[ -f "$ONEDRIVE_CONF/refresh_token" ]]; then
    ok "onedrive authorized (refresh_token present in $ONEDRIVE_CONF)"
elif [[ -d "$ONEDRIVE_CONF" ]]; then
    warn "no refresh_token in $ONEDRIVE_CONF — authorize the client first:"
    warn "  onedrive --reauth"
    warn "  (without it the sync fails; that is non-fatal by design, D9 — the backup"
    warn "   still exits 0 and only the off-host copy is missing)"
else
    warn "onedrive config dir missing: $ONEDRIVE_CONF"
fi

# ── 1. install the unit files ─────────────────────────────────────────────────
section "1. Unit files → $UNIT_DIR"

if [[ "$DRY_RUN" -eq 1 ]]; then
    for u in "${UNITS[@]}"; do
        warn "dry-run — would install $u"
    done
else
    mkdir -p "$UNIT_DIR" || { fail "could not create $UNIT_DIR"; exit 1; }
    ok "$UNIT_DIR ready"
    for u in "${UNITS[@]}"; do
        # Copy, not symlink: `systemctl --user enable` on a unit whose file is itself a
        # symlink into a repo has surprising [Install] behaviour, and a moved/renamed
        # checkout would silently break every installed unit.
        if install -m 0644 "$DEPLOY/$u" "$UNIT_DIR/$u"; then
            ok "installed $u"
        else
            fail "could not install $u"
        fi
    done
fi

# ── 2. daemon-reload ──────────────────────────────────────────────────────────
section "2. Reload the user manager"

if [[ "$DRY_RUN" -eq 1 ]]; then
    warn "dry-run — would run: systemctl --user daemon-reload"
else
    if systemctl --user daemon-reload; then
        ok "systemctl --user daemon-reload"
    else
        fail "daemon-reload failed"
    fi

    # Catches the classic authoring mistakes: a trailing `# comment` on a directive
    # value, or a [Service]-only key placed in [Unit].
    if command -v systemd-analyze >/dev/null 2>&1; then
        VERIFY_OUT="$(systemd-analyze --user verify \
            "$UNIT_DIR/cvc-remind.service" "$UNIT_DIR/cvc-remind.timer" \
            "$UNIT_DIR/cvc-backup.service" "$UNIT_DIR/cvc-backup.timer" 2>&1 \
            | grep -v 'remind\.env\|backup\.env' || true)"
        if [[ -z "$VERIFY_OUT" ]]; then
            ok "systemd-analyze verify: clean"
        else
            warn "systemd-analyze verify reported:"
            echo "$VERIFY_OUT" | sed 's/^/      /'
        fi
    fi
fi

# ── 3. state directories ──────────────────────────────────────────────────────
section "3. State directories"

make_dir_700() {
    local d="$1" label="$2"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        [[ -d "$d" ]] && ok "$label exists: $d" || warn "dry-run — would create $d (700)"
        return
    fi
    if mkdir -p "$d" && chmod 700 "$d"; then
        ok "$label ready (700): $d"
    else
        fail "could not create $d"
    fi
}

# 700 on ~/.config/cvc because the env files inside hold the vault master password.
make_dir_700 "$CONFIG_DIR" "env dir"
# bw writes data.json here (login state, encrypted key material).
make_dir_700 "$BW_DATA_DIR" "bw app-data dir"

# ── 4. OneDrive staging dir ───────────────────────────────────────────────────
section "4. Backup destination"

# Plain NVMe path inside the onedrive client's sync_dir — no PVC, no hostPath, and no
# chown: the timer runs AS admin, so the old "chown 1000:1000" step from the CronJob
# era is gone.
if [[ -d "$BACKUP_DIR" ]]; then
    ok "staging dir exists: $BACKUP_DIR"
elif [[ "$DRY_RUN" -eq 1 ]]; then
    warn "dry-run — would run: mkdir -p $BACKUP_DIR"
elif mkdir -p "$BACKUP_DIR"; then
    ok "created $BACKUP_DIR"
else
    fail "could not create $BACKUP_DIR as $(id -un) — run:"
    echo "        sudo mkdir -p $BACKUP_DIR && sudo chown $(id -u):$(id -g) $BACKUP_DIR"
fi

if [[ -d "$BACKUP_DIR" && -w "$BACKUP_DIR" ]]; then
    ok "staging dir is writable by $(id -un)"
elif [[ -d "$BACKUP_DIR" ]]; then
    fail "staging dir is NOT writable by $(id -un) — bw export will fail with EACCES"
    echo "        sudo chown $(id -u):$(id -g) $BACKUP_DIR"
fi

# ── 5. env files (reported, never created) ────────────────────────────────────
section "5. Env files (must be created by hand — real credentials)"

MISSING_ENV=()
for pair in "remind.env:remind.env.example" "backup.env:backup.env.example"; do
    f="${pair%%:*}"; ex="${pair##*:}"
    if [[ -f "$CONFIG_DIR/$f" ]]; then
        MODE="$(stat -c '%a' "$CONFIG_DIR/$f" 2>/dev/null || echo '?')"
        if [[ "$MODE" == "600" ]]; then
            ok "$CONFIG_DIR/$f exists (mode 600)"
        else
            warn "$CONFIG_DIR/$f exists but mode is $MODE — it holds the vault master"
            warn "  password. Fix:  chmod 600 $CONFIG_DIR/$f"
        fi
        # A left-in placeholder is worse than a missing file: the unit starts and then
        # fails authentication, which looks like a credential problem.
        if grep -q '<' "$CONFIG_DIR/$f" 2>/dev/null; then
            warn "$f still contains <placeholder> values — the run will fail auth"
        fi
    else
        fail "$CONFIG_DIR/$f is MISSING"
        MISSING_ENV+=("$f:$ex")
    fi
done

if [[ "${#MISSING_ENV[@]}" -gt 0 ]]; then
    echo
    echo "  Create the missing env file(s), then replace every <placeholder>:"
    for pair in "${MISSING_ENV[@]}"; do
        f="${pair%%:*}"; ex="${pair##*:}"
        echo
        echo "    install -m 600 $DEPLOY/$ex $CONFIG_DIR/$f"
        echo "    \${EDITOR:-nano} $CONFIG_DIR/$f"
    done
    echo
    echo "  These files are NOT in git (.gitignore covers *.env) and must never be."
    echo "  Values needed: BW_CLIENTID/BW_CLIENTSECRET from Vaultwarden Account"
    echo "  Settings → API Key, BW_PASSWORD = vault master password, and for remind"
    echo "  the MQTT_* credentials of the Home Assistant broker on its LAN address."
    echo
fi

# ── 6. enable + start the timers ──────────────────────────────────────────────
section "6. Timers"

if [[ "$NO_ENABLE" -eq 1 ]]; then
    warn "--no-enable — units installed but not enabled. To enable later:"
    warn "  systemctl --user enable --now ${TIMERS[*]}"
elif [[ "$DRY_RUN" -eq 1 ]]; then
    warn "dry-run — would run: systemctl --user enable --now ${TIMERS[*]}"
else
    # Enabling a .timer never runs the .service, so a missing env file is safe here:
    # the schedule is armed and the first real run happens at the next OnCalendar hit.
    if systemctl --user enable --now "${TIMERS[@]}"; then
        ok "enabled and started: ${TIMERS[*]}"
    else
        fail "could not enable/start the timers"
    fi

    for t in "${TIMERS[@]}"; do
        STATE="$(systemctl --user is-active "$t" 2>/dev/null || true)"
        if [[ "$STATE" == "active" ]]; then
            ok "$t is active"
        else
            fail "$t is '$STATE' — inspect with: systemctl --user status $t"
        fi
    done

    echo
    systemctl --user list-timers "${TIMERS[@]}" --all || true
fi

# ── summary ───────────────────────────────────────────────────────────────────
section "Summary"

echo "  Units:      $UNIT_DIR/cvc-{remind,backup}.{service,timer}"
echo "  Env files:  $CONFIG_DIR/{remind,backup}.env  (mode 600, not in git)"
echo "  bw appdata: $BW_DATA_DIR"
echo "  Backups:    $BACKUP_DIR"
echo "  cvc-remind: daily 07:00 UTC"
echo "  cvc-backup: weekly Sunday 02:00 UTC"
echo "  Logs:       journalctl --user -u cvc-remind   /   -u cvc-backup"

if [[ "$FAILURES" -eq 0 ]]; then
    echo
    echo -e "${GREEN}Timer install complete.${NC}"
    echo "Next steps: fill in ~/.config/cvc/remind.env and ~/.config/cvc/backup.env, then run: systemctl --user restart cvc-remind.timer cvc-backup.timer"
    echo
    echo "  Then prove a real run before trusting the schedule:"
    echo "    systemctl --user start cvc-remind.service && journalctl --user -u cvc-remind -n 50"
    echo "    systemctl --user start cvc-backup.service && journalctl --user -u cvc-backup -n 50"
    exit 0
fi

echo
echo -e "${RED}$FAILURES check(s) failed — see above.${NC}"
echo "Next steps: fill in ~/.config/cvc/remind.env and ~/.config/cvc/backup.env, then run: systemctl --user restart cvc-remind.timer cvc-backup.timer"
exit 1

# ── NOTES — the two non-obvious ways this deployment fails ────────────────────
#
# 1. ExecStart not found (status=203/EXEC).
#    `pip install -e .` installs the console scripts into the ACTIVE python's scripts
#    dir. On this host that is the mise interpreter, not ~/.local/bin. Step 0b links
#    them. A mise python upgrade moves the target — re-run this script to repair.
#    Also note that cvc-backup only exists once the package has been reinstalled since
#    the cvc-backup entry point was added to pyproject.toml.
#
# 2. "bw CLI not found — install Bitwarden CLI".
#    src/cvc/vault/client.py pins _BW = "/usr/local/bin/bw" as an absolute path. The
#    Bitwarden CLI here is a mise-managed node package, so that path does not exist
#    until the wrapper in step 0c is created. The wrapper (rather than a symlink) also
#    removes the dependency on node being on PATH, because bw's shebang is
#    `#!/usr/bin/env node` and node is not in /usr/bin.
#
# Both are environment facts, not bugs in the units — but each surfaces only at the
# first real run, which is why they are asserted here instead.
