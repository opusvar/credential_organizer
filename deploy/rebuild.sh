#!/usr/bin/env bash
#
# rebuild.sh — build the cvc broker image and load it into k3s containerd
#
# Why this exists:
#   k3s runs its own embedded containerd, completely separate from the
#   system/nerdctl containerd that `nerdctl build` populates. Building an
#   image with nerdctl does NOT make it visible to k3s's containerd, so a
#   `kubectl rollout restart` against cvc-broker would just re-pull (or
#   fail to find) the old image. The fix is to build the image with
#   nerdctl, save it to a tarball, and explicitly import that tarball into
#   k3s's own containerd namespace (`k3s ctr -n k8s.io images import`).
#   This script wraps that whole build -> save -> import pipeline, plus an
#   optional rollout restart, into one command.
#
# Steps performed:
#   1. sudo nerdctl build -t "$IMAGE" "$REPO_ROOT"
#   2. sudo nerdctl save "$IMAGE" -o "$TARBALL"
#   3. sudo k3s ctr -n k8s.io images import "$TARBALL"
#
# Usage:
#   deploy/rebuild.sh                # build, save, import
#   deploy/rebuild.sh --restart      # ...then rollout restart + wait for it
#   deploy/rebuild.sh --help         # show this usage text
#
# Configuration (environment variables, all optional):
#   CVC_IMAGE       image name:tag to build          (default: cvc:latest)
#   CVC_NAMESPACE   k8s namespace                    (default: cvc)
#   CVC_DEPLOYMENT  k8s deployment name               (default: cvc-broker)
#   KUBECONFIG      path to kubeconfig                (default: /home/admin/.kube/config)
#
# Notes:
#   - This script runs `sudo nerdctl` and `sudo k3s ctr`, which will prompt
#     interactively for your password (there is no NOPASSWD rule on this
#     host). Run it from an interactive terminal, not from a non-interactive
#     job that can't answer a password prompt.
#   - kubectl itself does NOT need sudo; only KUBECONFIG needs to be set.

set -euo pipefail

# ── resolve repo root from this script's own location, not the caller's cwd ──
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── configurable settings ─────────────────────────────────────────────────────
IMAGE="${CVC_IMAGE:-cvc:latest}"
NAMESPACE="${CVC_NAMESPACE:-cvc}"
DEPLOYMENT="${CVC_DEPLOYMENT:-cvc-broker}"
export KUBECONFIG="${KUBECONFIG:-/home/admin/.kube/config}"

RESTART=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }
section() { echo; echo "── $* ──────────────────────────────────────────────────"; }

usage() {
    cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [--restart] [--help]

Builds cvc:latest with nerdctl, saves it to a tarball, and imports it into
k3s's embedded containerd (namespace k8s.io) so the cvc-broker deployment
can actually pick up the new image.

Options:
  --restart   After a successful import, run
                kubectl -n <namespace> rollout restart deploy/<deployment>
              and wait for it to complete (--timeout=180s).
  --help, -h  Show this help text and exit.

Environment overrides:
  CVC_IMAGE       (default: cvc:latest)
  CVC_NAMESPACE   (default: cvc)
  CVC_DEPLOYMENT  (default: cvc-broker)
  KUBECONFIG      (default: /home/admin/.kube/config)

Examples:
  deploy/rebuild.sh
  deploy/rebuild.sh --restart
  CVC_IMAGE=cvc:dev deploy/rebuild.sh --restart
EOF
}

# ── argument parsing ──────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --restart)
            RESTART=1
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown flag: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# ── preflight checks ──────────────────────────────────────────────────────────
section "Preflight checks"

if [[ ! -f "${REPO_ROOT}/Dockerfile" ]]; then
    fail "No Dockerfile found at ${REPO_ROOT}/Dockerfile"
    exit 1
fi
ok "Dockerfile found at ${REPO_ROOT}/Dockerfile"

if ! command -v nerdctl >/dev/null 2>&1; then
    fail "nerdctl not found on PATH"
    exit 1
fi
ok "nerdctl found: $(command -v nerdctl)"

if ! command -v k3s >/dev/null 2>&1; then
    fail "k3s not found on PATH"
    exit 1
fi
ok "k3s found: $(command -v k3s)"

if [[ "$RESTART" -eq 1 ]]; then
    if ! command -v kubectl >/dev/null 2>&1; then
        fail "kubectl not found on PATH (required for --restart)"
        exit 1
    fi
    ok "kubectl found: $(command -v kubectl)"
fi

warn "sudo will prompt for your password (nerdctl build/save and k3s ctr import require it)"

# ── record old digest (tolerate image not existing yet) ──────────────────────
get_digest() {
    sudo k3s ctr -n k8s.io images ls 2>/dev/null | grep "$IMAGE" | awk '{print $3}' | head -1 || true
}

OLD_DIGEST="$(get_digest)"
if [[ -z "$OLD_DIGEST" ]]; then
    OLD_DIGEST="<none>"
fi
echo "  Old digest: ${OLD_DIGEST}"

# ── tarball in /tmp, cleaned up on exit; /tmp is used because sudo k3s ctr ───
# ── needs to be able to read the file as root ─────────────────────────────────
TARBALL="$(sudo mktemp /tmp/cvc-image-XXXXXX.tar)"
cleanup() { sudo rm -f "$TARBALL" 2>/dev/null || rm -f "$TARBALL" 2>/dev/null || true; }
trap cleanup EXIT

# ── 1. build ───────────────────────────────────────────────────────────────────
section "1. Build: nerdctl build -t ${IMAGE} ${REPO_ROOT}"
if ! sudo nerdctl build -t "$IMAGE" "$REPO_ROOT"; then
    fail "Build step failed (sudo nerdctl build)"
    exit 1
fi
ok "Build complete"

# ── 2. save ────────────────────────────────────────────────────────────────────
section "2. Save: nerdctl save ${IMAGE} -o ${TARBALL}"
if ! sudo nerdctl save "$IMAGE" -o "$TARBALL"; then
    fail "Save step failed (sudo nerdctl save)"
    exit 1
fi
ok "Saved to ${TARBALL}"

# ── 3. import ──────────────────────────────────────────────────────────────────
section "3. Import: k3s ctr -n k8s.io images import ${TARBALL}"
if ! sudo k3s ctr -n k8s.io images import "$TARBALL"; then
    fail "Import step failed (sudo k3s ctr images import)"
    exit 1
fi
ok "Import complete"

# ── confirm the image actually landed in k3s containerd ──────────────────────
section "Verify image in k3s containerd"
NEW_DIGEST="$(get_digest)"
if [[ -z "$NEW_DIGEST" ]]; then
    fail "${IMAGE} not found in k3s containerd after import"
    exit 1
fi

ok "${IMAGE} present in k3s containerd (${NEW_DIGEST})"
if [[ "$NEW_DIGEST" != "$OLD_DIGEST" ]]; then
    echo "  digest changed: ${OLD_DIGEST} -> ${NEW_DIGEST}"
else
    warn "digest unchanged (${NEW_DIGEST}) — image content did not change"
fi

# ── optional rollout restart ──────────────────────────────────────────────────
RESTARTED=0
if [[ "$RESTART" -eq 1 ]]; then
    section "Restart deployment"
    if ! kubectl -n "$NAMESPACE" rollout restart "deploy/${DEPLOYMENT}"; then
        fail "rollout restart failed for deploy/${DEPLOYMENT} in namespace ${NAMESPACE}"
        exit 1
    fi
    if ! kubectl -n "$NAMESPACE" rollout status "deploy/${DEPLOYMENT}" --timeout=180s; then
        fail "rollout status did not become ready within 180s for deploy/${DEPLOYMENT}"
        exit 1
    fi
    ok "deploy/${DEPLOYMENT} restarted and ready"
    RESTARTED=1
fi

# ── summary ────────────────────────────────────────────────────────────────────
section "Summary"
echo "  Image:      ${IMAGE}"
echo "  New digest: ${NEW_DIGEST}"
if [[ "$RESTARTED" -eq 1 ]]; then
    echo "  Restarted:  yes (deploy/${DEPLOYMENT} in namespace ${NAMESPACE})"
else
    echo "  Restarted:  no"
    echo
    echo "  To restart the deployment:"
    echo "    kubectl -n ${NAMESPACE} rollout restart deploy/${DEPLOYMENT}"
    echo "    kubectl -n ${NAMESPACE} rollout status deploy/${DEPLOYMENT} --timeout=180s"
    echo
    echo "  To smoke-test afterward:"
    echo "    deploy/smoke-test.sh"
fi

exit 0
