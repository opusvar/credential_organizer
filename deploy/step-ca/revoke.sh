#!/usr/bin/env bash
# revoke.sh <serial> [reason]
# Passive revocation via step-ca + CRL regeneration.
#
# CRL/OCSP note (per smallstep.com/docs/step-ca/revocation, read 2026-10-31):
#  - Open-source step-ca revocation is PASSIVE: a revoked cert cannot be renewed,
#    but it stays valid to relying parties until not_after UNLESS they check a CRL.
#  - CRL is enabled in ca.json ("crl.enabled", "generateOnRevoke"; marked
#    experimental) and served at $CA_URL/1.0/crl. Relying parties (Authentik
#    mTLS, nginx ssl_crl, etc.) must fetch it periodically.
#  - OCSP is NOT available in open-source step-ca (commercial only).
#  - Hence short (90d) lifetimes; for a lost device also remove its access in cvc.
set -euo pipefail
SERIAL="${1:?usage: revoke.sh <serial> [reason]}"
REASON="${2:-device lost or retired}"
CA_URL="${CA_URL:-${SITE_CA_URL}}"
ROOT="${ROOT:-$HOME/.step/certs/root_ca.crt}"

# Authenticates with the OIDC provisioner (admin email in ca.json "admins").
step ca revoke "$SERIAL" --reason "$REASON" --ca-url "$CA_URL" --root "$ROOT"

echo "Revoked $SERIAL. Current CRL:"
curl -fsS --cacert "$ROOT" "$CA_URL/1.0/crl" | step crl inspect --from - 2>/dev/null \
  || echo "(fetch $CA_URL/1.0/crl manually to confirm)"
