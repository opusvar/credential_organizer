"""`cvc-approvals list|show|decide` — owner CLI over the shared approvals state file.

Local shell access on the services node is owner-level, so the CLI decides as tier `owner`
with the same rules as the broker endpoint. For `requires_passkey` requests the owner must
pass `--passkey-verified` (an explicit attestation that they are physically present and
authenticated); the broker's HTTP path requires a real Authentik login instead.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .publisher import from_env
from .service import ApprovalService, DecideError

DEFAULT_STATE = "/var/lib/cvc/approvals.json"


def _service(args) -> ApprovalService:
    return ApprovalService(publisher=from_env(), state_path=args.state)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cvc-approvals", description=__doc__)
    p.add_argument("--state", default=os.environ.get("CVC_APPROVALS_STATE", DEFAULT_STATE),
                   help="approvals state file shared with the broker")
    sub = p.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list", help="list approvals")
    ls.add_argument("--all", action="store_true", help="include resolved (default: pending)")
    ls.add_argument("--json", action="store_true")
    sh = sub.add_parser("show", help="show one approval as JSON")
    sh.add_argument("id")
    de = sub.add_parser("decide", help="approve or deny")
    de.add_argument("id")
    de.add_argument("decision", choices=("approve", "deny"))
    de.add_argument("--as", dest="person", required=True, help="your person id (owner)")
    de.add_argument("--passkey-verified", action="store_true",
                    help="attest a passkey-level check for requires_passkey requests")
    args = p.parse_args(argv)
    svc = _service(args)

    if args.cmd == "list":
        items = svc.list(None if args.all else "pending")
        if args.json:
            print(json.dumps([r.to_dict() for r in items], indent=2))
        else:
            for r in items:
                print(f"{r.id}  {r.status:<9} {r.risk:<5} {r.urgency:<6} {r.deadline}  "
                      f"{r.requester.agent}: {r.summary}")
        return 0
    if args.cmd == "show":
        r = svc.get(args.id)
        if r is None:
            print("no such approval", file=sys.stderr)
            return 1
        print(json.dumps(r.to_dict(), indent=2))
        return 0
    try:
        r = svc.decide(args.id, args.decision, person=args.person, tier="owner",
                       passkey_user=args.person if args.passkey_verified else None)
    except DecideError as e:
        print(f"error: {e.detail}", file=sys.stderr)
        return 2
    print(f"{r.id} {r.status} by {r.decided_by}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
