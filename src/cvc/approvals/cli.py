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

from . import inspect as insp_mod
from .publisher import from_env
from .service import ApprovalService, DecideError

DEFAULT_STATE = "/var/lib/cvc/approvals.json"


def _service(args) -> ApprovalService:
    svc = ApprovalService(publisher=from_env(), state_path=args.state)
    insp_mod.attach(svc)
    return svc


def _table(rows: list[dict], cols: list[str]) -> str:
    cells = [[("" if r.get(c) is None else str(r.get(c))) for c in cols] for r in rows]
    w = [max([len(c)] + [len(x[i]) for x in cells]) for i, c in enumerate(cols)]
    lines = ["  ".join(c.ljust(w[i]) for i, c in enumerate(cols))]
    lines += ["  ".join(x[i].ljust(w[i]) for i in range(len(cols))) for x in cells]
    return "\n".join(lines)


def _inspect_cmd(args) -> int:
    # Read-only debug views: never publish to MQTT (no publisher configured).
    insp = insp_mod.attach(ApprovalService(state_path=args.state))
    if args.cmd == "etag":
        out = insp.etag_info(args.id)
        if out is None:
            print("no such approval", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            ev = out["last_event"] or {}
            print(f"{out['id']}  etag={out['etag']}  version={out['version']}  "
                  f"status={out['status']}  last_event={ev.get('event')} "
                  f"by {ev.get('actor')} at {ev.get('at')}")
        return 0
    if args.cmd == "history":
        rows = insp.history(args.id)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print(_table(rows, ["version", "etag", "at", "event", "actor", "status",
                                "mqtt_published_at", "mqtt_cleared_at"]))
        return 0 if rows or insp.svc.get(args.id) else 1
    if args.cmd == "check-etag":
        out = insp.check_etag(args.id, args.etag)
        if args.json:
            print(json.dumps(out, indent=2))
        elif out["result"] == "stale":
            print(f"stale: presented v{out['presented_version']}, "
                  f"current {out['current_etag']}")
            for h in out["changes_since"]:
                print(f"  v{h['version']} {h['event']} by {h['actor']} at {h['at']} "
                      f"-> {h['status']}")
        else:
            print(f"{out['result']}: current {out['current_etag']}")
        return {"current": 0, "stale": 3}.get(out["result"], 1)
    snapshot = None
    if args.mqtt_snapshot:
        with open(args.mqtt_snapshot, encoding="utf-8") as fh:
            snapshot = json.load(fh)
    out = insp.diag(snapshot)
    if args.json:
        print(json.dumps(out, indent=2))
        return 0
    print("counts: " + ", ".join(f"{k}={v}" for k, v in sorted(out["counts"].items())))
    print(f"recent 412/428 rejections: {len(out['recent_rejections'])}")
    for r in out["recent_rejections"]:
        print(f"  {r['at']} {r['code']} {r['id']} presented={r['presented_etag']} "
              f"current={r['current_etag']} person={r['person']}")
    if "mqtt_mismatches" in out:
        print(f"mqtt mismatches: {len(out['mqtt_mismatches'])}")
        for m in out["mqtt_mismatches"]:
            print(f"  {m['id']} {m['kind']}")
    return 0


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
    et = sub.add_parser("etag", help="current ETag, version, status and last event")
    et.add_argument("id")
    hi = sub.add_parser("history", help="full per-approval version history")
    hi.add_argument("id")
    ce = sub.add_parser("check-etag", help="is an ETag current, stale or unknown?")
    ce.add_argument("id")
    ce.add_argument("etag")
    dg = sub.add_parser("diag", help="status counts, 412/428 rejections, MQTT mismatches")
    dg.add_argument("--mqtt-snapshot", help="JSON {topic: retained payload} from a subscriber")
    for sp in (et, hi, ce, dg):
        sp.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if args.cmd in ("etag", "history", "check-etag", "diag"):
        return _inspect_cmd(args)
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
