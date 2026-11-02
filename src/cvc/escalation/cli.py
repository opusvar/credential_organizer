"""`cvc-escalate request|list|show|revoke` (D27).

- `request` is the agent side: POSTs one escalation to the broker with the agent's service
  token (env CVC_AGENT_TOKEN, never a flag). `--check` only classifies locally and prints
  whether the request would be refused, already permitted, or sent for approval.
- `list`, `show`, `revoke` are owner commands over the shared state file (local shell on the
  services node is owner-level, as with cvc-approvals).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from cvc.approvals.publisher import from_env
from cvc.approvals.service import ApprovalService

from .policy import EscalationRefused, evaluate
from .store import EscalationError, EscalationStore

DEFAULT_STATE = "/var/lib/cvc/escalations.json"
DEFAULT_APPROVALS = "/var/lib/cvc/approvals.json"


def _store(args) -> EscalationStore:
    svc = ApprovalService(publisher=from_env(), state_path=args.approvals_state)
    return EscalationStore(args.state, svc)


def _body(args) -> dict:
    body = {"action": args.action, "data": args.data, "resource": args.resource,
            "purpose": args.purpose, "justification": args.justification,
            "ttl_s": args.ttl_s}
    if args.on_behalf_of:
        body["on_behalf_of"] = args.on_behalf_of
    if args.physical:
        body["physical"] = True
    return body


def _request(args) -> int:
    body = _body(args)
    if args.check:
        try:
            a = evaluate(args.agent, args.tier, body)
        except EscalationRefused as e:
            print(f"refused ({e.code}): {e.reason}", file=sys.stderr)
            return 2
        if a.already_permitted:
            print("already permitted: no escalation needed")
            return 0
        print(f"would request: {a.action} {a.data} {a.resource}; current tier "
              f"{a.current_tier}, requested {a.required_tier}; approver >= "
              f"{a.approver_min_tier}{' (owner only)' if a.owner_only else ''}")
        return 0
    token = os.environ.get("CVC_AGENT_TOKEN")
    if not token:
        print("error: set CVC_AGENT_TOKEN to the agent's service token", file=sys.stderr)
        return 2
    import httpx
    r = httpx.post(args.broker.rstrip("/") + "/v1/escalations", json=body, timeout=30,
                   headers={"X-Agent-Id": args.agent, "Authorization": f"Bearer {token}"})
    print(json.dumps(r.json(), indent=2))
    return 0 if r.status_code in (200, 201) else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cvc-escalate", description=__doc__)
    p.add_argument("--state", default=os.environ.get("CVC_ESCALATIONS_STATE", DEFAULT_STATE))
    p.add_argument("--approvals-state",
                   default=os.environ.get("CVC_APPROVALS_STATE", DEFAULT_APPROVALS))
    sub = p.add_subparsers(dest="cmd", required=True)
    rq = sub.add_parser("request", help="agent: request one escalated action")
    rq.add_argument("--agent", required=True)
    rq.add_argument("--action", required=True)
    rq.add_argument("--data", required=True)
    rq.add_argument("--resource", required=True,
                    help="credential:<uuid> | ha:<entity_id> | system:<name> | task:<id>")
    rq.add_argument("--purpose", required=True)
    rq.add_argument("--justification", required=True)
    rq.add_argument("--on-behalf-of")
    rq.add_argument("--ttl-s", type=int, default=15 * 60)
    rq.add_argument("--physical", action="store_true")
    rq.add_argument("--broker", default=os.environ.get("CVC_BROKER_URL",
                                                       "https://broker.example.com"))
    rq.add_argument("--check", action="store_true", help="classify locally, send nothing")
    rq.add_argument("--tier", default="low", help="agent tier for --check")
    ls = sub.add_parser("list", help="owner: list escalations")
    ls.add_argument("--agent")
    ls.add_argument("--status")
    ls.add_argument("--json", action="store_true")
    sh = sub.add_parser("show", help="owner: one escalation and its history")
    sh.add_argument("id")
    rv = sub.add_parser("revoke", help="owner: revoke an unused grant or pending request")
    rv.add_argument("id")
    rv.add_argument("--as", dest="person", required=True, help="your person id (owner)")
    args = p.parse_args(argv)

    if args.cmd == "request":
        return _request(args)
    store = _store(args)
    if args.cmd == "list":
        rows = store.list(args.agent, args.status)
        if args.json:
            print(json.dumps([e.public() for e in rows], indent=2))
        else:
            for e in rows:
                obo = f" for {e.on_behalf_of}" if e.on_behalf_of else ""
                print(f"{e.id}  {e.status:<13} {e.agent}{obo}: {e.action} {e.data} "
                      f"{e.resource} ({e.current_tier} -> {e.required_tier})")
        return 0
    if args.cmd == "show":
        e = store.get(args.id)
        if e is None:
            print("no such escalation", file=sys.stderr)
            return 1
        print(json.dumps({"escalation": e.public(), "history": store.history(e.id)},
                         indent=2))
        return 0
    try:
        e = store.revoke(args.id, args.person)
    except EscalationError as err:
        print(f"error: {err.reason}", file=sys.stderr)
        return 2
    print(f"{e.id} revoked by {e.revoked_by}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
