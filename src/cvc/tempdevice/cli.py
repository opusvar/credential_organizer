"""`cvc-tempdevice request|approve|deny|extend|promote|revoke|list|sweep` (D27).

Prints the step-ca commands for an approved bridge; never runs them and never issues certs.
The factor flags (--password/--passkey/--yubikey) record what the operator verified (in the
web flow Authentik asserts them).
"""
from __future__ import annotations

import argparse
import os
import sys

from cvc.access.model import RegistryError, load_registry

from .certs import issue_commands, revoke_command
from .model import Bridge
from .service import ApprovalsLink, AuthProof, BridgeError, BridgeService, BridgeStore


def _proof(a: argparse.Namespace) -> AuthProof:
    return AuthProof(password=a.password, passkey=a.passkey, yubikey=a.yubikey)


def _factors(p: argparse.ArgumentParser) -> None:
    p.add_argument("--password", action="store_true", help="password verified")
    p.add_argument("--passkey", action="store_true", help="passkey verified")
    p.add_argument("--yubikey", action="store_true", help="physical YubiKey verified")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cvc-tempdevice",
                                 description="Temporary (bridge) device certs (D27)")
    ap.add_argument("--registry", default=os.environ.get("CVC_REGISTRY", "access/registry.yaml"))
    ap.add_argument("--state", default=None, help="state dir (default $CVC_TEMPDEVICE_STATE "
                                                  "or ~/.local/state/cvc/tempdevice)")
    ap.add_argument("--approvals-state", default=os.environ.get("CVC_APPROVALS_STATE"),
                    help="mirror requests into the approvals pipeline (card + ntfy)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("request", help="ask for a bridge")
    r.add_argument("person")
    r.add_argument("--reason", required=True)
    r.add_argument("--hours", type=int, default=None, help="default 72")
    r.add_argument("--self-issue", action="store_true", help="owner/admin with a YubiKey")
    _factors(r)
    a = sub.add_parser("approve", help="approve a pending bridge or extension")
    a.add_argument("bridge")
    a.add_argument("--by", required=True)
    a.add_argument("--passkey", action="store_true", help="approver's passkey verified")
    d = sub.add_parser("deny", help="deny a pending bridge or extension")
    d.add_argument("bridge")
    d.add_argument("--by", required=True)
    e = sub.add_parser("extend", help="ask for more time (needs approval again)")
    e.add_argument("bridge")
    e.add_argument("--by", required=True)
    e.add_argument("--hours", type=int, default=None)
    _factors(e)
    p = sub.add_parser("promote", help="permanent device enrolled: end the bridge")
    p.add_argument("person")
    p.add_argument("device")
    p.add_argument("--by", required=True)
    v = sub.add_parser("revoke", help="revoke a bridge (person, admin or owner)")
    v.add_argument("bridge")
    v.add_argument("--by", required=True)
    v.add_argument("--reason", default="revoked")
    li = sub.add_parser("list", help="list bridges")
    li.add_argument("--person")
    li.add_argument("--all", action="store_true", help="include ended bridges")
    sub.add_parser("sweep", help="expire ended bridges and timed-out asks")
    return ap


def _line(b: Bridge) -> str:
    end = b.expires_at or "-"
    extra = f" ext:{b.pending_extension['hours']}h pending" if b.pending_extension else ""
    return (f"{b.id:24} {b.person:12} {b.status:8} tier={b.tier:10} until={end}"
            f"{' LOST-REPORT' if b.lost_report else ''}{extra}")


def _print_issue(svc: BridgeService, b: Bridge) -> None:
    print(f"{b.id}: active until {b.expires_at} (tier {b.tier}, SANs: {', '.join(b.sans())})")
    print("Issue the cert (NOT executed):")
    for c in issue_commands(b, svc.clock()):
        print(f"  {c.shell()}")


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        reg = load_registry(a.registry)
    except (OSError, RegistryError) as e:
        print(f"error: cannot load registry: {e}", file=sys.stderr)
        return 1
    link = None
    if a.approvals_state:
        from cvc.approvals.service import ApprovalService
        link = ApprovalsLink(ApprovalService(state_path=a.approvals_state))
    svc = BridgeService(reg, BridgeStore(a.state), approvals=link)
    try:
        if a.cmd == "request":
            b = svc.request(a.person, a.reason, _proof(a), hours=a.hours,
                            self_issue=a.self_issue)
            if b.status == "active":
                _print_issue(svc, b)
            else:
                print(f"{b.id}: pending approval" + (f" ({b.approval_id})" if b.approval_id
                                                     else ""))
        elif a.cmd == "approve":
            cur = next((x for x in svc.list() if x.id == a.bridge), None)
            if cur is not None and cur.pending_extension:
                b = svc.approve_extension(a.bridge, a.by, passkey=a.passkey)
            else:
                b = svc.approve(a.bridge, a.by, passkey=a.passkey)
            _print_issue(svc, b)
        elif a.cmd == "deny":
            print(_line(svc.deny(a.bridge, a.by)))
        elif a.cmd == "extend":
            b = svc.extend(a.bridge, a.by, _proof(a), a.hours)
            print(f"{b.id}: extension of {b.pending_extension['hours']} h pending approval")
        elif a.cmd == "promote":
            b = svc.promote(a.person, a.device, a.by)
            if b is None:
                print(f"{a.person} has no open bridge")
            else:
                print(f"promoted {a.device}; {b.id} revoked")
                print(f"  [ ] {revoke_command(b)}")
        elif a.cmd == "revoke":
            b = svc.revoke(a.bridge, a.by, a.reason)
            print(f"{b.id} revoked\n  [ ] {revoke_command(b)}")
        elif a.cmd == "list":
            for b in svc.list(person=a.person, open_only=not a.all):
                print(_line(b))
        elif a.cmd == "sweep":
            for b in svc.sweep():
                print(f"{b.id}: {b.status} ({b.end_reason or 'extension timed out'})")
    except BridgeError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
