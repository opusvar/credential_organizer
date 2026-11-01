"""`cvc delegate ...` CLI (D17). Secrets come from prompts or env, never from argv.

Env: CVC_VW_URL, CVC_AUTHENTIK_ISSUER, CVC_AUTHENTIK_CLIENT_ID, CVC_TAKEOVER_WEBHOOK
(comma-separated notification channels), CVC_DELEGATE_STATE.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

from cvc.delegate import flow
from cvc.delegate.model import DEFAULT_STATE_DIR, SECTION_TITLES, SECTIONS, DelegationStore
from cvc.delegate.plan import EmptyInventory, OrgMembership, VaultEntry
from cvc.takeover.__main__ import _env, notifier_from_env
from cvc.takeover.model import TakeoverError, utcnow
from cvc.takeover.verifiers import (
    AuthentikPasskeyElevation,
    VaultwardenPasswordElevation,
    YkmanReader,
)

FAQ = Path(__file__).with_name("faq.md")


class JsonInventory:
    """{"items": [{"id","name","organizationId","folder","class"}], "orgs": [{"id","name",
    "role"}]} keyed by nothing: the file describes the delegator's vault (no secrets)."""

    def __init__(self, path: str | None):
        self.raw = json.loads(Path(path).read_text(encoding="utf-8")) if path else {}

    def items_for(self, person: str) -> list[VaultEntry]:
        return [VaultEntry(str(i["id"]), str(i.get("name", "")), i.get("organizationId"),
                           i.get("folder"), i.get("class", "private"))
                for i in self.raw.get("items", [])]

    def orgs_for(self, person: str) -> list[OrgMembership]:
        return [OrgMembership(str(o["id"]), str(o.get("name", o["id"])), o.get("role", "user"))
                for o in self.raw.get("orgs", [])]


def _passkey() -> AuthentikPasskeyElevation:
    return AuthentikPasskeyElevation(_env("CVC_AUTHENTIK_ISSUER"), _env("CVC_AUTHENTIK_CLIENT_ID"))


def _start(a: argparse.Namespace, d: flow.Deps) -> None:
    w = flow.StartWizard(d)
    print("[a] identity: device certificate")
    did = w.step1_cert(a.delegator, Path(a.cert).read_bytes(),
                       [Path(c).read_bytes() for c in a.chain], Path(a.root_ca).read_bytes())
    print(f"    ok: cert of {a.delegator} on device {did}")
    print("[a] identity: YubiKey (owner) or passkey (non-owner)")
    if w.cert.tier == "owner":
        input(f"    insert {a.delegator}'s YubiKey and press Enter ")
        print(f"    ok: {w.step2_factor()}")
    else:
        print(f"    ok: {w.step2_factor(_passkey())}")
    print(f"[a] elevation via {a.elevation}")
    w.step3_elevate(_passkey() if a.elevation == "passkey"
                    else VaultwardenPasswordElevation(_env("CVC_VW_URL")))
    recipient = a.recipient or input("[b] recipient id: ").strip()
    print(f"[b] recipient {recipient}, ceiling {w.step4_recipient(recipient)}")
    print("[c] " + w.step5_preview(JsonInventory(a.vault_inventory) if a.vault_inventory
                                   else EmptyInventory()))
    chosen = input(f"[d] sections to delegate [{','.join(SECTIONS)}] (Enter = all): ").strip()
    sel = w.step6_select([s.strip() for s in chosen.split(",")] if chosen else None)
    confirmed = [s for s in sel
                 if input(f"[e] confirm '{SECTION_TITLES[s]}'? type yes: ").strip() == "yes"]
    w.step7_confirm(confirmed, input("[e] type the recipient's name exactly: ").strip())
    rec = w.step8_start()
    print(f"[f] started {rec.id}: nothing moves before {rec.window_ends:%Y-%m-%d %H:%M} UTC")
    print(flow.status_line(rec, utcnow()))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    p = argparse.ArgumentParser(prog="cvc delegate", description="voluntary delegation (D17)")
    p.add_argument("--registry", default="access/registry.yaml")
    p.add_argument("--state-dir", default=os.environ.get("CVC_DELEGATE_STATE", DEFAULT_STATE_DIR))
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start", help="step-by-step delegation wizard")
    s.add_argument("--delegator", required=True)
    s.add_argument("--cert", required=True)
    s.add_argument("--chain", action="append", default=[])
    s.add_argument("--root-ca", required=True)
    s.add_argument("--elevation", choices=("passkey", "password"), default="passkey")
    s.add_argument("--recipient")
    s.add_argument("--vault-inventory", help="JSON description of the delegator's vault")
    sub.add_parser("revoke").add_argument("id")
    sub.add_parser("decline").add_argument("id")
    sub.add_parser("status").add_argument("id")
    c = sub.add_parser("complete")
    c.add_argument("id")
    c.add_argument("--vault-inventory")
    sub.add_parser("faq")
    sub.add_parser("verify-history")
    a = p.parse_args(argv)
    try:
        d = flow.Deps(Path(a.registry), DelegationStore(a.state_dir), YkmanReader(), utcnow,
                      notifier_from_env())
        if a.cmd == "start":
            _start(a, d)
        elif a.cmd == "revoke":
            rec = d.store.get(a.id)
            owner = (flow.load_registry(d.registry_path).get("people") or {}).get(
                rec.delegator, {}).get("tier") == "owner"
            if owner:
                input(f"insert {rec.delegator}'s YubiKey and press Enter ")
            print(f"revoked {flow.revoke(d, a.id, None if owner else _passkey()).id}")
        elif a.cmd == "decline":
            print(f"declined {flow.decline(d, a.id, _passkey()).id}")
        elif a.cmd == "status":
            print(flow.status(d, a.id))
        elif a.cmd == "complete":
            flow.complete(d, a.id, JsonInventory(a.vault_inventory) if a.vault_inventory
                          else EmptyInventory())
        elif a.cmd == "faq":
            print(FAQ.read_text(encoding="utf-8"))
        elif a.cmd == "verify-history":
            ok = d.store.verify_history()
            print("history chain ok" if ok else "history chain BROKEN")
            return 0 if ok else 1
    except (TakeoverError, OSError, httpx.HTTPError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
