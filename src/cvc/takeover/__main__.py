"""`cvc takeover ...` CLI (D15). Secrets come from prompts or env, never from argv.

Env: CVC_VW_URL, CVC_VW_TOKEN (Vaultwarden bearer), CVC_AUTHENTIK_ISSUER,
CVC_AUTHENTIK_CLIENT_ID, CVC_TAKEOVER_WEBHOOK (Home Assistant / push webhook URL).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

from cvc.takeover import flow
from cvc.takeover.model import DEFAULT_STATE_DIR, TakeoverError, TakeoverStore, utcnow
from cvc.takeover.recovery import RecoveryPasswordStore
from cvc.takeover.verifiers import (
    AuthentikPasskeyElevation,
    VaultwardenPasswordElevation,
    YkmanReader,
    verify_owner_key,
)
from cvc.takeover.vw import HttpEmergencyAccessClient, VaultItem


class WebhookNotifier:
    def __init__(self, url: str):
        self.url = url

    def notify(self, person: str, event: str, message: str) -> None:
        httpx.post(self.url, json={"person": person, "event": event, "message": message},
                   timeout=10)


class JsonInventory:
    """Vault items from a JSON export: [{"id", "name", "organizationId"}...] (no secrets)."""

    def __init__(self, path: str | None):
        self.path = path

    def items_for(self, person: str) -> list[VaultItem]:
        if not self.path:
            return []
        raw = json.loads(Path(self.path).read_text(encoding="utf-8"))
        return [VaultItem(str(i["id"]), str(i.get("name", "")), i.get("organizationId"))
                for i in raw]


def _env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise TakeoverError(f"set {name}")
    return v


def _deps(a: argparse.Namespace) -> flow.Deps:
    hook = os.environ.get("CVC_TAKEOVER_WEBHOOK")
    vw = (HttpEmergencyAccessClient(_env("CVC_VW_URL"), _env("CVC_VW_TOKEN"))
          if a.cmd in ("start", "cancel", "view", "complete") else None)
    return flow.Deps(Path(a.registry), TakeoverStore(a.state_dir), vw, YkmanReader(), utcnow,
                     WebhookNotifier(hook) if hook else None)


def _start(a: argparse.Namespace, d: flow.Deps) -> None:
    w = flow.StartWizard(d)
    print("[1/6] device certificate")
    did = w.step1_cert(a.initiator, Path(a.cert).read_bytes(),
                       [Path(c).read_bytes() for c in a.chain], Path(a.root_ca).read_bytes())
    print(f"      ok: owner cert of {a.initiator} on device {did}")
    input(f"[2/6] insert {a.initiator}'s YubiKey (only that one) and press Enter ")
    print(f"      ok: {w.step2_initiator_key()}")
    print(f"[3/6] elevation via {a.elevation}")
    elev = (AuthentikPasskeyElevation(_env("CVC_AUTHENTIK_ISSUER"), _env("CVC_AUTHENTIK_CLIENT_ID"))
            if a.elevation == "passkey" else VaultwardenPasswordElevation(_env("CVC_VW_URL")))
    w.step3_elevate(elev)
    print("      ok")
    target = a.target or input("[4/6] target owner id: ").strip()
    w.step4_target(target)
    print(f"[4/6] target: {target}")
    if a.recovery_password:
        print(f"[5/6] {target}'s sealed recovery password (180-day path)")
        w.step5_recovery_password(RecoveryPasswordStore(a.state_dir))
    else:
        input(f"[5/6] remove your key; insert {target}'s YubiKey (primary or backup), Enter ")
        print(f"      ok: {w.step5_target_key()}")
    rec = w.step6_start()
    print(f"[6/6] started takeover {rec.id} (path {rec.path}): viewer access from day 15, "
          f"completion from day {rec.wait_days}")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["takeover"]:
        argv = argv[1:]
    p = argparse.ArgumentParser(prog="cvc takeover", description="owner takeover (D15)")
    p.add_argument("--registry", default="access/registry.yaml")
    p.add_argument("--state-dir", default=os.environ.get("CVC_TAKEOVER_STATE", DEFAULT_STATE_DIR))
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start", help="step-by-step takeover wizard")
    s.add_argument("--initiator", required=True)
    s.add_argument("--cert", required=True, help="initiator's device cert (PEM)")
    s.add_argument("--chain", action="append", default=[], help="intermediate PEM(s)")
    s.add_argument("--root-ca", required=True)
    s.add_argument("--elevation", choices=("passkey", "password"), default="passkey")
    s.add_argument("--target")
    s.add_argument("--recovery-password", action="store_true",
                   help="no target YubiKey: use target's sealed recovery password (180 days)")
    for name in ("cancel", "view", "status"):
        sub.add_parser(name).add_argument("id")
    c = sub.add_parser("complete")
    c.add_argument("id")
    c.add_argument("--rebind-agents", action="store_true",
                   help="rebind target's assistant agents to the initiator instead of removing")
    c.add_argument("--vault-inventory", help="JSON list of target's vault items (no secrets)")
    c.add_argument("--execute-vault", action="store_true")
    sub.add_parser("tick", help="send due banner notifications")
    sub.add_parser("verify-history")
    r = sub.add_parser("recovery-set", help="set/rotate an owner's sealed recovery password")
    r.add_argument("person")
    a = p.parse_args(argv)
    try:
        d = _deps(a)
        if a.cmd == "start":
            _start(a, d)
        elif a.cmd == "cancel":
            input("insert the target owner's YubiKey and press Enter ")
            print(f"cancelled {flow.cancel(d, a.id).id}")
        elif a.cmd == "view":
            print(f"viewer access: {flow.view(d, a.id)} item(s) visible (read-only)")
        elif a.cmd == "status":
            rec = d.store.get(a.id)
            print(json.dumps({**rec.to_dict(), "phase": rec.phase(utcnow()),
                              "day": rec.day(utcnow())}, indent=2))
        elif a.cmd == "complete":
            if a.execute_vault:
                raise TakeoverError("no vault executor is configured in this build; run "
                                    "without --execute-vault and apply the plan by hand")
            flow.complete(d, a.id, JsonInventory(a.vault_inventory), None, a.rebind_agents)
        elif a.cmd == "tick":
            for tid, day in flow.tick(d):
                print(f"notified {tid} day {day}")
        elif a.cmd == "verify-history":
            ok = d.store.verify_history()
            print("history chain ok" if ok else "history chain BROKEN")
            return 0 if ok else 1
        elif a.cmd == "recovery-set":
            input(f"insert {a.person}'s YubiKey and press Enter ")
            verify_owner_key(d.reader.read(), flow.load_registry(d.registry_path), a.person)
            rotated = RecoveryPasswordStore(a.state_dir).set(a.person, utcnow().isoformat())
            print(f"{'rotated' if rotated else 'set'} sealed recovery password for {a.person}")
    except (TakeoverError, OSError, httpx.HTTPError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
