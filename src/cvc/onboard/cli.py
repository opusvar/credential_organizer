"""CLI: `cvc onboard person|agent ...` and `cvc-onboard person|agent ...`.

`cvc_main` is the `cvc` entry point: it handles `onboard` and hands everything else to
cvc.takeover.__main__.main (which already dispatches `takeover` and `delegate`).
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys

from cvc.access.model import (
    AGENT_TIERS,
    CERT_STORAGE,
    DEVICE_KINDS,
    HA_ACCESS,
    HWKEY_LOCATIONS,
    HWKEY_ROLES,
    PERSON_TIERS,
)
from cvc.onboard.authentik import client_from_env
from cvc.onboard.core import IO, OnboardError, subprocess_runner, terminal_io
from cvc.onboard.wizard import (
    AgentSpec,
    DeviceSpec,
    HwKeySpec,
    PersonSpec,
    Seams,
    onboard_agent,
    onboard_person,
)


def _device(s: str) -> DeviceSpec:
    """ID:KIND[:STORAGE[:HWKEY]]  e.g. pixel:phone  or  mbp:laptop:yubikey-piv:yk1"""
    parts = s.split(":")
    if len(parts) < 2 or parts[1] not in DEVICE_KINDS:
        raise argparse.ArgumentTypeError(f"--device wants ID:KIND[:STORAGE[:HWKEY]] with KIND "
                                         f"in {', '.join(DEVICE_KINDS)}; got {s!r}")
    storage = parts[2] if len(parts) > 2 else "p12"
    if storage not in CERT_STORAGE:
        raise argparse.ArgumentTypeError(f"storage must be one of {', '.join(CERT_STORAGE)}")
    return DeviceSpec(parts[0], parts[1], storage, parts[3] if len(parts) > 3 else None)


def _hwkey(s: str) -> HwKeySpec:
    """ID:ROLE[:LOCATION[:SERIAL:MODEL]]"""
    parts = s.split(":", 4)
    if len(parts) < 2 or parts[1] not in HWKEY_ROLES:
        raise argparse.ArgumentTypeError(f"--hwkey wants ID:ROLE[:LOCATION[:SERIAL:MODEL]]; "
                                         f"got {s!r}")
    loc = parts[2] if len(parts) > 2 else ("on-person" if parts[1] == "primary" else "home-safe")
    if loc not in HWKEY_LOCATIONS:
        raise argparse.ArgumentTypeError(f"location must be one of {', '.join(HWKEY_LOCATIONS)}")
    serial = parts[3] if len(parts) > 3 else None
    model = parts[4] if len(parts) > 4 else None
    return HwKeySpec(parts[0], parts[1], loc, serial, model)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cvc onboard", description="onboarding wizard")
    sub = ap.add_subparsers(dest="what", required=True)
    p = sub.add_parser("person", help="onboard a human (who, devices, keys, tailnet, "
                                      "Authentik, owner extras)")
    p.add_argument("--id")
    p.add_argument("--name", help="display name")
    p.add_argument("--tier", choices=PERSON_TIERS)
    p.add_argument("--granted-by", help="sponsoring person id (grant rule enforced)")
    p.add_argument("--tailnet", help="default: guests for guests, owner for owners, else family")
    p.add_argument("--email")
    p.add_argument("--expires", type=dt.date.fromisoformat, help="guests: YYYY-MM-DD "
                   "(default today + 5 days)")
    p.add_argument("--ha", choices=HA_ACCESS, default="none", help="guest HA level")
    p.add_argument("--device", action="append", type=_device, default=[],
                   metavar="ID:KIND[:STORAGE[:HWKEY]]")
    p.add_argument("--hwkey", action="append", type=_hwkey, default=[],
                   metavar="ID:ROLE[:LOCATION[:SERIAL:MODEL]]")
    p.add_argument("--out-dir", default="onboard-out", help="generated files for review")
    a = sub.add_parser("agent", help="onboard an AI agent")
    a.add_argument("--id")
    a.add_argument("--tier", choices=AGENT_TIERS)
    a.add_argument("--sponsor")
    a.add_argument("--granted-by")
    a.add_argument("--role", action="append", default=[], dest="roles")
    a.add_argument("--token-sha256")
    a.add_argument("--expires", type=dt.date.fromisoformat)
    for sp in (p, a):
        sp.add_argument("--registry", default="access/registry.yaml")
        sp.add_argument("--dry-run", action="store_true", help="show everything; write nothing")
    p.add_argument("--execute", action="store_true",
                   help="run step-ca commands (only if `step` is on PATH) and Authentik calls "
                        "(only with AUTHENTIK_URL + AUTHENTIK_TOKEN)")
    return ap


def _need(io: IO, val: str | None, prompt: str) -> str:
    while not val:
        val = io.ask(prompt).strip()
    return val


def main(argv: list[str] | None = None, *, io: IO | None = None,
         seams: Seams | None = None) -> int:
    a = build_parser().parse_args(argv)
    io = io or terminal_io()
    try:
        if a.what == "person":
            execute = a.execute
            s = seams or Seams(io=io, runner=subprocess_runner,
                               authentik=client_from_env() if execute else None)
            tier = _need(io, a.tier, f"Tier ({', '.join(PERSON_TIERS)}): ")
            spec = PersonSpec(
                id=_need(io, a.id, "Person id: "), name=_need(io, a.name, "Display name: "),
                tier=tier, granted_by=_need(io, a.granted_by, "Granted by (person id): "),
                tailnet=a.tailnet, email=a.email, expires=a.expires, ha=a.ha,
                devices=a.device, hwkeys=a.hwkey)
            return onboard_person(a.registry, spec, s, out_dir=a.out_dir, dry_run=a.dry_run,
                                  execute=execute)
        s = seams or Seams(io=io)
        spec = AgentSpec(
            id=_need(io, a.id, "Agent id: "),
            tier=_need(io, a.tier, f"Agent tier ({', '.join(AGENT_TIERS)}): "),
            sponsor=_need(io, a.sponsor, "Sponsor (person id): "),
            granted_by=_need(io, a.granted_by, "Granted by (person id): "),
            roles=a.roles, token_sha256=a.token_sha256, expires=a.expires)
        return onboard_agent(a.registry, spec, s, dry_run=a.dry_run)
    except OnboardError as e:
        io.out(f"error: {e}")
        if not io.echo:
            print(f"error: {e}", file=sys.stderr)
        return 1


def cvc_main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["onboard"]:
        return main(argv[1:])
    from cvc.takeover.__main__ import main as takeover_main
    return takeover_main(argv)


if __name__ == "__main__":
    sys.exit(main())
