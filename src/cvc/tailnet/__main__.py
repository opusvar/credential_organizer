"""`python -m cvc.tailnet policy [--owner ID] [--group NAME=ID,ID] [--out FILE]`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cvc import site as site_config
from cvc.access.model import RegistryError, load_registry
from cvc.tailnet.policy import PolicyError, build_policy, render_hujson


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cvc.tailnet")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("policy", help="emit the owner-tailnet HuJSON ACL policy")
    p.add_argument("--registry", default="access/registry.yaml")
    p.add_argument("--owner", action="append", help="owner person id (default: site default_owner_ids)")
    site_config.add_site_arg(p)
    p.add_argument("--group", action="append", default=[], metavar="NAME=ID,ID",
                   help="extra group of registry people")
    p.add_argument("--out", help="output file (default: stdout)")
    a = ap.parse_args(argv)
    try:
        site = site_config.load(a.site)
        reg = load_registry(a.registry)
        groups = {}
        for spec in a.group:
            name, sep, members = spec.partition("=")
            if not sep or not name:
                raise PolicyError(f"bad --group {spec!r} (want NAME=ID,ID)")
            groups[name] = [m for m in members.split(",") if m]
        policy, warnings = build_policy(reg, site_config.owners_or_default(a.owner, site), groups,
                                        service_host=site.node_ip)
    except RegistryError as e:
        for err in e.errors:
            print(f"error: {err}", file=sys.stderr)
        return 1
    except (OSError, PolicyError, site_config.SiteError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    text = render_hujson(policy)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
