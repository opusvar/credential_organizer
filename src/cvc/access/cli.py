"""`cvc-access` command line."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from cvc.access import brokeracl  # noqa: F401  (registers the broker-acl builder)
from cvc.access.builders import BUILDERS
from cvc.access.check import check_registry
from cvc.access.importacl import import_broker_acl
from cvc.access.model import RegistryError, load_registry

DEFAULT_REGISTRY = "access/registry.yaml"


def _load(path: str):
    try:
        return load_registry(path)
    except RegistryError as e:
        for err in e.errors:
            print(f"error: {err}", file=sys.stderr)
    except (OSError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cvc-access", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    reg_kw = dict(default=DEFAULT_REGISTRY, help="registry file (default: %(default)s)")

    sub.add_parser("validate").add_argument("--registry", **reg_kw)
    sub.add_parser("check").add_argument("--registry", **reg_kw)
    b = sub.add_parser("build", help="generate an artifact from the registry")
    b.add_argument("target", choices=sorted(BUILDERS))
    b.add_argument("--registry", **reg_kw)
    b.add_argument("--out", help="output file (default: stdout)")
    i = sub.add_parser("import-acl", help="bootstrap a registry from a broker ACL")
    i.add_argument("acl")
    i.add_argument("--out", default=DEFAULT_REGISTRY)
    i.add_argument("--force", action="store_true", help="overwrite --out if it exists")
    args = ap.parse_args(argv)

    if args.cmd == "import-acl":
        out = Path(args.out)
        if out.exists() and not args.force:
            print(f"error: {out} exists (use --force)", file=sys.stderr)
            return 1
        data = import_broker_acl(args.acl)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        print(f"wrote {out} ({len(data['agents'])} agents)")
        return 0

    reg = _load(args.registry)
    if reg is None:
        return 1
    if args.cmd == "validate":
        print(f"ok: {len(reg.systems)} systems, {len(reg.roles)} roles, "
              f"{len(reg.agents)} agents, {len(reg.machines)} machines")
        return 0
    if args.cmd == "check":
        findings = check_registry(reg)
        for f in findings:
            print(f"{f.level}: {f.path}: {f.message}")
        if not findings:
            print("ok: no findings")
        return 1 if any(f.level == "error" for f in findings) else 0
    text = BUILDERS[args.target](reg, None)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"wrote {out}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
