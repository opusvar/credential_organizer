"""CLI: `python -m cvc.deploygen {traefik,tiergate} --registry ... --base-domain ...`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cvc.access.model import RegistryError, load_registry
from cvc.deploygen.traefik import (
    DEFAULT_BASE_DOMAIN,
    DEFAULT_ENTRYPOINT,
    DEFAULT_NAMESPACE,
    Options,
    build_tiergate_configmap,
    build_traefik,
)

BUILDS = {"traefik": build_traefik, "tiergate": build_tiergate_configmap}


def _override(s: str) -> tuple[str, str]:
    rid, sep, host = s.partition("=")
    if not sep or not rid or not host:
        raise argparse.ArgumentTypeError(f"expected RESOURCE=HOST, got {s!r}")
    return rid, host


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cvc-deploygen", description=__doc__)
    ap.add_argument("what", choices=sorted(BUILDS))
    ap.add_argument("--registry", default="access/registry.yaml")
    ap.add_argument("--base-domain", default=DEFAULT_BASE_DOMAIN)
    ap.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    ap.add_argument("--entrypoint", action="append", dest="entrypoints",
                    help=f"Traefik entrypoint (repeatable; default {DEFAULT_ENTRYPOINT})")
    ap.add_argument("--host", action="append", type=_override, default=[], metavar="RES=HOST",
                    help="per-resource hostname override (repeatable)")
    ap.add_argument("--registry-hosts", action="store_true",
                    help="use each resource's registry host instead of <id>.<base-domain>")
    ap.add_argument("-o", "--out", help="write to file instead of stdout")
    a = ap.parse_args(argv)
    opts = Options(base_domain=a.base_domain, namespace=a.namespace,
                   entrypoints=tuple(a.entrypoints or [DEFAULT_ENTRYPOINT]),
                   host_overrides=dict(a.host), registry_hosts=a.registry_hosts)
    try:
        text = BUILDS[a.what](load_registry(a.registry), opts)
    except RegistryError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if a.out:
        Path(a.out).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
