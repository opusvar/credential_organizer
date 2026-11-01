"""cvc-notify: periodic tick (deferred flush, 50% escalation, daily digest) and a test push.

  cvc-notify tick [--state /var/lib/cvc/approvals.json] [--registry registry.yaml]
  cvc-notify test --person alex      # sends a harmless test push
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .config import NotifyConfig
from .message import Message
from .notifier import Notifier


def _people(registry: str | None) -> dict:
    path = registry or os.environ.get("CVC_REGISTRY")
    if not path or not Path(path).exists():
        return {}
    import yaml
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    people = data.get("people") or {}
    return people if isinstance(people, dict) else {}


def build_notifier(registry: str | None = None) -> Notifier | None:
    try:
        from cvc import site as _site
        site = _site.load()
    except Exception:                                   # noqa: BLE001
        site = None
    cfg = NotifyConfig.from_env(site, _people(registry))
    return Notifier(cfg) if cfg else None


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ap = argparse.ArgumentParser(prog="cvc-notify")
    ap.add_argument("--registry", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("tick")
    t.add_argument("--state", default=os.environ.get("CVC_APPROVALS_STATE",
                                                     "/var/lib/cvc/approvals.json"))
    s = sub.add_parser("test")
    s.add_argument("--person", required=True)
    args = ap.parse_args(argv)
    n = build_notifier(args.registry)
    if n is None:
        print("notifications disabled (CVC_NTFY_SERVERS unset)", file=sys.stderr)
        return 0
    if args.cmd == "tick":
        from cvc.approvals.service import ApprovalService
        n.tick(ApprovalService(state_path=args.state).list())
        return 0
    topic = n.cfg.topic_for(args.person)
    if not topic:
        print("no topic for that person", file=sys.stderr)
        return 2
    ok = n.sender.send(topic, Message("cvc test", "Test notification", 3,
                                      n.cfg.dashboard_url))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
