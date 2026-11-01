"""`cvc-audit run [--stdout] [--dry-run]` — the read-only audit admin process (D24)."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys

from cvc import site as sitecfg
from cvc.audit.checks import CHECKS, Context, env_int, run_checks
from cvc.audit.findings import StateFile, merge, summary
from cvc.audit.publish import MqttPublisher, Publisher, build_messages


def _vault_items_from_env():
    """Read-only vault metadata via an EXISTING bw session; None (check skipped) otherwise.
    The audit never logs in, unlocks, or writes to the vault."""
    if not (os.environ.get("BW_SESSION") and os.environ.get("BW_SERVER")):
        return None
    from cvc.vault.client import BwClient

    def items() -> list[dict]:
        return BwClient(server=os.environ["BW_SERVER"]).list_items()
    return items


def context_from_env(args: argparse.Namespace, now: dt.datetime) -> Context:
    from cvc.delegate.model import DEFAULT_STATE_DIR as DELEGATE_DIR
    from cvc.takeover.model import DEFAULT_STATE_DIR as TAKEOVER_DIR
    e = os.environ.get
    return Context(
        now=now,
        registry_path=args.registry or e("CVC_REGISTRY") or "access/registry.yaml",
        takeover_dir=e("CVC_TAKEOVER_STATE", TAKEOVER_DIR),
        delegate_dir=e("CVC_DELEGATE_STATE", DELEGATE_DIR),
        backup_dir=e("BACKUP_DIR"),
        backup_unit=e("CVC_AUDIT_BACKUP_UNIT", "cvc-backup.service"),
        backup_max_age_days=env_int("CVC_AUDIT_BACKUP_MAX_AGE_DAYS", 8),
        audit_log=e("AUDIT_LOG"),
        deny_threshold=env_int("CVC_AUDIT_DENY_THRESHOLD", 10),
        deny_window_hours=env_int("CVC_AUDIT_DENY_WINDOW_HOURS", 1),
        rotation_max_age_days=env_int("ROTATION_MAX_AGE_DAYS", 180),
        vault_items=_vault_items_from_env(),
    )


def run(ctx: Context, state: StateFile, publisher: Publisher | None, *,
        dry_run: bool = False, checks: list[str] | None = None,
        discovery_prefix: str = "homeassistant") -> tuple[dict, dict]:
    now = ctx.now.isoformat(timespec="seconds")
    merged = merge(state.load(), run_checks(ctx, checks), now)
    summ = summary(merged, now)
    msgs = build_messages(merged, summ, discovery_prefix)   # validates no-secret payloads
    if not dry_run:
        state.save(merged, now)
        if publisher is not None:
            publisher.publish(msgs)
    return merged, summ


def main(argv: list[str] | None = None, publisher: Publisher | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cvc-audit", description=__doc__)
    sitecfg.add_site_arg(ap)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run all checks, update state, publish")
    r.add_argument("--registry", help="registry file (default: $CVC_REGISTRY, "
                                      "then access/registry.yaml)")
    r.add_argument("--state", help="state file (default: $CVC_AUDIT_STATE, then "
                                   "~/.local/state/cvc/audit/findings.json)")
    r.add_argument("--check", action="append", choices=sorted(CHECKS),
                   help="run only these checks (repeatable)")
    r.add_argument("--stdout", action="store_true",
                   help="print findings JSON locally instead of publishing to MQTT")
    r.add_argument("--dry-run", action="store_true",
                   help="run checks and print; do not save state or publish")
    a = ap.parse_args(argv)
    try:
        site = sitecfg.load(a.site)
    except sitecfg.SiteError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    now = dt.datetime.now(dt.UTC)
    ctx = context_from_env(a, now)
    if publisher is None and not (a.stdout or a.dry_run):
        publisher = MqttPublisher.from_env(site)
    if a.stdout:
        publisher = None
    merged, summ = run(ctx, StateFile(a.state), publisher, dry_run=a.dry_run, checks=a.check,
                       discovery_prefix=os.environ.get("MQTT_DISCOVERY_PREFIX", "homeassistant"))
    if a.stdout or a.dry_run:
        print(json.dumps({"summary": summ, "findings": list(merged.values())}, indent=2))
    else:
        print(f"cvc-audit: {summ['open_total']} open ({summ['open']})")
    return 0     # findings are data, not a unit failure


if __name__ == "__main__":
    raise SystemExit(main())
