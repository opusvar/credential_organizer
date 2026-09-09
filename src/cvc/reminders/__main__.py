"""`cvc-remind` CLI — evaluate vault credentials against policy, publish to Home Assistant.

Run as a k8s CronJob (D6). Reads all vault items, evaluates age/reuse/weakness/breach,
and publishes a sensor + attributes to HA via MQTT discovery.

Vault auth: same API key flow as cvc-import (BW_CLIENTID + BW_CLIENTSECRET + BW_PASSWORD).
MQTT auth: MQTT_USERNAME + MQTT_PASSWORD from env.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

import httpx

from .. import config
from ..vault.client import BwClient, VaultError
from .hibp import times_pwned
from .mqtt_publish import publish
from .policy import CredRecord, evaluate


def _parse_rotated(item: dict) -> datetime | None:
    """Extract last password-change date from a vault item if present."""
    try:
        raw = item.get("revisionDate") or item.get("creationDate")
        if raw:
            return datetime.fromisoformat(raw.rstrip("Z")).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        pass
    return None


def _vault_records(cfg) -> list[CredRecord]:
    if not cfg.bw_server:
        raise RuntimeError("BW_SERVER not configured")
    client = BwClient(server=cfg.bw_server)
    client.configure()
    client.login_apikey()
    session = client.unlock()
    os.environ["BW_SESSION"] = session
    client.sync()

    items = client.list_items()
    records = []
    for item in items:
        if item.get("type") != 1:  # login items only
            continue
        login = item.get("login") or {}
        records.append(CredRecord(
            item_id=item["id"],
            name=item.get("name", ""),
            username=login.get("username") or "",
            password=login.get("password") or "",
            last_rotated=_parse_rotated(item),
        ))
    return records


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cvc-remind")
    p.add_argument("--dry-run", action="store_true",
                   help="evaluate and print findings; do not publish to MQTT")
    args = p.parse_args(argv)

    cfg = config.load()

    try:
        records = _vault_records(cfg)
    except (VaultError, RuntimeError) as exc:
        print(f"ERROR: vault read failed — {exc}", file=sys.stderr)
        return 1

    findings = evaluate(records, max_age_days=cfg.rotation_max_age_days)

    if cfg.hibp_enabled and records:
        with httpx.Client(timeout=10.0) as http:
            for rec in records:
                if not rec.password:
                    continue
                try:
                    count = times_pwned(rec.password, client=http)
                except Exception as exc:  # noqa: BLE001
                    print(f"WARNING: HIBP check failed for {rec.name!r}: {exc}", file=sys.stderr)
                    continue
                if count:
                    # Add breach reason to existing finding or create a new one.
                    match = next((f for f in findings if f.item_id == rec.item_id), None)
                    if match:
                        match.reasons.append(f"breached: found {count}x in HIBP")
                    else:
                        from .policy import Finding
                        findings.append(Finding(
                            item_id=rec.item_id,
                            name=rec.name,
                            reasons=[f"breached: found {count}x in HIBP"],
                        ))

    print(f"cvc-remind: {len(records)} credentials, {len(findings)} findings")
    for f in findings:
        print(f"  {f.name}: {', '.join(f.reasons)}")

    if args.dry_run:
        return 0

    try:
        publish(findings, cfg)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: MQTT publish failed — {exc}", file=sys.stderr)
        return 1

    print("published to Home Assistant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
