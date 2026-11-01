"""`cvc-remind` CLI — evaluate vault credentials against policy, publish to Home Assistant.

Run as a systemd user timer (see deploy/cvc-remind.service) or directly. Reads all vault
items, evaluates age/reuse/weakness/breach, and publishes a sensor + attributes to HA via
MQTT discovery.

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
from .policy import CredRecord, Finding, evaluate


def _parse_rotated(item: dict) -> datetime | None:
    """Extract last password-change date from a vault item if present."""
    try:
        # Not item["revisionDate"]: it resets on ANY edit (rename, note, folder move), which
        # would hide a stale password. passwordRevisionDate changes only with the password;
        # it is null if never changed, so fall back to creationDate.
        login = item.get("login") or {}
        raw = login.get("passwordRevisionDate") or item.get("creationDate")
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
        item_id = item.get("id")
        if not item_id:  # malformed item — nothing we could report on or link back to
            continue
        login = item.get("login") or {}
        password = login.get("password") or ""
        if not password:
            # A login with no password (URI-only bookmark, passkey-only entry) has nothing
            # to rotate, reuse, or breach-check. Including it produced false "weak" findings.
            continue
        records.append(CredRecord(
            item_id=item_id,
            name=item.get("name", ""),
            username=login.get("username") or "",
            password=password,
            last_rotated=_parse_rotated(item),
        ))
    return records


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cvc-remind")
    p.add_argument("--dry-run", action="store_true",
                   help="evaluate and print findings; do not publish to MQTT")
    p.add_argument("--verbose", action="store_true",
                   help="also list per-credential names and reasons (interactive use only; "
                        "never enable under systemd, output reaches the journal)")
    args = p.parse_args(argv)

    cfg = config.load()

    try:
        records = _vault_records(cfg)
    except (VaultError, RuntimeError) as exc:
        print(f"ERROR: vault read failed — {exc}", file=sys.stderr)
        return 1

    findings = evaluate(records, max_age_days=cfg.rotation_max_age_days)

    hibp_failures = 0
    if cfg.hibp_enabled and records:
        with httpx.Client(timeout=10.0) as http:
            for rec in records:
                if not rec.password:
                    continue
                try:
                    count = times_pwned(rec.password, client=http)
                except Exception as exc:  # noqa: BLE001
                    hibp_failures += 1
                    continue
                if count:
                    # Add breach reason to existing finding or create a new one.
                    match = next((f for f in findings if f.item_id == rec.item_id), None)
                    if match:
                        match.reasons.append(f"breached: found {count}x in HIBP")
                    else:
                        findings.append(Finding(
                            item_id=rec.item_id,
                            name=rec.name,
                            reasons=[f"breached: found {count}x in HIBP"],
                        ))

    # Counts only: account identities must never reach the journal.
    by_reason = {k: 0 for k in ("stale", "reused", "weak", "breached")}
    for f in findings:
        for r in f.reasons:
            key = r.split(":", 1)[0].split(" ", 1)[0].lower()
            if key in by_reason:
                by_reason[key] += 1
    breakdown = ", ".join(f"{k}={v}" for k, v in by_reason.items())
    print(f"cvc-remind: {len(records)} credentials, {len(findings)} findings ({breakdown})")
    print(f"cvc-remind: HIBP failures: {hibp_failures}")
    if args.verbose:
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
