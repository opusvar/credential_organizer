"""Printed step-ca commands for bridge certs. Never executed by cvc (an operator runs them).

The cert's lifetime is the bridge's remaining time; its tier is already capped and it carries
the temp flag `urn:cvc:temp:<expires_at>` (rendered by device-leaf.tpl from the `temp` claim).
"""
from __future__ import annotations

from datetime import datetime

from cvc import site as site_config
from cvc.onboard.certs import ROOT, CertCommand, provisioner_for

from .model import Bridge, parse_ts


def lifetime_hours(b: Bridge, now: datetime) -> int:
    secs = (parse_ts(b.expires_at) - now).total_seconds()
    return max(1, int(secs // 3600))


def issue_commands(b: Bridge, now: datetime, ca_url: str | None = None) -> list[CertCommand]:
    if b.status != "active" or not b.expires_at:
        raise ValueError(f"{b.id} is not active")
    ca_url = ca_url or site_config.load().ca_url
    prov, _ = provisioner_for(b.tier)          # capped tiers all use issuer-family
    dur = f"{lifetime_hours(b, now)}h"
    out = f"./out/{b.id}/{b.id}"
    return [
        CertCommand(("step", "ca", "token", b.id, "--provisioner", prov, "--ca-url", ca_url,
                     "--root", ROOT, "--set", f"person={b.person}", "--set", f"device={b.id}",
                     "--set", f"tier={b.tier}", "--set", f"temp={b.expires_at}",
                     "--not-after", dur), capture="TOKEN"),
        CertCommand(("step", "ca", "certificate", b.id, f"{out}.crt", f"{out}.key",
                     "--token", '"$TOKEN"', "--ca-url", ca_url, "--root", ROOT,
                     "--not-after", dur)),
    ]


def revoke_command(b: Bridge) -> str:
    return (f"step ca revoke --reason {b.end_reason or 'revoked'!r} "
            f"$(step certificate inspect ./out/{b.id}/{b.id}.crt --format json | jq -r .serial_number)")
