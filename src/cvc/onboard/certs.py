"""step-ca device-cert commands for onboarding (printed; run only behind --execute).

Provisioner/lifetime mapping mirrors deploy/step-ca/issue-p12.sh (a test keeps them in sync).
Identity SANs (urn:cvc:person/device/tier) are rendered by deploy/step-ca/templates/
device-leaf.tpl from signed token claims, never from the CSR.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass

from cvc import site as site_config

ISSUE_P12 = "deploy/step-ca/issue-p12.sh"
YK_ISSUE = "deploy/yubikey/issue-device-cert.sh"
YK_ENROLL = "deploy/yubikey/enroll-mac.sh"
TEMPLATE = "deploy/step-ca/templates/device-leaf.tpl"
ROOT = "$HOME/.step/certs/root_ca.crt"

_PROVISIONERS = {
    "guest-short": ("issuer-guest-short", "48h"),
    "guest-long": ("issuer-guest-long", "720h"),
    "media-only": ("issuer-family", "8760h"),
    "low": ("issuer-family", "8760h"),
    "medium": ("issuer-family", "8760h"),
    "high": ("issuer-family", "8760h"),
    "admin": ("issuer-admin", "2160h"),
    "owner": ("issuer-admin", "2160h"),
}


def provisioner_for(tier: str) -> tuple[str, str]:
    """(JWK provisioner, lifetime) for a person tier, as in issue-p12.sh."""
    return _PROVISIONERS[tier]


def expected_sans(tier: str, person: str, device: str) -> list[str]:
    return [f"urn:cvc:person:{person}", f"urn:cvc:device:{device}", f"urn:cvc:tier:{tier}"]


@dataclass(frozen=True)
class CertCommand:
    """One printable/executable command. `capture` names a shell var bound to its stdout."""
    argv: tuple[str, ...]
    capture: str | None = None

    def shell(self) -> str:
        cmd = " ".join(a if a.startswith(("$", '"$')) else shlex.quote(a) for a in self.argv)
        return f"{self.capture}=$({cmd})" if self.capture else cmd


def cert_commands(person: str, device: str, tier: str, kind: str, storage: str,
                  ca_url: str | None = None) -> list[CertCommand]:
    """Commands that issue this device's cert. Phones get the .p12/.mobileconfig bundle.

    `ca_url` defaults to the loaded site config's step-ca URL."""
    ca_url = ca_url or site_config.load().ca_url
    prov, dur = provisioner_for(tier)
    if storage == "yubikey-piv":
        # ACME device-attest-01: key generated on the YubiKey (slot 9a).
        return [CertCommand(("bash", YK_ISSUE, device))]
    if kind == "phone":
        return [CertCommand(("bash", ISSUE_P12, "--person", person, "--device", device,
                             "--tier", tier))]
    out = f"./out/{device}/{device}"
    return [
        CertCommand(("step", "ca", "token", device, "--provisioner", prov, "--ca-url", ca_url,
                     "--root", ROOT, "--set", f"person={person}", "--set", f"device={device}",
                     "--set", f"tier={tier}", "--not-after", dur), capture="TOKEN"),
        CertCommand(("step", "ca", "certificate", device, f"{out}.crt", f"{out}.key",
                     "--token", '"$TOKEN"', "--ca-url", ca_url, "--root", ROOT,
                     "--not-after", dur)),
    ]
