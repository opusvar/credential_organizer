"""Pure logic for tiergate: cert parsing, tier ordering, and the allow/deny decision."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote

import yaml
from cryptography import x509

TIERS: tuple[str, ...] = (
    "guest-short",
    "guest-long",
    "media-only",
    "low",
    "medium",
    "high",
    "admin",
    "owner",
)
TIER_RANK = {t: i for i, t in enumerate(TIERS)}
PASSKEY_TIERS = frozenset({"high", "admin", "owner"})

URN_TIER = "urn:cvc:tier:"
URN_PERSON = "urn:cvc:person:"
URN_DEVICE = "urn:cvc:device:"
URN_TEMP = "urn:cvc:temp:"          # bridge (temporary device) flag, value = expiry (D27)
TEMP_TIER_CAP = "medium"
_TEMP_DEVICE = re.compile(r"^.+-temp-[0-9]+$")

_PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
_PEM_END = "-----END CERTIFICATE-----"


class CertError(ValueError):
    pass


@dataclass(frozen=True)
class Identity:
    tier: str | None
    person: str | None
    device: str | None
    temp: bool = False
    temp_expires: str | None = None


@dataclass(frozen=True)
class Config:
    hosts: dict[str, str]
    default_min_tier: str | None = None  # None => unknown hosts are denied

    def min_tier_for(self, host: str) -> str | None:
        host = host.split(":", 1)[0].lower()
        return self.hosts.get(host, self.default_min_tier)


def _check_tier(t: str, where: str) -> str:
    if t not in TIER_RANK:
        raise ValueError(f"unknown tier {t!r} in {where}")
    return t


def parse_config(data: dict) -> Config:
    hosts_raw = data.get("hosts") or {}
    if not isinstance(hosts_raw, dict):
        raise TypeError("'hosts' must be a mapping of host -> min tier")
    hosts = {str(h).lower(): _check_tier(str(t), f"hosts.{h}") for h, t in hosts_raw.items()}
    default = data.get("default_min_tier")
    if default is not None:
        default = _check_tier(str(default), "default_min_tier")
    return Config(hosts=hosts, default_min_tier=default)


def load_config(path: str | Path) -> Config:
    with open(path, encoding="utf-8") as fh:
        return parse_config(yaml.safe_load(fh) or {})


def load_cert(header_value: str) -> x509.Certificate:
    """Decode the X-Forwarded-Tls-Client-Cert value.

    Traefik's passTLSClientCert(pem: true) sends URL-escaped PEM, with the BEGIN/END
    delimiters stripped; a chain is comma-separated (leaf first). Full PEM is also accepted.
    """
    raw = unquote(header_value.strip())
    if not raw:
        raise CertError("empty certificate header")
    first = raw.split(",", 1)[0].strip()
    body = first.replace(_PEM_BEGIN, "").replace(_PEM_END, "")
    body = "".join(body.split())
    try:
        der = base64.b64decode(body, validate=True)
        return x509.load_der_x509_certificate(der)
    except Exception as exc:  # any decode failure is a bad cert
        raise CertError(f"unparseable client certificate: {exc}") from exc


def extract_identity(cert: x509.Certificate) -> Identity:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return Identity(None, None, None)
    tier = person = device = temp_expires = None
    temp = False
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        if uri.startswith(URN_TEMP):
            temp = True
            temp_expires = temp_expires or uri[len(URN_TEMP):] or None
            continue
        if uri.startswith(URN_TIER) and tier is None:
            tier = uri[len(URN_TIER):]
        elif uri.startswith(URN_PERSON) and person is None:
            person = uri[len(URN_PERSON):]
        elif uri.startswith(URN_DEVICE) and device is None:
            device = uri[len(URN_DEVICE):]
    device = device or None
    temp = temp or bool(device and _TEMP_DEVICE.match(device))
    tier = tier or None
    if temp and tier in TIER_RANK and TIER_RANK[tier] > TIER_RANK[TEMP_TIER_CAP]:
        tier = TEMP_TIER_CAP           # never above medium from a temp device
    return Identity(tier, person or None, device, temp, temp_expires if temp else None)


def _temp_expired(ident: Identity, now: datetime) -> bool:
    if not ident.temp_expires:
        return False
    try:
        end = datetime.fromisoformat(ident.temp_expires)
    except ValueError:
        return True                    # unparseable flag: treat as expired (fail closed)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    return end <= now


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    identity: Identity | None = None


def decide(
    config: Config,
    host: str,
    cert_header: str | None,
    authentik_user: str | None,
    now: datetime | None = None,
) -> Decision:
    min_tier = config.min_tier_for(host or "")
    if min_tier is None:
        return Decision(False, "host not configured")
    if not cert_header:
        return Decision(False, "no client certificate")
    try:
        ident = extract_identity(load_cert(cert_header))
    except CertError as exc:
        return Decision(False, str(exc))
    if ident.tier is None or ident.tier not in TIER_RANK:
        return Decision(False, "certificate has no valid tier", ident)
    if ident.person is None:
        return Decision(False, "certificate has no person", ident)
    if ident.temp and _temp_expired(ident, now or datetime.now(UTC)):
        return Decision(False, "temporary device expired", ident)
    if TIER_RANK[ident.tier] < TIER_RANK[min_tier]:
        return Decision(False, f"tier {ident.tier} below required {min_tier}", ident)
    if min_tier in PASSKEY_TIERS and not (authentik_user or "").strip():
        return Decision(False, "passkey (Authentik) proof required", ident)
    return Decision(True, "ok", ident)
