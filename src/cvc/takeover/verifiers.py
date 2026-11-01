"""Factor verifiers for the takeover wizard: device cert, YubiKey, elevation (D15).

Every external dependency (ykman, Vaultwarden, Authentik) sits behind a small interface so the
tests use fakes. No verifier stores or logs a secret: elevation implementations prompt for the
secret themselves and only return a boolean.
"""
from __future__ import annotations

import base64
import getpass
import hashlib
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Protocol

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

from cvc.takeover.model import TakeoverError

TIER_PREFIX = "urn:cvc:tier:"
PERSON_PREFIX = "urn:cvc:person:"


# ── step 1: step-ca device certificate ──────────────────────────────────────
@dataclass(frozen=True)
class CertIdentity:
    fingerprint: str      # sha256 hex, lowercase
    tier: str
    person: str
    serial: str           # hex


def _valid_at(cert: x509.Certificate, now: datetime, what: str) -> None:
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise TakeoverError(f"refused: {what} is outside its validity window "
                            f"({cert.not_valid_before_utc:%Y-%m-%d} .. "
                            f"{cert.not_valid_after_utc:%Y-%m-%d})")


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca)
    except x509.ExtensionNotFound:
        return False


def _issued_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    if child.issuer != parent.subject:
        return False
    try:
        child.verify_directly_issued_by(parent)
    except Exception:  # noqa: BLE001 - InvalidSignature, unsupported key types
        return False
    return True


def verify_device_cert(leaf_pem: bytes, chain_pems: list[bytes], root_pem: bytes,
                       now: datetime) -> CertIdentity:
    """Verify leaf -> intermediates -> configured root, then read the cvc URI SANs."""
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    root = x509.load_pem_x509_certificate(root_pem)
    pool = [c for pem in chain_pems for c in x509.load_pem_x509_certificates(pem)]
    _valid_at(leaf, now, "device certificate")
    _valid_at(root, now, "root CA certificate")
    cur, depth = leaf, 0
    while not _issued_by(cur, root):
        nxt = next((c for c in pool if _is_ca(c) and _issued_by(cur, c)), None)
        depth += 1
        if nxt is None or depth > 4:
            raise TakeoverError("refused: device certificate does not chain to the configured "
                                "root CA")
        _valid_at(nxt, now, f"intermediate {nxt.subject.rfc4514_string()}")
        cur = nxt
    try:
        uris = leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
            x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        uris = []
    tiers = [u[len(TIER_PREFIX):] for u in uris if u.startswith(TIER_PREFIX)]
    persons = [u[len(PERSON_PREFIX):] for u in uris if u.startswith(PERSON_PREFIX)]
    if len(tiers) != 1 or len(persons) != 1:
        raise TakeoverError("refused: device certificate must carry exactly one "
                            f"{TIER_PREFIX}<tier> and one {PERSON_PREFIX}<id> URI SAN")
    fp = leaf.fingerprint(hashes.SHA256()).hex()
    return CertIdentity(fp, tiers[0], persons[0], format(leaf.serial_number, "x"))


def check_cert_registry(ident: CertIdentity, data: dict, person: str, today: date,
                        tier: str | None = "owner") -> str:
    """Cert must be the ``tier`` cert of ``person`` and active in the registry. Returns the
    device id. ``tier=None`` (delegation) accepts any tier, as long as the cert's tier equals
    the person's registry tier."""
    p = (data.get("people") or {}).get(person)
    want = tier if tier is not None else (p or {}).get("tier") if isinstance(p, dict) else None
    if ident.tier != want:
        raise TakeoverError(f"refused: certificate tier is {ident.tier!r}; need a "
                            f"{want or 'registered'}-tier device certificate")
    if ident.person != person:
        raise TakeoverError(f"refused: certificate belongs to {ident.person!r}, not {person!r}")
    if not isinstance(p, dict) or p.get("tier") != want or p.get("status", "active") != "active":
        raise TakeoverError(f"refused: {person!r} is not an active {want}-tier person")
    for did, dev in (data.get("devices") or {}).items():
        cert = (dev or {}).get("cert") or {}
        if str(cert.get("fingerprint_sha256") or "").lower() != ident.fingerprint:
            continue
        if dev.get("owner") != person:
            raise TakeoverError(f"refused: registry records device {did} as owned by "
                                f"{dev.get('owner')!r}")
        if cert.get("status") != "active":
            raise TakeoverError(f"refused: certificate of device {did} is {cert.get('status')} "
                                "in the registry")
        na = cert.get("not_after")
        if isinstance(na, str):
            na = date.fromisoformat(na)
        if na is not None and na < today:
            raise TakeoverError(f"refused: certificate of device {did} expired {na}")
        return did
    raise TakeoverError("refused: certificate fingerprint is not registered to any device")


# ── steps 2 and 5: YubiKey possession ───────────────────────────────────────
@dataclass(frozen=True)
class KeyReading:
    serial: str
    attested: bool     # PIV slot 9a attestation verified and its serial matches


class YubiKeyReader(Protocol):
    def read(self) -> KeyReading: ...


YUBICO_SERIAL_OID = x509.ObjectIdentifier("1.3.6.1.4.1.41482.3.7")


class YkmanReader:
    """Reads the single inserted YubiKey via ykman and checks the slot 9a attestation:
    the attestation cert must be signed by the key's f9 attestation intermediate and embed
    the same serial. (Chaining f9 up to Yubico's root is not checked here; see D15.)"""

    def __init__(self, run: Callable[..., Any] = subprocess.run):
        self.run = run

    def _out(self, *args: str) -> bytes:
        r = self.run(["ykman", *args], capture_output=True, check=False, timeout=30)
        if r.returncode != 0:
            raise TakeoverError(f"ykman {' '.join(args)} failed: "
                                f"{r.stderr.decode(errors='replace').strip()}")
        return r.stdout

    def read(self) -> KeyReading:
        serials = self._out("list", "--serials").decode().split()
        if len(serials) != 1:
            raise TakeoverError(f"insert exactly one YubiKey (found {len(serials)})")
        s = serials[0]
        att = x509.load_pem_x509_certificate(self._out("--device", s, "piv", "keys", "attest",
                                                       "9a", "-"))
        f9 = x509.load_pem_x509_certificate(self._out("--device", s, "piv", "certificates",
                                                      "export", "f9", "-"))
        ok = _issued_by(att, f9)
        try:
            der = att.extensions.get_extension_for_oid(YUBICO_SERIAL_OID).value.value
            ok = ok and der[0] == 0x02 and int.from_bytes(der[2:2 + der[1]], "big") == int(s)
        except (x509.ExtensionNotFound, AttributeError, IndexError, ValueError):
            ok = False
        return KeyReading(s, ok)


def verify_owner_key(reading: KeyReading, data: dict, person: str,
                     allow_suspended: bool = False) -> str:
    """Return the hardware key id if the reading is an active owner key registered to person.
    ``allow_suspended``: a suspended key (D14 lockout) is accepted too; lost/revoked never."""
    if not reading.attested:
        raise TakeoverError(f"refused: YubiKey {reading.serial} failed PIV slot 9a attestation")
    match = [(kid, k) for kid, k in (data.get("hardware_keys") or {}).items()
             if isinstance(k, dict) and str(k.get("serial")) == str(reading.serial)]
    if not match:
        raise TakeoverError(f"refused: YubiKey {reading.serial} is not registered")
    kid, key = match[0]
    if key.get("owner") != person:
        raise TakeoverError(f"refused: YubiKey {kid} is registered to {key.get('owner')!r}, "
                            f"not {person!r}")
    ok = ("active", "suspended") if allow_suspended else ("active",)
    if key.get("status", "active") not in ok:
        raise TakeoverError(f"refused: YubiKey {kid} is {key.get('status')}, not active")
    p = (data.get("people") or {}).get(person)
    if not isinstance(p, dict) or p.get("tier") != "owner" or p.get("status", "active") != "active":
        raise TakeoverError(f"refused: {person!r} is not an active owner-tier person, so "
                            f"{kid} is not an owner key")
    return kid


# ── step 3: elevation (passkey OR Vaultwarden master password) ──────────────
class Elevation(Protocol):
    method: str

    def verify(self, person: str, email: str) -> bool: ...


class VaultwardenPasswordElevation:
    """Proves the master password by a password-grant login. The secret is read with getpass,
    hashed locally (PBKDF2 only) and dropped; a 2FA challenge counts as password-correct."""
    method = "vaultwarden-password"

    def __init__(self, base_url: str, ask: Callable[[str], str] = getpass.getpass,
                 http: httpx.Client | None = None):
        self.base = base_url.rstrip("/")
        self.ask = ask
        self.http = http or httpx.Client(timeout=15)

    def verify(self, person: str, email: str) -> bool:
        email = email.strip().lower()
        pre = self.http.post(f"{self.base}/identity/accounts/prelogin", json={"email": email})
        pre.raise_for_status()
        kdf = pre.json()
        if kdf.get("kdf", kdf.get("Kdf", 0)) != 0:
            raise TakeoverError("Argon2id KDF accounts are not supported; use passkey elevation")
        iters = int(kdf.get("kdfIterations", kdf.get("KdfIterations", 600000)))
        pw = self.ask(f"Vaultwarden master password for {person}: ").encode()
        try:
            mk = hashlib.pbkdf2_hmac("sha256", pw, email.encode(), iters)
            h = base64.b64encode(hashlib.pbkdf2_hmac("sha256", mk, pw, 1)).decode()
        finally:
            del pw
        r = self.http.post(f"{self.base}/identity/connect/token", data={
            "grant_type": "password", "username": email, "password": h, "scope": "api offline_access",
            "client_id": "cli", "deviceType": "8", "deviceName": "cvc-takeover",
            "deviceIdentifier": "cvc-takeover"})
        if r.status_code == 200:
            return True
        try:
            body = r.json()
        except ValueError:
            return False
        return bool(body.get("TwoFactorProviders") or body.get("TwoFactorProviders2"))


class AuthentikPasskeyElevation:
    """OAuth device-authorization grant against Authentik; the user completes it with their
    passkey in a browser. Succeeds if the resulting userinfo names ``person``."""
    method = "passkey"

    def __init__(self, issuer: str, client_id: str, out: Callable[[str], None] = print,
                 http: httpx.Client | None = None, sleep: Callable[[float], None] = time.sleep,
                 timeout_s: int = 300):
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.out, self.sleep, self.timeout_s = out, sleep, timeout_s
        self.http = http or httpx.Client(timeout=15)

    def verify(self, person: str, email: str) -> bool:
        base = self.issuer.split("/application/o/")[0]
        d = self.http.post(f"{base}/application/o/device/",
                           data={"client_id": self.client_id, "scope": "openid profile email"})
        d.raise_for_status()
        dj = d.json()
        self.out(f"Open {dj.get('verification_uri_complete') or dj['verification_uri']} and "
                 f"confirm with your passkey (code {dj['user_code']})")
        waited, interval = 0, int(dj.get("interval", 5))
        while waited < self.timeout_s:
            t = self.http.post(f"{base}/application/o/token/", data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": dj["device_code"], "client_id": self.client_id})
            if t.status_code == 200:
                ui = self.http.get(f"{base}/application/o/userinfo/", headers={
                    "Authorization": f"Bearer {t.json()['access_token']}"}).json()
                return person in (ui.get("preferred_username"), ui.get("nickname")) or (
                    str(ui.get("email", "")).lower() == email.lower())
            self.sleep(interval)
            waited += interval
        return False
