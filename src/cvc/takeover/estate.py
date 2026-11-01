"""Estate recovery kit: a printed, single-use household code (D15 addendum).

``cvc takeover estate-kit generate`` creates a high-entropy code (150 bits, 30 Crockford
base32 symbols in groups of 5) meant to be printed once on paper and kept in a safety deposit
box. Only a scrypt hash is stored (``estate_kit.json``, mode 0600, under the takeover state
dir); the plaintext is returned to the caller for printing and never written anywhere.

Using it (wizard step 5, path ``estate-kit``) starts the 180-day path against any owner
target. On use the stored hash is destroyed and the kit is marked used: it cannot be used
again, and a new kit must be generated and printed (rotation). The used kit is never
replaced automatically, so whoever used it does not receive a fresh code.
"""
from __future__ import annotations

import getpass
import hmac
import json
import os
import secrets
from collections.abc import Callable
from pathlib import Path

from cvc.takeover.model import TakeoverError
from cvc.takeover.recovery import N, P, R, _hash

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"     # Crockford base32: no I, L, O, U
SYMBOLS = 30                                     # 30 * 5 bits = 150 bits of entropy
GROUP = 5


def normalize(code: str) -> str:
    c = "".join(ch for ch in code.upper() if ch.isalnum())
    return c.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))


def format_code(raw: str) -> str:
    return "-".join(raw[i:i + GROUP] for i in range(0, len(raw), GROUP))


class EstateKitStore:
    def __init__(self, state_dir: str | os.PathLike,
                 ask: Callable[[str], str] = getpass.getpass):
        self.path = Path(state_dir).expanduser() / "estate_kit.json"
        self.ask = ask

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def status(self) -> dict:
        d = self._load()
        return {k: v for k, v in d.items() if k not in ("hash", "salt")}

    def active(self) -> bool:
        return self._load().get("status") == "active"

    def generate(self, by: str, when: str) -> str:
        """Create (or rotate) the kit. Returns the formatted code for printing ONCE. Caller must
        already have verified ``by``'s own owner YubiKey."""
        raw = "".join(secrets.choice(ALPHABET) for _ in range(SYMBOLS))
        salt = secrets.token_bytes(16)
        prev = self._load()
        digest = _hash(raw.encode(), salt).hex()
        self._write({"alg": "scrypt", "n": N, "r": R, "p": P, "salt": salt.hex(),
                     "hash": digest, "status": "active",
                     "kit_id": digest[:8], "generated_at": when, "generated_by": by,
                     "replaces": prev.get("kit_id")})
        return format_code(raw)

    def verify(self) -> bool:
        rec = self._load()
        if rec.get("status") != "active":
            raise TakeoverError("refused: no active estate recovery kit (it was never generated, "
                                "or it was already used; generate and print a new one)")
        from cvc.takeover.estate_sheet import parse_code  # typed code or scanned URI
        code = parse_code(self.ask("Estate recovery kit code (type it, or scan the QR): ")
                          ).encode()
        try:
            got = _hash(code, bytes.fromhex(rec["salt"]), rec["n"], rec["r"], rec["p"])
        finally:
            del code
        return hmac.compare_digest(got, bytes.fromhex(rec["hash"]))

    def consume(self, takeover_id: str, when: str) -> str:
        """Single use: destroy the hash and mark the kit used. Returns the used kit id."""
        rec = self._load()
        if rec.get("status") != "active":
            raise TakeoverError("refused: estate recovery kit is not active")
        self._write({"status": "used", "kit_id": rec["kit_id"], "generated_at":
                     rec.get("generated_at"), "used_at": when, "used_by_takeover": takeover_id})
        return rec["kit_id"]
