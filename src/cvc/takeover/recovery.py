"""Sealed per-owner recovery passwords for the no-target-key takeover path (D15).

Only a scrypt hash (n=2**15, r=8, p=1, 16-byte salt) is stored, in ``recovery.json`` under the
takeover state dir. Plaintext is read via an injectable prompt, hashed, and dropped.
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from cvc.takeover.model import TakeoverError

N, R, P = 2 ** 15, 8, 1
MIN_LEN = 16


def _hash(pw: bytes, salt: bytes, n: int = N, r: int = R, p: int = P) -> bytes:
    return hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, maxmem=128 * 1024 * 1024, dklen=32)


class RecoveryVerifier(Protocol):
    def verify(self, person: str) -> bool: ...


class RecoveryPasswordStore:
    def __init__(self, state_dir: str | os.PathLike,
                 ask: Callable[[str], str] = getpass.getpass):
        self.path = Path(state_dir).expanduser() / "recovery.json"
        self.ask = ask

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def has(self, person: str) -> bool:
        return person in self._load()

    def set(self, person: str, when: str) -> bool:
        """Set or rotate. Returns True if a previous hash was replaced. Caller must already
        have verified ``person``'s own YubiKey."""
        pw = self.ask(f"New sealed recovery password for {person}: ")
        if len(pw) < MIN_LEN:
            raise TakeoverError(f"refused: recovery password must be at least {MIN_LEN} chars")
        if self.ask("Repeat: ") != pw:
            raise TakeoverError("refused: passwords do not match")
        salt = secrets.token_bytes(16)
        digest = _hash(pw.encode(), salt)
        del pw
        data = self._load()
        rotated = person in data
        data[person] = {"alg": "scrypt", "n": N, "r": R, "p": P, "salt": salt.hex(),
                        "hash": digest.hex(), "set_at": when}
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
        return rotated

    def verify(self, person: str) -> bool:
        rec = self._load().get(person)
        if rec is None:
            raise TakeoverError(f"refused: no sealed recovery password is set for {person!r}")
        pw = self.ask(f"Sealed recovery password of {person}: ").encode()
        try:
            got = _hash(pw, bytes.fromhex(rec["salt"]), rec["n"], rec["r"], rec["p"])
        finally:
            del pw
        return hmac.compare_digest(got, bytes.fromhex(rec["hash"]))
