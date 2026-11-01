"""Have-I-Been-Pwned breach check via k-anonymity.

Only the first 5 hex chars of the SHA-1 hash leave the machine.
Controlled by HIBP_ENABLED config flag (default off).
"""
from __future__ import annotations

import hashlib

import httpx

_API = "https://api.pwnedpasswords.com/range/{prefix}"
_TIMEOUT = 10.0


def _prefix_suffix(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def times_pwned(password: str, *, client: httpx.Client | None = None) -> int:
    """Return breach count for *password*. Only the 5-char SHA-1 prefix is sent."""
    prefix, suffix = _prefix_suffix(password)
    close_after = client is None
    if client is None:
        client = httpx.Client(timeout=_TIMEOUT)
    try:
        resp = client.get(_API.format(prefix=prefix))
        resp.raise_for_status()
    finally:
        if close_after:
            client.close()

    for line in resp.text.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix:
            return int(count.strip())
    return 0
