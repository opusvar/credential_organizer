"""Have-I-Been-Pwned breach check via k-anonymity (only a SHA-1 prefix leaves the machine).

SCAFFOLD: the k-anonymity flow is outlined but disabled by default (HIBP_ENABLED). Implement
with httpx during Phase 2 once D7 confirms breach checks are wanted.
"""
from __future__ import annotations

import hashlib


def _prefix_suffix(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324 (k-anon by design)
    return digest[:5], digest[5:]


def times_pwned(password: str) -> int:
    """Return breach count for a password. Only the 5-char SHA-1 prefix is ever sent."""
    _prefix, _suffix = _prefix_suffix(password)
    raise NotImplementedError(
        "TODO(D7/Phase 2): GET https://api.pwnedpasswords.com/range/{prefix}, match suffix"
    )
