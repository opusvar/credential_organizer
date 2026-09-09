"""Machine-generated agent service tokens.

Usage:
    python -m cvc.broker.tokens          # prints token + sha256
    from cvc.broker.tokens import mint_token
"""
from __future__ import annotations

import hashlib
import secrets
import sys


def mint_token() -> tuple[str, str]:
    """Return (token, sha256_hex). Store only the sha256 in the ACL."""
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


if __name__ == "__main__":
    token, digest = mint_token()
    print(f"token:      {token}")
    print(f"sha256:     {digest}")
    print("Store the sha256 in the ACL; give the token to the agent once.")
    sys.exit(0)
