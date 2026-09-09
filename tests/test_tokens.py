"""Tests for broker/tokens.py — machine-generated agent service tokens."""
import hashlib

from cvc.broker.tokens import mint_token


def test_mint_token_sha256_matches():
    token, digest = mint_token()
    expected = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert digest == expected


def test_mint_token_length():
    token, _ = mint_token()
    # secrets.token_urlsafe(32) produces ~43 base64url chars.
    assert len(token) >= 32


def test_mint_token_uniqueness():
    tokens = {mint_token()[0] for _ in range(10)}
    assert len(tokens) == 10, "mint_token() must never return the same token twice"
