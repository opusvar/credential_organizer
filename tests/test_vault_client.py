"""Tests for vault/client.py — env guards and pure helpers. No subprocess calls."""
import os

import pytest

from cvc.vault.client import BwClient, VaultError, _encode, _session


def test_session_raises_when_unset(monkeypatch):
    monkeypatch.delenv("BW_SESSION", raising=False)
    with pytest.raises(VaultError, match="BW_SESSION not set"):
        _session()


def test_session_returns_value(monkeypatch):
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    assert _session() == "fake-session-key"


def test_login_apikey_raises_when_clientid_missing(monkeypatch):
    monkeypatch.delenv("BW_CLIENTID", raising=False)
    monkeypatch.delenv("BW_CLIENTSECRET", raising=False)
    client = BwClient(server="https://vault.example.test")
    with pytest.raises(VaultError, match="BW_CLIENTID"):
        client.login_apikey()


def test_login_apikey_raises_when_clientsecret_missing(monkeypatch):
    monkeypatch.setenv("BW_CLIENTID", "some-id")
    monkeypatch.delenv("BW_CLIENTSECRET", raising=False)
    client = BwClient(server="https://vault.example.test")
    with pytest.raises(VaultError, match="BW_CLIENTSECRET"):
        client.login_apikey()


def test_unlock_raises_when_password_missing(monkeypatch):
    monkeypatch.delenv("BW_PASSWORD", raising=False)
    client = BwClient(server="https://vault.example.test")
    with pytest.raises(VaultError, match="BW_PASSWORD"):
        client.unlock()


def test_encode_is_valid_base64():
    import base64
    payload = '{"type":1,"name":"test"}'
    encoded = _encode(payload)
    assert base64.b64decode(encoded).decode() == payload
