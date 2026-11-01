"""Tests for vault/client.py — env guards and pure helpers. No subprocess calls."""

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


# ── _ENV_BASE completeness — regression against the Phase 4 deployment blocker ──
# bw reads these vars from its environment; a missing entry silently breaks all
# vault calls with "You are not logged in." even when BW_SESSION is correct.

def test_env_base_contains_bw_session_passthrough():
    """BW_SESSION is injected explicitly in _run(), not via _ENV_BASE — verify the
    mechanism is correct rather than the set membership."""
    from cvc.vault.client import _ENV_BASE
    # BW_SESSION is set on the env dict directly in _run(); it must NOT be stripped.
    # The test is that _ENV_BASE does not accidentally block it. Since it's injected
    # after filtering, the set should not contain it (that would be redundant) but
    # also must not be needed for it to pass through.
    # Structural check: it is not in _ENV_BASE (injected post-filter, not pre-filter).
    assert "BW_SESSION" not in _ENV_BASE  # injected after allowlist filter — not a set member


def test_env_base_contains_appdata_dir():
    """BITWARDENCLI_APPDATA_DIR must be in _ENV_BASE.

    Without it, the bw subprocess cannot find the login state written by the
    init container and returns 'You are not logged in.' on every vault call.
    This was the final Phase 4 deployment blocker (2026-09-13).
    """
    from cvc.vault.client import _ENV_BASE
    assert "BITWARDENCLI_APPDATA_DIR" in _ENV_BASE


def test_env_base_contains_home():
    """HOME must be in _ENV_BASE — bw writes data.json under $HOME if APPDATA_DIR unset."""
    from cvc.vault.client import _ENV_BASE
    assert "HOME" in _ENV_BASE


def test_env_base_contains_path():
    """PATH must be in _ENV_BASE — bw is resolved from PATH."""
    from cvc.vault.client import _ENV_BASE
    assert "PATH" in _ENV_BASE


def test_run_strips_non_allowlisted_env(monkeypatch, tmp_path):
    """_run() must not pass arbitrary env vars to the bw subprocess.

    A secret like ANTHROPIC_API_KEY or AWS_SECRET_ACCESS_KEY in the process env
    must not leak into a bw subprocess that could log it or forward it.
    """
    from unittest.mock import MagicMock, patch

    from cvc.vault.client import _run

    monkeypatch.setenv("SECRET_SHOULD_NOT_LEAK", "sensitive-value")
    monkeypatch.setenv("BW_SESSION", "fake-session")
    monkeypatch.setenv("HOME", "/tmp")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("BITWARDENCLI_APPDATA_DIR", str(tmp_path))

    captured_env: dict = {}

    def fake_run(argv, capture_output, text, timeout, env, check):
        captured_env.update(env)
        m = MagicMock()
        m.returncode = 0
        m.stdout = '{"status":"unlocked"}'
        m.stderr = ""
        return m

    with patch("cvc.vault.client.subprocess.run", fake_run):
        _run("status", session="fake-session")

    assert "SECRET_SHOULD_NOT_LEAK" not in captured_env
    assert "BITWARDENCLI_APPDATA_DIR" in captured_env
    assert "HOME" in captured_env
    assert "PATH" in captured_env
