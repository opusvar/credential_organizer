"""Tests for hibp.py — k-anonymity split and response parsing. No real HTTP calls."""
import hashlib
from unittest.mock import MagicMock

from cvc.reminders.hibp import _prefix_suffix, times_pwned


def _sha1_upper(pw: str) -> str:
    return hashlib.sha1(pw.encode()).hexdigest().upper()


def test_prefix_suffix_split():
    digest = _sha1_upper("hunter2")
    prefix, suffix = _prefix_suffix("hunter2")
    assert prefix == digest[:5]
    assert suffix == digest[5:]
    assert len(prefix) == 5
    assert len(suffix) == 35


def test_prefix_is_only_thing_sent(monkeypatch):
    """Verify only the 5-char prefix appears in the URL — suffix never leaves."""
    prefix, suffix = _prefix_suffix("secret")
    captured = {}

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = f"{suffix}:7\nDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEA:1"

    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp

    def capturing_get(url, **kwargs):
        captured["url"] = url
        return mock_resp

    mock_client.get.side_effect = capturing_get

    count = times_pwned("secret", client=mock_client)
    assert prefix in captured["url"]
    assert suffix not in captured["url"]
    assert count == 7


def test_returns_zero_when_not_found():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:3"

    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp

    assert times_pwned("not-in-list", client=mock_client) == 0


def test_returns_count_when_found():
    _, suffix = _prefix_suffix("pwned-pw")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = f"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n{suffix}:42"

    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp

    assert times_pwned("pwned-pw", client=mock_client) == 42
