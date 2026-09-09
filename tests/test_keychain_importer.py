"""Tests for the Keychain CSV importer (D2: Passwords-app CSV path)."""
import pytest

from cvc.importers.keychain import KeychainImporter
from cvc.importers.normalize import dedup

_KEYCHAIN_CSV = """\
Title,URL,Username,Password,Notes,OTPAuth
Example,https://example.test/login,user@example.test,not-a-real-pw-1,,
Example Dup,https://www.example.test/,user@example.test,not-a-real-pw-1,dup of above,
Other,https://other.test,someone@other.test,not-a-real-pw-2,,
NoURL,,local-user,not-a-real-pw-3,no uri so name used as key,
"""


@pytest.fixture
def keychain_csv(tmp_path):
    p = tmp_path / "keychain_passwords.csv"
    p.write_text(_KEYCHAIN_CSV, encoding="utf-8")
    return str(p)


def test_keychain_parses_rows(keychain_csv):
    items = KeychainImporter().parse(keychain_csv)
    assert len(items) == 4
    assert all(it.source == "keychain" for it in items)
    first = items[0]
    assert first.name == "Example"
    assert first.username == "user@example.test"
    assert first.uri == "https://example.test/login"


def test_keychain_tolerates_missing_note(keychain_csv):
    items = KeychainImporter().parse(keychain_csv)
    # Most rows have no note; the importer must not error on empty or absent Notes column.
    assert any(it.note == "" for it in items)


def test_keychain_no_uri_uses_name_as_key(keychain_csv):
    items = KeychainImporter().parse(keychain_csv)
    no_uri = next(it for it in items if not it.uri)
    assert no_uri.dedup_key == ("nourl", "local-user")


def test_keychain_then_dedup(keychain_csv):
    items = KeychainImporter().parse(keychain_csv)
    res = dedup(items)
    assert len(res.unique) == 3
    assert len(res.duplicates) == 1
