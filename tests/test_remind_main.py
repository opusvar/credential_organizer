"""Tests for the `cvc-remind` CLI entry point (reminders/__main__.py).

Everything external is patched: no vault, no MQTT broker, no HTTP. The vault is
replaced at the BwClient class level so no `bw` subprocess is ever spawned, and
MQTT publish / HIBP are patched where __main__ looks them up.
"""
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from cvc.reminders import __main__ as remind
from cvc.reminders.policy import CredRecord
from cvc.vault.client import VaultError

# ── helpers ───────────────────────────────────────────────────────────────────

def _iso(days_ago: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).isoformat().replace(
        "+00:00", "Z"
    )


def _login_item(item_id: str, name: str, password: str, days_ago: int = 5) -> dict:
    return {
        "id": item_id,
        "type": 1,
        "name": name,
        "revisionDate": _iso(1),  # edits bump this; must not affect credential age
        "login": {
            "username": f"{item_id}@example.test",
            "password": password,
            "passwordRevisionDate": _iso(days_ago),
        },
    }


@pytest.fixture
def base_env(monkeypatch):
    """Minimal environment for a remind run: vault configured, HIBP + MQTT off by default."""
    monkeypatch.setenv("BW_SERVER", "https://vault.example.test/vault")
    monkeypatch.setenv("MQTT_HOST", "mqtt.example.test")
    monkeypatch.setenv("MQTT_USERNAME", "cvc")
    monkeypatch.setenv("MQTT_PASSWORD", "not-a-real-mqtt-pw")
    monkeypatch.setenv("HIBP_ENABLED", "false")
    monkeypatch.setenv("ROTATION_MAX_AGE_DAYS", "180")
    monkeypatch.delenv("BW_SESSION", raising=False)


def _fake_vault(items: list[dict]) -> MagicMock:
    """A BwClient stand-in whose auth calls succeed and which returns *items*."""
    client = MagicMock()
    client.unlock.return_value = "fake-session-key"
    client.list_items.return_value = items
    return client


# ── _parse_rotated ────────────────────────────────────────────────────────────

def test_parse_rotated_uses_password_revision_date():
    item = {
        "revisionDate": "2026-09-01T00:00:00Z",
        "creationDate": "2025-01-01T00:00:00Z",
        "login": {"passwordRevisionDate": "2026-01-02T03:04:05Z"},
    }
    got = remind._parse_rotated(item)
    assert got == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_parse_rotated_null_password_revision_falls_back_to_creation_not_revision():
    item = {
        "revisionDate": "2026-09-01T00:00:00Z",
        "creationDate": "2025-06-07T00:00:00Z",
        "login": {"passwordRevisionDate": None},
    }
    assert remind._parse_rotated(item) == datetime(2025, 6, 7, tzinfo=UTC)


def test_parse_rotated_never_uses_revision_date():
    item = {"revisionDate": "2026-09-01T00:00:00Z", "login": {}}
    assert remind._parse_rotated(item) is None


def test_parse_rotated_returns_none_on_garbage():
    assert remind._parse_rotated({"login": {"passwordRevisionDate": "not-a-date"}}) is None
    assert remind._parse_rotated({}) is None


# ── _vault_records ────────────────────────────────────────────────────────────

def test_vault_records_filters_non_login_items(base_env):
    items = [
        _login_item("1", "Bank", "Str0ng!Unique#1"),
        {"id": "2", "type": 2, "name": "Secure Note", "notes": "nope"},  # not a login
        {"id": "3", "type": 3, "name": "Card"},
    ]
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)):
        records = remind._vault_records(remind.config.load())
    assert [r.item_id for r in records] == ["1"]


def test_vault_records_skips_passwordless_and_idless_items(base_env):
    items = [
        _login_item("1", "Real", "Str0ng!Unique#1"),
        {"id": "2", "type": 1, "name": "URI only", "login": {"username": "u"}},
        {"id": "3", "type": 1, "name": "Empty pw", "login": {"password": ""}},
        {"type": 1, "name": "No id", "login": {"password": "whatever"}},
    ]
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)):
        records = remind._vault_records(remind.config.load())
    assert [r.item_id for r in records] == ["1"]


def test_vault_records_exports_session_and_syncs(base_env):
    fake = _fake_vault([_login_item("1", "Bank", "Str0ng!Unique#1")])
    with patch.object(remind, "BwClient", return_value=fake):
        remind._vault_records(remind.config.load())
    fake.configure.assert_called_once()
    fake.login_apikey.assert_called_once()
    fake.unlock.assert_called_once()
    fake.sync.assert_called_once()
    import os
    assert os.environ["BW_SESSION"] == "fake-session-key"


def test_vault_records_raises_without_bw_server(monkeypatch):
    monkeypatch.delenv("BW_SERVER", raising=False)
    with pytest.raises(RuntimeError, match="BW_SERVER"):
        remind._vault_records(remind.config.load())


# ── main(): vault failure paths ───────────────────────────────────────────────

def test_main_returns_1_on_vault_error(base_env, capsys):
    fake = MagicMock()
    fake.login_apikey.side_effect = VaultError("vault command failed")
    with patch.object(remind, "BwClient", return_value=fake):
        rc = remind.main([])
    assert rc == 1
    assert "vault read failed" in capsys.readouterr().err


def test_main_returns_1_when_bw_server_unset(monkeypatch, capsys):
    monkeypatch.delenv("BW_SERVER", raising=False)
    rc = remind.main([])
    assert rc == 1
    assert "vault read failed" in capsys.readouterr().err


def test_main_does_not_publish_when_vault_fails(base_env):
    fake = MagicMock()
    fake.list_items.side_effect = VaultError("vault command failed")
    fake.unlock.return_value = "s"
    with patch.object(remind, "BwClient", return_value=fake), \
            patch.object(remind, "publish") as pub:
        assert remind.main([]) == 1
    pub.assert_not_called()


# ── main(): dry run ───────────────────────────────────────────────────────────

def test_main_dry_run_prints_findings_and_skips_publish(base_env, capsys):
    items = [_login_item("1", "Old Bank", "Str0ng!Unique#1", days_ago=400)]
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)), \
            patch.object(remind, "publish") as pub:
        rc = remind.main(["--dry-run", "--verbose"])
    assert rc == 0
    pub.assert_not_called()
    out = capsys.readouterr().out
    assert "1 credentials, 1 findings" in out
    assert "Old Bank" in out
    assert "stale" in out


def test_main_dry_run_never_prints_a_password(base_env, capsys):
    items = [_login_item("1", "Weak One", "abcdef", days_ago=1)]
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)), \
            patch.object(remind, "publish"):
        remind.main(["--dry-run"])
    captured = capsys.readouterr()
    assert "abcdef" not in captured.out
    assert "abcdef" not in captured.err


def test_main_clean_vault_reports_zero_findings(base_env, capsys):
    items = [
        _login_item("1", "A", "Zx9$kQ2!vLmP7wRt", days_ago=10),
        _login_item("2", "B", "Qw3#tYu8!zXc1Vbn", days_ago=10),
    ]
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)), \
            patch.object(remind, "publish") as pub:
        rc = remind.main([])
    assert rc == 0
    pub.assert_called_once()
    assert "2 credentials, 0 findings" in capsys.readouterr().out


# ── main(): HIBP paths ────────────────────────────────────────────────────────

def test_main_hibp_disabled_never_calls_hibp(base_env, monkeypatch):
    monkeypatch.setenv("HIBP_ENABLED", "false")
    items = [_login_item("1", "Bank", "Str0ng!Unique#1")]
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)), \
            patch.object(remind, "times_pwned") as pwned, \
            patch.object(remind, "publish"):
        assert remind.main([]) == 0
    pwned.assert_not_called()


def test_main_hibp_augments_existing_finding(base_env, monkeypatch):
    """A weak password that is also breached gets BOTH reasons on ONE finding."""
    monkeypatch.setenv("HIBP_ENABLED", "true")
    items = [_login_item("1", "Weak And Breached", "abcdef", days_ago=1)]
    published: list = []
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)), \
            patch.object(remind, "times_pwned", return_value=4242), \
            patch.object(remind, "publish", side_effect=lambda f, c: published.extend(f)):
        assert remind.main([]) == 0

    assert len(published) == 1, "breach must augment the existing finding, not add a second"
    reasons = published[0].reasons
    assert any("weak" in r for r in reasons)
    assert any("breached: found 4242x in HIBP" == r for r in reasons)


def test_main_hibp_creates_finding_for_otherwise_clean_credential(base_env, monkeypatch):
    """A strong, unique, recent password that is breached must still be flagged."""
    monkeypatch.setenv("HIBP_ENABLED", "true")
    items = [_login_item("1", "Strong But Breached", "Zx9$kQ2!vLmP7wRt", days_ago=1)]
    published: list = []
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)), \
            patch.object(remind, "times_pwned", return_value=7), \
            patch.object(remind, "publish", side_effect=lambda f, c: published.extend(f)):
        assert remind.main([]) == 0

    assert len(published) == 1
    assert published[0].item_id == "1"
    assert published[0].name == "Strong But Breached"
    assert published[0].reasons == ["breached: found 7x in HIBP"]


def test_main_hibp_zero_count_adds_no_finding(base_env, monkeypatch):
    monkeypatch.setenv("HIBP_ENABLED", "true")
    items = [_login_item("1", "Clean", "Zx9$kQ2!vLmP7wRt", days_ago=1)]
    published: list = []
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)), \
            patch.object(remind, "times_pwned", return_value=0), \
            patch.object(remind, "publish", side_effect=lambda f, c: published.extend(f)):
        assert remind.main([]) == 0
    assert published == []


def test_main_hibp_failure_is_non_fatal(base_env, monkeypatch, capsys):
    """A HIBP outage must warn and continue — policy findings still publish."""
    monkeypatch.setenv("HIBP_ENABLED", "true")
    items = [_login_item("1", "Old Bank", "Str0ng!Unique#1", days_ago=400)]
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)), \
            patch.object(remind, "times_pwned", side_effect=RuntimeError("503 from HIBP")), \
            patch.object(remind, "publish") as pub:
        rc = remind.main([])
    assert rc == 0
    pub.assert_called_once()
    err = capsys.readouterr().err
    assert "Old Bank" not in err


def test_main_hibp_skipped_entirely_when_vault_is_empty(base_env, monkeypatch):
    """`cfg.hibp_enabled and records` must not open an httpx client for an empty vault."""
    monkeypatch.setenv("HIBP_ENABLED", "true")
    with patch.object(remind, "BwClient", return_value=_fake_vault([])), \
            patch.object(remind.httpx, "Client") as http_client, \
            patch.object(remind, "publish"):
        assert remind.main([]) == 0
    http_client.assert_not_called()


# ── main(): publish paths ─────────────────────────────────────────────────────

def test_main_publishes_findings_and_config(base_env):
    items = [_login_item("1", "Old Bank", "Str0ng!Unique#1", days_ago=400)]
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)), \
            patch.object(remind, "publish") as pub:
        assert remind.main([]) == 0
    findings, cfg = pub.call_args[0]
    assert [f.name for f in findings] == ["Old Bank"]
    assert cfg.mqtt_host == "mqtt.example.test"


def test_main_returns_1_on_publish_failure(base_env, capsys):
    items = [_login_item("1", "Bank", "Str0ng!Unique#1")]
    with patch.object(remind, "BwClient", return_value=_fake_vault(items)), \
            patch.object(remind, "publish", side_effect=OSError("connection refused")):
        rc = remind.main([])
    assert rc == 1
    err = capsys.readouterr().err
    assert "MQTT publish failed" in err
    assert "connection refused" in err


def test_main_reports_success_after_publish(base_env, capsys):
    with patch.object(remind, "BwClient", return_value=_fake_vault([])), \
            patch.object(remind, "publish"):
        assert remind.main([]) == 0
    assert "published to Home Assistant" in capsys.readouterr().out


# ── argument parsing ──────────────────────────────────────────────────────────

def test_main_rejects_unknown_flag(base_env):
    with pytest.raises(SystemExit) as exc:
        remind.main(["--not-a-flag"])
    assert exc.value.code == 2


def test_records_carry_no_password_into_findings(base_env):
    """Regression guard: Finding objects must never carry the password field."""
    rec = CredRecord("1", "X", "u", "abcdef")
    assert not hasattr(remind.evaluate([rec], max_age_days=180)[0], "password")


# ── F13: logs carry counts only, never account identities ────────────────────

SECRET = "SuperSecretBank-alice@example.test"


def _f13_items():
    return [
        _login_item("1", SECRET, "abcdef", days_ago=400),
        _login_item("2", "Other-bob", "abcdef", days_ago=1),
    ]


def test_default_output_contains_no_credential_names(base_env, monkeypatch, capsys):
    monkeypatch.setenv("HIBP_ENABLED", "true")
    published: list = []
    with patch.object(remind, "BwClient", return_value=_fake_vault(_f13_items())), \
            patch.object(remind, "times_pwned", side_effect=RuntimeError("boom")), \
            patch.object(remind, "publish", side_effect=lambda f, c: published.extend(f)):
        assert remind.main([]) == 0
    cap = capsys.readouterr()
    text = cap.out + cap.err
    for needle in ("SuperSecretBank", "alice", "Other-bob", "bob"):
        assert needle not in text
    assert "2 credentials" in text
    assert "HIBP failures: 2" in text
    assert any(f.name == SECRET for f in published)  # MQTT payload unchanged


def test_dry_run_without_verbose_hides_names(base_env, capsys):
    with patch.object(remind, "BwClient", return_value=_fake_vault(_f13_items())), \
            patch.object(remind, "publish"):
        remind.main(["--dry-run"])
    assert SECRET not in capsys.readouterr().out
