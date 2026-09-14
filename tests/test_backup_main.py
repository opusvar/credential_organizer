"""Tests for the `cvc-backup` CLI entry point (backup/__main__.py).

BwClient and export_encrypted are patched at the module under test, so no `bw`
subprocess runs and no real vault is contacted. copy_to_onedrive is stubbed out
for every test by the autouse `_no_onedrive` fixture below — see its docstring.
"""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cvc.backup import __main__ as backup
from cvc.vault.client import VaultError


@pytest.fixture
def base_env(monkeypatch, tmp_path):
    monkeypatch.setenv("BW_SERVER", "https://vault.example.test/vault")
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("BACKUP_RETENTION_DAYS", "30")
    monkeypatch.delenv("BW_SESSION", raising=False)
    return tmp_path


@pytest.fixture(autouse=True)
def _no_onedrive(monkeypatch):
    """Stub the off-host copy for the whole module.

    main() calls copy_to_onedrive() after every successful export. Without this, tests
    that only patch export_encrypted would reach the real function, which mkdir()s the
    configured ONEDRIVE_DEST_DIR on the host and can spawn the real onedrive binary.
    Today those tests happen to be saved by their fake export paths not existing (the
    copy raises first) — that is luck, not isolation. Tests that care about the call
    patch it themselves; patch.object inside the test nests over this stub.
    """
    monkeypatch.setattr(backup, "copy_to_onedrive", MagicMock(name="copy_to_onedrive"))


def _fake_vault() -> MagicMock:
    client = MagicMock()
    client.unlock.return_value = "fake-session-key"
    return client


# ── configuration guard ───────────────────────────────────────────────────────

def test_main_returns_1_without_bw_server(monkeypatch, capsys):
    monkeypatch.delenv("BW_SERVER", raising=False)
    rc = backup.main([])
    assert rc == 1
    assert "BW_SERVER not configured" in capsys.readouterr().err


def test_main_does_not_touch_vault_without_bw_server(monkeypatch):
    monkeypatch.delenv("BW_SERVER", raising=False)
    with patch.object(backup, "BwClient") as cls:
        assert backup.main([]) == 1
    cls.assert_not_called()


# ── auth failures ─────────────────────────────────────────────────────────────

def test_main_returns_1_on_login_failure(base_env, capsys):
    fake = _fake_vault()
    fake.login_apikey.side_effect = VaultError("vault command failed")
    with patch.object(backup, "BwClient", return_value=fake), \
            patch.object(backup, "export_encrypted") as exp:
        rc = backup.main([])
    assert rc == 1
    assert "vault auth failed" in capsys.readouterr().err
    exp.assert_not_called()


def test_main_returns_1_on_unlock_failure(base_env, capsys):
    fake = _fake_vault()
    fake.unlock.side_effect = VaultError("BW_PASSWORD must be set to unlock the vault")
    with patch.object(backup, "BwClient", return_value=fake), \
            patch.object(backup, "export_encrypted") as exp:
        rc = backup.main([])
    assert rc == 1
    assert "vault auth failed" in capsys.readouterr().err
    exp.assert_not_called()


def test_main_returns_1_on_configure_failure(base_env):
    fake = _fake_vault()
    fake.configure.side_effect = VaultError("vault command failed")
    with patch.object(backup, "BwClient", return_value=fake), \
            patch.object(backup, "export_encrypted") as exp:
        assert backup.main([]) == 1
    exp.assert_not_called()


# ── auth ordering / session handoff ───────────────────────────────────────────

def test_main_exports_session_before_export(base_env):
    """export_encrypted() reads BW_SESSION from the environment, so main() must set it first."""
    import os
    seen: dict = {}

    def capture_export(dest_dir):
        seen["session"] = os.environ.get("BW_SESSION")
        return Path(dest_dir) / "vault-backup-20260913T000000Z.json"

    fake = _fake_vault()
    with patch.object(backup, "BwClient", return_value=fake), \
            patch.object(backup, "export_encrypted", side_effect=capture_export), \
            patch.object(backup, "prune", return_value=0):
        assert backup.main([]) == 0

    assert seen["session"] == "fake-session-key"
    fake.configure.assert_called_once()
    fake.login_apikey.assert_called_once()
    fake.unlock.assert_called_once()


# ── export failures ───────────────────────────────────────────────────────────

def test_main_returns_1_on_export_failure(base_env, capsys):
    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted",
                         side_effect=VaultError("bw export failed (exit 1): boom")), \
            patch.object(backup, "prune") as pr:
        rc = backup.main([])
    assert rc == 1
    assert "export failed" in capsys.readouterr().err
    # A failed export must not trigger pruning of the good backups already on disk.
    pr.assert_not_called()


def test_main_does_not_prune_when_export_produced_nothing(base_env):
    """Guard the dangerous ordering: prune must never run after a failed export."""
    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted",
                         side_effect=VaultError("produced no data")), \
            patch.object(backup, "prune") as pr:
        assert backup.main([]) == 1
    pr.assert_not_called()


# ── happy path + prune reporting ──────────────────────────────────────────────

def test_main_success_reports_path_and_prune_count(base_env, capsys):
    out_path = base_env / "backups" / "vault-backup-20260913T000000Z.json"
    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted", return_value=out_path), \
            patch.object(backup, "prune", return_value=3):
        rc = backup.main([])
    assert rc == 0
    out = capsys.readouterr().out
    assert f"exported to {out_path}" in out
    assert "pruned 3 export(s) older than 30d" in out


def test_main_reports_zero_pruned(base_env, capsys):
    """The count is always reported so a CronJob log shows retention actually ran."""
    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted", return_value=Path("/x/b.json")), \
            patch.object(backup, "prune", return_value=0):
        assert backup.main([]) == 0
    assert "pruned 0 export(s)" in capsys.readouterr().out


def test_main_passes_configured_dir_and_retention(base_env):
    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted", return_value=Path("/x/b.json")) as exp, \
            patch.object(backup, "prune", return_value=0) as pr:
        assert backup.main([]) == 0
    expected_dir = str(base_env / "backups")
    assert exp.call_args[0][0] == expected_dir
    assert pr.call_args[0] == (expected_dir, 30)


def test_main_honours_custom_retention(base_env, monkeypatch):
    monkeypatch.setenv("BACKUP_RETENTION_DAYS", "7")
    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted", return_value=Path("/x/b.json")), \
            patch.object(backup, "prune", return_value=0) as pr:
        assert backup.main([]) == 0
    assert pr.call_args[0][1] == 7


# ── prune is best-effort ──────────────────────────────────────────────────────

def test_main_survives_prune_oserror(base_env, capsys):
    """The export already succeeded — a retention failure must not fail the backup."""
    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted", return_value=Path("/x/b.json")), \
            patch.object(backup, "prune", side_effect=OSError("read-only file system")):
        rc = backup.main([])
    assert rc == 0
    err = capsys.readouterr().err
    assert "prune failed" in err
    assert "read-only file system" in err


# ── off-host OneDrive copy is non-fatal (D9) ──────────────────────────────────
#
# copy_to_onedrive is patched at the module under test in every case, so no onedrive
# binary is invoked and no real sync is attempted.

def test_main_logs_warning_on_onedrive_failure(base_env, capsys):
    """A sync outage must not fail the job — the PVC export already succeeded."""
    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted", return_value=Path("/x/b.json")), \
            patch.object(backup, "copy_to_onedrive",
                         side_effect=RuntimeError("onedrive sync failed (exit 1): boom")), \
            patch.object(backup, "prune", return_value=0) as pr:
        rc = backup.main([])

    assert rc == 0, "OneDrive failure must never make the CronJob exit non-zero"
    captured = capsys.readouterr()
    assert "OneDrive sync failed" in captured.err
    assert "boom" in captured.err
    assert "synced to OneDrive" not in captured.out
    # Retention must still run: the export is good, so the job completes normally.
    pr.assert_called_once()


def test_main_prints_synced_on_success(base_env, capsys):
    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted", return_value=Path("/x/b.json")), \
            patch.object(backup, "copy_to_onedrive") as cp, \
            patch.object(backup, "prune", return_value=0):
        rc = backup.main([])

    assert rc == 0
    out = capsys.readouterr().out
    assert "synced to OneDrive" in out
    cp.assert_called_once()


def test_main_passes_export_path_and_onedrive_config(base_env, monkeypatch):
    """The staged file must be the export just written, with the configured destinations."""
    monkeypatch.setenv("ONEDRIVE_DEST_DIR", "/mnt/data/onedrive/dan_ai_tool_dock/cvc-backups")
    monkeypatch.setenv("ONEDRIVE_BIN", "/usr/local/bin/onedrive")
    monkeypatch.setenv("ONEDRIVE_CONFIG_DIR", "/home/admin/.config/onedrive")
    out_path = Path("/backups/vault-backup-20260913T000000Z.json")

    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted", return_value=out_path), \
            patch.object(backup, "copy_to_onedrive") as cp, \
            patch.object(backup, "prune", return_value=0):
        assert backup.main([]) == 0

    assert cp.call_args[0] == (
        out_path,
        "/mnt/data/onedrive/dan_ai_tool_dock/cvc-backups",
        "/usr/local/bin/onedrive",
        "/home/admin/.config/onedrive",
    )


def test_main_does_not_copy_when_export_failed(base_env):
    """Nothing to stage off-host if the export never produced a file."""
    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted",
                         side_effect=VaultError("produced no data")), \
            patch.object(backup, "copy_to_onedrive") as cp, \
            patch.object(backup, "prune"):
        assert backup.main([]) == 1
    cp.assert_not_called()


# ── secret hygiene ────────────────────────────────────────────────────────────

def test_main_never_prints_the_session_key(base_env, capsys):
    with patch.object(backup, "BwClient", return_value=_fake_vault()), \
            patch.object(backup, "export_encrypted", return_value=Path("/x/b.json")), \
            patch.object(backup, "prune", return_value=1):
        backup.main([])
    captured = capsys.readouterr()
    assert "fake-session-key" not in captured.out
    assert "fake-session-key" not in captured.err
