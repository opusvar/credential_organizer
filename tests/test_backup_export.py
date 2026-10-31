"""Tests for backup/exporter.py::export_encrypted — supplements test_backup_exporter.py
(which covers prune only).

The `bw` subprocess is always patched. A fake that writes the output file stands in for a
successful export, so the filename contract and the empty-output guard are both exercised
without a vault.
"""
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cvc.backup.exporter import (
    _BW,
    _FILENAME_FMT,
    _ONEDRIVE_SINGLE_DIR,
    copy_to_onedrive,
    export_encrypted,
)
from cvc.vault.client import VaultError


def _result(returncode=0, stderr=""):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = ""
    m.stderr = stderr
    return m


_PROTECTED = '{"encrypted":true,"passwordProtected":true}'


@pytest.fixture(autouse=True)
def _export_password(monkeypatch):
    monkeypatch.setenv("BACKUP_EXPORT_PASSWORD", "test-passphrase")


def _list_result():
    r = _result(0)
    r.stdout = "[]"
    return r


def _writing_run(payload: str = _PROTECTED):
    """A subprocess.run stand-in: no orgs, empty item lists, a successful `bw export`.

    Only `bw export` calls are recorded, so calls[0] is the (personal) export.
    """
    calls: list[dict] = []

    def fake_run(argv, **kwargs):
        if argv[1] == "list":
            return _list_result()
        calls.append({"argv": argv, **kwargs})
        out = Path(argv[argv.index("--output") + 1])
        out.write_text(payload)
        return _result(0)

    fake_run.calls = calls  # type: ignore[attr-defined]
    return fake_run


def _list_ok_then(export_result=None, export_exc=None):
    """List calls succeed with []; the export call returns/raises as given."""
    def fake_run(argv, **kwargs):
        if argv[1] == "list":
            return _list_result()
        if export_exc is not None:
            raise export_exc
        return export_result
    return fake_run


# ── session guard ─────────────────────────────────────────────────────────────

def test_export_requires_bw_session(monkeypatch, tmp_path):
    monkeypatch.delenv("BW_SESSION", raising=False)
    with pytest.raises(VaultError, match="BW_SESSION not set"):
        export_encrypted(str(tmp_path))


def test_export_does_not_spawn_bw_without_session(monkeypatch, tmp_path):
    monkeypatch.delenv("BW_SESSION", raising=False)
    with patch("cvc.backup.exporter.subprocess.run") as run, pytest.raises(VaultError):
        export_encrypted(str(tmp_path))
    run.assert_not_called()


# ── happy path ────────────────────────────────────────────────────────────────

def test_export_creates_file_and_returns_path(monkeypatch, tmp_path):
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    dest = tmp_path / "backups"
    with patch("cvc.backup.exporter.subprocess.run", _writing_run()):
        (out,) = export_encrypted(str(dest))
    assert out.exists()
    assert out.parent == dest
    assert out.read_text() == _PROTECTED


def test_export_creates_dest_dir_if_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    dest = tmp_path / "deep" / "nested" / "backups"
    with patch("cvc.backup.exporter.subprocess.run", _writing_run()):
        (out,) = export_encrypted(str(dest))
    assert dest.is_dir()
    assert out.exists()


def test_export_filename_matches_prune_glob(monkeypatch, tmp_path):
    """The filename must match prune()'s `vault-backup-*.json` glob or retention never fires."""
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    with patch("cvc.backup.exporter.subprocess.run", _writing_run()):
        (out,) = export_encrypted(str(tmp_path))
    assert re.fullmatch(r"vault-backup-\d{8}T\d{6}Z-personal\.json", out.name), out.name
    assert out in set(tmp_path.glob("vault-backup-*.json"))
    assert _FILENAME_FMT == "vault-backup-{ts}-{scope}.json"


# ── subprocess invocation contract ────────────────────────────────────────────

def test_export_uses_absolute_bw_path(monkeypatch, tmp_path):
    """Bare `bw` would depend on PATH inside the pod; the npm global bin is absolute."""
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    fake = _writing_run()
    with patch("cvc.backup.exporter.subprocess.run", fake):
        export_encrypted(str(tmp_path))
    argv = fake.calls[0]["argv"]
    assert argv[0] == "/usr/local/bin/bw"
    assert argv[0] == _BW
    assert Path(argv[0]).is_absolute()


def test_export_uses_encrypted_json_format_only(monkeypatch, tmp_path):
    """D4: a plaintext export must never be written."""
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    fake = _writing_run()
    with patch("cvc.backup.exporter.subprocess.run", fake):
        export_encrypted(str(tmp_path))
    argv = fake.calls[0]["argv"]
    fmt = argv[argv.index("--format") + 1]
    assert fmt == "encrypted_json"
    assert fmt not in ("json", "csv")  # bw's plaintext export formats


def test_export_passes_session_in_env_not_argv(monkeypatch, tmp_path):
    """The session key must not appear on the command line (visible in `ps`)."""
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    fake = _writing_run()
    with patch("cvc.backup.exporter.subprocess.run", fake):
        export_encrypted(str(tmp_path))
    call = fake.calls[0]
    assert "fake-session-key" not in " ".join(call["argv"])
    assert call["env"]["BW_SESSION"] == "fake-session-key"


def test_export_sets_a_subprocess_timeout(monkeypatch, tmp_path):
    """Without a timeout a wedged bw would hang the CronJob pod indefinitely."""
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    fake = _writing_run()
    with patch("cvc.backup.exporter.subprocess.run", fake):
        export_encrypted(str(tmp_path))
    assert fake.calls[0]["timeout"] > 0


def test_export_forwards_appdata_dir(monkeypatch, tmp_path):
    """bw finds its login state via BITWARDENCLI_APPDATA_DIR (Phase 4 lesson)."""
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    monkeypatch.setenv("BITWARDENCLI_APPDATA_DIR", "/home/cvc/.bw")
    fake = _writing_run()
    with patch("cvc.backup.exporter.subprocess.run", fake):
        export_encrypted(str(tmp_path))
    assert fake.calls[0]["env"]["BITWARDENCLI_APPDATA_DIR"] == "/home/cvc/.bw"


# ── failure modes ─────────────────────────────────────────────────────────────

def test_export_raises_vault_error_on_nonzero_exit(monkeypatch, tmp_path):
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    with patch("cvc.backup.exporter.subprocess.run", _list_ok_then(_result(1, "You are not logged in."))), \
            pytest.raises(VaultError, match="bw export failed"):
        export_encrypted(str(tmp_path))


def test_export_error_includes_exit_code_and_stderr(monkeypatch, tmp_path):
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    with patch("cvc.backup.exporter.subprocess.run", _list_ok_then(_result(9, "vault is locked"))), pytest.raises(VaultError) as exc:
        export_encrypted(str(tmp_path))
    assert "exit 9" in str(exc.value)
    assert "vault is locked" in str(exc.value)


def test_export_leaves_no_file_on_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    with patch("cvc.backup.exporter.subprocess.run", _list_ok_then(_result(1, "nope"))), \
            pytest.raises(VaultError):
        export_encrypted(str(tmp_path))
    assert list(tmp_path.glob("vault-backup-*.json")) == []


def test_export_raises_when_bw_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    with patch("cvc.backup.exporter.subprocess.run", _list_ok_then(export_exc=FileNotFoundError())), \
            pytest.raises(VaultError, match="bw CLI not found"):
        export_encrypted(str(tmp_path))


def test_export_raises_on_timeout(monkeypatch, tmp_path):
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    with patch("cvc.backup.exporter.subprocess.run", _list_ok_then(export_exc=subprocess.TimeoutExpired(cmd="bw", timeout=300))), \
            pytest.raises(VaultError, match="timed out"):
        export_encrypted(str(tmp_path))


def test_export_rejects_silent_empty_output(monkeypatch, tmp_path):
    """bw exiting 0 without writing anything must be a loud failure, not a 'backup'."""
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    with patch("cvc.backup.exporter.subprocess.run", _list_ok_then(_result(0))), \
            pytest.raises(VaultError, match="produced no data"):
        export_encrypted(str(tmp_path))


def test_export_rejects_zero_byte_output(monkeypatch, tmp_path):
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    with patch("cvc.backup.exporter.subprocess.run", _writing_run(payload="")), \
            pytest.raises(VaultError, match="produced no data"):
        export_encrypted(str(tmp_path))


# ── prune interaction (round trip) ────────────────────────────────────────────

def test_fresh_export_survives_prune(monkeypatch, tmp_path):
    """End-to-end of the CronJob's two steps: a just-written export is never pruned."""
    from cvc.backup.exporter import prune
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    with patch("cvc.backup.exporter.subprocess.run", _writing_run()):
        (out,) = export_encrypted(str(tmp_path))
    assert prune(str(tmp_path), retention_days=30) == 0
    assert out.exists()


# ── copy_to_onedrive (D9 off-host copy) ───────────────────────────────────────
#
# No real onedrive binary is ever invoked: subprocess.run is patched in every test, and
# `onedrive_bin` points at a file inside tmp_path that only has to exist.

def _fake_onedrive_bin(tmp_path) -> str:
    """A stand-in for /usr/local/bin/onedrive — copy_to_onedrive only checks it exists."""
    p = tmp_path / "bin" / "onedrive"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("#!/bin/sh\nexit 0\n")
    return str(p)


def _staged_export(tmp_path) -> Path:
    src = tmp_path / "pvc" / "vault-backup-20260913T000000Z.json"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text('{"encrypted":true}')
    return src


def _recording_run(returncode: int = 0, stderr: str = ""):
    calls: list[dict] = []

    def fake_run(argv, **kwargs):
        calls.append({"argv": argv, **kwargs})
        return _result(returncode, stderr)

    fake_run.calls = calls  # type: ignore[attr-defined]
    return fake_run


def test_copy_to_onedrive_copies_file(tmp_path):
    src = _staged_export(tmp_path)
    dest = tmp_path / "onedrive" / "dan_ai_tool_dock" / "cvc-backups"
    with patch("cvc.backup.exporter.subprocess.run", _recording_run()):
        copy_to_onedrive(src, str(dest), _fake_onedrive_bin(tmp_path), str(tmp_path / "conf"))

    copied = dest / src.name
    assert dest.is_dir(), "dest dir must be created if absent"
    assert copied.exists()
    assert copied.read_text() == '{"encrypted":true}'
    # The PVC copy is primary and must be left untouched.
    assert src.exists()


def test_copy_to_onedrive_runs_sync_command(tmp_path):
    src = _staged_export(tmp_path)
    bin_path = _fake_onedrive_bin(tmp_path)
    conf = str(tmp_path / "conf")
    fake = _recording_run()
    with patch("cvc.backup.exporter.subprocess.run", fake):
        copy_to_onedrive(src, str(tmp_path / "od"), bin_path, conf)

    assert len(fake.calls) == 1
    argv = fake.calls[0]["argv"]
    assert argv[0] == bin_path

    # Flag spellings are asserted explicitly because they are version-sensitive and a wrong
    # one fails NON-FATALLY: the job still exits 0 and the off-host copy silently never
    # syncs. Installed client is abraunegg v2.5.11, which removed `--synchronize` (now
    # `--sync`) and has never accepted `--config-dir` (it is `--confdir`).
    assert "--sync" in argv
    assert "--synchronize" not in argv, "removed in abraunegg v2.5; would exit non-zero"
    assert "--config-dir" not in argv, "not a real flag; --confdir is the real one"

    # --confdir is what lets the pod find the refresh token from the mounted config.
    assert argv[argv.index("--confdir") + 1] == conf
    # --single-directory keeps the sync off the rest of the OneDrive tree.
    assert argv[argv.index("--single-directory") + 1] == _ONEDRIVE_SINGLE_DIR

    # A wedged sync must not hang the CronJob pod forever.
    assert fake.calls[0]["timeout"] == 120


def test_copy_to_onedrive_raises_on_missing_bin(tmp_path):
    src = _staged_export(tmp_path)
    dest = tmp_path / "od"
    missing = str(tmp_path / "bin" / "does-not-exist")
    with patch("cvc.backup.exporter.subprocess.run") as run, \
            pytest.raises(RuntimeError, match="onedrive not found at"):
        copy_to_onedrive(src, str(dest), missing, str(tmp_path / "conf"))
    run.assert_not_called()
    # Copy happens before the sync leg, so the export is still staged on the NVMe for a
    # later host-side sync — no re-export needed.
    assert (dest / src.name).exists()


def test_copy_to_onedrive_raises_on_sync_failure(tmp_path):
    src = _staged_export(tmp_path)
    with patch("cvc.backup.exporter.subprocess.run",
               _recording_run(1, "ERROR: refresh token expired")), \
            pytest.raises(RuntimeError) as exc:
        copy_to_onedrive(src, str(tmp_path / "od"), _fake_onedrive_bin(tmp_path),
                         str(tmp_path / "conf"))
    assert "exit 1" in str(exc.value)
    assert "refresh token expired" in str(exc.value), "stderr must reach the caller's log"


def test_copy_to_onedrive_raises_on_timeout(tmp_path):
    src = _staged_export(tmp_path)
    with patch("cvc.backup.exporter.subprocess.run", _list_ok_then(export_exc=subprocess.TimeoutExpired(cmd="onedrive", timeout=120))), \
            pytest.raises(RuntimeError, match="timed out after 120s"):
        copy_to_onedrive(src, str(tmp_path / "od"), _fake_onedrive_bin(tmp_path),
                         str(tmp_path / "conf"))


def test_copy_to_onedrive_raises_runtimeerror_not_oserror_on_bad_dest(tmp_path):
    """The caller only catches RuntimeError — an OSError here would fail the whole job."""
    src = _staged_export(tmp_path)
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")  # mkdir(parents=True) under a file raises NotADirectoryError
    with patch("cvc.backup.exporter.subprocess.run") as run, \
            pytest.raises(RuntimeError, match="copy to .* failed"):
        copy_to_onedrive(src, str(blocker / "cvc-backups"),
                         _fake_onedrive_bin(tmp_path), str(tmp_path / "conf"))
    run.assert_not_called()


def test_copy_to_onedrive_does_not_pass_env_or_shell(tmp_path):
    """No shell=True (the paths are operator-supplied) and no doctored env."""
    src = _staged_export(tmp_path)
    fake = _recording_run()
    with patch("cvc.backup.exporter.subprocess.run", fake):
        copy_to_onedrive(src, str(tmp_path / "od"), _fake_onedrive_bin(tmp_path),
                         str(tmp_path / "conf"))
    call = fake.calls[0]
    assert isinstance(call["argv"], list)
    assert not call.get("shell", False)


def test_prune_skips_directories_matching_the_glob(tmp_path):
    """A stray directory named like a backup must not make prune() raise."""
    import os
    import time

    from cvc.backup.exporter import prune
    d = tmp_path / "vault-backup-20200101T000000Z.json"
    d.mkdir()
    old = time.time() - 999 * 86400
    os.utime(d, (old, old))
    assert prune(str(tmp_path), retention_days=30) == 0
    assert d.is_dir()
