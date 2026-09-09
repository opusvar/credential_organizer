"""Tests for backup/exporter.py — prune logic only (no bw subprocess)."""
import time
from pathlib import Path

from cvc.backup.exporter import prune


def _make_export(dest: Path, name: str, age_days: float) -> Path:
    f = dest / name
    f.write_text("{}")
    mtime = time.time() - age_days * 86400
    import os
    os.utime(f, (mtime, mtime))
    return f


def test_prune_removes_old_keeps_new(tmp_path):
    old = _make_export(tmp_path, "vault-backup-20260101T000000Z.json", age_days=40)
    new = _make_export(tmp_path, "vault-backup-20260901T000000Z.json", age_days=5)
    removed = prune(str(tmp_path), retention_days=30)
    assert removed == 1
    assert not old.exists()
    assert new.exists()


def test_prune_returns_zero_when_nothing_old(tmp_path):
    _make_export(tmp_path, "vault-backup-20260901T000000Z.json", age_days=1)
    assert prune(str(tmp_path), retention_days=30) == 0


def test_prune_handles_missing_dir():
    assert prune("/tmp/cvc-nonexistent-dir-xyz", retention_days=30) == 0


def test_prune_ignores_non_backup_files(tmp_path):
    other = tmp_path / "not-a-backup.txt"
    other.write_text("keep me")
    import os, time as t
    mtime = t.time() - 999 * 86400
    os.utime(other, (mtime, mtime))
    removed = prune(str(tmp_path), retention_days=30)
    assert removed == 0
    assert other.exists()
