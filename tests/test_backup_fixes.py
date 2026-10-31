"""Regression tests for the F8/F9/F10 backup findings.

F8  — off-host copy never happened when BACKUP_DIR == ONEDRIVE_DEST_DIR (SameFileError
      skipped the sync) and copy/sync failures were swallowed with exit 0.
F9  — `bw export` without --organizationid exported only the personal vault (1 of 587).
F10 — encrypted_json without --password is account-restricted (unreadable after key
      rotation / account loss).

No real `bw` or `onedrive` runs: subprocess.run is patched everywhere.
"""
import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cvc.backup import __main__ as backup
from cvc.backup.exporter import copy_to_onedrive, export_encrypted, prune
from cvc.vault.client import VaultError

PW = "correct horse battery staple"
ORGS = [{"id": "org-aaa", "name": "Family"}, {"id": "org-bbb", "name": "Work"}]
PROTECTED = json.dumps({"encrypted": True, "passwordProtected": True, "data": "x"})


def _res(rc=0, stdout="", stderr=""):
    m = MagicMock()
    m.returncode, m.stdout, m.stderr = rc, stdout, stderr
    return m


def fake_bw(orgs=ORGS, personal=1, per_org=None, total=None, payload=PROTECTED,
            export_rc=0, export_stderr=""):
    """subprocess.run stand-in emulating the bw subcommands the exporter uses."""
    per_org = per_org if per_org is not None else {o["id"]: 293 for o in orgs}
    if total is None:
        total = personal + sum(per_org.values())
    calls: list[dict] = []

    def run(argv, **kw):
        calls.append({"argv": argv, **kw})
        a = argv[1:]
        if a[:2] == ["list", "organizations"]:
            return _res(stdout=json.dumps(orgs))
        if a[:2] == ["list", "items"]:
            if "--organizationid" in a:
                oid = a[a.index("--organizationid") + 1]
                n = personal if oid == "null" else per_org.get(oid, 0)
            else:
                n = total
            return _res(stdout=json.dumps([{"id": str(i)} for i in range(n)]))
        if a[0] == "export":
            if export_rc:
                return _res(export_rc, stderr=export_stderr)
            Path(a[a.index("--output") + 1]).write_text(payload)
            return _res()
        raise AssertionError(f"unexpected bw call {a}")

    run.calls = calls  # type: ignore[attr-defined]
    return run


def _exports(fake):
    return [c for c in fake.calls if c["argv"][1] == "export"]


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("BW_SESSION", "fake-session-key")
    monkeypatch.setenv("BACKUP_EXPORT_PASSWORD", PW)


# ── F10: password-protected export ────────────────────────────────────────────

def test_f10_missing_password_fails_without_spawning_bw(monkeypatch, tmp_path):
    monkeypatch.setenv("BW_SESSION", "s")
    monkeypatch.delenv("BACKUP_EXPORT_PASSWORD", raising=False)
    with patch("cvc.backup.exporter.subprocess.run") as run, \
            pytest.raises(VaultError, match="BACKUP_EXPORT_PASSWORD"):
        export_encrypted(str(tmp_path))
    run.assert_not_called()


def test_f10_every_export_uses_password(env, tmp_path):
    fake = fake_bw()
    with patch("cvc.backup.exporter.subprocess.run", fake):
        export_encrypted(str(tmp_path))
    for c in _exports(fake):
        argv = c["argv"]
        assert argv[argv.index("--format") + 1] == "encrypted_json"
        assert argv[argv.index("--password") + 1] == PW


def test_f10_rejects_account_restricted_output(env, tmp_path):
    fake = fake_bw(payload=json.dumps({"encrypted": True, "data": "x"}))
    with patch("cvc.backup.exporter.subprocess.run", fake), \
            pytest.raises(VaultError, match="password-protected"):
        export_encrypted(str(tmp_path))


def test_f10_password_never_in_error_message(env, tmp_path):
    fake = fake_bw(export_rc=1, export_stderr=f"bad thing with {PW}")
    with patch("cvc.backup.exporter.subprocess.run", fake), \
            pytest.raises(VaultError) as exc:
        export_encrypted(str(tmp_path))
    assert PW not in str(exc.value)


def test_f10_main_never_prints_password(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BW_SERVER", "https://v.test")
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "b"))
    monkeypatch.setenv("BACKUP_EXPORT_PASSWORD", PW)
    client = MagicMock()
    client.unlock.return_value = "sess"
    with patch.object(backup, "BwClient", return_value=client), \
            patch("cvc.backup.exporter.subprocess.run",
                  fake_bw(export_rc=1, export_stderr=PW)), \
            patch.object(backup, "copy_to_onedrive"):
        assert backup.main([]) == 1
    cap = capsys.readouterr()
    assert PW not in cap.out + cap.err


# ── F9: organizations exported, counts verified ───────────────────────────────

def test_f9_exports_personal_and_each_org(env, tmp_path):
    fake = fake_bw()
    with patch("cvc.backup.exporter.subprocess.run", fake):
        paths = export_encrypted(str(tmp_path))
    assert len(paths) == 3
    assert len({p.name for p in paths}) == 3
    org_args = [c["argv"][c["argv"].index("--organizationid") + 1]
                for c in _exports(fake) if "--organizationid" in c["argv"]]
    assert sorted(org_args) == ["org-aaa", "org-bbb"]
    assert sum("--organizationid" not in c["argv"] for c in _exports(fake)) == 1
    for p in paths:
        assert re.fullmatch(r"vault-backup-\d{8}T\d{6}Z-(personal|org-[\w-]+)\.json", p.name)
        assert p.exists()


def test_f9_count_mismatch_fails(env, tmp_path):
    fake = fake_bw(total=600)  # 13 items not covered by any export scope
    with patch("cvc.backup.exporter.subprocess.run", fake), \
            pytest.raises(VaultError, match="count mismatch"):
        export_encrypted(str(tmp_path))


def test_f9_unsafe_org_id_rejected(env, tmp_path):
    fake = fake_bw(orgs=[{"id": "../evil", "name": "x"}], per_org={"../evil": 0})
    with patch("cvc.backup.exporter.subprocess.run", fake), pytest.raises(VaultError):
        export_encrypted(str(tmp_path))


def test_f9_bw_env_carries_session_and_appdata(env, tmp_path, monkeypatch):
    monkeypatch.setenv("BITWARDENCLI_APPDATA_DIR", "/x/bw")
    fake = fake_bw()
    with patch("cvc.backup.exporter.subprocess.run", fake):
        export_encrypted(str(tmp_path))
    for c in fake.calls:
        assert c["env"]["BW_SESSION"] == "fake-session-key"
        assert c["env"]["BITWARDENCLI_APPDATA_DIR"] == "/x/bw"
        assert "fake-session-key" not in " ".join(c["argv"])


def test_prune_handles_multi_file_names(tmp_path):
    import os
    import time
    old = time.time() - 40 * 86400
    names = ["vault-backup-20260101T000000Z-personal.json",
             "vault-backup-20260101T000000Z-org-org-aaa.json"]
    for n in names:
        f = tmp_path / n
        f.write_text("{}")
        os.utime(f, (old, old))
    fresh = tmp_path / "vault-backup-20261001T000000Z-org-org-aaa.json"
    fresh.write_text("{}")
    assert prune(str(tmp_path), 30) == 2
    assert fresh.exists()


# ── F8: same-dir staging still syncs; failures are fatal ──────────────────────

def _bin(tmp_path):
    p = tmp_path / "onedrive"
    p.write_text("")
    return str(p)


def test_f8_same_dir_skips_copy_but_still_syncs(tmp_path):
    src = tmp_path / "vault-backup-20260913T000000Z-personal.json"
    src.write_text("{}")
    calls = []
    with patch("cvc.backup.exporter.subprocess.run",
               side_effect=lambda argv, **kw: calls.append(argv) or _res()):
        copy_to_onedrive(src, str(tmp_path), _bin(tmp_path), str(tmp_path / "c"))
    assert len(calls) == 1 and "--sync" in calls[0]
    assert src.read_text() == "{}"


def test_f8_multiple_files_one_sync(tmp_path):
    srcs = []
    for n in ("a", "b"):
        s = tmp_path / "pvc" / f"vault-backup-x-{n}.json"
        s.parent.mkdir(exist_ok=True)
        s.write_text(n)
        srcs.append(s)
    dest = tmp_path / "od"
    calls = []
    with patch("cvc.backup.exporter.subprocess.run",
               side_effect=lambda argv, **kw: calls.append(argv) or _res()):
        copy_to_onedrive(srcs, str(dest), _bin(tmp_path), str(tmp_path / "c"))
    assert len(calls) == 1
    assert (dest / "vault-backup-x-a.json").read_text() == "a"
    assert (dest / "vault-backup-x-b.json").read_text() == "b"


def _run_main(monkeypatch, tmp_path, copy_side_effect):
    monkeypatch.setenv("BW_SERVER", "https://v.test")
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "b"))
    client = MagicMock()
    client.unlock.return_value = "sess"
    with patch.object(backup, "BwClient", return_value=client), \
            patch.object(backup, "export_encrypted", return_value=[Path("/x/a.json")]), \
            patch.object(backup, "copy_to_onedrive", side_effect=copy_side_effect), \
            patch.object(backup, "prune", return_value=0) as pr:
        rc = backup.main([])
    return rc, pr


def test_f8_main_exits_nonzero_on_sync_failure(monkeypatch, tmp_path, capsys):
    rc, pr = _run_main(monkeypatch, tmp_path, RuntimeError("onedrive sync failed (exit 1)"))
    assert rc != 0
    assert "OneDrive" in capsys.readouterr().err
    pr.assert_called_once()  # local export is good; retention still runs


def test_f8_unit_backup_dir_is_separate_from_onedrive_dir():
    unit = (Path(__file__).parents[1] / "deploy" / "cvc-backup.service").read_text()
    m = re.search(r"^Environment=BACKUP_DIR=(.+)$", unit, re.M)
    assert m and m.group(1).strip() == "/mnt/data/cvc-backups"
    assert "onedrive" not in m.group(1)


def test_env_example_documents_export_password():
    text = (Path(__file__).parents[1] / ".env.example").read_text()
    assert re.search(r"^BACKUP_EXPORT_PASSWORD=", text, re.M)
