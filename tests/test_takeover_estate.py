"""Takeover additions: veto warning, primary/backup key factor, estate recovery kit (D15)."""
from __future__ import annotations

import os
import stat

import pytest
from test_takeover import Elev, Env

from cvc.takeover import flow
from cvc.takeover.estate import EstateKitStore, normalize
from cvc.takeover.keys import key_factor, key_role
from cvc.takeover.model import TakeoverError
from cvc.takeover.vw import EmergencyGrant


class Channel:
    def __init__(self, name):
        self.name, self.sent = name, []

    def notify(self, person, event, message):
        self.sent.append((person, event, message))


class RejectRefusingVW:
    """Vaultwarden refuses a reject that does not come from the grantor's account."""

    def __init__(self, inner):
        self.inner = inner

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def reject(self, g):
        raise RuntimeError("403: only the grantor can reject")


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# ── veto ────────────────────────────────────────────────────────────────────
def test_veto_warns_vw_view_persists(env):
    _, rec = env.wizard()
    env.deps.vw = RejectRefusingVW(env.vw)
    env.reader.serial = "444"                                  # erin, a non-target owner
    printed = []
    r = flow.cancel(env.deps, rec.id, out=printed.append)
    assert r.status == "cancelled" and r.vetoed_by == "erin"
    assert env.store.history(rec.id)[-1]["event"] == "vetoed"
    assert "View access" in printed[0] and "PERSISTS" in printed[0]
    assert "only accepts a reject from the grantor" in printed[0]
    vetoed = [(p, m) for p, ev, m in env.notifier.sent if ev == "takeover-vetoed"]
    assert {p for p, _ in vetoed} == {"alex", "dana", "erin"}
    assert all("PERSISTS" in m for _, m in vetoed)


def test_target_cancel_has_no_warning(env):
    _, rec = env.wizard()
    env.reader.serial = "333"
    printed = []
    flow.cancel(env.deps, rec.id, out=printed.append)
    assert printed == []
    assert ("reject", "g-view") in env.vw.calls


# ── primary / backup ────────────────────────────────────────────────────────
def test_key_role_explicit_and_heuristics():
    assert key_role({"role": "backup", "location": "on-person"}, on_cert=True) == "backup"
    assert key_role({"role": "primary"}, on_cert=False) == "primary"
    assert key_role({}, on_cert=True) == "primary"
    assert key_role({}, on_cert=False) == "backup"
    assert key_role({"location": "home-safe"}) == "backup"
    assert key_role({"location": "on-person"}) == "primary"

    class K:
        location = "offsite"
    assert key_role(K()) == "backup"
    assert key_factor({"role": "backup"}, on_cert=True) == "backup-key"


def test_explicit_role_overrides_cert_heuristic(env):
    env.data["hardware_keys"]["yk-dana"]["role"] = "backup"       # yk-dana is on dana-mac's cert
    env.data["hardware_keys"]["yk-dana-backup"]["role"] = "primary"
    env.save()
    _, rec = env.wizard()
    assert rec.factor == "backup-key"


def test_without_role_cert_heuristic_kept(env):
    _, rec = env.wizard(target_serial="334")
    assert rec.factor == "backup-key"


# ── estate recovery kit ─────────────────────────────────────────────────────
def _kit(env):
    box = {}
    return EstateKitStore(env.store.dir, ask=lambda _: box["code"]), box


def _estate_wizard(env, kit, target="dana", name="Dana Smith"):
    w = flow.StartWizard(env.deps)
    w.step1_cert("alex", env.pem(env.leaf), [env.pem(env.pki.inter)], env.pem(env.pki.root))
    env.reader.serial = "111"
    w.step2_initiator_key()
    w.step3_elevate(Elev())
    w.step4_target(target)
    w.step5_estate_kit(kit)
    assert "estate recovery kit" in w.summary()
    return w.step6_start(name)


def test_estate_kit_generate_hash_only_0600(env):
    kit, _ = _kit(env)
    code = kit.generate("alex", "2026-11-01")
    raw = normalize(code)
    assert len(raw) == 30 and code.count("-") == 5
    text = kit.path.read_text()
    assert raw not in text and code not in text and '"hash"' in text
    assert stat.S_IMODE(os.stat(kit.path).st_mode) == 0o600
    assert kit.generate("alex", "2026-11-02") != code


def test_estate_kit_path_180_days_notifies_all_owners_every_channel(env):
    a, b = Channel("ha"), Channel("push")
    env.deps.notifier = flow.MultiNotifier([a, b])
    kit, box = _kit(env)
    box["code"] = kit.generate("erin", "2026-11-01").lower().replace("-", " ")
    rec = _estate_wizard(env, kit)
    assert rec.path == rec.factor == "estate-kit" and rec.wait_days == 180
    assert rec.target_key is None and ("initiate", "g-take180") in env.vw.calls
    for ch in (a, b):
        assert {p for p, ev, _ in ch.sent if ev == "takeover-estate-kit-used"} == \
            {"alex", "dana", "erin"}
    banner = [m for p, ev, m in a.sent if ev == "takeover-banner"]
    assert banner and "estate recovery kit" in banner[0]
    env.clock.days(179)
    with pytest.raises(TakeoverError, match="day 180"):
        flow.complete(env.deps, rec.id, None)
    assert kit.status()["status"] == "used" and "hash" not in kit.path.read_text()
    with pytest.raises(TakeoverError, match="no active estate recovery kit"):
        kit.verify()


def test_estate_kit_any_owner_target(env):
    kit, box = _kit(env)
    box["code"] = kit.generate("alex", "2026-11-01")
    env.vw.grants += [EmergencyGrant("e-view", "erin@local", "view", 15),
                      EmergencyGrant("e-take", "erin@local", "takeover", 180)]
    rec = _estate_wizard(env, kit, target="erin", name="erin")
    assert rec.target == "erin" and rec.path == "estate-kit"


def test_estate_kit_wrong_code_and_missing(env):
    kit, box = _kit(env)
    with pytest.raises(TakeoverError, match="no active estate recovery kit"):
        _estate_wizard(env, kit)
    kit.generate("alex", "2026-11-01")
    box["code"] = "0" * 30
    with pytest.raises(TakeoverError, match="code is wrong"):
        _estate_wizard(env, kit)
    assert kit.active()


def test_estate_kit_not_consumed_when_start_fails(env):
    kit, box = _kit(env)
    box["code"] = kit.generate("alex", "2026-11-01")
    env.vw.grants = [g for g in env.vw.grants if g.wait_days != 180]
    with pytest.raises(TakeoverError, match="180-day wait"):
        _estate_wizard(env, kit)
    assert kit.active()


# ── printable sheet / QR ────────────────────────────────────────────────────
def test_uri_round_trip_and_typed_forms():
    from cvc.takeover.estate_sheet import build_uri, parse_code
    code = "ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567"
    uri = build_uri(code)
    assert uri == "cvc-estate:v1:ABCDEFGHJKMNPQRSTVWXYZ01234567"
    assert parse_code(uri) == parse_code(code.lower().replace("-", " ")) == uri.split(":")[2]
    with pytest.raises(TakeoverError, match="unsupported"):
        parse_code("cvc-estate:v2:ABC")
    with pytest.raises(TakeoverError, match="malformed"):
        parse_code("cvc-estate:https://x")


def test_scanned_uri_accepted_by_verify(env):
    from cvc.takeover.estate_sheet import build_uri
    kit, box = _kit(env)
    box["code"] = build_uri(kit.generate("alex", "2026-11-01"))
    assert kit.verify()


def test_sheet_pdf_0600_no_code_in_state_or_logs(env, tmp_path, capsys, caplog):
    segno = pytest.importorskip("segno")
    from cvc.takeover.estate_sheet import build_uri, generate_and_emit, qr_matrix
    kit, _ = _kit(env)
    outdir = tmp_path / "print"
    outdir.mkdir()
    lines = []
    kit_id, path = generate_and_emit(kit, "alex", "2026-11-01T00:00:00", outdir,
                                     out=lines.append)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600 and path.parent == outdir
    pdf = path.read_bytes()
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    assert b"DO NOT PHOTOGRAPH" in pdf and f"Kit id {kit_id}".encode() in pdf
    assert b"cvc takeover start --estate-kit" in pdf
    code_line = next(x for x in pdf.split(b"\n") if b"(Code:" in x)
    groups = code_line.split(b"(Code:")[1].split(b")")[0].split()
    assert len(groups) == 6 and all(len(g) == 5 for g in groups)
    code = b"".join(groups).decode()
    # QR payload round-trip: the drawn matrix is exactly the QR of the v1 URI
    assert qr_matrix(build_uri(code)) == [list(r) for r in
                                          segno.make(build_uri(code), error="m").matrix]
    assert kit_id == kit.status()["kit_id"] and kit_id not in code
    state_text = "".join(p.read_text() for p in env.store.dir.glob("*") if p.is_file())
    assert code not in state_text
    assert all(code not in x for x in lines) and code not in capsys.readouterr().out
    assert code not in caplog.text
    assert any("shred -u" in x for x in lines)
    env.reader.serial = "111"
    from cvc.takeover.estate_sheet import write_sheet
    with pytest.raises(TakeoverError, match="state dir"):
        write_sheet(env.store.dir / "x.pdf", code, kit_id, "2026-11-01", env.store.dir)


def test_terminal_mode(env):
    pytest.importorskip("segno")
    from cvc.takeover.estate_sheet import generate_and_emit
    kit, _ = _kit(env)
    lines = []
    _, path = generate_and_emit(kit, "alex", "2026-11-01", terminal=True, out=lines.append)
    assert path is None and "█" in lines[0] and "LEGACY RECOVERY CODE" in lines[1]


def test_missing_qr_lib_message(env, monkeypatch, tmp_path):
    import builtins

    from cvc.takeover.estate_sheet import generate_and_emit
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "segno":
            raise ImportError(name)
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    kit, _ = _kit(env)
    with pytest.raises(TakeoverError, match=r"pip install 'cvc\[estate\]'"):
        generate_and_emit(kit, "alex", "2026-11-01", tmp_path)
    assert not kit.active()                      # no kit created that nobody can print
