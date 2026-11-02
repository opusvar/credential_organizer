"""D27: temporary (bridge) device certs."""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import pytest
import yaml

from cvc.access.model import parse_registry
from cvc.approvals.service import ApprovalService
from cvc.audit.checks import Context, tempdevice_check
from cvc.broker.audit import AuditLog
from cvc.tempdevice import certs as tcerts
from cvc.tempdevice import cli, hooks
from cvc.tempdevice.model import (
    Bridge,
    approver_ok,
    bridge_sans,
    capped_tier,
    device_id,
    is_temp_device,
    iso,
    required_approver_rank,
)
from cvc.tempdevice.service import (
    ApprovalsLink,
    AuthProof,
    BridgeError,
    BridgeService,
    BridgeStore,
    lost_report_active,
)

T0 = dt.datetime(2026, 11, 1, 12, 0, tzinfo=dt.UTC)
STRONG = AuthProof(password=True, passkey=True)
YK = AuthProof(yubikey=True)
FP = "ab" * 32


def registry_dict(history: list | None = None) -> dict:
    return {
        "version": 1,
        "systems": {"workers": {"kind": "http"}},
        "roles": {"r": {"grants": [{"system": "workers", "paths": ["/"]}]}},
        "agents": {"bot": {"roles": ["r"], "token_sha256": "0" * 64, "tier": "low",
                           "sponsor": "alex"}},
        "people": {
            "alex": {"email": "alex@example.com", "tier": "owner"},
            "sam": {"email": "sam@example.com", "tier": "admin", "granted_by": "alex"},
            "robin": {"email": "robin@example.com", "tier": "high", "granted_by": "alex"},
            "kim": {"email": "kim@example.com", "tier": "medium", "granted_by": "alex",
                    "history": history or []},
            "lee": {"email": "lee@example.com", "tier": "low", "granted_by": "alex"},
            "gus": {"tier": "guest-short", "tailnet": "guests", "granted_by": "alex",
                    "expires": dt.date(2026, 12, 31)},
        },
        "hardware_keys": {
            k: {"owner": "alex", "model": "YubiKey 5C NFC", "serial": s,
                "uses": ["fido2-vaultwarden", "recovery"], "location": loc,
                "enrolled": dt.date(2026, 10, 1), "status": "active", "role": role}
            for k, s, loc, role in (("yk-a", 11111111, "on-person", "primary"),
                                    ("yk-b", 22222222, "home-safe", "backup"))},
        "devices": {
            "kim-phone2": {"owner": "kim", "kind": "phone",
                           "cert": {"storage": "p12", "serial": "0a1b",
                                    "fingerprint_sha256": FP,
                                    "not_after": dt.date(2027, 11, 1), "status": "active"}},
            "kim-laptop": {"owner": "kim", "kind": "laptop",
                           "cert": {"storage": "p12", "status": "pending"}},
            "lee-phone": {"owner": "lee", "kind": "phone",
                          "cert": {"storage": "p12", "serial": "0c1d",
                                   "fingerprint_sha256": FP,
                                   "not_after": dt.date(2027, 11, 1), "status": "active"}},
        },
    }


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += dt.timedelta(**kw)


@pytest.fixture
def clock():
    return Clock()


def make(tmp_path, clock, history=None, approvals=None):
    reg = parse_registry(registry_dict(history))
    return BridgeService(reg, BridgeStore(tmp_path / "state"), clock=clock, approvals=approvals)


@pytest.fixture
def svc(tmp_path, clock):
    return make(tmp_path, clock)


def audit_lines(tmp_path):
    p = tmp_path / "state" / "audit.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


# ── model / SAN format ────────────────────────────────────────────────────
@pytest.mark.parametrize("tier,cap", [("owner", "medium"), ("admin", "medium"),
                                      ("high", "medium"), ("medium", "medium"),
                                      ("low", "low"), ("media-only", "media-only")])
def test_capped_tier(tier, cap):
    assert capped_tier(tier) == cap


def test_capped_tier_unknown():
    with pytest.raises(ValueError):
        capped_tier("root")


def test_sans_and_temp_ids():
    assert device_id("kim", 2) == "kim-temp-2"
    assert is_temp_device("kim-temp-2") and is_temp_device("a-b-temp-10")
    for bad in ("kim-phone", "kim-temp-", "temp-1", None, "", "kim-temp-x"):
        assert not is_temp_device(bad)
    assert bridge_sans("alex", "alex-temp-1", "owner", "2026-11-04T12:00:00Z") == [
        "urn:cvc:person:alex", "urn:cvc:device:alex-temp-1", "urn:cvc:tier:medium",
        "urn:cvc:temp:2026-11-04T12:00:00Z"]


def test_grant_rule():
    # granted tier is the capped tier; approver >= 2 above it, owners always.
    assert approver_ok("admin", "medium") and approver_ok("admin", "owner")
    assert not approver_ok("high", "medium")
    assert approver_ok("high", "low") and not approver_ok("medium", "low")
    assert approver_ok("owner", "high")
    assert not approver_ok(None, "low") and not approver_ok("guest-short", "low")
    assert required_approver_rank("owner") == required_approver_rank("medium")


def test_bridge_from_dict_rejects_bad_status():
    with pytest.raises(ValueError):
        Bridge.from_dict({"id": "x-temp-1", "person": "x", "person_tier": "low", "tier": "low",
                          "reason": "r", "requested_at": iso(T0), "status": "weird"})


# ── request ───────────────────────────────────────────────────────────────
def test_request_then_approve(svc, tmp_path, clock):
    b = svc.request("kim", "borrowed phone", STRONG)
    assert (b.id, b.status, b.tier, b.requested_hours) == ("kim-temp-1", "pending", "medium", 72)
    clock.advance(minutes=5)
    b = svc.approve(b.id, "sam", passkey=True)
    assert b.status == "active" and b.approved_by == "sam"
    assert b.expires_at == iso(T0 + dt.timedelta(minutes=5, hours=72))
    assert b.hours_left(clock()) == 72
    assert b.sans()[-1] == f"urn:cvc:temp:{b.expires_at}"
    ev = [e["purpose"] for e in audit_lines(tmp_path)]
    assert ev == ["tempdevice:request", "tempdevice:approve"]
    assert AuditLog(str(tmp_path / "state" / "audit.jsonl")).verify()


def test_state_file_private(svc, tmp_path):
    svc.request("kim", "loaner laptop", STRONG)
    p = tmp_path / "state" / "bridges.json"
    assert p.stat().st_mode & 0o777 == 0o600
    assert "kim-temp-1" in json.loads(p.read_text())["bridges"]


@pytest.mark.parametrize("proof", [AuthProof(), AuthProof(password=True),
                                   AuthProof(passkey=True)])
def test_request_needs_strong_auth(svc, proof):
    with pytest.raises(BridgeError, match="password \\+ passkey"):
        svc.request("kim", "travel", proof)


def test_request_with_yubikey_only(svc):
    assert svc.request("alex", "travel", YK).status == "pending"


@pytest.mark.parametrize("who,msg", [("gus", "guests"), ("bot", "agents"),
                                     ("nobody", "unknown person")])
def test_who_cannot_get_one(svc, who, msg):
    with pytest.raises(BridgeError, match=msg):
        svc.request(who, "x", STRONG)


def test_inactive_person_refused(tmp_path, clock):
    d = registry_dict()
    d["people"]["lee"]["status"] = "checked-out"
    s = BridgeService(parse_registry(d), BridgeStore(tmp_path / "s"), clock=clock)
    with pytest.raises(BridgeError, match="not active"):
        s.request("lee", "x", STRONG)


def test_one_active_bridge_per_person(svc):
    b = svc.request("kim", "a", STRONG)
    with pytest.raises(BridgeError, match="already has"):
        svc.request("kim", "b", STRONG)
    svc.approve(b.id, "sam", passkey=True)
    with pytest.raises(BridgeError, match="already has"):
        svc.request("kim", "b", STRONG)
    svc.revoke(b.id, "kim")
    assert svc.request("kim", "c", STRONG).id == "kim-temp-2"   # numbering continues


def test_request_hours_bounds(svc):
    with pytest.raises(BridgeError, match="positive"):
        svc.request("kim", "x", STRONG, hours=0)
    with pytest.raises(BridgeError, match="14 days"):
        svc.request("kim", "x", STRONG, hours=14 * 24 + 1)
    assert svc.request("kim", "x", STRONG, hours=24).requested_hours == 24


# ── approval rules ────────────────────────────────────────────────────────
@pytest.mark.parametrize("approver,ok", [("alex", True), ("sam", True), ("robin", False),
                                         ("lee", False), ("gus", False), ("bot", False)])
def test_approver_two_tiers_above(svc, approver, ok):
    b = svc.request("kim", "x", STRONG)
    if ok:
        assert svc.approve(b.id, approver, passkey=True).status == "active"
    else:
        with pytest.raises(BridgeError):
            svc.approve(b.id, approver, passkey=True)
        assert svc.list(open_only=True)[0].status == "pending"


def test_low_person_high_approver(svc):
    b = svc.request("lee", "x", STRONG)
    assert svc.approve(b.id, "robin", passkey=True).status == "active"


def test_approver_needs_passkey(svc):
    b = svc.request("kim", "x", STRONG)
    with pytest.raises(BridgeError, match="passkey"):
        svc.approve(b.id, "sam", passkey=False)


def test_no_self_approval(svc):
    b = svc.request("sam", "x", STRONG)
    with pytest.raises(BridgeError, match="self-approval"):
        svc.approve(b.id, "sam", passkey=True)


def test_refused_approval_is_audited(svc, tmp_path):
    b = svc.request("kim", "x", STRONG)
    with pytest.raises(BridgeError):
        svc.approve(b.id, "robin", passkey=True)
    last = audit_lines(tmp_path)[-1]
    assert last["agent"] == "robin" and last["outcome"].startswith("deny:")


def test_approve_twice_refused(svc):
    b = svc.request("kim", "x", STRONG)
    svc.approve(b.id, "sam", passkey=True)
    with pytest.raises(BridgeError, match="not pending"):
        svc.approve(b.id, "alex", passkey=True)


def test_deny(svc):
    b = svc.request("kim", "x", STRONG)
    assert svc.deny(b.id, "sam").status == "denied"
    with pytest.raises(BridgeError, match="nothing pending"):
        svc.deny(b.id, "sam")
    with pytest.raises(BridgeError, match="unknown bridge"):
        svc.deny("nope-temp-1", "sam")


# ── self-issue (owners/admins with a YubiKey) ─────────────────────────────
def test_owner_self_issue(svc):
    b = svc.request("alex", "travel", YK, self_issue=True)
    assert b.status == "active" and b.self_issued and b.approved_by == "alex"
    assert b.tier == "medium"


def test_admin_self_issue_needs_yubikey(svc):
    with pytest.raises(BridgeError, match="YubiKey"):
        svc.request("sam", "travel", STRONG, self_issue=True)


def test_non_admin_cannot_self_issue(svc):
    with pytest.raises(BridgeError, match="owners and admins"):
        svc.request("robin", "travel", YK, self_issue=True)


# ── lost-device report (D23) ──────────────────────────────────────────────
LOST = [{"date": "2026-10-30", "event": "passwordless-block"}]


def test_lost_report_detection(clock):
    reg = parse_registry(registry_dict(LOST))
    assert lost_report_active(reg, "kim", T0)
    assert not lost_report_active(reg, "kim", T0 + dt.timedelta(days=5))   # day 7 over
    assert not lost_report_active(reg, "lee", T0)
    assert not lost_report_active(reg, "ghost", T0)
    lifted = parse_registry(registry_dict(LOST + [{"date": "2026-10-31",
                                                   "event": "passwordless-unblock"}]))
    assert not lost_report_active(lifted, "kim", T0)


def test_bridge_works_during_lost_block_with_other_approver(tmp_path, clock):
    s = make(tmp_path, clock, history=LOST)
    b = s.request("kim", "lost phone", STRONG)
    assert b.lost_report
    assert s.approve(b.id, "sam", passkey=True).status == "active"


def test_lost_block_owner_cannot_self_issue(tmp_path, clock):
    d = registry_dict()
    d["people"]["alex"]["history"] = LOST
    s = BridgeService(parse_registry(d), BridgeStore(tmp_path / "s"), clock=clock)
    with pytest.raises(BridgeError, match="someone else"):
        s.request("alex", "lost phone", YK, self_issue=True)
    b = s.request("alex", "lost phone", YK)
    with pytest.raises(BridgeError, match="self-approval"):
        s.approve(b.id, "alex", passkey=True)


# ── extend ────────────────────────────────────────────────────────────────
def _active(svc, person="kim", approver="sam"):
    b = svc.request(person, "x", STRONG)
    return svc.approve(b.id, approver, passkey=True)


def test_extend_needs_approval(svc):
    b = _active(svc)
    old = b.expires_at
    b = svc.extend(b.id, "kim", STRONG, 48)
    assert b.pending_extension["hours"] == 48 and b.expires_at == old
    with pytest.raises(BridgeError, match="already has an extension"):
        svc.extend(b.id, "kim", STRONG)
    with pytest.raises(BridgeError, match="self-approval"):
        svc.approve_extension(b.id, "kim", passkey=True)
    b = svc.approve_extension(b.id, "alex", passkey=True)
    assert b.pending_extension is None and len(b.extensions) == 1
    assert b.expires_at == iso(T0 + dt.timedelta(hours=120))


def test_extend_capped_at_14_days(svc):
    b = _active(svc)
    for _ in range(3):        # 72 + 3*72 = 288 h = 12 days
        svc.extend(b.id, "kim", STRONG, 72)
        svc.approve_extension(b.id, "sam", passkey=True)
    with pytest.raises(BridgeError, match="14 days"):
        svc.extend(b.id, "kim", STRONG, 72)
    svc.extend(b.id, "kim", STRONG, 48)          # exactly 14 days is allowed
    b = svc.approve_extension(b.id, "sam", passkey=True)
    assert b.expires_at == iso(T0 + dt.timedelta(days=14))


def test_extend_rules(svc):
    b = _active(svc)
    with pytest.raises(BridgeError, match="only the bridge's person"):
        svc.extend(b.id, "sam", STRONG)
    with pytest.raises(BridgeError, match="password"):
        svc.extend(b.id, "kim", AuthProof(password=True))
    with pytest.raises(BridgeError, match="no extension waiting"):
        svc.approve_extension(b.id, "sam", passkey=True)
    p = svc.request("lee", "x", STRONG)
    with pytest.raises(BridgeError, match="only an active"):
        svc.extend(p.id, "lee", STRONG)


def test_deny_extension_keeps_bridge(svc):
    b = _active(svc)
    svc.extend(b.id, "kim", STRONG)
    b = svc.deny(b.id, "sam")
    assert b.status == "active" and b.pending_extension is None


# ── end of life ───────────────────────────────────────────────────────────
def test_auto_expire(svc, clock, tmp_path):
    b = _active(svc)
    clock.advance(hours=71)
    assert svc.sweep() == []
    clock.advance(hours=2)
    out = svc.sweep()
    assert [x.id for x in out] == [b.id] and out[0].status == "expired"
    assert audit_lines(tmp_path)[-1]["purpose"] == "tempdevice:expire"
    assert svc.active_for("kim") is None


def test_pending_times_out(svc, clock):
    b = svc.request("kim", "x", STRONG)
    clock.advance(hours=24)
    assert svc.sweep()[0].status == "denied"
    assert svc.list(person="kim")[0].end_reason == "approval timed out"
    assert b.id == "kim-temp-1"


def test_pending_extension_times_out(svc, clock):
    b = _active(svc)
    svc.extend(b.id, "kim", STRONG)
    clock.advance(hours=25)
    svc.sweep()
    b = svc.active_for("kim")
    assert b is not None and b.pending_extension is None


def test_revoke_by_person_admin_or_owner_only(svc):
    b = _active(svc)
    for who in ("robin", "lee", "gus", "nobody"):
        with pytest.raises(BridgeError, match="person, an admin or an owner"):
            svc.revoke(b.id, who)
    assert svc.revoke(b.id, "alex").status == "revoked"
    with pytest.raises(BridgeError, match="already"):
        svc.revoke(b.id, "kim")
    b2 = _active(svc)
    assert svc.revoke(b2.id, "kim", "found my phone").end_reason == "found my phone"


def test_admin_revoke_succeeds_and_is_audited(svc, tmp_path):
    b = _active(svc)
    with pytest.raises(BridgeError):
        svc.revoke(b.id, "robin")
    r = svc.revoke(b.id, "sam", "lost phone found by IT")
    assert r.status == "revoked" and r.ended_by == "sam"
    rev = [x for x in audit_lines(tmp_path) if "revoke" in json.dumps(x)]
    assert any("robin" in json.dumps(x) and "deny" in json.dumps(x) for x in rev)
    assert any("sam" in json.dumps(x) and "lost phone found by IT" in json.dumps(x) for x in rev)


def test_active_grants(svc):
    assert svc.active_grants() == []
    b = _active(svc)
    g = svc.active_grants()
    assert g == [{"kind": "tempdevice", "id": b.id, "person": "kim",
                  "expires_at": b.expires_at,
                  "revoke_hint": f"cvc-tempdevice revoke {b.id} --by <you>"}]
    svc.revoke(b.id, "kim")
    assert svc.active_grants() == []


def test_revoke_all_offboard(svc):
    b = _active(svc)
    out = svc.revoke_all("kim", "offboard")
    assert [x.id for x in out] == [b.id] and out[0].end_reason == "offboard"
    assert svc.revoke_all("kim", "offboard") == []


def test_promote_revokes_bridge(svc):
    b = _active(svc)
    p = svc.promote("kim", "kim-phone2", "kim")
    assert p.id == b.id and p.status == "revoked" and p.promoted_to == "kim-phone2"
    assert p.end_reason == "promoted:kim-phone2"
    assert svc.promote("kim", "kim-phone2", "kim") is None


@pytest.mark.parametrize("device,msg", [("kim-temp-1", "cannot be promoted"),
                                        ("lee-phone", "not a registered device of kim"),
                                        ("ghost", "not a registered device"),
                                        ("kim-laptop", "no active cert")])
def test_promote_refusals(svc, device, msg):
    _active(svc)
    with pytest.raises(BridgeError, match=msg):
        svc.promote("kim", device, "kim")


# ── approvals pipeline (card + ntfy) ──────────────────────────────────────
def test_card_published_and_resolved(tmp_path, clock):
    aps = ApprovalService(state_path=str(tmp_path / "approvals.json"),
                          clock=lambda: clock())
    s = make(tmp_path, clock, approvals=ApprovalsLink(aps))
    b = s.request("kim", "borrowed phone", STRONG)
    card = aps.get(b.approval_id)
    assert card.status == "pending" and card.approver_min_tier == "admin"
    assert card.requires_passkey and card.requester.on_behalf_of == "kim"
    assert "kim-temp-1" in card.summary
    s.approve(b.id, "sam", passkey=True)
    assert aps.get(b.approval_id).status == "approved"


def test_card_decision_synced_and_rechecked(tmp_path, clock):
    aps = ApprovalService(state_path=str(tmp_path / "approvals.json"),
                          clock=lambda: clock())
    s = make(tmp_path, clock, approvals=ApprovalsLink(aps))
    b = s.request("lee", "x", STRONG)
    aps.record_external(b.approval_id, "approved", "robin")
    assert s.sync_approvals()[0].status == "active"
    # A card approved by the person themselves is re-checked and denied.
    b2 = s.request("sam", "x", STRONG)
    aps.record_external(b2.approval_id, "approved", "sam")
    s.sync_approvals()
    assert s.list(person="sam")[0].status == "denied"


def test_card_for_extension_and_cancel(tmp_path, clock):
    aps = ApprovalService(state_path=str(tmp_path / "approvals.json"),
                          clock=lambda: clock())
    s = make(tmp_path, clock, approvals=ApprovalsLink(aps))
    b = s.request("kim", "x", STRONG)
    s.revoke(b.id, "kim")
    assert aps.get(b.approval_id).status == "cancelled"
    b = s.request("kim", "x", STRONG)
    s.approve(b.id, "sam", passkey=True)
    b = s.extend(b.id, "kim", STRONG)
    aid = b.pending_extension["approval_id"]
    aps.record_external(aid, "approved", "alex")
    s.sync_approvals()
    assert len(s.active_for("kim").extensions) == 1


# ── certs (printed, never executed) ───────────────────────────────────────
def test_issue_commands(svc, clock):
    b = _active(svc, "alex", "sam")
    cmds = [c.shell() for c in tcerts.issue_commands(b, clock(), ca_url="https://10.0.0.5:9000")]
    tok = cmds[0]
    assert "tier=medium" in tok and f"temp={b.expires_at}" in tok and "device=alex-temp-1" in tok
    assert "issuer-family" in tok and "--not-after 72h" in tok
    assert "tier=owner" not in tok
    assert "step ca revoke" in tcerts.revoke_command(b)


def test_issue_commands_need_active(svc, clock):
    b = svc.request("kim", "x", STRONG)
    with pytest.raises(ValueError):
        tcerts.issue_commands(b, clock(), ca_url="https://10.0.0.5:9000")


def test_template_caps_temp_tier():
    t = (Path(__file__).resolve().parent.parent / "deploy/step-ca/templates/device-leaf.tpl"
         ).read_text()
    assert "urn:cvc:temp:%s" in t and ".Token.temp" in t
    assert '(list "media-only" "low" "medium")' in t


# ── audit check ───────────────────────────────────────────────────────────
def test_audit_flags_old_and_repeat(tmp_path, clock):
    s = make(tmp_path, clock)
    for _ in range(2):
        b = _active(s)
        s.revoke(b.id, "kim")
    b = _active(s)
    for _ in range(2):
        s.extend(b.id, "kim", STRONG, 72)
        s.approve_extension(b.id, "sam", passkey=True)
    ctx = Context(now=clock() + dt.timedelta(days=8), tempdevice_dir=str(tmp_path / "state"))
    subjects = {f.subject for f in tempdevice_check(ctx)}
    assert subjects == {"bridge:kim-temp-3", "people.kim:repeat"}


def test_audit_quiet_and_readonly(tmp_path, clock):
    ctx = Context(now=clock(), tempdevice_dir=str(tmp_path / "none"))
    assert tempdevice_check(ctx) == []
    assert not (tmp_path / "none").exists()
    assert tempdevice_check(Context(now=clock())) == []
    s = make(tmp_path, clock)
    _active(s)
    assert tempdevice_check(Context(now=clock(), tempdevice_dir=str(tmp_path / "state"))) == []


def test_audit_unreadable_state(tmp_path, clock):
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "bridges.json").write_text("{not json")
    f = tempdevice_check(Context(now=clock(), tempdevice_dir=str(tmp_path / "bad")))
    assert f[0].severity == "warn"


# ── hooks: promote on set-cert, revoke on offboard ────────────────────────
def _write_reg(tmp_path) -> Path:
    p = tmp_path / "registry.yaml"
    p.write_text(yaml.safe_dump(registry_dict(), sort_keys=False))
    return p


def test_hook_set_cert_promotes(tmp_path, clock, monkeypatch):
    reg = _write_reg(tmp_path)
    s = make(tmp_path, clock)
    b = _active(s)
    st = str(tmp_path / "state")
    ns = argparse.Namespace(registry=str(reg), id="kim-phone2")
    out = hooks.after_set_cert(ns, st)
    assert f"bridge {b.id} revoked" in out
    assert hooks.after_set_cert(ns, st) == ""
    assert hooks.after_set_cert(argparse.Namespace(registry=str(reg), id="kim-temp-9"), st) == ""
    assert hooks.after_set_cert(ns, str(tmp_path / "missing")) == ""


def test_access_cli_set_cert_triggers_promote(tmp_path, clock, monkeypatch):
    from cvc.access.cli import main as access_main
    reg = _write_reg(tmp_path)
    s = make(tmp_path, clock)
    _active(s)
    monkeypatch.setenv("CVC_TEMPDEVICE_STATE", str(tmp_path / "state"))
    rc = access_main(["device", "set-cert", "kim-laptop", "--serial", "0e0f",
                      "--fingerprint", FP, "--not-after", "2027-11-01", "--registry", str(reg)])
    assert rc == 0
    assert s.list(person="kim")[0].promoted_to == "kim-laptop"


def test_access_cli_offboard_revokes(tmp_path, clock, monkeypatch, capsys):
    from cvc.access.cli import main as access_main
    reg = _write_reg(tmp_path)
    s = make(tmp_path, clock)
    _active(s)
    monkeypatch.setenv("CVC_TEMPDEVICE_STATE", str(tmp_path / "state"))
    assert access_main(["person", "remove", "kim", "--registry", str(reg)]) == 0
    assert "offboard: bridge kim-temp-1 revoked" in capsys.readouterr().out
    assert s.list(person="kim")[0].status == "revoked"


def test_device_add_refuses_temp_id(tmp_path, capsys):
    from cvc.access.cli import main as access_main
    reg = _write_reg(tmp_path)
    assert access_main(["device", "add", "kim-temp-1", "--owner", "kim", "--kind",
                        "phone", "--storage", "p12", "--registry", str(reg)]) == 1
    assert "temporary-device id" in capsys.readouterr().err


# ── CLI ───────────────────────────────────────────────────────────────────
def test_cli_full_flow(tmp_path, capsys):
    reg = _write_reg(tmp_path)
    base = ["--registry", str(reg), "--state", str(tmp_path / "cs")]
    assert cli.main([*base, "request", "kim", "--reason", "travel", "--password",
                     "--passkey"]) == 0
    assert "pending approval" in capsys.readouterr().out
    assert cli.main([*base, "approve", "kim-temp-1", "--by", "robin", "--passkey"]) == 2
    assert cli.main([*base, "approve", "kim-temp-1", "--by", "sam", "--passkey"]) == 0
    out = capsys.readouterr().out
    assert "urn:cvc:temp:" in out and "NOT executed" in out
    assert cli.main([*base, "extend", "kim-temp-1", "--by", "kim", "--hours", "24",
                     "--yubikey"]) == 0
    assert cli.main([*base, "approve", "kim-temp-1", "--by", "alex", "--passkey"]) == 0
    assert cli.main([*base, "list"]) == 0
    assert "kim-temp-1" in capsys.readouterr().out
    assert cli.main([*base, "promote", "kim", "kim-phone2", "--by", "kim"]) == 0
    assert "revoked" in capsys.readouterr().out
    assert cli.main([*base, "list"]) == 0
    assert capsys.readouterr().out == ""
    assert cli.main([*base, "list", "--all", "--person", "kim"]) == 0
    assert "revoked" in capsys.readouterr().out
    assert cli.main([*base, "promote", "kim", "kim-phone2", "--by", "kim"]) == 0
    assert cli.main([*base, "sweep"]) == 0


def test_cli_self_issue_revoke_deny(tmp_path, capsys):
    reg = _write_reg(tmp_path)
    base = ["--registry", str(reg), "--state", str(tmp_path / "cs")]
    assert cli.main([*base, "request", "alex", "--reason", "travel", "--yubikey",
                     "--self-issue"]) == 0
    assert "tier medium" in capsys.readouterr().out
    assert cli.main([*base, "revoke", "alex-temp-1", "--by", "alex"]) == 0
    assert cli.main([*base, "request", "lee", "--reason", "x", "--yubikey"]) == 0
    assert cli.main([*base, "deny", "lee-temp-1", "--by", "robin"]) == 0
    assert cli.main([*base, "request", "gus", "--reason", "x", "--yubikey"]) == 2
    assert "guests" in capsys.readouterr().err


def test_cli_bad_registry(tmp_path):
    assert cli.main(["--registry", str(tmp_path / "nope.yaml"), "list"]) == 1


def test_cli_with_approvals_state(tmp_path):
    reg = _write_reg(tmp_path)
    ap = tmp_path / "approvals.json"
    assert cli.main(["--registry", str(reg), "--state", str(tmp_path / "cs"),
                     "--approvals-state", str(ap), "request", "kim", "--reason", "x",
                     "--password", "--passkey"]) == 0
    assert len(json.loads(ap.read_text())["approvals"]) == 1
