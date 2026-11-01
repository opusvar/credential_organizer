"""Onboarding wizard (`cvc onboard person|agent`). All seams are fakes; nothing external."""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

import pytest
import yaml

from cvc.access import load_registry
from cvc.onboard import cli
from cvc.onboard.authentik import HttpAuthentik, RecordingAuthentik
from cvc.onboard.certs import cert_commands, provisioner_for
from cvc.onboard.core import IO, OnboardError
from cvc.onboard.wizard import (
    AgentSpec,
    DeviceSpec,
    HwKeySpec,
    PersonSpec,
    Seams,
    onboard_agent,
    onboard_person,
)

TODAY = dt.date(2026, 11, 1)
UUID1 = "11111111-2222-3333-4444-555555555555"
REPO = Path(__file__).resolve().parents[1]


def base() -> dict:
    return {
        "version": 1,
        "systems": {
            "vw": {"kind": "credential-store", "data": "private", "action": "act"},
            "mq": {"kind": "mqtt", "data": "internal", "action": "act"},
        },
        "roles": {
            "pay": {"grants": [{"system": "vw", "credential": UUID1, "purposes": ["x"],
                                "action": "act"}]},
            "readmq": {"grants": [{"system": "mq", "topics": ["t"], "access": "read",
                                   "action": "read"}]},
        },
        "people": {
            "nathan": {"email": "nathan@local", "tier": "owner", "tailnet": "owner"},
            "kate": {"email": "kate@local", "tier": "owner", "tailnet": "owner"},
            "sam": {"tier": "medium", "tailnet": "family", "granted_by": "nathan"},
        },
        "resources": {"books": {"name": "Books", "host": "books.x", "kind": "library",
                                "min_tier": "guest-long"}},
        "hardware_keys": {"yk1": {"owner": "nathan", "model": "YK5", "serial": 1,
                                  "uses": ["recovery"], "location": "on-person",
                                  "status": "active", "role": "primary"}},
    }


@pytest.fixture
def reg(tmp_path):
    p = tmp_path / "registry.yaml"
    p.write_text(yaml.safe_dump(base(), sort_keys=False), encoding="utf-8")
    return p


def seams(answers=None, **kw) -> Seams:
    return Seams(io=IO(answers=answers if answers is not None else []), today=TODAY, **kw)


class FakeRunner:
    def __init__(self, rc=0):
        self.calls: list[list[str]] = []
        self.rc = rc

    def __call__(self, argv):
        self.calls.append(argv)
        return self.rc, "tok-123\n" if argv[:3] == ["step", "ca", "token"] else ""


def person(**kw) -> PersonSpec:
    d = {"id": "alice", "name": "Alice A", "tier": "medium", "granted_by": "nathan",
             "email": "alice@local"}
    d.update(kw)
    return PersonSpec(**d)


# ── dry run ─────────────────────────────────────────────────────────────────

def test_dry_run_writes_nothing(reg, tmp_path):
    before = reg.read_text()
    out = tmp_path / "out"
    s = seams()
    sp = person(tier="owner", devices=[DeviceSpec("pix", "phone"), DeviceSpec("mbp", "laptop")],
                hwkeys=[HwKeySpec("a-yk", "primary", serial="42", model="YK5")])
    assert onboard_person(reg, sp, s, out_dir=out, dry_run=True) == 0
    assert reg.read_text() == before
    assert not out.exists()
    t = s.io.text
    for n in range(1, 8):
        assert f"== Step {n}:" in t
    assert "dry run: registry not written" in t
    assert "would write owner-tailnet policy" in t and "would write tiergate config" in t


def test_dry_run_cli_agent(reg):
    before = reg.read_text()
    io = IO(answers=[])
    rc = cli.main(["agent", "--registry", str(reg), "--id", "bot", "--tier", "low",
                   "--sponsor", "nathan", "--granted-by", "nathan", "--role", "readmq",
                   "--dry-run"], io=io, seams=Seams(io=io, today=TODAY))
    assert rc == 0 and reg.read_text() == before


# ── step 1: who ─────────────────────────────────────────────────────────────

def test_write_person_after_confirmation(reg, tmp_path):
    s = seams(answers=["alice"])
    onboard_person(reg, person(), s, out_dir=tmp_path / "o")
    r = load_registry(reg)
    p = r.people["alice"]
    assert (p.tier, p.tailnet, p.granted_by) == ("medium", "family", "nathan")
    assert p.name == "Alice A" and p.history[0]["via"] == "cvc onboard"
    assert "display_name" not in p.history[0]
    assert (tmp_path / "o" / "tiergate-configmap.yaml").exists()
    assert (tmp_path / "o" / "tailnet-policy.hujson").exists()
    assert "&id" not in reg.read_text()


def test_confirmation_mismatch_aborts(reg, tmp_path):
    before = reg.read_text()
    with pytest.raises(OnboardError, match="aborted"):
        onboard_person(reg, person(), seams(answers=["yes"]), out_dir=tmp_path)
    assert reg.read_text() == before


def test_guest_defaults_expiry_and_ha(reg, tmp_path):
    s = seams(answers=["g1"])
    onboard_person(reg, person(id="g1", tier="guest-short", ha="view", email=None), s,
                   out_dir=tmp_path)
    g = load_registry(reg).people["g1"]
    assert g.expires == TODAY + dt.timedelta(days=5)
    assert (g.tailnet, g.ha) == ("guests", "view")
    assert "default 5 days" in s.io.text


@pytest.mark.parametrize("kw,msg", [
    ({"tier": "guest-short", "tailnet": "family"}, "belongs on tailnet guests"),
    ({"tier": "owner", "tailnet": "family"}, "belongs on tailnet owner"),
    ({"tailnet": "agents"}, "may not be on tailnet agents"),
    ({"tailnet": "long-guests"}, "merged"),
])
def test_tailnet_refusals(reg, tmp_path, kw, msg):
    before = reg.read_text()
    with pytest.raises(OnboardError, match=msg):
        onboard_person(reg, person(**kw), seams(), out_dir=tmp_path)
    assert reg.read_text() == before


@pytest.mark.parametrize("kw,msg", [
    ({"tier": "high", "granted_by": "sam"}, "only an owner may grant tier high"),
    ({"tier": "low", "granted_by": "sam"}, "at least 2 tiers above"),
    ({"granted_by": "ghost"}, "unknown person"),
])
def test_grant_refusals(reg, tmp_path, kw, msg):
    with pytest.raises(OnboardError, match=msg):
        onboard_person(reg, person(**kw), seams(), out_dir=tmp_path)


def test_input_refusals(reg, tmp_path):
    with pytest.raises(OnboardError, match="already exists"):
        onboard_person(reg, person(id="sam"), seams(), out_dir=tmp_path)
    with pytest.raises(OnboardError, match="only for guest"):
        onboard_person(reg, person(ha="view"), seams(), out_dir=tmp_path)
    with pytest.raises(OnboardError, match="not a person tier"):
        onboard_person(reg, person(tier="assistant"), seams(), out_dir=tmp_path)


# ── step 2: devices / certs ─────────────────────────────────────────────────

def test_cert_commands_shapes():
    ph = cert_commands("alice", "pix", "medium", "phone", "p12")
    assert ph[0].shell() == ("bash deploy/step-ca/issue-p12.sh --person alice --device pix "
                             "--tier medium")
    lap = cert_commands("alice", "mbp", "admin", "laptop", "p12")
    tok = lap[0].shell()
    assert tok.startswith("TOKEN=$(step ca token mbp --provisioner issuer-admin")
    for claim in ("person=alice", "device=mbp", "tier=admin"):
        assert f"--set {claim}" in tok
    assert '--token "$TOKEN"' in lap[1].shell()
    yk = cert_commands("alice", "mbp", "owner", "laptop", "yubikey-piv")
    assert yk[0].argv[:2] == ("bash", "deploy/yubikey/issue-device-cert.sh")


def test_provisioners_match_issue_script():
    text = (REPO / "deploy/step-ca/issue-p12.sh").read_text()
    for tiers, prov, dur in re.findall(r"^\s*([a-z|-]+)\) PROV=(\S+); DUR=(\S+) ;;", text,
                                       re.MULTILINE):
        for t in tiers.split("|"):
            assert provisioner_for(t) == (prov, dur)


def test_devices_print_sans_and_do_not_run(reg, tmp_path):
    runner = FakeRunner()
    s = seams(runner=runner, which=lambda _: "/usr/bin/step")
    onboard_person(reg, person(devices=[DeviceSpec("pix", "phone")]), s, out_dir=tmp_path,
                   dry_run=True)
    assert runner.calls == []
    assert "urn:cvc:person:alice, urn:cvc:device:pix, urn:cvc:tier:medium" in s.io.text
    assert "device-leaf.tpl" in s.io.text


def test_execute_runs_via_runner_and_threads_token(reg, tmp_path):
    runner = FakeRunner()
    s = seams(answers=["alice"], runner=runner, which=lambda _: "/usr/bin/step")
    onboard_person(reg, person(devices=[DeviceSpec("mbp", "laptop")]), s, out_dir=tmp_path,
                   execute=True)
    assert runner.calls[0][:3] == ["step", "ca", "token"]
    assert runner.calls[1][runner.calls[1].index("--token") + 1] == "tok-123"
    assert load_registry(reg).devices["mbp"].cert.status == "pending"


def test_execute_without_step_on_path(reg, tmp_path):
    runner = FakeRunner()
    s = seams(answers=["alice"], runner=runner, which=lambda _: None)
    onboard_person(reg, person(devices=[DeviceSpec("pix", "phone")]), s, out_dir=tmp_path,
                   execute=True)
    assert runner.calls == [] and "not on PATH" in s.io.text


def test_execute_failure_refuses_before_write(reg, tmp_path):
    before = reg.read_text()
    s = seams(answers=["alice"], runner=FakeRunner(rc=1), which=lambda _: "x")
    with pytest.raises(OnboardError, match="command failed"):
        onboard_person(reg, person(devices=[DeviceSpec("pix", "phone")]), s, out_dir=tmp_path,
                       execute=True)
    assert reg.read_text() == before


def test_yubikey_device_needs_known_key(reg, tmp_path):
    with pytest.raises(OnboardError, match="unknown hardware key"):
        onboard_person(reg, person(devices=[DeviceSpec("m", "laptop", "yubikey-piv", "nope")]),
                       seams(), out_dir=tmp_path)


# ── step 3: hardware keys ───────────────────────────────────────────────────

def test_hwkeys_for_owner_enrolled_and_printed(reg, tmp_path):
    s = seams(answers=["alice"])
    sp = person(tier="owner", tailnet=None,
                hwkeys=[HwKeySpec("a-yk1", "primary", serial="42", model="YK5"),
                        HwKeySpec("a-yk2", "backup", "home-safe")],
                devices=[DeviceSpec("mac", "laptop", "yubikey-piv", "a-yk1")])
    onboard_person(reg, sp, s, out_dir=tmp_path)
    r = load_registry(reg)
    assert r.hardware_keys["a-yk1"].role == "primary"
    assert "a-yk2" not in r.hardware_keys           # no serial yet: printed, not written
    assert "enroll-mac.sh a-yk2" in s.io.text and "--from-ykman" in s.io.text


def test_hwkeys_refused_for_low_tiers(reg, tmp_path):
    with pytest.raises(OnboardError, match="owners/admins only"):
        onboard_person(reg, person(hwkeys=[HwKeySpec("k", "primary")]), seams(),
                       out_dir=tmp_path)


def test_hwkeys_step_skipped_for_medium(reg, tmp_path):
    s = seams()
    onboard_person(reg, person(), s, out_dir=tmp_path, dry_run=True)
    assert "skipped: tier medium does not enroll hardware keys" in s.io.text


# ── step 4: tailscale ───────────────────────────────────────────────────────

def test_tailscale_family_share_and_policy_file(reg, tmp_path):
    s = seams(answers=["alice"])
    onboard_person(reg, person(), s, out_dir=tmp_path)
    assert "joins the 'family' tailnet" in s.io.text
    pol = (tmp_path / "tailnet-policy.hujson").read_text()
    assert "nathan@local" in pol and "kate@local" in pol and "alice@local" not in pol


def test_tailscale_owner_in_policy(reg, tmp_path):
    s = seams()
    onboard_person(reg, person(tier="owner"), s, out_dir=tmp_path, dry_run=True)
    assert "member of the owner tailnet" in s.io.text
    assert '"alice@local"' in s.io.text


def test_tailscale_policy_skipped_without_email(reg, tmp_path):
    s = seams()
    onboard_person(reg, person(tier="owner", email=None), s, out_dir=tmp_path, dry_run=True)
    assert "policy NOT regenerated" in s.io.text


# ── step 5: authentik ───────────────────────────────────────────────────────

def test_authentik_plan_only_without_execute(reg, tmp_path):
    live = RecordingAuthentik()
    s = seams(authentik=live)
    onboard_person(reg, person(tier="high"), s, out_dir=tmp_path, dry_run=True)
    assert live.calls == []
    assert "passkey REQUIRED" in s.io.text and "cvc-tier-high" in s.io.text


def test_authentik_execute_uses_client(reg, tmp_path):
    live = RecordingAuthentik()
    s = seams(answers=["alice"], authentik=live)
    onboard_person(reg, person(), s, out_dir=tmp_path, execute=True)
    assert live.calls == [("ensure_user", "alice", "Alice A", "alice@local"),
                          ("ensure_group", "cvc-tier-medium"),
                          ("add_to_group", "alice", "cvc-tier-medium")]
    assert "passkey: optional" in s.io.text


def test_authentik_execute_without_token(reg, tmp_path):
    s = seams(answers=["alice"])
    onboard_person(reg, person(), s, out_dir=tmp_path, execute=True)
    assert "AUTHENTIK_URL/AUTHENTIK_TOKEN not set" in s.io.text


def test_http_authentik_with_mock_transport():
    import httpx
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        if req.method == "GET":
            return httpx.Response(200, json={"results": [{"pk": 7}]
                                             if "groups" in req.url.path else []})
        return httpx.Response(201, json={})

    c = httpx.Client(base_url="https://ak/api/v3", transport=httpx.MockTransport(handler))
    ak = HttpAuthentik("https://ak", "t", client=c)
    assert ak.ensure_user("alice", "A", None) == "created user alice"
    assert ak.ensure_group("g") == "group g exists"
    assert ("POST", "/api/v3/core/users/") in seen


def test_cli_env_client_only_with_execute(monkeypatch):
    monkeypatch.setenv("AUTHENTIK_URL", "https://ak")
    monkeypatch.setenv("AUTHENTIK_TOKEN", "t")
    from cvc.onboard.authentik import client_from_env
    assert client_from_env() is not None
    monkeypatch.delenv("AUTHENTIK_TOKEN")
    assert client_from_env() is None


# ── step 6: owners ──────────────────────────────────────────────────────────

def test_owner_emergency_access_checklist(reg, tmp_path):
    s = seams()
    onboard_person(reg, person(tier="owner"), s, out_dir=tmp_path, dry_run=True)
    t = s.io.text
    for o in ("nathan", "kate"):
        for kind, days in (("View", 15), ("Takeover", 90), ("Takeover", 180)):
            assert f"alice -> {o}: Emergency Access {kind}, wait {days} days" in t
            assert f"{o} -> alice: Emergency Access {kind}, wait {days} days" in t
    assert "cvc takeover recovery-set alice" in t


def test_owner_step_skipped_for_non_owner(reg, tmp_path):
    s = seams()
    onboard_person(reg, person(), s, out_dir=tmp_path, dry_run=True)
    assert "skipped: not an owner" in s.io.text


# ── agent ───────────────────────────────────────────────────────────────────

def agent(**kw) -> AgentSpec:
    d = {"id": "bot", "tier": "low", "sponsor": "nathan", "granted_by": "nathan", "roles": ["readmq"]}
    d.update(kw)
    return AgentSpec(**d)


def test_agent_written(reg):
    s = seams(answers=["bot"])
    onboard_agent(reg, agent(token_sha256="a" * 64), s)
    a = load_registry(reg).agents["bot"]
    assert (a.tier, a.tailnet, a.sponsor, a.roles) == ("low", "agents", "nathan", ("readmq",))
    assert "readmq -> mq [internal/read]" in s.io.text


def test_agent_token_note(reg):
    s = seams()
    onboard_agent(reg, agent(), s, dry_run=True)
    assert "token_sha256 not set yet" in s.io.text


@pytest.mark.parametrize("kw,msg", [
    ({"roles": ["pay"]}, "exceeds tier ceiling"),                # low may not act on private
    ({"roles": ["ghost"]}, "unknown role"),
    ({"tier": "high", "granted_by": "sam", "sponsor": "sam"}, "only an owner may grant"),
    ({"tier": "owner"}, "not an agent tier"),
    ({"id": "sam_dev", "sponsor": "ghost"}, "unknown person"),
])
def test_agent_refusals(reg, kw, msg):
    before = reg.read_text()
    with pytest.raises(OnboardError, match=msg):
        onboard_agent(reg, agent(**kw), seams())
    assert reg.read_text() == before


# ── CLI ─────────────────────────────────────────────────────────────────────

def test_cli_prompts_for_missing_and_parses_devices(reg, tmp_path):
    io = IO(answers=["alice", "Alice A", "nathan", "alice"])
    rc = cli.main(["person", "--registry", str(reg), "--tier", "medium",
                   "--device", "pix:phone", "--device", "mbp:laptop:p12",
                   "--out-dir", str(tmp_path)], io=io, seams=Seams(io=io, today=TODAY))
    assert rc == 0
    assert set(load_registry(reg).devices) == {"pix", "mbp"}


def test_cli_refusal_returns_1(reg, tmp_path):
    io = IO(answers=[])
    rc = cli.main(["person", "--registry", str(reg), "--id", "x", "--name", "X", "--tier",
                   "high", "--granted-by", "sam", "--dry-run"], io=io,
                  seams=Seams(io=io, today=TODAY))
    assert rc == 1 and "only an owner" in io.text


def test_cli_bad_device_spec():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["person", "--device", "pix:toaster"])


def test_cvc_main_dispatch(monkeypatch):
    called = {}
    monkeypatch.setattr(cli, "main", lambda argv: called.setdefault("onboard", argv) and 0)
    cli.cvc_main(["onboard", "agent", "--dry-run"])
    assert called["onboard"] == ["agent", "--dry-run"]
    import cvc.takeover.__main__ as tk
    monkeypatch.setattr(tk, "main", lambda argv: called.setdefault("takeover", argv) and 0)
    cli.cvc_main(["takeover", "status"])
    assert called["takeover"] == ["takeover", "status"]
