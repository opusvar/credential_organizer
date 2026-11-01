"""D16: data/action labels, tier ceilings, sponsors, guests, primary owner keys."""
from __future__ import annotations

import copy
import datetime as dt
from pathlib import Path

import pytest
import yaml

from cvc.access import RegistryError, parse_registry
from cvc.access.check import check_classification, check_registry
from cvc.access.classify import MATRIX, ceiling, effective
from cvc.access.cli import main
from cvc.access.edit import active_owner_keys, owner_primary_keys
from cvc.access.graph import build_graph

ROOT = Path(__file__).resolve().parent.parent
TODAY = dt.date(2026, 11, 1)
UUID1 = "11111111-2222-3333-4444-555555555555"


def base() -> dict:
    return {
        "version": 1,
        "systems": {
            "vw": {"kind": "credential-store", "data": "private", "action": "act"},
            "mq": {"kind": "mqtt", "data": "internal", "action": "act"},
            "web": {"kind": "http", "data": "public", "action": "read"},
        },
        "roles": {
            "pub-read": {"grants": [{"system": "web"}]},
            "int-write": {"grants": [{"system": "mq", "topics": ["t"], "access": "write",
                                      "action": "write"}]},
            "int-act": {"grants": [{"system": "mq", "topics": ["c"], "access": "write"}]},
            "priv-read": {"grants": [{"system": "vw", "credential": UUID1, "purposes": ["x"],
                                      "action": "read"}]},
            "priv-write": {"grants": [{"system": "vw", "credential": UUID1, "purposes": ["x"],
                                       "action": "write"}]},
            "vault-root": {"grants": [{"system": "vw", "credential": "backup", "purposes": ["*"],
                                   "data": "secret", "action": "read"}]},
            "secret-broker": {"grants": [{"system": "vw", "credential": "backup",
                                          "purposes": ["*"], "data": "secret",
                                          "action": "read", "via": "broker-approved"}]},
        },
        "people": {
            "alex": {"tier": "owner", "tailnet": "owner"},
            "sam": {"tier": "medium", "tailnet": "family", "granted_by": "alex"},
            "ada": {"tier": "admin", "tailnet": "family", "granted_by": "alex"},
            "g": {"tier": "guest-long", "tailnet": "guests", "expires": "2026-11-20",
                  "granted_by": "alex"},
        },
        "agents": {},
    }


def agent(d, roles, tier, sponsor="alex", **kw):
    d["agents"]["a"] = {"tier": tier, "roles": roles, "sponsor": sponsor, **kw}
    return d


def find(d, level=None):
    return [f"{f.level}: {f.message}" for f in check_classification(parse_registry(d), TODAY)
            if level is None or f.level == level]


# ── matrix ──────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("row,data,action,want", [
    ("scoped", "internal", "read", "A"), ("low", "public", "write", "D"),
    ("low", "private", "read", "D"), ("medium", "internal", "write", "A"),
    ("medium", "private", "write", "P"), ("medium", "public", "act", "P"),
    ("high", "private", "write", "A"), ("high", "private", "act", "P"),
    ("assistant", "private", "write", "P"), ("high", "internal", "delegate", "A"),
    ("medium", "internal", "delegate", "D"), ("assistant", "public", "delegate", "D"),
])
def test_matrix_cells(row, data, action, want):
    assert ceiling(row, data, action) == want


def test_secret_always_denied_in_matrix():
    assert all(MATRIX[r][("secret", a)] == "D" for r in MATRIX
               for a in ("read", "relay", "write", "act", "delegate"))


# ── labels ──────────────────────────────────────────────────────────────────
def test_labels_parsed_and_validated():
    reg = parse_registry(base())
    assert (reg.systems["vw"].data, reg.systems["vw"].action) == ("private", "act")
    assert "data" not in reg.systems["vw"].attrs
    g = reg.roles["secret-broker"].grants[0]
    assert (g.data, g.action, g.via) == ("secret", "read", "broker-approved")
    d = base()
    d["systems"]["vw"]["data"] = "confidential"
    d["roles"]["pub-read"]["grants"][0]["action"] = "destroy"
    d["roles"]["vault-root"]["grants"][0]["via"] = "standing"
    with pytest.raises(RegistryError) as e:
        parse_registry(d)
    msg = str(e.value)
    assert "systems.vw.data" in msg and "action" in msg and ".via" in msg


def test_documented_kind_labels_not_in_extra():
    reg = parse_registry(base())
    assert reg.systems["web"].data == "public" and "data" not in reg.systems["web"].attrs
    d = base()
    d["roles"]["pub-read"]["grants"][0].update(action="read", paths=["/x"])
    g = parse_registry(d).roles["pub-read"].grants[0]
    assert g.action == "read" and g.extra == {"paths": ["/x"]}


def test_grant_action_above_system_errors():
    d = base()
    d["roles"]["pub-read"]["grants"][0]["action"] = "write"
    assert any("exceeds what system web exposes" in m for m in find(d, "error"))


# ── tier ceilings ───────────────────────────────────────────────────────────
def test_low_agent_reading_internal_ok():
    assert find(agent(base(), ["pub-read", "int-write"][:1], "low")) == []


def test_low_agent_write_is_error():
    errs = find(agent(base(), ["int-write"], "low"), "error")
    assert errs and "exceeds tier ceiling" in errs[0] and "internal/write" in errs[0]


def test_medium_private_write_warns_approval():
    out = find(agent(base(), ["priv-read", "priv-write"], "medium"))
    assert out == [next(m for m in out if "needs per-action approval" in m)]
    assert "private/write" in out[0]


def test_act_needs_approval_for_high():
    out = find(agent(base(), ["int-act"], "high"))
    assert len(out) == 1 and out[0].startswith("warning") and "internal/act" in out[0]


def test_unlabeled_grants_are_skipped():
    d = agent(base(), ["int-write"], "low")
    d["systems"]["mq"].pop("action")
    d["roles"]["int-write"]["grants"][0].pop("action")
    assert find(d, "error") == []


def test_secret_standing_grant_always_error():
    for tier in ("low", "medium", "high", "assistant"):
        errs = find(agent(base(), ["vault-root"], tier), "error")
        assert errs and "never a standing grant" in errs[0], tier


def test_secret_via_broker_only_for_high():
    out = find(agent(base(), ["secret-broker"], "high"))
    assert len(out) == 1 and out[0].startswith("warning") and "broker-approved" in out[0]
    assert find(agent(base(), ["secret-broker"], "medium"), "error")


def test_via_on_non_secret_warns():
    d = base()
    d["roles"]["priv-read"]["grants"][0]["via"] = "broker-approved"
    assert any("only meaningful for secret" in m for m in find(d, "warning"))


def test_check_registry_includes_classification():
    d = agent(base(), ["int-write"], "low")
    assert any(f.level == "error" and "exceeds tier ceiling" in f.message
               for f in check_registry(parse_registry(d), TODAY))


# ── sponsors ────────────────────────────────────────────────────────────────
def eff(d):
    reg = parse_registry(d)
    return effective(reg, reg.agents["a"]).row


def test_guest_sponsored_capped_low():
    d = agent(base(), ["int-write"], "medium", sponsor="g")
    assert eff(d) == "low"
    assert find(d, "error")      # write denied at low


def test_family_sponsor_caps_at_medium():
    assert eff(agent(base(), [], "high", sponsor="ada")) == "medium"
    assert eff(agent(base(), [], "high", sponsor="sam")) == "medium"
    assert eff(agent(base(), [], "high", sponsor="alex")) == "high"


def test_low_sponsor_caps_assistant():
    d = agent(base(), [], "assistant", sponsor="sam")
    d["people"]["sam"]["tier"] = "low"
    assert eff(d) == "low"
    d["people"]["sam"]["tier"] = "medium"
    assert eff(d) == "assistant"


def test_owner_fallback_when_no_sponsor():
    d = agent(base(), [], "high", sponsor=None, owner="sam")
    del d["agents"]["a"]["sponsor"]
    assert eff(d) == "medium"


def test_unknown_sponsor_rejected():
    with pytest.raises(RegistryError, match="agents.a.sponsor: unknown person 'ghost'"):
        parse_registry(agent(base(), [], "low", sponsor="ghost"))


def test_guest_sponsored_agent_expires_with_guest():
    d = agent(base(), ["pub-read"], "low", sponsor="g", expires="2027-06-01")
    a = parse_registry(d).agents["a"]
    assert a.expires == dt.date(2026, 11, 20)
    d["people"]["g"].update(status="checked-out", expires="2026-11-01")
    a = parse_registry(d).agents["a"]
    assert not a.active(TODAY) and a.active(dt.date(2026, 10, 31))


# ── tailnets ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("old", ["long-guests", "short-guests"])
def test_legacy_guest_tailnets_rejected(old):
    d = base()
    d["people"]["g"]["tailnet"] = old
    with pytest.raises(RegistryError, match="merged into 'guests'"):
        parse_registry(d)


# ── guests: add / checkout ──────────────────────────────────────────────────
@pytest.fixture
def regfile(tmp_path):
    d = base()
    d["agents"] = {"helper": {"tier": "low", "sponsor": "g", "roles": ["pub-read"]},
                   "other": {"tier": "low", "sponsor": "sam", "roles": ["pub-read"]}}
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(d, sort_keys=False))
    return p


def load(p):
    return yaml.safe_load(p.read_text())


def test_guest_add_default_expiry(regfile):
    assert main(["guest", "add", "bob", "--registry", str(regfile)]) == 0
    bob = load(regfile)["people"]["bob"]
    today = dt.datetime.now().astimezone().date()
    assert bob["expires"] == today + dt.timedelta(days=5)
    assert bob["tailnet"] == "guests" and bob["tier"] == "guest-short"
    assert main(["guest", "add", "eve", "--expires", "2026-12-24", "--tier", "guest-long",
                 "--registry", str(regfile)]) == 0
    assert load(regfile)["people"]["eve"]["expires"] == dt.date(2026, 12, 24)
    assert main(["guest", "add", "eve", "--registry", str(regfile)]) == 1


def test_guest_checkout_cascades(regfile, capsys):
    assert main(["guest", "checkout", "g", "--registry", str(regfile)]) == 0
    d = load(regfile)
    today = dt.datetime.now().astimezone().date()
    g = d["people"]["g"]
    assert g["status"] == "checked-out" and g["expires"] == today
    assert g["history"][-1]["event"] == "checked-out"
    assert d["agents"]["helper"]["expires"] == today - dt.timedelta(days=1)
    assert d["agents"]["helper"]["history"][-1]["event"] == "revoked"
    assert "expires" not in d["agents"]["other"]
    reg = parse_registry(d)
    assert not reg.people["g"].active(today) and not reg.agents["helper"].active(today)
    assert "revoked 1 sponsored agent" in capsys.readouterr().out
    assert main(["guest", "checkout", "g", "--registry", str(regfile)]) == 1
    assert main(["guest", "checkout", "sam", "--registry", str(regfile)]) == 1


def test_checked_out_guest_cannot_reach_resources():
    from cvc.access.catalog import can_reach
    d = base()
    d["people"]["g"].update(status="checked-out", expires=TODAY.isoformat())
    d["resources"] = {"books": {"host": "b.home", "kind": "library", "min_tier": "guest-long"}}
    reg = parse_registry(d)
    assert not can_reach(reg.people["g"], reg.resources["books"], TODAY)


# ── owner primary/backup keys ───────────────────────────────────────────────
def keys_data(*roles):
    d = base()
    d["hardware_keys"] = {
        f"k{i}": {"owner": "alex", "model": "YK", "serial": 100 + i, "uses": ["recovery"],
                  "location": loc, "status": "active", **({"role": r} if r else {})}
        for i, (r, loc) in enumerate(zip(roles, ("on-person", "home-safe", "offsite"),
                                         strict=False))}
    return d


def primary_errs(d):
    return [f.message for f in check_registry(parse_registry(d), TODAY)
            if f.path == "people.alex" and "primary" in f.message]


def test_exactly_one_primary_required():
    assert primary_errs(keys_data("primary", "backup")) == []
    assert "has 0" in primary_errs(keys_data("backup", "backup"))[0]
    assert "has 0" in primary_errs(keys_data(None, None))[0]
    assert "has 2" in primary_errs(keys_data("primary", "primary"))[0]


def test_bad_role_rejected():
    with pytest.raises(RegistryError, match="role"):
        parse_registry(keys_data("main"))


def test_helpers_expose_role():
    d = keys_data("primary", "backup")
    assert active_owner_keys(d) == ["k0", "k1"]
    assert active_owner_keys(d, role="primary") == ["k0"]
    assert active_owner_keys(d, role="backup") == ["k1"]
    assert owner_primary_keys(d) == {"alex": ["k0"]}


def test_enroll_assigns_role(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(base(), sort_keys=False))
    common = ["--uses", "recovery", "--model", "YK", "--registry", str(p)]
    assert main(["hwkey", "enroll", "--id", "a", "--serial", "1", "--location", "on-person",
                 *common]) == 0
    assert main(["hwkey", "enroll", "--id", "b", "--serial", "2", "--location", "home-safe",
                 *common]) == 0
    assert main(["hwkey", "enroll", "--id", "c", "--serial", "3", "--location", "offsite",
                 "--role", "primary", *common]) == 1
    hk = load(p)["hardware_keys"]
    assert hk["a"]["role"] == "primary" and hk["b"]["role"] == "backup"


def test_replace_moves_primary(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(keys_data("primary", "backup"), sort_keys=False))
    assert main(["hwkey", "replace", "k0", "--new", "k9", "--serial", "999", "--model", "YK",
                 "--registry", str(p)]) == 0
    hk = load(p)["hardware_keys"]
    assert hk["k9"]["role"] == "primary" and hk["k0"]["status"] == "retired"
    assert primary_errs(load(p)) == []


def test_guard_still_refuses_last_owner_key(tmp_path, capsys):
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(keys_data("primary"), sort_keys=False))
    assert main(["hwkey", "revoke", "k0", "--reason", "lost", "--registry", str(p)]) == 1
    assert "zero active owner hardware keys" in capsys.readouterr().err


# ── example, template, graph ────────────────────────────────────────────────
def test_example_has_no_errors():
    from cvc.access import load_registry
    reg = load_registry(ROOT / "access" / "registry.example.yaml")
    errs = [f for f in check_registry(reg, TODAY) if f.level == "error"]
    assert errs == []
    assert effective(reg, reg.agents["visitor-helper"]).row == "low"


def test_roster_template_is_yaml_and_mentions_tiers():
    text = (ROOT / "access" / "roster.template.yaml").read_text()
    data = yaml.safe_load(text)
    assert data["people"]["alex"]["tier"] == "owner"
    for t in ("guest-short", "media-only", "medium", "admin", "assistant", "scoped"):
        assert t in text


def test_graph_shows_labels_and_sponsors():
    d = agent(base(), ["priv-read"], "high", sponsor="ada")
    out = build_graph(parse_registry(copy.deepcopy(d)), TODAY)
    assert "private/act" in out                         # system label
    assert "#91;private/read#93;" in out                 # grant edge label
    assert 'u_ada -.->|"sponsors"| p_a' in out
    assert "tier: high (effective medium)" in out
    assert "| a | agent | high (effective medium) | ada |" in out
    assert "| vw | credential-store | private | act | yes |" in out
