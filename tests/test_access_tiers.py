"""Tests for tier rules (people/agent tiers, tailnets, guest HA, grant rule)."""
from __future__ import annotations

import datetime as dt

import pytest

from cvc.access import RegistryError, parse_registry
from cvc.access.check import check_registry, check_tiers
from cvc.access.graph import build_graph

UUID1 = "11111111-2222-3333-4444-555555555555"


def base() -> dict:
    return {
        "version": 1,
        "systems": {
            "vw": {"kind": "credential-store"},
            "mq": {"kind": "mqtt"},
            "web": {"kind": "http"},
        },
        "roles": {
            "a": {"grants": [{"system": "vw", "credential": UUID1, "purposes": ["x"]}]},
            "b": {"grants": [{"system": "mq", "topics": ["t"], "access": "read"}]},
            "c": {"grants": [{"system": "web"}]},
        },
        "people": {
            "nathan": {"tier": "owner", "tailnet": "owner"},
            "admin1": {"tier": "admin", "tailnet": "family", "granted_by": "nathan"},
            "kid": {"tier": "low", "tailnet": "family", "granted_by": "admin1"},
        },
        "agents": {},
    }


def errors(data) -> list[str]:
    return [f"{f.path}: {f.message}" for f in check_tiers(parse_registry(data))]


def test_valid_baseline():
    assert errors(base()) == []


@pytest.mark.parametrize("field,val", [("tier", "superuser"), ("tailnet", "lan"),
                                       ("ha", "full")])
def test_enum_validation(field, val):
    d = base()
    d["people"]["kid"][field] = val
    with pytest.raises(RegistryError, match=f"people.kid.{field}"):
        parse_registry(d)


def test_agent_enum_validation():
    d = base()
    d["agents"]["x"] = {"tier": "god"}
    with pytest.raises(RegistryError, match="agents.x.tier"):
        parse_registry(d)


def test_unknown_granted_by_rejected():
    d = base()
    d["people"]["kid"]["granted_by"] = "ghost"
    with pytest.raises(RegistryError, match="unknown person 'ghost'"):
        parse_registry(d)


def test_guest_requires_expiry_and_ha():
    d = base()
    d["people"]["g"] = {"tier": "guest-short", "tailnet": "guests",
                        "granted_by": "admin1", "ha": "view"}
    assert any("requires an expires" in e for e in errors(d))
    d["people"]["g"]["expires"] = "2026-12-01"
    assert errors(d) == []
    reg = parse_registry(d)
    assert reg.people["g"].ha == "view" and reg.people["kid"].ha == "none"


def test_ha_only_for_guests():
    d = base()
    d["people"]["kid"]["ha"] = "limited-control"
    assert any("only valid for guest" in e for e in errors(d))


def test_guest_tailnet_mismatch():
    d = base()
    d["people"]["g"] = {"tier": "guest-long", "tailnet": "family", "expires": "2027-01-01"}
    assert any("belongs on tailnet guests" in e for e in errors(d))


@pytest.mark.parametrize("grantor,tier,ok", [
    ("admin1", "medium", True),
    ("admin1", "high", False),       # owner-only
    ("admin1", "admin", False),
    ("nathan", "high", True),
    ("nathan", "admin", True),
    ("nathan", "owner", True),
    ("kid", "guest-long", True),     # low(3) - guest-long(1) = 2
    ("kid", "media-only", False),    # only 1 above
])
def test_grant_rule_people(grantor, tier, ok):
    d = base()
    d["people"]["new"] = {"tier": tier, "granted_by": grantor, "expires": "2027-01-01"}
    errs = [e for e in errors(d) if e.startswith("people.new")]
    assert (errs == []) is ok, errs


def test_admin_grants_medium_agent_not_high():
    d = base()
    d["agents"]["m"] = {"tier": "medium", "tailnet": "agents", "granted_by": "admin1"}
    d["agents"]["h"] = {"tier": "high", "granted_by": "admin1"}
    errs = errors(d)
    assert not any(e.startswith("agents.m") for e in errs)
    assert any(e.startswith("agents.h") and "only an owner" in e for e in errs)


def test_assistant_binding_and_cap():
    d = base()
    d["agents"]["asst"] = {"tier": "assistant"}
    assert any("bind to one person" in e for e in errors(d))
    # bound to owner: capped at medium, so an admin may grant it
    d["agents"]["asst"] = {"tier": "assistant", "owner": "nathan", "granted_by": "admin1"}
    assert errors(d) == []
    # bound to a low person: effective low; a low person can't grant it
    d["agents"]["asst"] = {"tier": "assistant", "owner": "kid", "granted_by": "kid"}
    assert any("2 tiers above granted tier low" in e for e in errors(d))


def test_scoped_max_two_systems():
    d = base()
    d["agents"]["s"] = {"tier": "scoped", "roles": ["a", "b"]}
    assert errors(d) == []
    d["agents"]["s"]["roles"] = ["a", "b", "c"]
    assert any("at most 2 systems" in e for e in errors(d))


def test_agent_tailnet():
    d = base()
    d["agents"]["x"] = {"tier": "low", "tailnet": "family"}
    assert any("tailnet agents" in e for e in errors(d))


def test_check_registry_includes_tier_errors():
    d = base()
    d["people"]["kid"]["ha"] = "view"
    fs = check_registry(parse_registry(d), dt.date(2026, 11, 1))
    assert any(f.level == "error" and f.path == "people.kid" for f in fs)


def test_graph_tier_column():
    d = base()
    d["agents"]["s"] = {"tier": "scoped", "roles": ["a"]}
    out = build_graph(parse_registry(d), dt.date(2026, 11, 1))
    assert "| id | type | tier | sponsor | roles | expires | status |" in out
    assert "| s | agent | scoped | - |" in out
    assert "tier: scoped" in out and "tier: owner" in out
    assert "## People" in out
