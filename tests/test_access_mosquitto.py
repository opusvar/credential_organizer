import datetime as dt

import pytest

from cvc.access import parse_registry, RegistryError
from cvc.access.builders import BUILDERS
from cvc.access import mosquitto as mq

TODAY = dt.date(2026, 10, 31)


def reg(machines=None, extra_roles=None, agents=None, systems=None):
    roles = {
        "pub": {"grants": [{"system": "m1", "topics": ["sensors/{id}/#"], "access": "write"}]},
        "ha": {"grants": [{"system": "m1", "topics": ["#"], "access": "readwrite"}]},
    }
    roles.update(extra_roles or {})
    return parse_registry({
        "version": 1,
        "systems": systems or {"m1": {"kind": "mqtt"}},
        "roles": roles,
        "agents": agents or {},
        "machines": machines or {},
    })


def mach(roles, user, **kw):
    return {"roles": roles, "auth": {"type": "mqtt-user", "username": user}, **kw}


def test_registered():
    assert "mosquitto" in BUILDERS


def test_blocks_sorted_and_expanded():
    r = reg({"b": mach(["pub"], "b-user"), "a": mach(["pub"], "a-user"),
             "ha": mach(["ha"], "hass")})
    out = BUILDERS["mosquitto"](r, TODAY)
    assert out.index("user a-user") < out.index("user b-user") < out.index("user hass")
    assert "topic write sensors/a/#" in out
    assert "topic readwrite #" in out
    assert out == BUILDERS["mosquitto"](r, TODAY)


def test_expired_skipped():
    r = reg({"a": mach(["pub"], "a-user", expires="2020-01-01"), "ha": mach(["ha"], "hass")})
    assert "a-user" not in BUILDERS["mosquitto"](r, TODAY)


def test_missing_username_errors():
    r = reg({"a": {"roles": ["pub"]}})
    with pytest.raises(RegistryError) as e:
        BUILDERS["mosquitto"](r, TODAY)
    assert "machines.a" in str(e.value)


def test_agent_with_mqtt_grant_errors_without_username():
    r = reg(agents={"bot": {"roles": ["pub"]}})
    with pytest.raises(RegistryError):
        BUILDERS["mosquitto"](r, TODAY)


@pytest.mark.parametrize("t", ["a/b#", "a/#/b", "a+/b", "a/+b", "#a", "a/b+"])
def test_bad_wildcards(t):
    r = reg({"a": mach(["bad"], "u")},
            {"bad": {"grants": [{"system": "m1", "topics": [t], "access": "read"}]}})
    with pytest.raises(RegistryError):
        BUILDERS["mosquitto"](r, TODAY)


def test_good_wildcards():
    r = reg({"a": mach(["ok"], "u")},
            {"ok": {"grants": [{"system": "m1", "topics": ["a/+/b/#", "+/x"], "access": "read"}]}})
    out = BUILDERS["mosquitto"](r, TODAY)
    assert "topic read a/+/b/#" in out and "topic read +/x" in out


def test_warning_without_broad_read(capsys):
    r = reg({"a": mach(["pub"], "a-user")})
    out = BUILDERS["mosquitto"](r, TODAY)
    assert out.splitlines()[2].startswith("# WARNING")
    assert "applying this ACL may cut off Home Assistant" in capsys.readouterr().err


def test_no_warning_with_broad_read(capsys):
    r = reg({"ha": mach(["ha"], "hass")})
    out = BUILDERS["mosquitto"](r, TODAY)
    assert "WARNING" not in out
    assert capsys.readouterr().err == ""


def test_system_filter():
    r = reg({"a": mach(["pub", "o"], "a-user"), "ha": mach(["ha"], "hass")},
            {"o": {"grants": [{"system": "m2", "topics": ["other/#"], "access": "read"}]}},
            systems={"m1": {"kind": "mqtt"}, "m2": {"kind": "mqtt"}})
    out = mq.build_mosquitto(r, TODAY, system="m2")
    assert "other/#" in out and "sensors/" not in out
    assert "other/#" in BUILDERS["mosquitto"](r, TODAY)


def test_passwd_usernames():
    r = reg({"b": mach(["pub"], "b-user"), "a": mach(["pub"], "a-user"),
             "x": mach(["pub"], "a-user"), "old": mach(["pub"], "old", expires="2020-01-01")})
    assert mq.mqtt_usernames(r, TODAY) == ["a-user", "b-user"]
