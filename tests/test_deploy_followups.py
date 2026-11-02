"""Site MQTT/ntfy fields (env overrides site.yaml), cvc/# ACL guard, notify timer units."""
import datetime as dt
from pathlib import Path

import pytest
import yaml

from cvc import site as site_mod
from cvc.access import RegistryError, parse_registry
from cvc.access.mosquitto import build_mosquitto
from cvc.approvals import publisher
from cvc.notify.config import NotifyConfig

ROOT = Path(__file__).resolve().parents[1]
TODAY = dt.date(2026, 11, 1)


def _site(**kw):
    return site_mod.from_mapping({"base_domain": "cvc.example.com", **kw})


# --- site fields ---------------------------------------------------------------------------

def test_site_defaults_empty():
    s = site_mod.GENERIC
    assert s.mqtt_host == "" and s.mqtt_port == 1883 and s.mqtt_username == ""
    assert s.ntfy_servers == () and s.ntfy_topics == {} and s.approval_card_url == ""


def test_site_parses_fields():
    s = _site(mqtt_host="10.0.0.5", mqtt_port="1884", mqtt_username="cvc-broker",
              ntfy_servers="https://ntfy.cvc.example.com, https://ntfy.sh",
              ntfy_topics={"alex": "cvc-alex-x"}, approval_card_url="{dashboard}/a/{id}")
    assert s.mqtt_port == 1884
    assert s.ntfy_servers == ("https://ntfy.cvc.example.com", "https://ntfy.sh")
    assert s.ntfy_topics == {"alex": "cvc-alex-x"}
    assert s.template_vars()["SITE_NTFY_HOST"] == "ntfy.cvc.example.com"
    assert s.template_vars()["SITE_MQTT_USER"] == "cvc-broker"


def test_site_rejects_bad_topics():
    with pytest.raises(site_mod.SiteError):
        _site(ntfy_topics=["x"])


def test_example_site_yaml_still_loads_with_commented_keys_uncommented():
    text = (ROOT / "site.example.yaml").read_text()
    keys = ("# mqtt_", "# ntfy_", "#   - ", "# approval_card_url")
    lines = [ln[2:] if ln.startswith(keys) else ln for ln in text.splitlines()]
    s = site_mod.from_mapping(yaml.safe_load("\n".join(lines)))
    assert s.mqtt_username and len(s.ntfy_servers) == 2 and s.approval_card_url


# --- ntfy config ---------------------------------------------------------------------------

def test_notify_from_site_only():
    s = _site(ntfy_servers=["https://a.example.com", "https://ntfy.sh"],
              ntfy_topics={"alex": "t-site"}, approval_card_url="{dashboard}/c/{id}")
    cfg = NotifyConfig.from_env(s, env={})
    assert [b.url for b in cfg.backends] == ["https://a.example.com", "https://ntfy.sh"]
    assert [b.token_env for b in cfg.backends] == ["CVC_NTFY_TOKEN_1", "CVC_NTFY_TOKEN_2"]
    assert cfg.topics == {"alex": "t-site"}
    assert cfg.card_url("r1") == "https://dashboard.cvc.example.com/c/r1"


def test_notify_env_overrides_site():
    s = _site(ntfy_servers=["https://a.example.com"], ntfy_topics={"alex": "t-site"},
              approval_card_url="{dashboard}/c/{id}")
    cfg = NotifyConfig.from_env(s, env={"CVC_NTFY_SERVERS": "https://b.example.com",
                                        "CVC_NTFY_TOPICS": "alex=t-env",
                                        "CVC_APPROVAL_CARD_URL": "{dashboard}/e/{id}"})
    assert [b.url for b in cfg.backends] == ["https://b.example.com"]
    assert cfg.topics == {"alex": "t-env"}
    assert cfg.card_url("r1").endswith("/e/r1")


def test_notify_disabled_without_servers():
    assert NotifyConfig.from_env(_site(), env={}) is None


# --- MQTT publisher ------------------------------------------------------------------------

def test_publisher_null_without_host():
    assert isinstance(publisher.from_env(_site()), publisher.NullPublisher)


def test_publisher_uses_site(monkeypatch):
    p = publisher.from_env(_site(mqtt_host="10.0.0.5", mqtt_port=1884,
                                 mqtt_username="cvc-broker"))
    assert isinstance(p, publisher.MqttPublisher)
    assert (p.host, p.port, p.username) == ("10.0.0.5", 1884, "cvc-broker")


def test_publisher_env_overrides_site(monkeypatch):
    monkeypatch.setenv("MQTT_HOST", "10.0.0.6")
    monkeypatch.setenv("MQTT_PORT", "1885")
    monkeypatch.setenv("MQTT_USERNAME", "other")
    p = publisher.from_env(_site(mqtt_host="10.0.0.5", mqtt_username="cvc-broker"))
    assert (p.host, p.port, p.username) == ("10.0.0.6", 1885, "other")


def test_publisher_flag_off_wins(monkeypatch):
    monkeypatch.setenv("CVC_APPROVALS_MQTT", "0")
    assert isinstance(publisher.from_env(_site(mqtt_host="10.0.0.5")), publisher.NullPublisher)


# --- Mosquitto cvc/# guard -----------------------------------------------------------------

def _snippet():
    return parse_registry(yaml.safe_load(
        (ROOT / "deploy/mosquitto/cvc-acl.registry-snippet.yaml").read_text()))


def test_snippet_builds_with_guard():
    out = build_mosquitto(_snippet(), TODAY, cvc_writer="cvc-broker")
    assert "user cvc-broker\ntopic readwrite cvc/#" in out
    dash = out.split("user cvc-dashboard\n", 1)[1].split("\n\n", 1)[0]
    assert dash.splitlines() == ["topic read cvc/approvals/#", "topic read cvc/audits/#"]
    hass = out.split("user hass\n", 1)[1]
    assert "topic read cvc/approvals/#" in hass and "write cvc" not in hass


@pytest.mark.parametrize("topic", ["#", "cvc/approvals/#", "+/approvals/x"])
def test_guard_rejects_other_writers(topic):
    data = yaml.safe_load((ROOT / "deploy/mosquitto/cvc-acl.registry-snippet.yaml").read_text())
    data["roles"]["ha-core"]["grants"].append(
        {"system": "ha-mqtt", "topics": [topic], "access": "readwrite"})
    with pytest.raises(RegistryError) as e:
        build_mosquitto(parse_registry(data), TODAY, cvc_writer="cvc-broker")
    assert "'hass'" in str(e.value)
    build_mosquitto(parse_registry(data), TODAY)          # guard off -> builds


def test_guard_ignores_unrelated_write():
    data = yaml.safe_load((ROOT / "deploy/mosquitto/cvc-acl.registry-snippet.yaml").read_text())
    data["roles"]["ha-core"]["grants"].append(
        {"system": "ha-mqtt", "topics": ["cvcx/#"], "access": "write"})
    build_mosquitto(parse_registry(data), TODAY, cvc_writer="cvc-broker")


# --- deploy units --------------------------------------------------------------------------

def test_notify_timer_units():
    svc = (ROOT / "deploy/cvc-notify.service").read_text()
    tmr = (ROOT / "deploy/cvc-notify.timer").read_text()
    assert "ExecStart=%h/.local/bin/cvc-notify tick" in svc
    assert "EnvironmentFile=%h/.config/cvc/notify.env" in svc
    assert "OnCalendar=*:*:00" in tmr and "Unit=cvc-notify.service" in tmr
    setup = (ROOT / "deploy/setup-timers.sh").read_text()
    assert "cvc-notify.service cvc-notify.timer" in setup
    assert "notify.env.example" in setup
    assert (ROOT / "deploy/notify.env.example").is_file()


def test_ntfy_templates_render(tmp_path):
    s = _site()
    site_mod.render_tree(ROOT / "deploy/ntfy", tmp_path, s)
    cf = (tmp_path / "cloudflared/config.yml").read_text()
    assert "hostname: ntfy.cvc.example.com" in cf and "http_status:404" in cf
    assert 'base-url: "https://ntfy.cvc.example.com"' in (tmp_path / "server.yml").read_text()
    compose = (tmp_path / "compose.yaml").read_text()
    assert "127.0.0.1:2586:2586" in compose and "docker compose" not in compose


def test_ntfy_host_override_and_default():
    from cvc.site import Site
    assert Site(base_domain="x.example.com").template_vars()["SITE_NTFY_HOST"] == "ntfy.x.example.com"
    assert Site(ntfy_host="push.example.org").template_vars()["SITE_NTFY_HOST"] == "push.example.org"
