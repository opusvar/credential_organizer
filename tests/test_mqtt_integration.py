"""Tests for mqtt_publish.publish() — the connect/publish/disconnect cycle.

Supplements test_mqtt_publish.py (payload helpers only). paho's Client class is
replaced with a recorder, so no socket is ever opened.
"""
import json
from typing import ClassVar
from unittest.mock import patch

import pytest

from cvc import config
from cvc.reminders import mqtt_publish
from cvc.reminders.mqtt_publish import _ATTRIBUTES_TOPIC, _STATE_TOPIC, publish
from cvc.reminders.policy import Finding


class FakeMqttClient:
    """Records every paho call publish() makes. One instance per test via the factory."""

    # Reset by the fake_mqtt fixture before every test, so cross-test leakage is impossible.
    instances: ClassVar[list["FakeMqttClient"]] = []

    def __init__(self, *args, **kwargs):
        self.init_args = args
        self.init_kwargs = kwargs
        self.credentials: tuple | None = None
        self.connected: tuple | None = None
        self.published: list[tuple] = []
        self.loops: list[float] = []
        self.disconnected = False
        self.order: list[str] = []
        FakeMqttClient.instances.append(self)

    def username_pw_set(self, username, password=None):
        self.credentials = (username, password)
        self.order.append("auth")

    def connect(self, host, port, keepalive=None):
        self.connected = (host, port, keepalive)
        self.order.append("connect")

    def publish(self, topic, payload, retain=False, qos=0):
        self.published.append((topic, payload, retain))
        self.order.append("publish")

    def loop(self, timeout=None):
        self.loops.append(timeout)
        self.order.append("loop")

    def disconnect(self):
        self.disconnected = True
        self.order.append("disconnect")


@pytest.fixture
def fake_mqtt(monkeypatch):
    """Patch paho's Client and return the list that collects constructed instances."""
    FakeMqttClient.instances = []
    monkeypatch.setattr(mqtt_publish.mqtt, "Client", FakeMqttClient)
    return FakeMqttClient.instances


@pytest.fixture
def cfg(monkeypatch):
    monkeypatch.setenv("MQTT_HOST", "mqtt.example.test")
    monkeypatch.setenv("MQTT_PORT", "1883")
    monkeypatch.setenv("MQTT_USERNAME", "cvc")
    monkeypatch.setenv("MQTT_PASSWORD", "not-a-real-mqtt-pw")
    monkeypatch.setenv("MQTT_DISCOVERY_PREFIX", "homeassistant")
    return config.load()


def _findings():
    return [
        Finding(item_id="1", name="Bank Login", reasons=["stale: 200d since rotation (> 180)"]),
        Finding(item_id="2", name="Email", reasons=["breached: found 7x in HIBP"]),
    ]


def _topics(client: FakeMqttClient) -> list[str]:
    return [t for t, _, _ in client.published]


# ── configuration guard ───────────────────────────────────────────────────────

def test_publish_raises_without_mqtt_host(monkeypatch, fake_mqtt):
    monkeypatch.delenv("MQTT_HOST", raising=False)
    with pytest.raises(RuntimeError, match="MQTT_HOST not configured"):
        publish(_findings(), config.load())
    assert fake_mqtt == [], "must not construct a client before validating config"


# ── connection ────────────────────────────────────────────────────────────────

def test_publish_connects_to_configured_host_and_port(cfg, fake_mqtt):
    publish(_findings(), cfg)
    client = fake_mqtt[0]
    assert client.connected == ("mqtt.example.test", 1883, 10)


def test_publish_honours_custom_port(monkeypatch, fake_mqtt):
    monkeypatch.setenv("MQTT_HOST", "mqtt.example.test")
    monkeypatch.setenv("MQTT_PORT", "8883")
    publish([], config.load())
    assert fake_mqtt[0].connected[1] == 8883


def test_publish_uses_stable_client_id(cfg, fake_mqtt):
    publish([], cfg)
    assert fake_mqtt[0].init_kwargs.get("client_id") == "cvc-remind"


def test_publish_sets_credentials_from_env(cfg, fake_mqtt):
    publish([], cfg)
    assert fake_mqtt[0].credentials == ("cvc", "not-a-real-mqtt-pw")


def test_publish_authenticates_before_connecting(cfg, fake_mqtt):
    """username_pw_set() after connect() would send an unauthenticated CONNECT packet."""
    publish([], cfg)
    order = fake_mqtt[0].order
    assert order.index("auth") < order.index("connect")


def test_publish_skips_auth_without_username(monkeypatch, fake_mqtt):
    """An anonymous broker: no credentials set, but the publish still happens."""
    monkeypatch.setenv("MQTT_HOST", "mqtt.example.test")
    monkeypatch.delenv("MQTT_USERNAME", raising=False)
    publish([], config.load())
    assert fake_mqtt[0].credentials is None
    assert fake_mqtt[0].connected is not None


def test_publish_tolerates_missing_mqtt_password(monkeypatch, cfg, fake_mqtt):
    """Username set but password absent — paho accepts None; must not KeyError."""
    monkeypatch.delenv("MQTT_PASSWORD", raising=False)
    publish([], cfg)
    assert fake_mqtt[0].credentials == ("cvc", None)


# ── topics + payloads ─────────────────────────────────────────────────────────

def test_publish_emits_all_three_topics(cfg, fake_mqtt):
    publish(_findings(), cfg)
    assert _topics(fake_mqtt[0]) == [
        "homeassistant/sensor/cvc_stale_credentials/config",
        _STATE_TOPIC,
        _ATTRIBUTES_TOPIC,
    ]


def test_publish_discovery_precedes_state(cfg, fake_mqtt):
    """HA must see the discovery config before the state it describes."""
    publish(_findings(), cfg)
    topics = _topics(fake_mqtt[0])
    assert topics.index("homeassistant/sensor/cvc_stale_credentials/config") < \
        topics.index(_STATE_TOPIC)


def test_publish_honours_discovery_prefix(monkeypatch, fake_mqtt):
    monkeypatch.setenv("MQTT_HOST", "mqtt.example.test")
    monkeypatch.setenv("MQTT_DISCOVERY_PREFIX", "ha-custom")
    publish([], config.load())
    assert _topics(fake_mqtt[0])[0] == "ha-custom/sensor/cvc_stale_credentials/config"


def test_publish_all_topics_retained(cfg, fake_mqtt):
    """Retained: HA restarts must re-read the sensor without waiting for the next CronJob."""
    publish(_findings(), cfg)
    assert all(retain for _, _, retain in fake_mqtt[0].published)


def test_publish_state_is_the_finding_count(cfg, fake_mqtt):
    publish(_findings(), cfg)
    state = {t: p for t, p, _ in fake_mqtt[0].published}[_STATE_TOPIC]
    assert state == "2"


def test_publish_zero_findings_still_publishes_state(cfg, fake_mqtt):
    """A clean vault must publish "0", not skip — otherwise HA shows a stale count forever."""
    publish([], cfg)
    payloads = {t: p for t, p, _ in fake_mqtt[0].published}
    assert payloads[_STATE_TOPIC] == "0"
    assert json.loads(payloads[_ATTRIBUTES_TOPIC])["items"] == []


def test_publish_attributes_are_valid_json(cfg, fake_mqtt):
    publish(_findings(), cfg)
    payloads = {t: p for t, p, _ in fake_mqtt[0].published}
    data = json.loads(payloads[_ATTRIBUTES_TOPIC])
    assert [i["name"] for i in data["items"]] == ["Bank Login", "Email"]
    json.loads(payloads["homeassistant/sensor/cvc_stale_credentials/config"])


def test_publish_never_sends_passwords_or_usernames(cfg, fake_mqtt):
    """Findings carry no secrets by construction — assert nothing leaks onto the wire."""
    findings = [Finding(item_id="1", name="Bank Login", reasons=["weak: short"])]
    publish(findings, cfg)
    wire = " ".join(f"{t} {p}" for t, p, _ in fake_mqtt[0].published)
    assert "not-a-real-pw" not in wire
    assert "not-a-real-mqtt-pw" not in wire
    assert "@example.test" not in wire


# ── flush + teardown ──────────────────────────────────────────────────────────

def test_publish_flushes_before_disconnect(cfg, fake_mqtt):
    """loop() must run after the publishes and before disconnect, or messages are dropped."""
    publish(_findings(), cfg)
    order = fake_mqtt[0].order
    assert order.index("loop") > max(i for i, s in enumerate(order) if s == "publish")
    assert order.index("loop") < order.index("disconnect")


def test_publish_disconnects(cfg, fake_mqtt):
    """A CronJob must not leave a half-open connection behind."""
    publish(_findings(), cfg)
    assert fake_mqtt[0].disconnected is True


def test_publish_propagates_connect_failure(cfg, fake_mqtt):
    """main() turns this into exit 1 — it must not be swallowed here."""
    with patch.object(FakeMqttClient, "connect",
                      side_effect=OSError("connection refused")), \
            pytest.raises(OSError, match="connection refused"):
        publish(_findings(), cfg)


def test_publish_propagates_publish_failure(cfg, fake_mqtt):
    with patch.object(FakeMqttClient, "publish", side_effect=OSError("broker gone")), \
            pytest.raises(OSError, match="broker gone"):
        publish(_findings(), cfg)
