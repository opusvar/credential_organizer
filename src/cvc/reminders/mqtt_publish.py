"""Publish reminder state to Home Assistant via MQTT discovery.

Emits a sensor (count of flagged credentials) and attributes listing item NAMES only —
never usernames or passwords. Uses paho-mqtt in a short-lived connect/publish/disconnect
cycle suitable for a CronJob; not a long-running daemon.
"""
from __future__ import annotations

import json

import paho.mqtt.client as mqtt

from ..config import Config
from .policy import Finding

_STATE_TOPIC = "cvc/reminders/state"
_ATTRIBUTES_TOPIC = "cvc/reminders/attributes"


def discovery_config(prefix: str = "homeassistant") -> tuple[str, str]:
    """Return (topic, payload) for HA MQTT discovery of the stale-credential sensor."""
    topic = f"{prefix}/sensor/cvc_stale_credentials/config"
    payload = json.dumps({
        "name": "Vault stale credentials",
        "state_topic": _STATE_TOPIC,
        "json_attributes_topic": _ATTRIBUTES_TOPIC,
        "unit_of_measurement": "creds",
        "unique_id": "cvc_stale_credentials",
        "icon": "mdi:key-alert",
    })
    return topic, payload


def state_payload(findings: list[Finding]) -> str:
    """Sensor state value — the flagged credential count."""
    return str(len(findings))


def attributes_payload(findings: list[Finding]) -> str:
    """Sensor attributes — names and reasons only, no secrets."""
    return json.dumps({
        "items": [{"name": f.name, "reasons": f.reasons} for f in findings]
    })


def publish(findings: list[Finding], cfg: Config) -> None:
    """Connect to HA MQTT broker, publish discovery + state, disconnect."""
    if not cfg.mqtt_host:
        raise RuntimeError("MQTT_HOST not configured")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="cvc-remind")
    if cfg.mqtt_username:
        passwd = __import__("os").environ.get("MQTT_PASSWORD")
        client.username_pw_set(cfg.mqtt_username, passwd)

    client.connect(cfg.mqtt_host, cfg.mqtt_port, keepalive=10)

    disc_topic, disc_payload = discovery_config(cfg.mqtt_discovery_prefix)
    client.publish(disc_topic, disc_payload, retain=True)
    client.publish(_STATE_TOPIC, state_payload(findings), retain=True)
    client.publish(_ATTRIBUTES_TOPIC, attributes_payload(findings), retain=True)

    client.loop(timeout=2.0)  # flush outbound queue
    client.disconnect()
