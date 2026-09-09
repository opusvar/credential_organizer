"""Publish reminder state to Home Assistant via MQTT discovery.

Emits a sensor (count of flagged credentials) and can push notifications. Publishes only counts
and item *names* — never usernames or passwords.

SCAFFOLD: message shapes are defined; the paho-mqtt connection is stubbed until D6 (where the
service runs) and MQTT creds are provisioned.
"""
from __future__ import annotations

import json

from .policy import Finding


def discovery_config(prefix: str = "homeassistant") -> tuple[str, str]:
    """Return (topic, payload) for HA MQTT-discovery of the stale-credential sensor."""
    topic = f"{prefix}/sensor/cvc_stale_credentials/config"
    payload = json.dumps({
        "name": "Vault stale credentials",
        "state_topic": "cvc/reminders/state",
        "unit_of_measurement": "creds",
        "unique_id": "cvc_stale_credentials",
        "icon": "mdi:key-alert",
    })
    return topic, payload


def state_payload(findings: list[Finding]) -> str:
    """Sensor state = count; attributes list flagged item NAMES only (no secrets)."""
    return json.dumps({
        "count": len(findings),
        "items": [{"name": f.name, "reasons": f.reasons} for f in findings],
    })


def publish(findings: list[Finding]) -> None:
    raise NotImplementedError("TODO(D6/Phase 2): connect paho-mqtt and publish discovery+state")
