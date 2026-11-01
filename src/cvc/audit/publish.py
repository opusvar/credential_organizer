"""Publish audit findings over MQTT (retained) + HA discovery. Payloads carry no secrets."""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Protocol

from cvc.audit.findings import assert_no_secrets

SUMMARY_TOPIC = "cvc/audits/summary"
TOPIC_PREFIX = "cvc/audits/"


class Publisher(Protocol):
    def publish(self, messages: list[tuple[str, str]]) -> None: ...


def build_messages(findings: dict[str, dict], summary: dict,
                   discovery_prefix: str = "homeassistant") -> list[tuple[str, str]]:
    """(topic, payload) list. Resolved findings are published too (status resolved) so
    retained topics never show a stale open finding."""
    msgs: list[tuple[str, str]] = []
    disc = {"name": "cvc audit open findings", "unique_id": "cvc_audit_open",
            "object_id": "cvc_audit_open", "state_topic": SUMMARY_TOPIC,
            "value_template": "{{ value_json.open_total }}",
            "json_attributes_topic": SUMMARY_TOPIC, "unit_of_measurement": "findings",
            "icon": "mdi:shield-search"}
    msgs.append((f"{discovery_prefix}/sensor/cvc_audit_open/config", json.dumps(disc)))
    for fid, f in sorted(findings.items()):
        assert_no_secrets(f)
        msgs.append((TOPIC_PREFIX + fid, json.dumps(f, sort_keys=True)))
    assert_no_secrets(summary)
    msgs.append((SUMMARY_TOPIC, json.dumps(summary, sort_keys=True)))
    return msgs


class MqttPublisher:
    """Short connect/publish/disconnect. Host/port/user from env (MQTT_*), defaulting the
    host to the site's node_ip; MQTT_PASSWORD read at the moment of use."""

    def __init__(self, host: str, port: int = 1883, username: str | None = None,
                 client_factory: Callable | None = None):
        self.host, self.port, self.username = host, port, username
        self.client_factory = client_factory

    @classmethod
    def from_env(cls, site) -> MqttPublisher:
        return cls(os.environ.get("MQTT_HOST") or site.node_ip,
                   int(os.environ.get("MQTT_PORT") or 1883),
                   os.environ.get("MQTT_USERNAME") or None)

    def publish(self, messages: list[tuple[str, str]]) -> None:
        if self.client_factory is None:
            import paho.mqtt.client as mqtt
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="cvc-audit")
        else:
            client = self.client_factory()
        if self.username:
            client.username_pw_set(self.username, os.environ.get("MQTT_PASSWORD"))
        client.connect(self.host, self.port, keepalive=10)
        client.loop_start()
        try:
            for topic, payload in messages:
                client.publish(topic, payload, qos=1, retain=True).wait_for_publish(5)
        finally:
            client.loop_stop()
            client.disconnect()
