"""MQTT publishing for approvals: retained per-request topics, a summary, and HA discovery.

Topics (all retained):
  cvc/approvals/<id>        full `cvc.approval.v1` JSON (updated on decide/expiry; cleared
                            with an empty retained payload 24h after resolution)
  cvc/approvals/summary     {"pending": n, "most_urgent_deadline": iso|null, ...}
  <prefix>/sensor/cvc_pending_approvals/config   HA MQTT discovery

Broker host/port come from env MQTT_HOST/MQTT_PORT, or (with CVC_APPROVALS_MQTT=1) the
site's services node (`cvc.site` node_ip) and 1883. Username from MQTT_USERNAME, password from MQTT_PASSWORD at the moment
of connect. Credentials are never logged or stored on the publisher object.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Protocol

TOPIC_PREFIX = "cvc/approvals"
SUMMARY_TOPIC = f"{TOPIC_PREFIX}/summary"
SENSOR_ID = "cvc_pending_approvals"

_log = logging.getLogger(__name__)


class Publisher(Protocol):
    def publish(self, topic: str, payload: str, retain: bool) -> None: ...


def request_topic(approval_id: str) -> str:
    return f"{TOPIC_PREFIX}/{approval_id}"


def discovery_config(prefix: str = "homeassistant") -> tuple[str, str]:
    topic = f"{prefix}/sensor/{SENSOR_ID}/config"
    payload = json.dumps({
        "name": "cvc pending approvals",
        "unique_id": SENSOR_ID,
        "state_topic": SUMMARY_TOPIC,
        "value_template": "{{ value_json.pending }}",
        "json_attributes_topic": SUMMARY_TOPIC,
        "unit_of_measurement": "requests",
        "icon": "mdi:account-check",
    })
    return topic, payload


class NullPublisher:
    """Used when MQTT is not configured: approvals still work, nothing is broadcast."""

    def publish(self, topic: str, payload: str, retain: bool) -> None:
        return None


class MqttPublisher:
    def __init__(self, host: str, port: int = 1883, username: str | None = None,
                 client_id: str = "cvc-approvals", timeout: float = 5.0):
        self.host, self.port, self.username = host, port, username
        self.client_id, self.timeout = client_id, timeout

    def publish(self, topic: str, payload: str, retain: bool) -> None:
        import paho.mqtt.client as mqtt

        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=self.client_id)
        if self.username:
            client.username_pw_set(self.username, os.environ.get("MQTT_PASSWORD"))
        try:
            client.connect(self.host, self.port, keepalive=10)
            client.loop_start()
            info = client.publish(topic, payload, qos=1, retain=retain)
            info.wait_for_publish(timeout=self.timeout)
        except Exception:  # noqa: BLE001 - publishing is best-effort; never log creds
            _log.warning("approval_publish_failed topic=%s host=%s", topic, self.host)
        finally:
            client.loop_stop()
            client.disconnect()


def from_env(site=None) -> Publisher:
    """MqttPublisher when opted in, else NullPublisher.

    Opt-in is explicit so that tests and dev runs never broadcast to a real broker:
    MQTT_HOST set, or site.yaml `mqtt_host` set, or CVC_APPROVALS_MQTT=1 (falls back to the
    site's node_ip). CVC_APPROVALS_MQTT=0 forces off. Env MQTT_HOST/MQTT_PORT/MQTT_USERNAME
    override the site's mqtt_host/mqtt_port/mqtt_username; MQTT_PASSWORD is env-only.
    """
    flag = os.environ.get("CVC_APPROVALS_MQTT", "").strip().lower()
    if flag in ("0", "false", "no"):
        return NullPublisher()
    if site is None:
        from cvc import site as site_mod
        try:
            site = site_mod.load()
        except Exception:  # noqa: BLE001 - unreadable site config -> env only
            site = None
    host = os.environ.get("MQTT_HOST") or getattr(site, "mqtt_host", "")
    if not host:
        if flag not in ("1", "true", "yes") or site is None:
            return NullPublisher()
        host = site.node_ip
    port = int(os.environ.get("MQTT_PORT") or getattr(site, "mqtt_port", 1883) or 1883)
    user = os.environ.get("MQTT_USERNAME") or getattr(site, "mqtt_username", "") or None
    return MqttPublisher(host, port, user)
