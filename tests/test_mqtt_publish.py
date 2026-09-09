"""Tests for mqtt_publish.py — payload shapes only. No real MQTT connection."""
import json

from cvc.reminders.mqtt_publish import attributes_payload, discovery_config, state_payload
from cvc.reminders.policy import Finding


def _findings():
    return [
        Finding(item_id="1", name="Bank Login", reasons=["stale: 200d since rotation (> 180)"]),
        Finding(item_id="2", name="Email", reasons=["weak: short or single character class"]),
    ]


def test_discovery_config_topic_shape():
    topic, _ = discovery_config("homeassistant")
    assert topic == "homeassistant/sensor/cvc_stale_credentials/config"


def test_discovery_config_payload_fields():
    _, payload = discovery_config()
    data = json.loads(payload)
    assert data["unique_id"] == "cvc_stale_credentials"
    assert "state_topic" in data
    assert "json_attributes_topic" in data


def test_state_payload_is_count_string():
    findings = _findings()
    assert state_payload(findings) == "2"
    assert state_payload([]) == "0"


def test_attributes_payload_contains_names_not_secrets():
    findings = _findings()
    data = json.loads(attributes_payload(findings))
    names = [it["name"] for it in data["items"]]
    assert "Bank Login" in names
    assert "Email" in names
    # Reasons are included; passwords must never appear
    for item in data["items"]:
        for reason in item["reasons"]:
            assert "not-a-real-pw" not in reason


def test_attributes_payload_empty():
    data = json.loads(attributes_payload([]))
    assert data["items"] == []
