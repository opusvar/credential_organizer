"""Environment-driven configuration. No secrets are hardcoded; everything comes from the
process environment (see .env.example). Env is read at load() time (not import time) so the
config is testable and reflects the current environment. Secret *values* are never logged.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _get(key: str, default: str | None = None) -> str | None:
    val = os.environ.get(key, default)
    return val if val not in ("", None) else default


@dataclass(frozen=True)
class Config:
    # Vault
    bw_server: str | None
    # NOTE: BW_SESSION is intentionally NOT on the config — read it only at the moment of use
    # via os.environ so an unlock session never lingers in a shared object.

    # Reminders / HA
    mqtt_host: str | None
    mqtt_port: int
    mqtt_username: str | None
    mqtt_discovery_prefix: str
    rotation_max_age_days: int
    hibp_enabled: bool

    # Backup
    backup_dir: str
    backup_retention_days: int

    # Broker
    broker_bind: str
    broker_port: int
    audit_log: str
    broker_acl: str


def load() -> Config:
    """Build a Config from the current environment."""
    return Config(
        bw_server=_get("BW_SERVER"),
        mqtt_host=_get("MQTT_HOST"),
        mqtt_port=int(_get("MQTT_PORT", "1883")),
        mqtt_username=_get("MQTT_USERNAME"),
        mqtt_discovery_prefix=_get("MQTT_DISCOVERY_PREFIX", "homeassistant"),
        rotation_max_age_days=int(_get("ROTATION_MAX_AGE_DAYS", "180")),
        hibp_enabled=_get("HIBP_ENABLED", "false").lower() == "true",
        backup_dir=_get("BACKUP_DIR", "./backups"),
        backup_retention_days=int(_get("BACKUP_RETENTION_DAYS", "30")),
        broker_bind=_get("BROKER_BIND", "127.0.0.1"),
        broker_port=int(_get("BROKER_PORT", "8710")),
        audit_log=_get("AUDIT_LOG", "./audit/access.jsonl"),
        broker_acl=_get("BROKER_ACL", "./deploy/broker-acl.yaml"),
    )
