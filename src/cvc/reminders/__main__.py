"""`cvc-remind` CLI — evaluate the vault against policy and publish to Home Assistant.

SCAFFOLD: wiring only. Pulls config, but the vault read + MQTT publish are stubbed pending
Phase 1/2 implementation.
"""
from __future__ import annotations

from .. import config


def main(argv: list[str] | None = None) -> int:
    cfg = config.load()
    print(f"cvc-remind: max_age={cfg.rotation_max_age_days}d hibp={cfg.hibp_enabled} "
          f"mqtt={cfg.mqtt_host}:{cfg.mqtt_port}")
    print("TODO(Phase 1/2): read vault -> policy.evaluate -> mqtt_publish.publish")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
