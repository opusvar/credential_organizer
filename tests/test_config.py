"""Config reads the environment at load() time (regression: it used to read at import)."""
from cvc import config


def test_defaults_when_unset(monkeypatch):
    for k in ("BROKER_PORT", "ROTATION_MAX_AGE_DAYS", "HIBP_ENABLED", "BROKER_BIND"):
        monkeypatch.delenv(k, raising=False)
    cfg = config.load()
    assert cfg.broker_port == 8710
    assert cfg.rotation_max_age_days == 180
    assert cfg.hibp_enabled is True
    assert cfg.broker_bind == "127.0.0.1"


def test_env_overrides_are_read_at_load_time(monkeypatch):
    monkeypatch.setenv("BROKER_PORT", "9999")
    monkeypatch.setenv("HIBP_ENABLED", "true")
    monkeypatch.setenv("ROTATION_MAX_AGE_DAYS", "30")
    cfg = config.load()
    assert cfg.broker_port == 9999
    assert cfg.hibp_enabled is True
    assert cfg.rotation_max_age_days == 30


def test_empty_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("BROKER_BIND", "")   # empty string treated as unset
    assert config.load().broker_bind == "127.0.0.1"
