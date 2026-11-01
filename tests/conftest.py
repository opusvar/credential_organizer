"""Shared test fixtures. All data here is SYNTHETIC — no real credentials."""
import os

import pytest
import yaml

# Obviously-fake Chrome password export (columns: name,url,username,password,note).
# Includes a duplicate (same host+username via www/non-www) to exercise dedup.
_CHROME_CSV = """\
name,url,username,password,note
Example,https://example.test/login,user@example.test,not-a-real-pw-1,
Example WWW,https://www.example.test/,user@example.test,not-a-real-pw-1,dup of above
Other,https://other.test,someone@other.test,not-a-real-pw-2,
NoScheme,other.test,someone@other.test,not-a-real-pw-2,dup by host+user
"""


@pytest.fixture
def chrome_csv(tmp_path):
    """Write a synthetic Chrome export and return its path."""
    p = tmp_path / "chrome_passwords.csv"
    p.write_text(_CHROME_CSV, encoding="utf-8")
    return str(p)


# --- Test isolation -------------------------------------------------------------------
# Env vars cvc reads (config.load() and direct os.environ lookups). Production CLIs such as
# cvc.backup/remind/importers __main__ write os.environ["BW_SESSION"] directly, and the
# host shell/systemd may export real values; either leaks into later tests in a
# single-process run. Every test therefore starts from a clean cvc env and any direct
# os.environ mutation is rolled back afterwards.
_CVC_ENV_PREFIXES = (
    "BW_", "MQTT_", "BACKUP_", "BROKER_", "ONEDRIVE_", "ROTATION_", "HIBP_",
    "AUDIT_", "OPS_", "CVC_",
)


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    saved = dict(os.environ)
    for key in list(os.environ):
        if key.startswith(_CVC_ENV_PREFIXES):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "_home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    for var, sub in (("XDG_CONFIG_HOME", ".config"), ("XDG_DATA_HOME", ".local/share"),
                     ("XDG_CACHE_HOME", ".cache"), ("XDG_STATE_HOME", ".local/state")):
        monkeypatch.setenv(var, str(home / sub))
    # Generic test site: never the developer's ~/.config/cvc/site.yaml (HOME/XDG are
    # redirected above, and CVC_SITE points at this synthetic file).
    site = tmp_path / "_site.yaml"
    site.write_text(yaml.safe_dump(TEST_SITE), encoding="utf-8")
    monkeypatch.setenv("CVC_SITE", str(site))
    yield
    os.environ.clear()
    os.environ.update(saved)


TEST_SITE = {
    "node_ip": "100.64.0.10",
    "lan_ip": "10.0.0.10",
    "base_domain": "cvc.example.ts.net",
    "tailnet": "example",
    "default_owner_ids": ["alex"],
}
