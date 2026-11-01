# Testing strategy

Credential infrastructure — tests are part of the deliverable, not an afterthought. The import
pipeline (the migration) and the broker (agent access) are the two areas where a bug is
expensive, so they carry the most coverage.

## Hard rules
- **No real credentials in tests, ever.** Fixtures use obviously-fake values
  (`not-a-real-password`, `user@example.test`). CI would reject a real-looking secret; more
  importantly, test data lands in git and logs.
- **Security-critical code fails closed under test.** The broker ACL must deny unknown agents,
  unlisted credentials, wrong purposes, and empty allow-lists; the audit chain must detect
  tampering. These are asserted, not assumed (`tests/test_broker.py`).
- **Pure logic is unit-tested directly** (no network, no vault, no MQTT). External effects
  (`bw` CLI, MQTT, HIBP, FastAPI I/O) are covered with fakes/mocks.
- **Tests are order-independent** (PR #10): an autouse fixture in `tests/conftest.py` isolates
  `os.environ`/`HOME` per test, so CLI code that writes `os.environ` no longer leaks between tests.

## Current size
251 tests collected on origin/main at 2026-10-31
(`PYTHONPATH=src python -m pytest -q --co | tail -1`).

## Areas covered (non-exhaustive)
| Area | Test | Kind |
|---|---|---|
| Import normalize + dedup (Phase 1) | `test_normalize.py` | unit |
| Chrome CSV importer (Phase 1) | `test_chrome_importer.py` | fixture-based |
| Reminder policy: stale/reuse/weak (Phase 2) | `test_policy.py` | unit |
| Config (env → Config at load time) | `test_config.py` | unit |
| Broker ACL default-deny + audit integrity (Phase 4) | `test_broker.py` | unit / security |

Other suites present: `test_vault_client`, `test_keychain_importer`, `test_hibp`, `test_mqtt_publish`,
`test_mqtt_integration`, `test_remind_main`, `test_backup_*` (export, main, fixes), `test_tokens`,
`test_access_*` (registry, mosquitto, graph, cli), `test_step_ca_manifests`.

## Gaps still open
- Restore test of a password-protected export (manual, see RUNBOOK-recovery); not yet done.

## Running
```bash
make setup      # pip install -e .[dev]
make test       # pytest -q
make cov        # pytest with coverage summary
```
`pyproject.toml` sets `pythonpath = ["src"]`, so tests import `cvc.*` without an install.
CI (`.github/workflows/ci.yml`) runs ruff + pytest on push/PR.
