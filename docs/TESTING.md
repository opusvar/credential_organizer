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
  (`bw` CLI, MQTT, HIBP, FastAPI I/O) are stubbed/`NotImplementedError` in the scaffold and will
  be covered with fakes/mocks as each phase is implemented.

## What is covered now (scaffold)
| Area | Test | Kind |
|---|---|---|
| Import normalize + dedup (Phase 1) | `test_normalize.py` | unit |
| Chrome CSV importer (Phase 1) | `test_chrome_importer.py` | fixture-based |
| Reminder policy: stale/reuse/weak (Phase 2) | `test_policy.py` | unit |
| Config (env → Config at load time) | `test_config.py` | unit |
| Broker ACL default-deny + audit integrity (Phase 4) | `test_broker.py` | unit / security |

## Coverage to add as phases land
- **Phase 1:** vault write path via a fake `bw` (subprocess boundary mocked); shred-after-import.
- **Phase 2:** HIBP k-anonymity (mock the range endpoint; assert only the 5-char prefix is sent);
  MQTT publish shape (fake client; assert no secret/username in payloads).
- **Phase 3:** encrypted-export invariant (never writes a plaintext export); retention pruning.
- **Phase 4:** FastAPI endpoint tests via `TestClient` (401/403/501 paths, audit-written-before-
  return); once retrieval exists, a "secret never appears in logs/audit" test. **Opus security
  review gates this phase.**

## Running
```bash
make setup      # pip install -e .[dev]
make test       # pytest -q
make cov        # pytest with coverage summary
```
`pyproject.toml` sets `pythonpath = ["src"]`, so tests import `cvc.*` without an install.
CI (`.github/workflows/ci.yml`) runs ruff + pytest on push/PR.
