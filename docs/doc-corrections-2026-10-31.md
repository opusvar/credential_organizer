# Documentation corrections, 2026-10-31

Every claim was checked against origin/main (02423f8) or live read-only state. Test count:
`PYTHONPATH=src python -m pytest -q --co | tail -1` gave 251 tests. `docs/DECISIONS.md` is not
edited here (open PR #13); the fixes it needs are listed at the end.

| file | what changed | why (evidence) | location |
|---|---|---|---|
| README.md | Status changed from "planning / scaffold, nothing implemented" to Phases 0-4 live; layout lists `access/` and password-protected backup; rebuild-after-merge note | All modules exist in `src/cvc`; broker/timers live; `cvc-access` in pyproject scripts | repo |
| docs/ARCHITECTURE.md | Backup wording, new `access/` module, broker 409/413/redacted stderr, deploy section rewritten (no `k8s/`/`systemd/` dirs) | `deploy/` has flat manifests, units, step-ca/, yubikey/; `broker/app.py` `_backup_lock`, `_MAX_BODY`, `_redacted_stderr_tail` | repo |
| docs/TESTING.md | Removed "stubbed/NotImplementedError" claims; added 251 count and order-independence | `pytest --co` = 251; PR #10 added autouse env isolation in `tests/conftest.py` | repo |
| docs/RUNBOOK-recovery.md | "encrypted export" became password-protected export with `BACKUP_EXPORT_PASSWORD`, per-scope files; restore not yet rehearsed | `backup/__main__.py` docstring, PR #3 (F9/F10); `/mnt/data/cvc-backups` does not exist yet | repo |
| docs/API.md | Trigger: added 409 and 413; OneDrive failure is now fatal (exit non-zero), not "non-fatal"; stderr redacted; rebuild required; port 8710 | `app.py` lines ~432 (409), body middleware (413), `backup/__main__.py` F8 comment; `broker-deployment.yaml` hostPort 8710 | repo |
| .env.example | Comment: `BACKUP_DIR` is the local copy and must differ from `ONEDRIVE_DEST_DIR` | PR #9, `deploy/backup.env.example` | repo |
| architecture.md | Module table: vault/client, keychain, hibp, mqtt_publish, exporter changed from "Stub (blocked Dn)" to Implemented; added access/, backup main, ops_log, tokens, new broker features; deployment says only the broker is in k3s | Files exist and are tested (`ls src/cvc`, tests/); D10 | projectTracking |
| checkpoint.md | status/updated refreshed; Remaining Steps rewritten (done items removed, 10 outstanding steps); 2026-10-31 change log for PRs #1-#12, open #13, opi_base_config#3; test count 168 to 251; backup wording | `gh pr list --state all` (#1-#12 MERGED, #13 OPEN); `systemctl --user list-timers` shows both timers; `/mnt/data/cvc-backups` absent; untracked deploy files in `git status` | projectTracking |
| checkpoint.md | Removed MQTT host/user/password detail (F4); pointer to vault kept; also in handoff.md the `mqtt_user` line | Credential in a tracking doc; rotation still advised | projectTracking |
| checkpoint.md, usage.md | Rotation-age caveat: imported items have no real password dates | `reminders/__main__.py` uses `passwordRevisionDate`, falling back to `creationDate` (PR #8) | projectTracking |
| usage.md | Removed "most commands stubbed"; added cvc-remind (counts only, `--verbose`), cvc-backup, cvc-access; test count | `reminders/__main__.py` `--verbose`; PR #1; pyproject scripts | projectTracking |
| README.md (tracking) | Phase table "Blocked on Dn" changed to done; "7 decisions open" removed; "encrypted backup" reworded | Phase 0 all decided (DECISIONS.md); code implemented | projectTracking |
| setup.md | `BACKUP_DIR` description fixed; added `BACKUP_EXPORT_PASSWORD`, `ONEDRIVE_DEST_DIR`; test count | `.env.example`, PR #3/#9 | projectTracking |
| reference.md | Broker base URL/port, endpoint list, 409/413, rebuild; HTTP 501 claim removed (fetch is implemented); cvc-backup/cvc-access commands; backup env vars | `app.py` routes; `fetch` returns the value; pyproject scripts | projectTracking |
| troubleshooting.md | "Scaffold stage, no issues" replaced; added stale-broker-image and backup-exit-nonzero entries | PR #2/#3, `rebuild.sh` header | projectTracking |
| handoff.md | Updated date; backup phase wording and caveats; local vs OneDrive dirs; MQTT user removed | PR #3/#9; `/mnt/data/cvc-backups` absent | projectTracking |
| backlog-logging.md | Added status note: LOG-1..6 appear implemented | `_request_log` middleware, `acl_load_failed`, `ops_log.py`, `elapsed_ms` in `vault/client.py` (spot-checked, not line-by-line) | projectTracking |

Snapshots of the original projectTracking files (not a git repo): `/home/admin/backups/doc-snapshots-2026-10-31/projectTracking/`.

## Not verified

- The "tier model" and "separate tailnets" are not in credential_organizer on origin/main; only noted as sourced from opi_base_config work.
- The stale k3s CronJobs: `kubectl` is not readable by this user, so deletion status was not re-checked (listed as outstanding).
- Restore syntax for a password-protected export was not tested.

## Needed fixes in docs/DECISIONS.md (not edited, PR #13 open)

1. D9 "Mechanism" still says export writes to the PVC `/backups/` and that copy/sync failures are non-fatal (exit 0); both contradict the F8 correction in the same section.
2. D9 "Constraint" and D10 still describe the CronJob bind-mounting the onedrive config; superseded by host timers.
3. D11 still says the export is "encrypted with the vault master password" and lists "does the export need a separate decryption step" as open; it uses `BACKUP_EXPORT_PASSWORD` (see the D4 correction).
4. D11 is headed DECIDED but still carries "Open questions"; PR #13 marks it resolved, so check that it removes this text.
5. Section order puts D11 and D8 after D10; D12 does not mention the tier model.
