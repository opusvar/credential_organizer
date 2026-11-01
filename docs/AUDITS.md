# Audits (D24)

A read-only admin **system process** (not an LLM) runs scheduled checks. It reports findings; it does not fix anything. Fixes are owner actions.

## Checks

- Registry check errors
- Guests past expiry but still active
- Unrevoked certs (e.g. for lost or retired devices)
- Rotation overdue (D19)
- Denied-access patterns
- Takeovers (D15) and delegations (D17) in progress
- 7-day passwordless blocks (D23)
- Backup health

## Publishing

- Each finding: `cvc/audits/<id>` (schema `cvc.audit.v1`).
- Rollup: `cvc/audits/summary`.
- Shown to **owners only** on the dashboard.

## Schema `cvc.audit.v1`

```json
{
  "schema": "cvc.audit.v1",
  "id": "string",
  "check": "string",
  "severity": "info | warn | error",
  "title": "string",
  "detail": "string",
  "suggested_fix": "string",
  "first_seen": "RFC 3339",
  "last_seen": "RFC 3339",
  "status": "open | resolved"
}
```

No secrets in payloads.
