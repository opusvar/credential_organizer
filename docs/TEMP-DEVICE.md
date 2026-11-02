# Temporary (bridge) devices (D27)

A **bridge** gives a person cert-based access from a temporary device while their permanent
device is sorted out. It is a short-lived step-ca cert, capped at tier **medium**, that ends on
its own.

## When to use it

- A new phone that is not enrolled yet, or a borrowed phone.
- A loaner laptop from work or a repair shop.
- A lost or broken device that is being replaced (also during the D23 7-day passwordless block).
- Travel with a device you do not want to enroll permanently.

## Cert format

```
urn:cvc:person:kim
urn:cvc:device:kim-temp-1
urn:cvc:tier:medium                       # min(person tier, medium)
urn:cvc:temp:2026-11-04T12:00:00Z         # temp flag = expiry
```

## Rules

| Rule | Value |
|------|-------|
| Default lifetime | 72 h |
| Maximum total (with extensions) | 14 days; each extension needs approval again |
| Effective tier | min(person tier, medium) |
| Who requests | the person, with password + passkey, or a YubiKey |
| Who approves | someone ≥ 2 tiers above the capped tier, or an owner, with a passkey; never the person |
| Self-issue | owners and admins, with a physical YubiKey, when no lost-device report is active |
| Limit | one open bridge per person |
| Never | guests, agents, machines |
| Ends | promote, auto-expiry, revoke (person, admin or owner), offboarding |

## Flow

```
cvc-tempdevice request kim --reason "borrowed phone" --password --passkey
cvc-tempdevice approve kim-temp-1 --by sam --passkey      # prints the step commands
cvc-tempdevice extend kim-temp-1 --by kim --hours 48 --password --passkey
cvc-tempdevice approve kim-temp-1 --by sam --passkey      # approves the extension
cvc-access device add kim-phone2 --owner kim --kind phone --storage p12 ...
cvc-access device set-cert kim-phone2 ...                 # promotes, revokes kim-temp-1
cvc-tempdevice list [--all] [--person kim]
cvc-tempdevice sweep                                      # run on a timer: expiry + timeouts
```

Set `CVC_TEMPDEVICE_STATE` (default `~/.local/state/cvc/tempdevice`) so `cvc-access`, the
audit and the CLI share one store. `--approvals-state` mirrors requests into the approvals
pipeline (dashboard card + ntfy). cvc never runs `step`: it prints the issue and revoke commands.

## Positive examples

- **Kim (medium) borrows a phone.** Kim asks with password + passkey. Sam (admin, 2 above
  medium) approves with a passkey. `kim-temp-1` works for 72 h at medium.
- **Lee (low) on a loaner laptop.** Robin (high, 2 above low) can approve.
- **Kim lost her phone yesterday** (lost-device report, passwordless blocked). The bridge is
  her way back to cert access; Sam approves it. The request is marked `LOST-REPORT`.
- **Alex (owner) travelling.** Alex self-issues with a YubiKey. The bridge is medium; for an
  owner action Alex plugs in the YubiKey, whose own cert and FIDO2 key do the owner step.
- **Kim enrolls her new phone.** `cvc-access device set-cert kim-phone2` revokes `kim-temp-1`
  automatically.
- **Extension.** Kim needs 2 more days; she asks, Sam approves again. 72 h + 48 h is under 14
  days.
- **Dashboard.** `/v1/whoami` returns `{"temp": true, "temp_hours_left": 30, ...}` and the
  dashboard shows "Temporary device: 30 hours left".

## Negative examples (refused)

- Kim asks with only a password (needs password + passkey, or a YubiKey).
- Robin (high) approves Kim (medium): only 1 tier above.
- Sam (admin) requests a bridge and approves it himself: self-approval.
- Alex has an active lost-device report and tries to self-issue: someone else must approve.
- Robin (high) tries to self-issue: only owners and admins can.
- A guest or an agent asks: never.
- Kim asks for a second bridge while `kim-temp-1` is pending or active.
- A fourth 72 h extension that would pass 14 days in total.
- Alex on `alex-temp-1` opens an admin-tier host: tier-gate sees medium and denies it.
- A cert with the temp flag and `urn:cvc:tier:owner`: step-ca's template refuses to issue it,
  and tier-gate would cap it at medium anyway.
- `cvc-access device add kim-temp-1`: a bridge id can never become a permanent device.
- Robin (high, not admin) revokes Kim's bridge: only Kim, an admin or an owner may.
  (Sam, an admin, may: revoking only reduces access. Decided 2026-11-01.)

## Audit

Every request, approval, refusal, extension, expiry, promotion and revocation is written to
`$CVC_TEMPDEVICE_STATE/audit.jsonl` (hash-chained, `cvc.broker.audit.AuditLog`). The D24
`tempdevice` check warns about bridges older than 7 days and people with 3+ bridges in 90 days.
