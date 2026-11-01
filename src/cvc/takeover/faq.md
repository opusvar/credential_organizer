# Owner takeover FAQ

## What is an owner takeover?
An owner takeover is how one owner takes over another owner's accounts if that owner has died or
can no longer act. It covers the Vaultwarden vault and the cvc account: hardware keys, device
certificates, assistant agents and grants. Start it with `cvc takeover start`.

## What do I need to start?
1. Your own owner device certificate.
2. Your own YubiKey.
3. Your passkey or your Vaultwarden master password.
4. **One of these** from the person you are taking over:
   - **their YubiKey**, primary or backup (a suspended key also works); or
   - **their sealed recovery password**, which they set in advance with
     `cvc takeover recovery-set`.

The wizard checks each item before it moves to the next. Before anything starts, it shows a
summary. To confirm, you type the target's name.

## What is the timeline?
All days count from the day you start, and the clock never restarts.

| When | What happens |
|------|--------------|
| Day 0 | The target sees a banner and gets alerts on every channel. All other owners are told. |
| Day 15 | You get read-only view access to the target's vault. |
| Day 90 | You can run `cvc takeover complete` (YubiKey path). |
| Day 180 | You can run `cvc takeover complete` (recovery-password path). |

## Why are there waits?
The waits protect an owner who is alive but away, or whose key or password was stolen. They
give that owner, and every other owner, time to notice and say no.

The recovery-password path waits twice as long. A password can be copied; a YubiKey has to be
physically held.

## How do I cancel?
- **The target** can cancel at any time before completion: `cvc takeover cancel <id>` with any
  of their own YubiKeys.
- **Any other owner** can veto the same way, with their own YubiKey. The person who vetoed is
  recorded.
- **The initiator** cannot veto their own takeover.

Cancelling withdraws the Vaultwarden emergency-access requests.

## What does the target see?
- A banner, "takeover request in progress", saying who started it, which factor was used, and
  the completion date.
- Alerts on days 0, 7, 14 and 85. On the recovery-password path, also every 30 days and on day
  170.

## What happens when it completes?
1. Vaultwarden emergency takeover.
2. cvc account takeover:
   - the target's hardware keys are transferred to you
   - the target's device certificates are revoked (you run the printed `step ca revoke` steps)
   - their assistant agents are removed, or rebound to you with `--rebind-agents`
   - they are marked `taken-over`
3. A plan to merge their vault into yours. Personal items are copied. Organization items change
   ownership instead of being copied.

The rule that at least one active owner YubiKey must always exist still applies.

## What if Vaultwarden is reset or loses the requests?
The cvc record is the source of truth. Run `cvc takeover reconcile <id>` to re-initiate the
requests. The original start date is kept, so the timeline never restarts and never gets
shorter. If Vaultwarden's own wait now ends later, completion still waits for the original cvc
deadline, and the Vaultwarden step may also wait for its own timer.

## Can the target start a takeover back against me?
No. Someone who is the target of an active takeover cannot start one. Each person can be the
target of only one active takeover at a time, and the first one started wins.

## What if I stop being an owner during the wait?
If the initiator is removed, taken over or demoted below owner, the takeover is voided and the
Vaultwarden requests are withdrawn. A different owner must start again.

## Where is the record kept?
In `~/.local/state/cvc/takeover/`:
- `takeovers.json`: the current records
- `history.jsonl`: a hash-chained history
- `recovery.json`: hashes of the recovery passwords

This directory must be included in the identity backup.
