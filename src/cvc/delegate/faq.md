# Delegation FAQ (`cvc delegate faq`)

**What is a delegation?** You hand some or all of your access to another person in the
registry. It is planned and consensual. Takeover is the emergency version.

**What moves?** Only the sections you selected (default: all): vault items/folders,
organization memberships, hardware keys, devices, grants you gave to others, your agents and
sponsored agents, and your tier. The preview lists each item as **transfer** or
**cannot transfer — will be revoked**.

**What is revoked instead of transferred?** Anything above the recipient's tier ceiling. For
example, private vault items, email-read or task-creation grants go to a medium recipient but
are revoked for a low one. Nothing is ever escalated silently. Revocations happen only at
execution, never during the window.

**What happens to my tier?** If you include "roles", you drop to `low` at execution. If the
recipient's tier is lower than yours, your tier is not given to them.

**What happens to my agents?** They get the recipient as their new sponsor. Their tier is
capped at min(agent tier, recipient ceiling). With a guest recipient they also expire with
the guest.

**What happens to my devices?** Their certificates are revoked (the `step ca revoke` command
is printed, not run) and re-issued for the recipient.

**When does it happen?** Nothing moves for 48 hours. After that, `cvc delegate complete <id>`
runs it. The diff is recomputed then: anything new that is above the recipient's ceiling is
revoked, and the D14 rule (at least one active owner YubiKey) is checked again. If it would
break, the delegation is **refused**.

**How do I cancel?** Within the 48 hours: `cvc delegate revoke <id>` (with your YubiKey, or
your passkey if you are not an owner). After 48 hours it cannot be revoked; you need a new
delegation back. The recipient can refuse it before it executes: `cvc delegate decline <id>`.

**Who is told?** You, the recipient and every owner, on every configured channel, when it
starts, is revoked, declined, refused or executed.

**Status icons** (`cvc delegate status <id>`):

| Icon | State | Meaning |
|------|-------|---------|
| `[~]` | revocable | Inside the 48-hour window. Nothing has moved. |
| `[..]` | pending | Window closed; waiting for `cvc delegate complete`. |
| `[ok]` | executed | Done. |
| `[x]` | revoked | Cancelled by the delegator. Nothing moved. |
| `[x]` | declined | Refused by the recipient. Nothing moved. |
| `[!]` | refused | The execution re-check failed (for example D14). Nothing moved. |

**Why was I refused at the start?** You need a device certificate plus your YubiKey (owner)
or passkey (non-owner), then a passkey or password elevation. A password alone is never
enough. A delegation that would leave zero active owner YubiKeys is refused.
