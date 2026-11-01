# Agent gateway — "Clear for agents" (D26)

Modelled on airport fast-lane screening: enroll once, then move quickly, but screening still applies.

| Airport | cvc |
|---|---|
| Enrollment | `onboard agent`: sponsor, tier, token |
| Fast lane | Brokered short-lived scoped tokens |
| Screening | Tier ceilings (D16) and approvals (D18) still apply |
| Boarding pass | Per-task token |
| Records | Full audit with dual attribution (agent + sponsor/on_behalf_of) |

## Interfaces

- **MCP server:** agents request credentials/actions as tool calls.
- **HTTP credential proxy:** in proxy mode the broker performs the API call itself, so the agent never sees a token.

## Onboarding

Onboarding migrates any raw credentials an agent already held into the broker and rotates them (D19), so the old copies are useless.

## Limits

The gateway only protects what flows through it. Credentials or paths that bypass it are out of scope.
