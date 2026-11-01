# Approvals (D18)

Agents and assistants sometimes need a human to approve an action. cvc publishes each request to MQTT, Home Assistant picks it up, and it appears on the personal-dashboard **Agents** page under **Approvals**.

## Flow

1. The broker creates a request and publishes it **retained** to `cvc/approvals/<id>` (schema `cvc.approval.v1`).
2. Home Assistant subscribes and exposes it to the dashboard.
3. The approver reviews it and decides. The decision goes **over HTTPS to the broker behind the tier gate**, never via MQTT. Act/physical actions need a passkey.
4. The broker re-publishes the request with its new `status`.
5. If nobody decides before `deadline`, the request becomes `expired` and is treated as **deny**. `on_timeout` is always `"deny"`.

## Who can approve

- The approver's tier must be ≥ the request's level (`approver_min_tier`).
- Requests from an assistant go to that assistant's person first, then escalate to the owner.

## What the card shows

- **Time sensitivity:** urgency (`low` | `normal` | `urgent`) and a countdown to `deadline`.
- **Intent:** what the agent is trying to do.
- **Summary:** with D16 data/action labels and a risk colour taken from the D16 cell (green/amber/red).
- **If approved / if denied:** the consequences of each choice.
- **On timeout:** deny (always).
- **Details on review:** agent, tier, sponsor, on_behalf_of, the exact credential/device, prior similar requests, and an audit link.

## No secrets in payloads

MQTT payloads never contain secrets, tokens or credential values. They name the credential/device; they do not carry it.

## Schema `cvc.approval.v1`

```json
{
  "schema": "cvc.approval.v1",
  "id": "string",
  "created_at": "RFC 3339",
  "deadline": "RFC 3339",
  "urgency": "low | normal | urgent",
  "requester": {
    "agent": "string",
    "tier": "string",
    "sponsor": "string",
    "on_behalf_of": "string"
  },
  "intent": "string",
  "summary": "string",
  "labels": { "data": "public|internal|private|secret", "action": "read|relay|write|act|delegate" },
  "risk": "green | amber | red",
  "if_approved": "string",
  "if_denied": "string",
  "on_timeout": "deny",
  "approver_min_tier": "string",
  "requires_passkey": true,
  "details_url": "https://...",
  "status": "pending | approved | denied | expired | cancelled",
  "decided_by": "string (optional)",
  "decided_at": "RFC 3339 (optional)"
}
```
