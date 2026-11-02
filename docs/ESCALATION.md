# Agent escalation (D27)

**Status:** Decided 2026-11-01 (D27). Builds on D16 (access classification), D18 (approvals)
and the D12 grant rule.

An agent sometimes needs to do one thing its tier does not allow. Instead of raising its tier,
it asks a human for a **single-use, short-lived exemption for exactly one action**.

**Implemented in:** `src/cvc/escalation/` (`policy.py` validation and classification,
`store.py` limits, grants and history, `cli.py` `cvc-escalate`), broker endpoints
`POST /v1/escalations`, `GET /v1/escalations/{id}`, and the escalation branch of
`POST /v1/credentials/fetch`.

---

## 1. The request

| Field | Rule |
|-------|------|
| agent | From `X-Agent-Id`, authenticated with the agent's **service token** (not a session token) |
| action | Exactly one of `read`, `relay`, `write`, `act`, `delegate` |
| data | Exactly one of `public`, `internal`, `private`, `secret` |
| resource | `credential:<uuid>`, `ha:<domain.object_id>`, `system:<name>` or `task:<id>`. One exact identifier |
| purpose | Free text, 256 chars max, run through the shared text normalizer |
| justification | Free text, 512 chars max, normalized |
| on_behalf_of | Optional person id. Required for assistant agents (defaults to the ACL value) |
| ttl_s | Grant lifetime, default 900 (15 min), from 60 up to 86400 (24 h) |
| physical | Optional. Always true for `ha:` + `act` |

Unknown fields are rejected. Wildcards (`*`, `?`, `%`, `#`, `+`, `[]`, `{}`, `..`, a
trailing `/`, and the words `all`, `any`, `every`, `everything`) are rejected.

## 2. Classification

The request is checked against the D16 matrix at the agent's effective row:

- Cell **A** (allowed): the response is `already_permitted` and no request is created.
- Cell **D** or **P**: the request is valid. A P cell is approved the same way, with a
  single-use grant.

`required_tier` is the lowest tier whose cell allows the action, or else approves it. For
`secret` it is `owner`.

## 3. Who approves

| Case | Approver |
|------|----------|
| Required tier low/scoped | person tier **high** or above (low + 2) |
| Required tier medium | **admin** or above (medium + 2) |
| Required tier high | **owner** (the grant rule makes high-tier grants owner-only) |
| Any `secret` data | **owner** |
| Any `delegate` action | **owner** |
| Physical actuation | Human with a passkey. D18's red floor still applies, so the owner. If an agent identity approves, the grant is voided |

For escalations the D18 on_behalf_of exemption does **not** apply. The person an assistant
works for must still meet the approver tier. D18's "denied cell is red, so owner" floor is
replaced by the grant rule, except for physical actions.

## 4. Hard ceilings (never escalatable)

| Resource kind / case | Why |
|----------------------|-----|
| `owner-key:*` | Owner key changes need the YubiKey |
| `takeover:*` | D15 takeover is an owner/YubiKey flow |
| `delegation:*` | D17 estate delegation ("delegation of everything") |
| `tier:*`, `role:*` | Changing the agent's tier or roles is a registry change by its grantor |
| `grant:*`, `agent:*` | Granting access to other agents |
| `delegate` on `system:*` | Delegating a whole system is delegation of everything on it |

These return HTTP 403 with `code: hard_ceiling` and a reason.

## 5. The grant

- Approval sets `uses_left = 1` and `grant_expires_at = decided_at + ttl_s`.
- It is bound to the sha256 of the agent's service token, the exact resource, the action and
  the request nonce. The nonce is returned to the agent once and only its hash is stored.
- The broker consumes it under a file lock. A second use gets `403 escalation grant already
  used`.
- Owners can revoke an unused grant or withdraw a pending request (`cvc-escalate revoke`).
  Withdrawing a pending request cancels its approval card.
- Timeout means deny: an unanswered card expires at its deadline (15 min).

Using a credential grant:

```
POST /v1/credentials/fetch
X-Agent-Id: lowbot
Authorization: Bearer <service token>
X-Escalation-Id: <id>
X-Escalation-Nonce: <nonce>
{"credential": "<uuid>", "purpose": "..."}
```

The escalation branch replaces the ACL and tier checks for that one fetch. Other enforcement
points (HA proxy, ltaskq) call `EscalationStore.consume()` with their own resource string.

## 6. Delivery

The approval reuses the D18 pipeline: a `cvc.approval.v1` record with `kind: "escalation"`
and an `escalation` block (`current_tier`, `requested_tier`, `resource`, `uses`, `ttl_s`,
`physical`, `owner_only`). It also states what happens if approved or denied, and that
timeout means deny. Approvers decide through the usual `/v1/approvals/{id}/decide` (ETag,
nonce, passkey). ntfy priority follows urgency as before. The title reads
"Escalation needed".

## 7. Abuse limits

| Limit | Value | Response |
|-------|-------|----------|
| Pending per agent | 3 | 429 `too_many_pending` |
| Requests per agent per rolling 24 h | 10 | 429 `daily_limit` |
| Identical request already pending | — | 409 `duplicate` |
| Identical request denied < 1 h ago | — | 429 `denied_cooldown` |
| Same agent + data + action 3 times in 7 days | — | request proceeds; an `audit_suggestion` is logged and returned, suggesting a proper tier/role change |

## 8. Audit

- The broker audit log (hash-chained) records `escalation:requested|refused|already_permitted`,
  `allow:escalation:<id>` and `deny:escalation:<code>`, with `on_behalf_of`.
- `escalations.history.jsonl` holds every lifecycle event (requested, approved, denied,
  expired, consumed, use_denied, revoked, grant_expired, void, audit_suggestion). Each row
  carries `agent` and `on_behalf_of` and is chained by sha256 like the takeover history.
  `EscalationStore.verify_history()` detects tampering.

---

## 9. Examples

### Positive

| Agent (tier) | Request | Result |
|--------------|---------|--------|
| `report-bot` (low) | write / internal / `task:nightly-report` | Sent. Current low, requested medium, approver admin+. One use within 15 min |
| `lowbot` (low) | read / private / `credential:11111111-1111-4111-8111-111111111111` | Sent. Approver admin+. The broker releases that one credential once |
| `orchestrator` (high) | act / private / `ha:lock.front_door`, physical | Sent. Red, passkey, owner. One unlock |
| `orchestrator` (high) | read / secret / `credential:<uuid>` | Sent. Owner only. This is the §3.2 single-use fetch |
| `homework-helper` (assistant, for `alex`) | write / private / `task:essay-draft` | Sent with on_behalf_of `alex`. Approver must still be at least the grant-rule tier |

### Negative

| Agent (tier) | Request | Result |
|--------------|---------|--------|
| `planner` (medium) | write / internal / `task:x` | `already_permitted`. No request is created |
| `lowbot` (low) | read / private / `credential:*` | 422 `invalid`: wildcard |
| `lowbot` (low) | write / internal / `system:all` | 422 `invalid`: wildcard word |
| `orchestrator` (high) | delegate / internal / `tier:orchestrator` | 403 `hard_ceiling`: own tier |
| `orchestrator` (high) | delegate / internal / `agent:helper-bot` | 403 `hard_ceiling`: granting to other agents |
| any | any / `owner-key:yubikey-1` | 403 `hard_ceiling`: owner key |
| any | any / `delegation:all` | 403 `hard_ceiling`: estate delegation |
| `lowbot` | a 4th request while 3 are pending | 429 `too_many_pending` |
| `lowbot` | the same request again 10 min after a deny | 429 `denied_cooldown` |
| `lowbot` | reuses an approved grant | 403 `escalation grant already used` |
| `lowbot` | uses the grant for a different credential | 403 `grant covers a different resource` |
| `otherbot` | presents `lowbot`'s escalation id and nonce | 403 (unknown for this agent, and the token binding fails) |

## 10. CLI

```
cvc-escalate request --agent report-bot --action write --data internal \
    --resource task:nightly-report --purpose "..." --justification "..." [--check --tier low]
cvc-escalate list [--agent A] [--status S] [--json]
cvc-escalate show <id>
cvc-escalate revoke <id> --as <owner-person-id>
```

`request` reads the service token from `CVC_AGENT_TOKEN` and posts to `CVC_BROKER_URL`.
`--check` classifies locally and sends nothing. State: `CVC_ESCALATIONS_STATE` (default
`/var/lib/cvc/escalations.json`), shared with the broker. Approvals: `CVC_APPROVALS_STATE`.
