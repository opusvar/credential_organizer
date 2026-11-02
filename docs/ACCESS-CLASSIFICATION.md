# Access Classification — agents, credentials, systems

**Status:** Approved by the owner, 2026-11-01 (decision D16). Policy document.
Builds on D12 (access registry: roles for agents and machines) and D13 (human devices).

Every access decision is set by two things: **how sensitive the data is** and **what the
action does**. An agent's tier sets a ceiling over that grid. Human sponsors cap the ceiling
further, and explicit role grants can only narrow inside it.

**Implemented in:**
- `src/cvc/access/classify.py` — the sensitivity x action grid, tier ceilings and sponsor caps.
- `src/cvc/access/check.py` — `check_classification()` rules, run by `cvc-access check`.

---

## 1. The two axes

### 1.1 Data sensitivity

| Level | Definition | Home-lab examples |
|-------|-----------|-------------------|
| **public** | Already public. No harm if it leaks. | Public web pages, public search results, open-source docs, public model weights |
| **internal** | Belongs to the home lab, not to a person. A leak shows how things run but exposes nothing personal. | Service status/health, ltaskq task queue, mcp-dispatcher routing, agent-to-agent messages, MQTT sensor telemetry (temperature, uptime), Calibre catalogue metadata |
| **private** | About or belonging to a specific person. A leak hurts that person. | Emails, calendars, personal documents/notes, ordinary user credentials (service logins in Vaultwarden), camera feeds, presence/location from HA, Calibre reading history |
| **secret** | Lets someone take over the trust root or recover everything else. | Vaultwarden master password and admin token, home CA (step-ca) keys, recovery codes, YubiKey PINs/PUKs/management keys, broker signing keys |

### 1.2 Action type

| Action | Definition | Examples |
|--------|-----------|----------|
| **read** | Look at data. Nothing changes. | Query HA sensor state, search the web, read a task |
| **relay** | Move a message between agents without interpreting or acting on it | Forward a dispatcher payload to a worker, pass a result back to `_outbox/ai/handoff` |
| **write** | Create or change data, reversibly | Create an ltaskq task, write a note, save a file, tag a Calibre book |
| **act** | Real-world or irreversible effects | Actuate HA devices (locks, heaters, garage), send email/messages externally, payments, deletes |
| **delegate** | Assign work, and the tier it runs at, to other agents | An orchestrator splitting a job into sub-tasks and choosing their tiers |

Order of risk: read < relay < write < act. **delegate** is separate: it is limited by the
delegator's own tier (see high tier).

---

## 2. Tier ceilings matrix

Legend: **A** = allowed, **P** = approval required (per action, from the human principal),
**D** = denied. "Relay" of a level means carrying opaque payloads of that level. A relaying
agent should never need to decrypt them.

| Tier | public R / Rl / W / Act | internal R / Rl / W / Act | private R / Rl / W / Act | secret (any) | delegate |
|------|------|------|------|------|------|
| **scoped** | A / A / D / D | A / A / D / D | D / D / D / D | D | D |
| **low** | A / A / D / D | A / A / D / D | D / D / D / D | D | D |
| **medium** | A / A / A / P | A / A / A / P | A / A / P / P | D | D |
| **high** | A / A / A / P | A / A / A / P | A / A / A / P | D¹ | A (≤ own tier) |
| **assistant** | A / A / A / P | A / A / A / P | A / A / P / P | D | D |

¹ Only through the broker-mediated, single-use, approved fetch (§3.2). Never a standing grant.

Notes per tier:
- **scoped**: the low ceiling, plus a hard limit of **at most 2 systems** named in its roles.
  Use it for a narrow bot that needs nothing else.
- **low**: new, or tested but not yet trusted. Read-only on public/internal data, relaying,
  and limited tasks (embeddings, public search). "Write" here means only returning its own
  result through the relay path. It cannot create other records.
- **medium**: more dangerous tasks. Some private search, writes such as creating tasks,
  reading email, and use of *some* (explicitly granted) ordinary user credentials. Writing
  private data needs approval. All acts need approval.
- **high**: orchestrators that decide what tier each task goes out at. They may delegate at
  or below their own tier and **never self-escalate** (they cannot grant themselves or a
  sub-agent anything above `high`, or above their own effective permission). **Physical
  actuation always needs per-action human approval.** Other acts need approval unless a role
  grants a named, reversible act (for example "restart a container").
- **assistant**: acts for one user and is capped at **min(user tier, medium)**. Acts always
  need approval. Secret is always denied. It does not delegate. If it needs help, it asks its
  user or files a task that a high orchestrator picks up.

---

## 3. Effective permission rule

### 3.1 Formula

```
effective(agent, level, action) =
    min( tier_ceiling(agent.tier),
         tier_ceiling(agent.sponsor or principal) )
    ∩ explicit_role_grants(agent)          # D12 roles
```

- **Ceilings cap. Grants enable.** A role grant can never lift an agent above `min(...)`. An
  agent with no grant for a system has no access to it, even if its ceiling would allow it.
- When "A" and "P" combine, P wins. When either side is "D", the result is D.
- The human principal's ceiling is their D12/D13 role. The owner has the full matrix
  including secret.

### 3.2 Secret: never a standing grant

**Decision:** no agent tier holds standing access to **secret** data, including `high` and
an assistant acting for the owner. The only path is a **broker-mediated, single-use,
approved fetch**:

1. The agent asks cvc-broker for a named secret, stating the purpose and the task id.
2. The broker sends an approval request to the owner. Approval covers one fetch and one
   purpose.
3. On approval the broker releases the value once, with a short TTL, or better, performs
   the operation for the agent so the agent never sees the raw value. The fetch is
   audit-logged.
4. Nothing is cached or re-used. The next use needs a new approval.

**Why:** secrets are the recovery root (D11, D13). One leaked prompt, log line or context
window would compromise everything, and agents carry context across tasks in ways that are
hard to audit. Standing access gives agents little extra convenience at a large risk. Per-use
approval keeps a human on every trust-root operation and leaves an audit trail. Broker
mediation also lets the broker *use* a secret without exposing it, which is the preferred
mode.

### 3.3 Exception: service self-credentials (D27)

**Decision (owner-approved 2026-11-01):** a registered service may fetch **only its own
authentication secrets**, **only at startup**, for a **fixed purpose**. This is the single
exception to §3.2. It exists because a service that verifies logins or signs tokens cannot
ask for human approval every time it starts.

Conditions, all required:

1. The secret authenticates *the service itself* (its own login check or signing key). It
   never belongs to, or unlocks, another principal.
2. The ACL allow entry sets `self_credentials: true` and `owner_agent: <the service's agent
   id>`. The broker denies the fetch if `owner_agent` is missing or names anyone else.
3. Every purpose is in the broker's fixed list (`SELF_CREDENTIAL_PURPOSES` in
   `cvc/broker/acl.py`). `"*"` is rejected. Adding a purpose is a reviewed code change and
   cannot be done by editing the ACL.
4. The service fetches at startup and keeps the value in memory only. It does not fetch per
   request and does not write the value to disk or logs.
5. Every fetch is audited with outcome `allow:self-credential`.

**Positive examples (allowed):**

- personal-dashboard fetches `DASHBOARD_PASSWORD_HASH` and `DASHBOARD_TOTP_SECRET` at startup
  with purpose `dashboard-login-verify`, to check the owner's dashboard login.
- personal-dashboard fetches `DASHBOARD_CONFIRM_SECRET` at startup with purpose
  `dashboard-confirm-hmac`, to sign and verify its own confirm tokens.
- personal-dashboard reads `DASHBOARD_CVC_CREDENTIALS`, the path to its mapping file from
  variable name to vault item id. The path is not a secret.

**Negative examples (still need §3.2 per-use approval, or are refused):**

- personal-dashboard fetching the owner's email password, a bank login, or any item whose
  `owner_agent` is not `personal-dashboard`, even with a self-credential purpose.
- Any agent using `self_credentials` with purpose `*` or a purpose outside the fixed list.
- A service re-fetching its secret on every request, or caching it on disk.
- An LLM agent claiming a vault item as "its own" to get standing access to user data.
- Recovery-root secrets (vault master password, YubiKey PINs, CA keys); these are never
  service self-credentials.

---

## 4. Examples per tier

### scoped (e.g. `calibre-tagger`, systems: Calibre + ltaskq)
| Allowed | Denied / approval |
|---------|------------------|
| Read Calibre catalogue metadata | Read any third system (e.g. HA): D, outside its 2 systems |
| Pick up its own ltaskq tasks | Read reading history (private): D |
| Return a tag suggestion via relay | Write tags directly into Calibre: D (low ceiling) |
| | Gain a third system by role: D, a scoped agent must be re-tiered instead |

### low (e.g. a new embedding worker, a public-search agent)
| Allowed | Denied / approval |
|---------|------------------|
| Embed public documents and return vectors | Embed personal notes or emails (private): D |
| Run public web search | Create an ltaskq task: D (write) |
| Read MQTT temperature telemetry (internal) | Publish to an MQTT command topic or HA `outbox/`: D (act) |
| Relay a dispatcher message to a worker unchanged | Fetch any Vaultwarden item: D |

### medium (e.g. an email-triage agent, task planner)
| Allowed | Denied / approval |
|---------|------------------|
| Read the owner's email to summarize it (private read) | Send an email externally: P |
| Create ltaskq tasks and notes (internal write) | Delete emails: P (act) |
| Use a granted ordinary credential (e.g. a news-site login) via broker | Read Vaultwarden master/admin token: D |
| Search personal documents for one topic | Turn on a heater via HA: P |
| | Delegate a sub-task to another agent: D |

### high (e.g. mcp-dispatcher orchestrator)
| Allowed | Denied / approval |
|---------|------------------|
| Split a job and assign sub-tasks at low/medium | Assign a sub-task at a tier above its own, or raise its own tier: D |
| Read camera-feed metadata to route a vision job to the Mac | Unlock the front door / open the garage: P (per action, every time) |
| Write and reprioritize ltaskq tasks across workers | Read the step-ca root key: D (only §3.2 single-use fetch, with approval) |
| Read private calendars to schedule work | Delete files in `data/`: P |

### assistant (e.g. the owner's personal assistant agent)
| Allowed | Denied / approval |
|---------|------------------|
| Read the owner's calendar and email | Send a reply to an external address: P |
| Draft (not send) an email in Drafts | Place an order or payment: P |
| Create reminder tasks in ltaskq | See the owner's YubiKey PIN or recovery codes: D, even with the owner's tier |
| Read HA presence and sensor state | Delegate work to other agents: D |
| | Operate above medium because the owner is the principal: D (capped) |

---

## 5. Labeling guide

### 5.1 Data level checklist (pick the first "yes")
1. Could it be used to recover, take over or forge the trust root (vault master/admin, CA
   keys, recovery codes, hardware-key PINs, broker keys)? → **secret**
2. Is it about, belongs to, or authenticates as a specific person (messages, calendar,
   documents, location, camera, a person's service login)? → **private**
3. Is it home-lab operational data not meant for outsiders? → **internal**
4. Is it already public? → **public**
5. Not sure → label it one level **higher**, and lower it later on review.

Label credentials by **what they unlock**, not by what they are: a credential takes the
highest level of data reachable with it.

### 5.2 Action checklist for a system
For each capability the system exposes, ask: does it only return data (read)? Does it move
opaque payloads (relay)? Does it change data reversibly (write)? Does it affect the physical
world or the outside world, spend money, or destroy data (act)? Record the **highest** action
any granted operation can reach. A token that can both read and delete is an **act** token.

### 5.3 Label examples
| Item | Correct label | Wrong label and why |
|------|--------------|---------------------|
| MQTT temperature topic (read) | internal / read | ~~public~~: it shows occupancy patterns of the home |
| MQTT `cmnd/heater/POWER` topic | internal / **act** | ~~internal / write~~: it actuates physical devices |
| HA long-lived token | **private / act** | ~~internal / read~~: it unlocks cameras, presence and actuators |
| Calibre catalogue | internal / read | ~~private~~: titles are not personal. Reading *history* is private |
| Gmail OAuth token (read-only scope) | private / read | ~~private / act~~ is too high. If the scope includes send, label it act |
| Vaultwarden admin token | **secret** | ~~private~~: it controls every vault |
| step-ca intermediate key | **secret** | ~~internal~~: it can mint device identities (D13) |
| Public search API key | internal / read | ~~public~~: the key itself is not public. Misuse costs quota |

---

## 6. Sponsored agents (guest and family)

Guest and family agents are **not separate tiers**. They use the same ladder
(scoped/low/medium/high/assistant) plus a **`sponsor`** attribute naming a human principal.

```
effective = min(agent tier ceiling, sponsor's ceiling)   ∩ role grants
```

| Rule | Detail |
|------|--------|
| Guest-sponsored | Capped at **low**, whatever tier is requested. They **expire with the guest**: when the guest's access ends (or at its expiry date), the agent is revoked. |
| Family-sponsored | Capped by the sponsor's ceiling and **at most medium**, unless the sponsor is the owner and the owner explicitly approves a higher tier. |
| Network | **All agents live on the agents tailnet**, whatever their sponsor. Sponsorship never puts an agent on a human or device network. |
| Data scope | A sponsored agent sees the sponsor's private data, never another person's, unless that person grants it. |

Examples:
- A visiting friend's agent, sponsor = guest, requested medium: **effective low**. It can do
  public search and read the Calibre catalogue. It is revoked when the guest Wi-Fi/tailnet
  access ends.
- A family member's homework helper, tier assistant, sponsor = family member (medium):
  it reads that person's calendar and creates tasks. It cannot read the owner's email, and
  sending messages needs the sponsor's approval.
- A family member asks for a high orchestrator: denied. Family sponsorship caps at medium.
  Only an owner-sponsored agent can be high, and only with owner approval.
- A family agent asks to turn off the living-room lights: an act, so the sponsor approves.
  The agent still runs on the agents tailnet and calls HA through the broker/dispatcher.

---

## 7. Mapping to known patterns

| Pattern | How it appears here |
|---------|---------------------|
| **Least privilege** | Ceilings cap. Explicit grants enable. With no grant there is no access. Secret is fetched per use. |
| **Cloud IAM access levels** (list/read/write/permissions-management, as in AWS-style policies) | The action axis is a smaller version: read/relay/write/act. delegate is the counterpart of permissions-management. |
| **Data classification** (public/internal/confidential/restricted schemes) | The 4-level sensitivity axis, with "private" in place of confidential and "secret" in place of restricted. |
| **OAuth on-behalf-of delegation** | Assistant and sponsored agents act with the *intersection* of the agent's and the principal's rights, like a delegated token scoped down from the user. |
| **Agent autonomy levels** (graduated human-in-the-loop) | Tier ladder plus "P" cells: low autonomy at low, approval-gated acts at medium/assistant, orchestration at high with a human kept on physical and irreversible actions. |
| **Broker / vault-mediated secrets** | §3.2: short-lived, single-use, audited release, or the broker performs the operation so the secret is never exposed. |
