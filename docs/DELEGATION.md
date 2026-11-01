# Voluntary Delegation

**Status:** Approved by the owner, 2026-11-01 (decision D17). Design only; no code yet.
Related: D14 (at least one active owner YubiKey), D16 / [ACCESS-CLASSIFICATION.md](ACCESS-CLASSIFICATION.md)
(tier ceilings), takeover flow (execution machinery reused).

Voluntary delegation lets a living, authenticated principal hand some or all of their
access to another principal. It is the planned, consensual counterpart to takeover. It
**never escalates silently**: anything above the recipient's tier ceiling is revoked, not
transferred.

---

## 1. Wizard: `cvc delegate start`

| Step | What happens |
|------|-------------|
| **(a) Identity** | Delegator proves who they are with their **device cert** (D13) + **YubiKey** (owner) or **passkey** (non-owner), then a **passkey/password elevation** step. |
| **(b) Recipient** | Choose an existing principal from the registry. The recipient's tier ceiling is loaded. |
| **(c) Itemised preview** | Lists exactly what would be delegated, by section: vault items/folders, org memberships, hardware keys, devices, grants given to others, agents and sponsored agents, roles. Each item is marked **transfer** or **cannot transfer — will be revoked** (above the recipient's ceiling). |
| **(d) Section selection** | Delegator may deselect sections. Default = **everything**. |
| **(e) Confirmation** | Confirm each selected section, then type the recipient's name exactly. |
| **(f) 48-hour revoke window** | Nothing moves yet. The recipient, all other owners and the delegator are notified. The delegator can revoke at any time in the window. The recipient may decline, which cancels it. |
| **(g) Execution** | After 48 h it runs through the **same machinery as takeover completion**: key transfer, cert revocation/re-issue, and the vault merge plan. The **≥1 active owner YubiKey guard (D14)** is always enforced. If execution would break it, the delegation is refused. |
| **(h) Status + FAQ** | The same status icon as takeover (pending / revocable / executed / revoked / declined / refused), plus an FAQ page covering what moves, what is revoked, and how to cancel. |

### Rules
- **No silent escalation.** Items above the recipient's ceiling are revoked at execution and
  listed as such in the preview and notifications.
- The preview is a snapshot. If anything changes during the window, the execution diff is
  recomputed, and any newly added item that is above the recipient's ceiling is revoked.
- Revocations of items that cannot be transferred happen only at execution, never during the
  window.
- Delegated agents and sponsored agents get the recipient as their new sponsor. Their effective
  permission is recomputed as min(agent ceiling, new sponsor ceiling).

---

## 2. Examples

| Scenario | Outcome |
|----------|---------|
| Owner → owner, full delegation | **OK.** Everything transfers, including hardware keys and owner roles. The D14 guard holds. |
| Medium delegator → low recipient | **Partial.** Low-tier items transfer. Medium-tier grants (e.g. email read, task creation, private vault items) are **revoked, not transferred**, and shown as such in the preview. |
| Delegation that would leave zero active owner YubiKeys | **Refused** by the D14 guard, at preview time and again at execution. |
| Delegator revokes at hour 47 | **OK.** Nothing has moved. All parties are notified. |
| Delegator tries to revoke at hour 49 | **Refused.** It has already executed. Undoing it needs a new delegation back. |
| Recipient declines at hour 10 | **Cancelled.** Nothing moves. |
| Delegator deselects "hardware keys" | **OK.** Keys stay with the delegator. The rest proceeds. |
| Delegation started using only a password | **Refused.** Step (a) needs a device cert and a YubiKey/passkey. |
| Owner delegates a high orchestrator agent to a family member (medium) | The agent transfers with the new sponsor. Its effective tier drops to medium (D16 §6). |
| A guest-sponsored agent included in a delegation to another guest | Transfers capped at low, and expires with the new guest. |
