# Push notifications (ntfy)

Approvers are often off Tailscale and cannot reach Home Assistant, so cvc also pushes
approval and audit alerts through ntfy. Two backends, usable together (failover order):

- **D (primary):** self-hosted ntfy on the services node as a nerdctl container, public
  only through Cloudflare Tunnel at `ntfy.<base_domain>` (D27). Templates in `deploy/ntfy/`
  (not applied).
- **C (fallback):** ntfy.sh (or any ntfy server) on reserved, access-controlled per-approver
  topics, published with a write-only access token (Bearer).

Code: `src/cvc/notify/`. Disabled unless `CVC_NTFY_SERVERS` or site.yaml `ntfy_servers`
is set.

## Configuration (env overrides site.yaml; tokens env-only, never logged)

site.yaml keys `ntfy_servers` (list), `ntfy_topics` (map) and `approval_card_url` are
the defaults for the matching variables below; a set variable wins. MQTT works the same
way: `mqtt_host` / `mqtt_port` / `mqtt_username` in site.yaml, overridden by `MQTT_HOST`
/ `MQTT_PORT` / `MQTT_USERNAME`. `MQTT_PASSWORD` and `CVC_NTFY_TOKEN_<n>` are env-only.

| Variable | Meaning |
|---|---|
| `CVC_NTFY_SERVERS` | comma list in failover order, e.g. `https://ntfy.example.com,https://ntfy.sh` |
| `CVC_NTFY_TOKEN_<n>` | write-only token for server n (1-based), read at send time |
| `CVC_NTFY_TOPICS` | fallback topic map `alex=cvc-alex-k3j9,sam=cvc-sam-p2x8` |
| `CVC_REGISTRY` | registry file; `people.<id>.notify.ntfy_topic` wins over the env map |
| `CVC_DASHBOARD_URL` | dashboard base (default `https://dashboard.<site base_domain>`) |
| `CVC_APPROVAL_CARD_URL` | card link template (default `{dashboard}/agents/approvals/{id}`) |
| `CVC_NOTIFY_QUIET` | quiet hours, local, default `22:00-07:00` (`""` = off) |
| `CVC_NOTIFY_TZ` / `CVC_NOTIFY_DIGEST_AT` | zone for quiet/digest; digest time (default `08:00`) |
| `CVC_NOTIFY_STATE` | notifier state (deferred queue, escalations, last digest) |

Run `cvc-notify tick` every minute for deferred flush, escalation and the digest:
`deploy/cvc-notify.{service,timer}` (systemd user timer, installed by
`deploy/setup-timers.sh`, env from `~/.config/cvc/notify.env`, see
`deploy/notify.env.example`); `cvc-notify test --person alex` sends a harmless test push.

## Message rule (enforced in `cvc/notify/message.py`, tested)

An approval push contains **only**: agent id, short intent (<= 80 chars, truncated),
urgency, minutes left, and a deep link to the dashboard approval card. Never the summary,
credential names, accounts, addresses, IPs, or secrets. Agent id and intent are run through
the existing secret scans (`approvals.model.scan_secrets`, `audit.findings.assert_no_secrets`)
plus a sensitive-value scan (IPs, emails, URLs/hostnames, long numbers, credential words);
any hit drops the text to **"Approval needed (open dashboard)"**. Audit pushes carry only
counts ("1 new error finding").

## Policy

- Priority: urgent -> 5 (bypasses DND), normal -> 3, low -> no push (daily digest only).
- Quiet hours delay non-urgent pushes; deferred approvals are re-checked and dropped if
  already decided/expired.
- Routing: assistant requests -> the on_behalf_of person, then owners; others -> eligible
  non-owners (tier >= approver_min_tier, highest first), then owners. First recipient on
  submit; at 50% of the deadline with no decision, the next one (once).
- Digest: daily push to owners with pending/low counts and open audit warn/error counts.
- Failure safety: each backend is retried, then the next is tried; all errors are swallowed.
  Notification failure never changes an approval outcome. Logs carry counts only.

## D18 addendum

D18 addendum (2026-11-01): approval and audit alerts are also pushed via ntfy (self-hosted
primary, ntfy.sh fallback) with content limited to agent id, short intent, urgency, minutes
left and a dashboard link; unanswered requests escalate to the next eligible approver
(owner fallback) at 50% of the deadline. Decisions still happen only on the dashboard.

## Deployment (D27)

- ntfy runs on the services node from `deploy/ntfy/compose.yaml` with `sudo nerdctl compose`
  (never docker). It listens on 127.0.0.1:2586 only.
- A `cloudflared` sidecar (`deploy/ntfy/cloudflared/config.yml`) dials out to Cloudflare and
  publishes only `ntfy.<base_domain>`. No router port forwards and no inbound listener.
  `base_domain` must be a Cloudflare zone.
- iOS: `upstream-base-url: https://ntfy.sh` in `server.yml`, so APNs wake-ups go via
  ntfy.sh (it sees only a topic hash) and the app fetches the message from our server.
- Fallback (option C): the same reserved topics on ntfy.sh, as the second entry in
  `ntfy_servers` / `CVC_NTFY_SERVERS` with its own write-only token.
- Known gap: if the services node is down, nothing can send an "it is down" push, because
  the notifier runs on that node. That needs an external uptime check (for example a hosted
  monitor polling `https://ntfy.<base_domain>/v1/health`). Not set up yet.
