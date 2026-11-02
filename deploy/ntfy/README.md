# Self-hosted ntfy (option D) - templates and hardening

Not applied. Files: `server.yml` (deny-all auth, per-user topic ACLs, behind-proxy,
`upstream-base-url: https://ntfy.sh` for iOS instant push, rate limits, attachments off) and
`compose.yaml` (nerdctl; ntfy on loopback + a `cloudflared` sidecar) and
`cloudflared/config.yml` (tunnel ingress for `ntfy.<base_domain>` only). Render all three
with `cvc-site render-deploy --out DIR` (fills `${SITE_NTFY_HOST}`). Client side:
docs/NOTIFICATIONS.md.

## Exposure (decided: D27, 2026-11-01)

ntfy runs on the services node and is public **only** through Cloudflare Tunnel:

- `cloudflared` makes outbound connections to Cloudflare; there are no router port
  forwards and nothing listens on a public interface. ntfy binds 127.0.0.1:2586.
- The tunnel ingress publishes exactly one hostname, `ntfy.<base_domain>`, and returns 404
  for anything else. `base_domain` must be a zone on the Cloudflare account.
- ntfy keepalive (45 s) is below the Cloudflare idle timeout (100 s), so phone
  subscriptions stay open.
- Cloudflare terminates TLS and can see message text. That is acceptable because messages
  are minimal by design (see docs/NOTIFICATIONS.md, message rule).
- ntfy.sh reserved topics remain the fallback (option C); iOS uses
  `upstream-base-url: https://ntfy.sh`.

Options considered and rejected: a small VPS (an extra box to patch and pay for) and
Tailscale Funnel (publishes a tailnet node to the internet).

Known gap: a "services node is down" alert cannot come from the services node. It needs an
external uptime check on `https://ntfy.<base_domain>/v1/health` (to be added later).

## Setup and hardening checklist (services node; NOT applied)

1. Tunnel: follow the header of `cloudflared/config.yml` (`cloudflared tunnel create`,
   credentials JSON at mode 0600 outside the repo, `tunnel route dns`). In the Cloudflare
   dashboard, add a rate-limit rule for the host and leave Access off (phones cannot do
   interactive login).
2. Start: `sudo nerdctl compose -f compose.yaml up -d` from the rendered dir. Use nerdctl
   (standalone containerd); docker is not used on this host.
3. `compose.yaml` as given: loopback bind, read-only rootfs, non-root, no capabilities,
   for both ntfy and cloudflared.
4. Users/ACLs (`auth-default-access: deny-all`):
   - `ntfy user add cvc-publisher`, `ntfy access cvc-publisher 'cvc-*' write-only`,
     `ntfy token add cvc-publisher` -> `CVC_NTFY_TOKEN_1` (k8s Secret / 0600 env file).
     Never in site.yaml, the registry, or git.
   - one read-only user per approver: `ntfy access alex cvc-alex-<random> read-only`.
     Keep unguessable topic suffixes even with ACLs.
5. Option C fallback on ntfy.sh: reserve the same topic names on an ntfy.sh account with
   "only me" access, create a write-only access token -> `CVC_NTFY_TOKEN_2`.
6. Monitor `/v1/health`; rotate the publisher token on the cvc rotation schedule (D19).
7. Back up `/var/lib/ntfy/user.db` (ACLs only; messages are ephemeral).
