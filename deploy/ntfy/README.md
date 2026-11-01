# Self-hosted ntfy (option D) - templates and hardening

Not applied. Files: `server.yml` (deny-all auth, per-user topic ACLs, behind-proxy,
`upstream-base-url: https://ntfy.sh` for iOS instant push, rate limits, attachments off) and
`compose.yaml` (nerdctl/docker, loopback bind). Client side: docs/NOTIFICATIONS.md.

## Exposure options (phones must reach it off-tailnet)

| | Small VPS (recommended) | Cloudflare Tunnel | Tailscale Funnel |
|---|---|---|---|
| Inbound ports at home | none | none (outbound tunnel) | none (relayed) |
| Where the public service runs | off-site, isolated box | on the home services node | on the home services node |
| Blast radius if ntfy is exploited | a throwaway VPS with no cvc secrets | node that also runs broker/vault | node that is also a tailnet device |
| TLS terminated by | you (Caddy, Let's Encrypt) | Cloudflare (sees message text) | your node |
| Long-lived subscriptions | fine | fine (ntfy keepalive 45 s < CF 100 s idle) | fine; relay bandwidth limited |
| Cost / effort | ~$4-5/mo, one more box to patch | free, needs a domain on CF | free, `*.ts.net` name, ports 443/8443/10000 only |

**Recommendation: small VPS.** The services node holds the credential broker; nothing on it
should accept internet traffic. A VPS keeps the only internet-facing piece on a box holding
no cvc secrets (the publisher token is write-only to `cvc-*`; each reader can read one
topic). If a VPS is unwanted, Cloudflare Tunnel is the runner-up (no open ports, CF rate
limiting); message text is minimal by design, so CF seeing it is acceptable. Avoid Funnel
here: it publishes a service on a tailnet node to the whole internet.

## Hardening checklist (VPS)

1. Minimal Debian/Ubuntu, unattended-upgrades, SSH keys only (or SSH via Tailscale only);
   firewall allows only 80/443 inbound.
2. Caddy in front: `ntfy.example.com { reverse_proxy 127.0.0.1:2586 }` (sets
   X-Forwarded-For, which `behind-proxy: true` relies on). HSTS on.
3. `compose.yaml` as given: loopback bind, read-only rootfs, non-root, no capabilities.
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
