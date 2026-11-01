# cvc deploy runbook: mTLS + tier-gated routes on k3s Traefik

Nothing in this repo applies anything to the cluster. Every step below runs by hand, after
review. Host: OPi 6 Plus, k3s v1.36 with bundled Traefik v3, Tailscale IP `100.106.97.34`,
LAN IP `192.168.1.208`.

## Request path

```
client (device cert from step-ca)
  -> Traefik websecure (Tailscale IP only), TLSOption cvc-mtls: RequireAndVerifyClientCert
  -> cvc-strip-identity-headers   delete client-sent X-Forwarded-Tls-Client-Cert*, X-Cvc-*, X-authentik-*
  -> cvc-client-cert              passTLSClientCert: X-Forwarded-Tls-Client-Cert = verified cert
  -> cvc-authentik                forwardAuth to the Authentik outpost (high/admin/owner hosts only)
  -> cvc-tiergate                 forwardAuth: cert identity + tier >= host min tier, else 403
  -> upstream
```

Generate the Traefik objects and the matching tier-gate config from the registry:

```sh
python -m cvc.deploygen traefik  --registry access/registry.yaml -o /tmp/routes.yaml
python -m cvc.deploygen tiergate --registry access/registry.yaml -o /tmp/tiergate-cm.yaml
# options: --base-domain D (default orangepi6.humpback-krait.ts.net)
#          --host RES=FQDN (repeatable per-resource override)
#          --registry-hosts (use each resource's registry host verbatim)
```

Route host = `<resource-id>.<base-domain>` unless overridden. Always generate both files with
the same flags: tier-gate matches on the host name, so the keys must be identical. `cvc-access build tiergate`
uses the same canonical resolver (`cvc.access.catalog.tiergate_hosts`) with the same defaults,
so its host keys equal `cvc-deploygen tiergate` and the route hosts (a test checks this). Committed examples from `access/registry.example.yaml` are in
`deploy/traefik/routes.example.yaml` and `deploy/tiergate/configmap.generated.yaml` (a test
keeps them in sync with the generator).

## Ordered deploy

1. **step-ca** (`deploy/step-ca/`, see its README). Follow `init.sh`, create the namespace, PV/PVC,
   secrets and ConfigMap, then apply `deployment.yaml`. step-ca listens on `100.106.97.34:9000`.
2. **Root key offline / on YubiKey.** Once the intermediate is issued, move the root private key
   off the host: store it in YubiKey PIV (`deploy/yubikey/RUNBOOK-yubikey.md`) or offline
   media, and keep only `root_ca.crt` on the PV. Publish the root to Traefik:
   `kubectl -n cvc create secret generic cvc-step-ca-root --from-file=tls.ca=root_ca.crt`.
   Issue the server wildcard for the routes from step-ca:
   `step ca certificate '*.<base-domain>' tls.crt tls.key` and then
   `kubectl -n cvc create secret tls cvc-routes-tls --cert=tls.crt --key=tls.key`. Renew it
   before expiry (a cron or a `step ca renew --daemon` sidecar; not built yet).
3. **Authentik outpost.** In Authentik, create a Proxy provider in *forward auth (domain level)*
   mode for `<base-domain>`, with a passkey (WebAuthn) authentication flow, and bind it to the
   embedded outpost. Check the outpost Service name against `cvc.deploygen.traefik.AUTHENTIK_OUTPOST`
   (`ak-outpost-authentik-embedded-outpost.auth.svc:9000`) and change the constant if it differs.
4. **tier-gate.** `kubectl apply -f deploy/namespace.yaml`, apply the generated tier-gate
   ConfigMap, then apply `deploy/tiergate/tiergate.yaml` without its example ConfigMap. Import
   the image with `sudo k3s ctr images import` (LL-013).
5. **Routes.** First restrict Traefik to Tailscale (see below). Then create one upstream
   Service per resource (`cvc-upstream-<id>`, port 80). For host-side services such as
   calibre-web on `:8083`, use a selector-less Service plus an EndpointSlice pointing at
   `100.106.97.34`. Then `kubectl apply -f /tmp/routes.yaml`.
6. **Takeover API** (`deploy/takeover/takeover.yaml`). Add the `takeover` (min `guest-short`,
   meaning any authenticated tier) and `takeover-admin` (min `owner`) resources to the
   registry, then regenerate and apply the tier-gate ConfigMap and apply the manifest. The
   banner and FAQ live on `takeover.<d>`. Status is only on `takeover-admin.<d>`, which also
   gets the Authentik passkey step, and the app itself checks `X-Cvc-Tier: owner` as well.
   The banner takes the identity from the `X-Cvc-Person` header set by the gate, never from
   a query parameter.

Smoke test, from a tailnet device that has a cert:
`curl --cert dev.crt --key dev.key https://books.<d>/` should return 200 or the app. The same
request without a cert should fail the TLS handshake. Spoofing with
`-H 'X-Cvc-Person: nathan'` should change nothing.

## Entrypoints: Tailscale only (finding F5)

k3s currently publishes Traefik 80/443 through klipper-lb on **every** node address, including
the LAN IP `192.168.1.208`. `deploy/traefik/helmchartconfig-tailscale-only.yaml` (not applied)
turns the Service into a ClusterIP and binds hostPorts 80/443 to `100.106.97.34` only:

```yaml
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata: {name: traefik, namespace: kube-system}
spec:
  valuesContent: |-
    service: {type: ClusterIP}
    ports:
      web:       {hostPort: 80,  hostIP: 100.106.97.34}
      websecure: {hostPort: 443, hostIP: 100.106.97.34}
```

To apply, copy it to `/var/lib/rancher/k3s/server/manifests/traefik-config.yaml`. Then check
that `ss -ltnp` shows only the Tailscale IP. Back this up with a host firewall rule that drops
80/443 on the LAN interface. Note that existing LAN users of Traefik routes will lose access.

## Hostname strategy

- **Now: `*.orangepi6.humpback-krait.ts.net`.** MagicDNS resolves only the machine name, not
  sub-names, and `tailscale cert` cannot issue for sub-names. So: (a) the server cert is a
  step-ca wildcard (clients already trust the step-ca root for mTLS), and (b) the sub-names
  need DNS. Either run a small resolver on the OPi (for example CoreDNS/dnsmasq answering
  `*.orangepi6...` with `100.106.97.34`) and register it as Tailscale split DNS for that
  suffix, or use per-device hosts entries as a stopgap.
- **Later: an owned domain.** Pick a subdomain (for example `home.<owned>`), add a public
  wildcard A record pointing at `100.106.97.34`. It is a CGNAT tailnet address, so it is
  useless off-tailnet, and that is intended. Get a public wildcard server cert by ACME
  DNS-01 (Traefik certResolver or cert-manager). Then regenerate with
  `--base-domain home.<owned>`. Client auth still uses the step-ca root, and nothing else
  changes. Keep both domains routed during the cutover by generating twice with different
  `--namespace` or `--host` overrides.

## Design: future off-tailnet enrollment path (not built)

Goal: a new person or device that is not yet on the tailnet can join and get a device cert,
without exposing any tier-gated service publicly.

- **One public endpoint, nothing else.** `enroll.<owned-domain>` runs on a separate entrypoint
  (or a tiny VPS or Funnel). It serves only `/enroll/*`, has no route to tier-gated hosts, and
  uses no client-cert requirement.
- **One-time invite.** The owner runs `cvc-access invite <person> --tier T --ttl 24h` (future
  command), which creates a random 128-bit token stored hashed with person, tier and expiry,
  and shares it out of band (QR code or Signal). The token can be used once and is
  invalidated on first use or when it expires.
- **Flow.** The client presents the invite. The server validates it and burns it. It then
  (1) mints a single-use, pre-authorized, tagged Tailscale auth key (ephemeral=false,
  expiry 1h, tag `tag:cvc-<tier>`) through the Tailscale API, and (2) returns a step-ca
  one-time token (JWK provisioner, SAN-bound to the device name, short validity) so the
  device generates its own key locally (on a YubiKey or in the platform keystore) and
  requests its cert over the tailnet after joining. The private key never leaves the device.
- **Controls.** Per-IP and global rate limits (for example 5/min per IP, 50/day total),
  constant-time token comparison, generic error messages, an audit log entry per attempt, an
  owner notification on every successful enrollment, and new devices start in registry
  status `pending` until the owner approves them (tier-gate denies `pending`).
- **Threats.** Token theft is limited by single use, short TTL and owner approval. Endpoint
  compromise exposes no secrets beyond the Tailscale API key scoped to auth-key creation, kept
  in a Secret and rotated. The endpoint is never a CA itself: it only hands out tokens.
