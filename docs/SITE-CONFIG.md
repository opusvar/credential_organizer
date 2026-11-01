# Site config: product vs. site

cvc is split into two parts:

| | Lives in | Contains |
|---|---|---|
| **Product** | this repo | code, tests, generic examples, deploy *templates* (`${SITE_*}` placeholders) |
| **Site** | outside this repo | one installation's values: node IPs, tailnet, base domain, default owner ids, rendered manifests, the real access registry |

Nothing in this repo may name a real installation. `tests/test_site.py::test_no_private_site_values_in_repo`
fails CI if known private values appear in any tracked file. It has no allowlist.

## site.yaml

`cvc.site.load()` resolves the site config in this order (first hit wins):

1. `--site FILE` (on `cvc-site`, `cvc-deploygen`, `python -m cvc.tailnet`)
2. `$CVC_SITE`
3. `$XDG_CONFIG_HOME/cvc/site.yaml` (default `~/.config/cvc/site.yaml`)
4. built-in generic defaults: `100.64.0.1`, `cvc.example.ts.net`, no default owner

Start from [`site.example.yaml`](../site.example.yaml). Keys:

| Key | Used for |
|---|---|
| `node_ip` | hostIP binds, tailnet ACL `services-node`, default `ca_url` and broker URL |
| `lan_ip` | docs/comments in the Traefik override |
| `base_domain` | route hosts `<resource>.<base_domain>`, default `vault_url` |
| `tailnet` | tailnet name |
| `default_owner_ids` | default `--owner`/`--granted-by` (`cvc-access`) and `--owner` (`cvc.tailnet`). If empty, the flag is required. |
| `ca_admin_email` | step-ca OIDC admin in `ca.json.tmpl` |
| `broker_port`, `vault_port`, `ca_port`, `ca_url`, `vault_url`, `namespaces` | optional overrides |

`cvc-site show` prints the resolved values and which file they came from.

## Deploy templates

Files under `deploy/` use `${SITE_NODE_IP}`, `${SITE_LAN_IP}`, `${SITE_BASE_DOMAIN}`,
`${SITE_TAILNET}`, `${SITE_CA_URL}`, `${SITE_VAULT_URL}`, `${SITE_BROKER_URL}`,
`${SITE_BROKER_PORT}`, `${SITE_CA_ADMIN_EMAIL}` and `${SITE_NS_*}`. Render them:

```sh
cvc-site render-deploy --out ~/cvc-site/deploy
```

Only `${SITE_*}` is replaced. Other `${...}` (shell variables in scripts) are left alone, and an
unknown `${SITE_*}` name is an error. The generated examples
(`deploy/traefik/routes.example.yaml`, `deploy/tiergate/configmap.generated.yaml`) use the
generic base domain. Regenerate yours with `cvc-deploygen` (it reads `base_domain` from the site).

## Where your site data goes

- `~/.config/cvc/site.yaml`: your site values (never commit it here).
- A private site repo or directory (for example `~/cvc-site/`): rendered `deploy/`, the real
  `access/registry.yaml`, and generated tier-gate/tailnet files. Keep it in its own private git
  repo if you want history.
- `*.env` secrets stay where they are today and are never part of either repo.

Tests never read your real config. `tests/conftest.py` redirects `HOME`/`XDG_CONFIG_HOME` to a
temp dir and points `CVC_SITE` at a synthetic site (`100.64.0.10`, `cvc.example.ts.net`, owner
`alex`).
