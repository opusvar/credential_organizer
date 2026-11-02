# Agent onboarding: moving a service onto the cvc broker

This runbook moves an agent from secrets in an env file to fetching each secret from the cvc
broker by Vaultwarden item UUID and purpose. It uses two agents as worked examples:

| Agent | Tier | Purpose | Placeholder item UUID |
|-------|------|---------|-----------------------|
| `personal-dashboard` | high | `startup` | `22222222-3333-4444-5555-666666666666` |
| `db-query` | medium | `startup` | `33333333-4444-5555-6666-777777777777` |

Both agents have placeholder entries in `access/registry.example.yaml` and
`deploy/broker-acl.yaml`. Every value below is a placeholder (`example.com`, `10.0.0.x`, the
UUIDs and hashes above). Put real values only in the gitignored live files.

> **Approval gate.** Steps 5 (rebuild/redeploy) and 7 (restart the agent) change running
> services. the owner has to approve each one before it runs. Steps 1–4 and 6 are preparation and
> can be done ahead of time.

## 0. Inventory the secrets

List the env keys the service reads, by name only. Do not open the `.env` file:

```bash
grep -rnoE 'os\.(environ|getenv)[^)]*' /path/to/service --include='*.py'
```

Each secret becomes one Vaultwarden item (or one field on a shared item). Non-secret settings
such as hosts, ports and DB names stay in env.

## 1. Create the vault items

Make one item per secret in the broker's Vaultwarden account, for example
`db-query/db-password` and `personal-dashboard/api-key`. Put the secret in the item's
**password** field. The broker returns `password`, `username` or `totp` only.

```bash
bw sync
bw get template item | jq '.name="db-query/db-password" | .login={"username":"dbq","password":"<paste>"}' \
  | bw encode | bw create item
```

## 2. Get each item's UUID

The ACL is keyed by UUID, not by item name:

```bash
bw get item "db-query/db-password" | jq -r .id
# -> 33333333-4444-5555-6666-777777777777   (placeholder)
```

## 3. Generate the agent token

```bash
PYTHONPATH=src python -m cvc.broker.tokens
```

The command prints the token and its sha256. The **sha256** goes in the ACL and registry.
The **token** is handed to the agent once (step 6) and is never committed or logged.

## 4. Add the registry and ACL entries

`access/registry.yaml` (live copy of the example): give the agent a role with a vaultwarden
grant for the item UUID and purpose `startup`, then set `tier`, `sponsor` and `token_sha256`.
Run `cvc-access validate && cvc-access check`, then regenerate the ACL:

```bash
cvc-access build broker-acl --out deploy/broker-acl.yaml
```

The ACL entry has this shape:

```yaml
  db-query:
    tier: medium
    token_sha256: "<sha256 from step 3>"
    allow:
      - credential: "<uuid from step 2>"
        purposes: ["startup"]
```

## 5. Push the ACL, and rebuild/redeploy the broker if needed (NEEDS APPROVAL)

**Does the broker reload its ACL without a redeploy? Yes.** `cvc.broker.app._acl()` calls
`Acl.load()` on every request, and the ACL is mounted from the `cvc-broker-acl` Secret as a
volume at `/etc/cvc` with no `subPath`, so the kubelet refreshes the file in place (usually
within about 60s). An ACL-only change therefore needs only the Secret update:

```bash
kubectl -n cvc create secret generic cvc-broker-acl \
  --from-file=broker-acl.yaml=deploy/broker-acl.yaml --dry-run=client -o yaml | kubectl apply -f -
```

(`deploy/rotate-token.sh` does the same for token rotation.) If the ACL fails to parse, the
broker logs `acl_load_failed` and denies everything (fails closed), so check the logs after
pushing.

A **broker image rebuild and redeploy** is needed only when broker code changed. On this host
k3s has its own containerd, so the image has to be imported with `k3s ctr`, not
`nerdctl --namespace k8s.io`:

```bash
deploy/rebuild.sh            # nerdctl build -> nerdctl save -> sudo k3s ctr -n k8s.io images import
deploy/rebuild.sh --restart  # also rollout-restarts cvc-broker (APPROVAL REQUIRED)
```

## 6. Install the token file on the agent host

```bash
install -d -m 700 ~/.config/cvc
install -m 600 /dev/stdin ~/.config/cvc/db-query.token   # paste the token, then Ctrl-D
```

The file must be mode 600 and owned by the service user. Then set the agent's env (systemd
`Environment=` or its env file). These are not secrets:

```bash
CVC_BROKER_URL=https://broker.example.com:8710
CVC_AGENT_ID=db-query
CVC_AGENT_TOKEN_FILE=/home/svc/.config/cvc/db-query.token
CVC_CA_BUNDLE=/etc/ssl/certs/home-ca.pem
```

Map each secret to its UUID, for example
`CVC_SECRET_DB_PASSWORD=33333333-4444-5555-6666-777777777777`. After the first successful
broker-backed start, remove the plaintext values from the env file.

## 7. Restart the agent (NEEDS APPROVAL)

Check the service's logs for active connections first, then restart it, for example
`systemctl --user restart db-query`. Confirm:

- the broker audit log shows `allow` for the agent/UUID/purpose `startup`;
- the service is healthy;
- no secret value appears in the service logs or the broker logs.

**Rollback:** unset `CVC_BROKER_URL`. Clients fall back to env only when it is unset, so
restore the env values before restarting.

## Worked examples

### personal-dashboard (tier high)

- Items: the dashboard's API keys. Purpose `startup`; role `dashboard-startup` in the registry.
- Tier high: an allow entry marked `physical: true` would require per-use human approval.
  Keep startup secrets non-physical.
- The agent already holds `backup-runner` (the `backup` sentinel, broker-approved). That grant
  is unchanged.

### db-query (tier medium)

- Items: the database credentials. Purpose `startup`; role `db-query-startup`.
- Client changes: a broker client that reads `CVC_BROKER_URL`, `CVC_AGENT_TOKEN_FILE` and
  `CVC_CA_BUNDLE`, fetches each secret by UUID with purpose `startup`, keeps values only in
  memory, fails closed if any fetch fails, and falls back to env only when `CVC_BROKER_URL` is
  unset. db-query is not under version control yet. Make it a git repo before applying the
  change.
