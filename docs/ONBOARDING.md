# Onboarding wizard: `cvc onboard person|agent`

Also available as `cvc-onboard person|agent` and `python -m cvc.onboard`.

The wizard walks through every step of adding a person or an AI agent. Each step prints
what it will do and a `verify:` line that tells you how to check it. Missing required
values are prompted for.

| Flag | Effect |
|---|---|
| `--dry-run` | Show every step, the registry diff and the generated files. Nothing is written. |
| (default) | Print commands and plans. The registry is written only after you type the person/agent id to confirm. Review files go to `--out-dir` (default `onboard-out/`). |
| `--execute` (person only) | Run the step-ca commands, but only if `step` is on PATH. Make the Authentik API calls, but only if `AUTHENTIK_URL` and `AUTHENTIK_TOKEN` are set. |

Site-specific values (step-ca URL, services-node IP, base domain, default owner ids for
`cvc-access ... --owner/--granted-by` and `python -m cvc.tailnet policy --owner`) come from
the site config, not from code. See [SITE-CONFIG.md](SITE-CONFIG.md). With no
`default_owner_ids` set, those flags are required. The `deploy/...` scripts the wizard prints
must be run from a copy rendered with `cvc-site render-deploy`.

The wizard never calls the Tailscale API. Generated files (tailnet policy, tiergate
ConfigMap) are written for you to review, and nothing applies them.

## `cvc onboard person`

```
cvc onboard person --id alice --name "Alice A" --tier medium --granted-by alex \
  --email alice@example.com --device alice-pixel:phone --device alice-mbp:laptop --dry-run
```

1. **Who.** Sets the id, display name (stored in the `added` history entry), tier, tailnet, `granted_by`
   and email. The tailnet defaults to `guests` for guests, `owner` for owners, and `family` for everyone else.
   Guests (`guest-short`/`guest-long`) default to expiring in 5 days and take `--ha none|view|limited-control`.
   The tier, tailnet and grant rules come from `cvc-access check` (`check_tiers`). Any error for the new person
   is a refusal.
2. **Devices.** `--device ID:KIND[:STORAGE[:HWKEY]]` can be repeated. Each device is added with its cert set
   to `pending` (`device_add`). The wizard prints the step-ca command, the provisioner and lifetime (the same
   values as `deploy/step-ca/issue-p12.sh`), and the URI SANs `urn:cvc:person/device/tier` that
   `templates/device-leaf.tpl` renders from token claims:
   - phone: `deploy/step-ca/issue-p12.sh` (.p12 + .mobileconfig)
   - p12 laptop/desktop: `step ca token --set person=… --set device=… --set tier=…` then `step ca certificate`
   - `yubikey-piv`: `deploy/yubikey/issue-device-cert.sh` (key on slot 9a)

   Record the result afterwards with `cvc-access device set-cert`.
3. **Hardware keys** (owner/admin only). `--hwkey ID:ROLE[:LOCATION[:SERIAL:MODEL]]`. The wizard prints the
   `deploy/yubikey/enroll-mac.sh` → `cvc-access hwkey enroll --from-ykman` → `issue-device-cert.sh` steps.
   If you give a serial and model, the key is enrolled now (`hwkey_enroll`).
4. **Tailscale.** Prints the invite step (an owner joins the owner tailnet; anyone else joins their own
   tailnet and is shared `services-node`). Regenerates the owner-tailnet policy (`build_policy`) into
   `onboard-out/tailnet-policy.hujson`.
5. **Authentik.** Plans the user, the tier group `cvc-tier-<tier>` and the membership. A passkey is required
   for high/admin/owner.
6. **Owners only.** A checklist of Vaultwarden Emergency Access grants to and from every other active owner
   (View 15 days, Takeover 90 days, Takeover 180 days), plus `cvc takeover recovery-set <id>`.
7. **Summary.** Shows the registry diff and asks for typed confirmation, then writes the registry.
   Regenerates the tiergate ConfigMap into `onboard-out/tiergate-configmap.yaml` and prints the final
   checklist.

As with `cvc-access` edits, writing the registry keeps key order but drops YAML comments.

## `cvc onboard agent`

```
cvc onboard agent --id helper --tier low --sponsor sam --granted-by alex --role readmq --dry-run
```

The agent is placed on tailnet `agents`. The roles must exist. Each grant is classified against the D16
matrix (`classify_grant`). A grant that exceeds the ceiling, a bad sponsor, or a grant-rule violation is a
refusal. A grant that needs per-action approval is shown as a warning. The session token is minted out of
band, and the registry stores only `--token-sha256`.
