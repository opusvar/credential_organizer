# Mosquitto ACL for the cvc/ topic namespace

cvc publishes approval requests (`cvc/approvals/...`, D18) and audit findings
(`cvc/audits/...`, D24) as retained MQTT messages. A client that can write there could forge
or wipe an approval card, so:

| MQTT user | cvc/approvals/# | cvc/audits/# | rest of cvc/# |
|---|---|---|---|
| broker user (site.yaml `mqtt_username`) | readwrite | readwrite | readwrite |
| dashboard | read | read | none |
| Home Assistant | read | read | none |
| everyone else | none | none | none |

## How it is generated

The access registry already generates the Mosquitto `acl_file`
(`cvc-access build mosquitto`, `src/cvc/access/mosquitto.py`), so there is no separate cvc
ACL generator. Merge the roles in `deploy/mosquitto/cvc-acl.registry-snippet.yaml` into your
registry. `tests/test_access_mosquitto.py` checks that the snippet builds and that the output
matches the table above.

The build enforces the rule. With `--cvc-writer USER` (default: site.yaml `mqtt_username`;
`-` turns the check off), the build fails if any OTHER user has `write` or `readwrite` on a
topic whose first level is `cvc`, `+` or `#`. A Home Assistant grant of `readwrite #` must
be narrowed, for example to `readwrite homeassistant/#` plus the cvc reads. That is
intended: `readwrite #` would let HA overwrite approvals.

## Applying it (cvc does not do this)

1. `cvc-access build mosquitto --registry REG.yaml --out acl.generated`, then review the
   diff against the live file. Mosquitto denies everything not granted once `acl_file` is
   set, so every other device's block must be in the same generated file.
2. Create a `mosquitto_passwd` entry for each user in the file. cvc never handles MQTT
   passwords; the broker's password is `MQTT_PASSWORD`, which is env-only.
3. Install the file as the broker's `acl_file` and reload Mosquitto. Check that HA still
   connects and that the dashboard still shows approvals.
