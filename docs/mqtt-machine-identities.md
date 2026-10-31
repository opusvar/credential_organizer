# MQTT machine identities

Goal: replace the shared `mqtt_user` login with one Mosquitto user per sensor, with
least-privilege topics from `access/registry.yaml`.

## Migrate one sensor at a time
1. Add the machine (`auth: {type: mqtt-user, username: ...}`) and a role; see `access/registry.example.yaml`.
   Keep the `home-assistant` and `cvc-remind` entries: once an ACL is active, anything unlisted is denied.
2. Generate the ACL (`mosquitto` builder). It warns if no principal can read `#`/`homeassistant/#`.
3. Add the user to the password file, then reconfigure that one sensor and confirm in HA.
4. Repeat. Retire the shared `mqtt_user` only after every client has its own login.

Usernames needing a password entry: `cvc.access.mosquitto.mqtt_usernames(registry)`.

## Passwords
Never in the registry or this repo. Store each in Vaultwarden, then create the entry on the
broker host with `mosquitto_passwd <passwd_file> <user>` (prompts; no password on the command line).

## Apply and roll back
Existing config (found read-only): `/home/admin/containers/mosquitto/config/mosquitto.conf`
(also `/mnt/data/mosquitto/config/mosquitto.conf`). Back it up first, then add:

    per_listener_settings true
    password_file /mosquitto/config/passwd
    acl_file /mosquitto/config/acl

`per_listener_settings` must come before listener lines; `allow_anonymous`, password and ACL
then apply per listener. Restart Mosquitto and check HA and cvc-remind reconnect.

Rollback: restore the backed-up `mosquitto.conf`, restart. Keep the shared `mqtt_user`
working until migration is complete so rollback is a single file.

## Multiple mqtt systems
The `mosquitto` builder merges all mqtt systems (one broker, one ACL). For one system, call
`build_mosquitto(registry, today, system="<id>")`.
