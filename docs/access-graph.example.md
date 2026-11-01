# Access graph

Generated 2026-10-31 by `cvc-access build graph` from the access registry.

```mermaid
flowchart LR
    subgraph agents["AI agents"]
        p_personal_dashboard["personal-dashboard"]
        p_playwright_billing["playwright-billing"]
    end
    subgraph machines["Machines / sensors"]
        p_cvc_remind["cvc-remind"]
        p_garage_temp["garage-temp"]
        p_home_assistant["home-assistant"]
    end
    subgraph people["People"]
        u_nathan["nathan"]
    end
    subgraph hwkeys["Hardware keys"]
        k_yk_backup["yk-backup<br/>home-safe"]
        k_yk_primary["yk-primary<br/>on-person"]
    end
    subgraph devices["Devices"]
        p_nathan_iphone["nathan-iphone<br/>phone<br/>cert: active (p12)"]
        p_nathan_mac["nathan-mac<br/>laptop<br/>cert: pending (yubikey-piv)"]
    end
    subgraph roles["Roles"]
        r_backup_runner["backup-runner"]
        r_billing_agent["billing-agent"]
        r_cvc_remind_publisher["cvc-remind-publisher"]
        r_home_assistant["home-assistant"]
        r_sensor_publish["sensor-publish"]
        r_worker_caller["worker-caller"]
    end
    subgraph systems["Systems"]
        s_ha_mqtt["ha-mqtt<br/>mqtt"]
        s_vaultwarden["vaultwarden<br/>credential-store"]
        s_workers["workers<br/>http<br/>(not enforced)"]
    end
    u_nathan --> p_nathan_iphone
    u_nathan --> p_nathan_mac
    p_nathan_mac --> k_yk_primary
    p_personal_dashboard --> r_backup_runner
    p_personal_dashboard --> r_worker_caller
    p_playwright_billing --> r_billing_agent
    p_cvc_remind --> r_cvc_remind_publisher
    p_garage_temp --> r_sensor_publish
    p_home_assistant --> r_home_assistant
    p_nathan_iphone --> r_worker_caller
    p_nathan_mac --> r_worker_caller
    r_backup_runner -->|"1 credential #40;backup#41;: *"| s_vaultwarden
    r_billing_agent -->|"1 credential: pay-invoice"| s_vaultwarden
    r_cvc_remind_publisher -->|"write: cvc/reminders/#35;, homeassistant/sensor/cvc_stale_credentials/config"| s_ha_mqtt
    r_home_assistant -->|"readwrite: #35;"| s_ha_mqtt
    r_sensor_publish -->|"write: sensors/#123;id#125;/#35;"| s_ha_mqtt
    r_worker_caller -.->|"documented only"| s_workers
    classDef enforced fill:#dbeafe,stroke:#1d4ed8,color:#0f172a,stroke-width:2px
    classDef unenforced fill:#f1f5f9,stroke:#64748b,color:#0f172a,stroke-dasharray:5 4
    classDef role fill:#ede9fe,stroke:#6d28d9,color:#0f172a
    classDef orphan fill:#fef9c3,stroke:#a16207,color:#0f172a,stroke-dasharray:2 3
    classDef principal fill:#dcfce7,stroke:#15803d,color:#0f172a
    classDef expired fill:#e5e7eb,stroke:#9ca3af,color:#6b7280,stroke-dasharray:3 3
    classDef person fill:#fce7f3,stroke:#be185d,color:#0f172a
    classDef hwkey fill:#fef3c7,stroke:#b45309,color:#0f172a
    classDef soon fill:#fed7aa,stroke:#c2410c,color:#0f172a,stroke-width:2px
    class s_ha_mqtt,s_vaultwarden enforced
    class k_yk_backup,k_yk_primary hwkey
    class u_nathan person
    class p_personal_dashboard,p_playwright_billing,p_cvc_remind,p_garage_temp,p_home_assistant,p_nathan_iphone,p_nathan_mac principal
    class r_backup_runner,r_billing_agent,r_cvc_remind_publisher,r_home_assistant,r_sensor_publish,r_worker_caller role
    class s_workers unenforced
```

Solid blue = enforced; dashed = documented only (not enforced); grey = expired; orange = expires within 30 days; yellow dashed = unused role. Revoked certs and lost/revoked/retired hardware keys are grey. Cert serials and fingerprints are never shown.

## Principals

| id | type | roles | expires | status |
|---|---|---|---|---|
| personal-dashboard | agent | backup-runner, worker-caller | 2027-01-31 | active |
| playwright-billing | agent | billing-agent | - | active |
| cvc-remind | machine | cvc-remind-publisher | - | active |
| garage-temp | machine | sensor-publish | - | active |
| home-assistant | machine | home-assistant | - | active |
| nathan-iphone | device | worker-caller | - | active |
| nathan-mac | device | worker-caller | - | active |

## Devices

| id | owner | kind | cert storage | cert status | cert not after | history entries |
|---|---|---|---|---|---|---|
| nathan-iphone | nathan | phone | p12 | active | 2027-01-31 | 1 |
| nathan-mac | nathan | laptop | yubikey-piv | pending | - | 0 |

## Hardware keys

| id | owner | model | uses | location | status | device certs |
|---|---|---|---|---|---|---|
| yk-backup | nathan | YubiKey 5 NFC | fido2-vaultwarden, recovery | home-safe | active | 0 |
| yk-primary | nathan | YubiKey 5C NFC | fido2-vaultwarden, piv-device-cert, recovery | on-person | active | 1 |

## Systems

| id | kind | enforced |
|---|---|---|
| ha-mqtt | mqtt | yes |
| vaultwarden | credential-store | yes |
| workers | http | no |
