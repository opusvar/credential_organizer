# Access graph

Generated 2026-10-31 by `cvc-access build graph` from the access registry.

```mermaid
flowchart LR
    subgraph agents["AI agents"]
        p_db_query["db-query<br/>tier: medium"]
        p_personal_dashboard["personal-dashboard<br/>tier: high"]
        p_playwright_billing["playwright-billing<br/>tier: medium"]
        p_visitor_helper["visitor-helper<br/>tier: medium (effective low)"]
    end
    subgraph machines["Machines / sensors"]
        p_cvc_remind["cvc-remind"]
        p_garage_temp["garage-temp"]
        p_home_assistant["home-assistant"]
    end
    subgraph people["People"]
        u_alex["alex<br/>tier: owner"]
        u_sam["sam<br/>tier: medium"]
        u_visitor["visitor<br/>tier: guest-long"]
    end
    subgraph hwkeys["Hardware keys"]
        k_yk_backup["yk-backup<br/>home-safe"]
        k_yk_primary["yk-primary<br/>on-person"]
    end
    subgraph devices["Devices"]
        p_alex_iphone["alex-iphone<br/>phone<br/>cert: active (p12)"]
        p_alex_mac["alex-mac<br/>laptop<br/>cert: pending (yubikey-piv)"]
    end
    subgraph roles["Roles"]
        r_backup_runner["backup-runner"]
        r_billing_agent["billing-agent"]
        r_cvc_remind_publisher["cvc-remind-publisher"]
        r_dashboard_startup["dashboard-startup"]
        r_db_query_startup["db-query-startup"]
        r_home_assistant["home-assistant"]
        r_sensor_publish["sensor-publish"]
        r_worker_caller["worker-caller"]
        r_worker_caller_read["worker-caller-read"]
    end
    subgraph systems["Systems"]
        s_ha_mqtt["ha-mqtt<br/>mqtt<br/>internal/act"]
        s_vaultwarden["vaultwarden<br/>credential-store<br/>private/act"]
        s_workers["workers<br/>http<br/>internal/write<br/>(not enforced)"]
    end
    u_alex --> p_alex_iphone
    u_alex --> p_alex_mac
    p_alex_mac --> k_yk_primary
    u_alex -.->|"sponsors"| p_db_query
    u_alex -.->|"sponsors"| p_personal_dashboard
    u_alex -.->|"sponsors"| p_playwright_billing
    u_visitor -.->|"sponsors"| p_visitor_helper
    p_db_query --> r_db_query_startup
    p_personal_dashboard --> r_backup_runner
    p_personal_dashboard --> r_dashboard_startup
    p_personal_dashboard --> r_worker_caller
    p_playwright_billing --> r_billing_agent
    p_visitor_helper --> r_worker_caller_read
    p_cvc_remind --> r_cvc_remind_publisher
    p_garage_temp --> r_sensor_publish
    p_home_assistant --> r_home_assistant
    p_alex_iphone --> r_worker_caller
    p_alex_mac --> r_worker_caller
    r_backup_runner -->|"1 credential #40;backup#41;: * #91;secret/read via broker-approved#93;"| s_vaultwarden
    r_billing_agent -->|"1 credential: pay-invoice #91;private/act#93;"| s_vaultwarden
    r_cvc_remind_publisher -->|"write: cvc/reminders/#35;, homeassistant/sensor/cvc_stale_credentials/config #91;internal/write#93;"| s_ha_mqtt
    r_dashboard_startup -->|"1 credential: startup #91;private/read#93;"| s_vaultwarden
    r_db_query_startup -->|"1 credential: startup #91;private/read#93;"| s_vaultwarden
    r_home_assistant -->|"readwrite: #35; #91;internal/act#93;"| s_ha_mqtt
    r_sensor_publish -->|"write: sensors/#123;id#125;/#35; #91;internal/write#93;"| s_ha_mqtt
    r_worker_caller -.->|"documented only #91;internal/write#93;"| s_workers
    r_worker_caller_read -.->|"documented only #91;internal/read#93;"| s_workers
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
    class u_alex,u_sam,u_visitor person
    class p_db_query,p_personal_dashboard,p_playwright_billing,p_visitor_helper,p_cvc_remind,p_garage_temp,p_home_assistant,p_alex_iphone,p_alex_mac principal
    class r_backup_runner,r_billing_agent,r_cvc_remind_publisher,r_dashboard_startup,r_db_query_startup,r_home_assistant,r_sensor_publish,r_worker_caller,r_worker_caller_read role
    class s_workers unenforced
```

Solid blue = enforced; dashed = documented only (not enforced); grey = expired; data/action labels (D16) are shown on systems and in brackets on grant edges; dotted 'sponsors' edges link a person to the agents they sponsor; orange = expires within 30 days; yellow dashed = unused role. Revoked certs and lost/revoked/retired hardware keys are grey. Cert serials and fingerprints are never shown.

## Principals

| id | type | tier | sponsor | roles | expires | status |
|---|---|---|---|---|---|---|
| db-query | agent | medium | alex | db-query-startup | - | active |
| personal-dashboard | agent | high | alex | backup-runner, dashboard-startup, worker-caller | 2027-01-31 | active |
| playwright-billing | agent | medium | alex | billing-agent | - | active |
| visitor-helper | agent | medium (effective low) | visitor | worker-caller-read | 2026-12-31 | active |
| cvc-remind | machine | - | - | cvc-remind-publisher | - | active |
| garage-temp | machine | - | - | sensor-publish | - | active |
| home-assistant | machine | - | - | home-assistant | - | active |
| alex-iphone | device | - | - | worker-caller | - | active |
| alex-mac | device | - | - | worker-caller | - | active |

## People

| id | tier | tailnet | ha | expires | granted by |
|---|---|---|---|---|---|
| alex | owner | owner | none | - | - |
| sam | medium | family | none | - | alex |
| visitor | guest-long | guests | none | 2026-12-31 | alex |

## Devices

| id | owner | kind | cert storage | cert status | cert not after | history entries |
|---|---|---|---|---|---|---|
| alex-iphone | alex | phone | p12 | active | 2027-01-31 | 1 |
| alex-mac | alex | laptop | yubikey-piv | pending | - | 0 |

## Hardware keys

| id | owner | model | uses | location | status | device certs |
|---|---|---|---|---|---|---|
| yk-backup | alex | YubiKey 5 NFC | fido2-vaultwarden, recovery | home-safe | active | 0 |
| yk-primary | alex | YubiKey 5C NFC | fido2-vaultwarden, piv-device-cert, recovery | on-person | active | 1 |

## Resources

| id | name | host | kind | min tier | ha level | passkey |
|---|---|---|---|---|---|---|
| books | Calibre library | books.example.home | library | guest-long | - | no |
| dashboard | Personal dashboard | dash.example.home | dashboard | high | - | yes |
| ha | Home Assistant | ha.example.home | ha | medium | limited-control | no |
| media | Jellyfin | media.example.home | media | media-only | - | no |
| portainer | Portainer | portainer.example.home | admin | admin | - | yes |

## What each person can reach

Same rule as the tier gate: active person, tier >= resource min tier. `yes*` = passkey (Authentik) also required.

| person | tier | books | dashboard | ha | media | portainer |
|---|---|---|---|---|---|---|
| alex | owner | yes | yes* | yes | yes | yes* |
| sam | medium | yes | - | yes | yes | - |
| visitor | guest-long | yes | - | - | - | - |

## Systems

| id | kind | data | action | enforced |
|---|---|---|---|---|
| ha-mqtt | mqtt | internal | act | yes |
| vaultwarden | credential-store | private | act | yes |
| workers | http | internal | write | no |
