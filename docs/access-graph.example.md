# Access graph

Generated 2026-10-31 by `cvc-access build graph` from the access registry.

```mermaid
flowchart LR
    subgraph agents["AI agents"]
        p_personal_dashboard["personal-dashboard"]
        p_playwright_billing["playwright-billing"]
    end
    subgraph machines["Machines / sensors"]
        p_garage_temp["garage-temp"]
    end
    subgraph roles["Roles"]
        r_backup_runner["backup-runner"]
        r_billing_agent["billing-agent"]
        r_sensor_publish["sensor-publish"]
        r_worker_caller["worker-caller"]
    end
    subgraph systems["Systems"]
        s_ha_mqtt["ha-mqtt<br/>mqtt"]
        s_vaultwarden["vaultwarden<br/>credential-store"]
        s_workers["workers<br/>http<br/>(not enforced)"]
    end
    p_personal_dashboard --> r_backup_runner
    p_personal_dashboard --> r_worker_caller
    p_playwright_billing --> r_billing_agent
    p_garage_temp --> r_sensor_publish
    r_backup_runner -->|"1 credential #40;backup#41;: *"| s_vaultwarden
    r_billing_agent -->|"1 credential: pay-invoice"| s_vaultwarden
    r_sensor_publish -->|"write: sensors/#123;id#125;/#35;"| s_ha_mqtt
    r_worker_caller -.->|"documented only"| s_workers
    classDef enforced fill:#dbeafe,stroke:#1d4ed8,color:#0f172a,stroke-width:2px
    classDef unenforced fill:#f1f5f9,stroke:#64748b,color:#0f172a,stroke-dasharray:5 4
    classDef role fill:#ede9fe,stroke:#6d28d9,color:#0f172a
    classDef orphan fill:#fef9c3,stroke:#a16207,color:#0f172a,stroke-dasharray:2 3
    classDef principal fill:#dcfce7,stroke:#15803d,color:#0f172a
    classDef expired fill:#e5e7eb,stroke:#9ca3af,color:#6b7280,stroke-dasharray:3 3
    classDef soon fill:#fed7aa,stroke:#c2410c,color:#0f172a,stroke-width:2px
    class s_ha_mqtt,s_vaultwarden enforced
    class p_personal_dashboard,p_playwright_billing,p_garage_temp principal
    class r_backup_runner,r_billing_agent,r_sensor_publish,r_worker_caller role
    class s_workers unenforced
```

Solid blue = enforced; dashed = documented only (not enforced); grey = expired; orange = expires within 30 days; yellow dashed = unused role.

## Principals

| id | type | roles | expires | status |
|---|---|---|---|---|
| personal-dashboard | agent | backup-runner, worker-caller | 2027-01-31 | active |
| playwright-billing | agent | billing-agent | - | active |
| garage-temp | machine | sensor-publish | - | active |

## Systems

| id | kind | enforced |
|---|---|---|
| ha-mqtt | mqtt | yes |
| vaultwarden | credential-store | yes |
| workers | http | no |
