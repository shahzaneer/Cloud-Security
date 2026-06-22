# 03 — Azure Log Analytics & Sentinel

> **Level:** Intermediate
> **Prereqs:** [The Security Log Mosaic per Cloud](the-security-log-mosaic-per-cloud.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Discovery, Collection, Defense Evasion
> **Authorization scope:** Configure Log Analytics and Sentinel in your own Azure subscription (pay-as-you-go). All queries run against your own tenant.

## What & why

Azure Log Analytics workspace is the universal sink for all Azure diagnostic telemetry — Activity Logs, resource diagnostics, Entra ID sign-in and audit logs, NSG flow logs, and more. Microsoft Sentinel layers analytics rules (with MITRE mappings), workbooks, and SOAR playbooks on top. Without the workspace + diagnostic pair, your Azure security telemetry is invisible after 90 days.

## The OnPrem reality

Windows Event Forwarding (WEF) with subscriptions pointing domain controllers and servers at a collector node → SCOM for correlation → custom alerts. The whole stack required AD schema extensions, GPOs, and fragile subscription config. Azure Log Analytics replaces this with a single `diagnosticSettings` resource and KQL.

## Core concepts

### The ingestion pipeline

```
[Entra ID Sign-in] ──┐
[Activity Log] ──────┤
[Storage diagnostics]─┤──> Log Analytics Workspace ──> Sentinel Analytics Rules ──> Incidents
[NSG Flow Logs] ─────┤       │
[VM Insights] ───────┘       └──> Workbooks / Dashboards
```

### Key services

| Service | Role | Free-tier friendly? |
|---|---|---|
| Log Analytics workspace | Central telemetry store; KQL query engine | Pay-as-you-go; first 5 GB/month free |
| Diagnostic settings | Per-resource log forwarding to workspace | Free; you pay for ingested data |
| Microsoft Sentinel | SIEM/SOAR layer on top of workspace | Pay-as-you-go; free 31-day trial |
| Azure Data Explorer (ADX) | KQL engine — can query workspace directly | Pay per query |
| Entra ID diagnostic settings | Ships sign-in & audit logs to workspace | Requires Entra ID P1/P2 license |

### KQL essentials

Sentinel detection rules are KQL queries with a recurrence schedule. The building blocks:

```
<TableReference>
| where <column> <operator> <value>
| summarize <aggregation> by <grouping_column>
| project <columns>
| join ...
```

## Azure — enabling the full pipeline

### Step 1: Create a Log Analytics workspace

```bash
az monitor log-analytics workspace create \
  --resource-group rg-sec-monitor \
  --workspace-name central-workspace \
  --location eastus \
  --sku PerGB2018 \
  --retention-time 90
```

### Step 2: Ship Entra ID logs to workspace

```bash
az monitor diagnostic-settings create \
  --name entra-logs \
  --resource "/providers/microsoft.aadiam" \
  --workspace /subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-sec-monitor/providers/microsoft.operationalinsights/workspaces/central-workspace \
  --logs '[
    {"category": "AuditLogs", "enabled": true},
    {"category": "SignInLogs", "enabled": true},
    {"category": "NonInteractiveUserSignInLogs", "enabled": true},
    {"category": "ServicePrincipalSignInLogs", "enabled": true}
  ]'
```

### Step 3: Ship Activity Log to workspace

```bash
az monitor diagnostic-settings create \
  --name sub-activity \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000 \
  --workspace central-workspace-id \
  --logs '[
    {"category": "Administrative", "enabled": true},
    {"category": "Security", "enabled": true},
    {"category": "ServiceHealth", "enabled": true}
  ]'
```

### Step 4: Enable diagnostic settings on a Storage Account

```bash
az monitor diagnostic-settings create \
  --name sa-diag \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/saprod111 \
  --workspace central-workspace-id \
  --logs '[
    {"category": "StorageRead", "enabled": true},
    {"category": "StorageWrite", "enabled": true},
    {"category": "StorageDelete", "enabled": true}
  ]'
```

### Step 5: Onboard Microsoft Sentinel

```bash
az monitor log-analytics workspace sentinel onboard \
  --resource-group rg-sec-monitor \
  --workspace-name central-workspace

# List built-in analytics rule templates (MITRE-mapped)
az sentinel analytics-setting list \
  --resource-group rg-sec-monitor \
  --workspace-name central-workspace
```

### Step 6: Create a custom analytics rule

```bash
az sentinel alert-rule create \
  --resource-group rg-sec-monitor \
  --workspace-name central-workspace \
  --rule-name "Suspicious SPN sign-in from new IP" \
  --query 'SigninLogs
    | where AppDisplayName != ""
    | where ResultType == 0
    | summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Count=count() by IPAddress, AppDisplayName
    | where Count > 10
    | project IPAddress, AppDisplayName, Count' \
  --display-name "Suspicious SPN sign-in volume" \
  --severity Medium \
  --trigger-operator GreaterThan \
  --trigger-threshold 0 \
  --frequency 1h \
  --query-frequency 1h
```

### Terraform equivalent (workspace + Sentinel)

```hcl
resource "azurerm_log_analytics_workspace" "central" {
  name                = "central-workspace"
  resource_group_name = azurerm_resource_group.monitor.name
  location            = azurerm_resource_group.monitor.location
  sku                 = "PerGB2018"
  retention_in_days   = 90
}

resource "azurerm_log_analytics_solution" "sentinel" {
  solution_name         = "SecurityInsights"
  resource_group_name   = azurerm_resource_group.monitor.name
  location              = azurerm_resource_group.monitor.location
  workspace_resource_id = azurerm_log_analytics_workspace.central.id
  workspace_name        = azurerm_log_analytics_workspace.central.name

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/SecurityInsights"
  }
}
```

## AWS (equivalent capability)

AWS equivalent of the "workspace + Sentinel" pair: CloudWatch Logs as the sink, CloudWatch Logs Insights as the KQL analogue, with GuardDuty as the native threat-detection layer.

```bash
aws logs create-log-group --log-group-name /aws/central/audit
aws logs put-retention-policy --log-group-name /aws/central/audit --retention-in-days 90

# CloudWatch Logs Insights query (CloudTrail events forwarded to CW Logs)
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress
| filter eventName = "ConsoleLogin"
| filter responseElements.ConsoleLogin = "Failure"
| stats count() by userIdentity.arn, bin(1h)
```

## GCP (equivalent capability)

GCP equivalent: Cloud Logging → BigQuery sink for SQL, or Cloud Logging → Pub/Sub → Cloud Function for real-time alerting. The "SIEM layer" is either the Log Explorer web console or a BigQuery dataset with scheduled queries.

```bash
gcloud logging sinks create audit-to-bq \
  bigquery.googleapis.com/projects/project-id-111111/datasets/audit \
  --log-filter='logName:"cloudaudit.googleapis.com"'

bq query --use_legacy_sql=false \
  "INSERT INTO \`project-id-111111.audit.alerts\`
   SELECT timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.methodName
   FROM \`project-id-111111.audit.cloudaudit_googleapis_com_activity\`
   WHERE protoPayload.authorizationInfo[0].granted = false
     AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)"
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Central log store | Splunk / ELK index | CloudWatch Logs / S3 | Log Analytics workspace | Cloud Logging / BigQuery |
| Query language | SPL / Lucene | CloudWatch Logs Insights | KQL | Logging query language / SQL |
| SIEM layer | Splunk ES / Elastic SIEM | GuardDuty + CW Alarms | Microsoft Sentinel | SCC + scheduled queries |
| SOAR playbooks | Cortex XSOAR / custom script | EventBridge → Lambda | Sentinel Playbooks (Logic Apps) | Cloud Functions / Workflows |
| Data-plane logs | File audit SACLs | S3 data events (CloudTrail) | Resource diagnostics | Data Access logs |
| IdP log source | AD Event Log | CloudTrail `sts:*` + IAM reports | Entra ID Sign-in / Audit Logs | Cloud Identity login audit |

## 🔴 Red Team view

### Silent detection gap: diagnostic settings disabled per-resource

An attacker who compromises a principal with `Microsoft.Insights/diagnosticSettings/write` can update (or delete) the diagnostic setting on a sensitive storage account, stopping data-plane telemetry from reaching the workspace — and Sentinel rules go silent on reads.

```bash
# Attacker disables StorageRead logging on a blob storage account
az monitor diagnostic-settings create \
  --name sa-diag \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/saprod111 \
  --workspace central-workspace-id \
  --logs '[
    {"category": "StorageRead", "enabled": false},
    {"category": "StorageWrite", "enabled": false},
    {"category": "StorageDelete", "enabled": true}
  ]'

# Then quietly download all blobs:
az storage blob download-batch \
  --destination /tmp/exfil \
  --source saprod111 \
  --account-name saprod111 \
  --sas-token "sv=2024...&se=2027..."
```

**Result:** The Activity Log records the `diagnosticSettings/write` operation, but no `StorageRead` events flow to Log Analytics. Any Sentinel rule watching `StorageBlobLogs | where OperationName == "GetBlob"` never triggers.

### Detection pairing

The Activity Log's `diagnosticSettings/write` call is the salient detection signal. Query for it:

```kql
AzureActivity
| where OperationNameValue contains "diagnosticSettings/write"
| where Properties contains "enabled: false"
| project TimeGenerated, Caller, ResourceId
```

**Artifacts:** `diagnosticSettings/write` in Activity Log, caller identity + timestamp. The setting change itself is audited even if it disables subsequent audits.

## 🔵 Blue Team view

### Azure Policy — enforce diagnostic settings at scale

```json
{
  "mode": "Indexed",
  "policyRule": {
    "if": {
      "field": "type",
      "in": [
        "Microsoft.Storage/storageAccounts",
        "Microsoft.KeyVault/vaults",
        "Microsoft.Network/networkSecurityGroups",
        "Microsoft.Network/publicIPAddresses"
      ]
    },
    "then": {
      "effect": "deployIfNotExists",
      "details": {
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "deployIfNotExists",
        "roleDefinitionIds": [
          "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
        ],
        "existenceCondition": {
          "allOf": [
            {
              "field": "Microsoft.Insights/diagnosticSettings/logs[*].enabled",
              "equals": "true"
            }
          ]
        },
        "deployment": {
          "properties": {
            "mode": "incremental",
            "template": {
              "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              "parameters": {
                "workspaceId": {"type": "string"},
                "resourceName": {"type": "string"}
              },
              "resources": [{
                "name": "[concat(parameters('resourceName'), '/Microsoft.Insights/centralizedDiag')]",
                "type": "Microsoft.Insights/diagnosticSettings",
                "apiVersion": "2021-05-01-preview",
                "properties": {
                  "workspaceId": "[parameters('workspaceId')]",
                  "logs": [
                    {"category": "StorageRead", "enabled": true},
                    {"category": "StorageWrite", "enabled": true}
                  ]
                }
              }]
            }
          }
        }
      }
    }
  }
}
```

### KQL detection samples for Sentinel

```kql
// Diagnostic setting deleted
AzureActivity
| where OperationNameValue contains "diagnosticSettings/delete"
| extend Caller = CallerIpAddress
| project TimeGenerated, Caller, ResourceId, OperationNameValue

// Sign-in from impossible-travel geography (two countries in < 1 hour)
SigninLogs
| where ResultType == 0
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Identity, Country
| extend Countries = pack_array(Country)
| mv-expand Countries to typeof(string)
| summarize CountryCount=dcount(Countries) by Identity
| where CountryCount > 1

// Storage account key access from unknown IP
StorageBlobLogs
| where OperationName == "GetBlob"
| where AuthenticationType == "AccountKey"
| summarize Count=count() by CallerIpAddress, AccountName
| where Count > 100
| order by Count desc

// Sentinel incident auto-creation trigger
// This is done from the Sentinel portal or ARM template, not KQL
```

### Response steps

1. If diagnostic setting deleted: re-deploy via Azure Policy or `az monitor diagnostic-settings create`.
2. If sign-in anomaly: disable the user, revoke sessions: `az ad user update --id "user@example.com" --account-enabled false`.
3. If storage data exfiltration suspected: rotate storage account keys immediately (`az storage account keys renew`), then review Log Analytics for `ListKeys` calls in the preceding hours.

## Hands-on lab

1. Create free-tier Log Analytics workspace:
```bash
az monitor log-analytics workspace create \
  --resource-group rg-lab \
  --workspace-name lab-workspace \
  --location eastus \
  --sku PerGB2018
```

2. Create a storage account and enable diagnostics:
```bash
az storage account create --name salab111 --resource-group rg-lab --location eastus --sku Standard_LRS
az monitor diagnostic-settings create \
  --name lab-diag \
  --resource $(az storage account show --name salab111 --resource-group rg-lab --query id -o tsv) \
  --workspace $(az monitor log-analytics workspace show --resource-group rg-lab --workspace-name lab-workspace --query id -o tsv) \
  --logs '[{"category":"StorageRead","enabled":true},{"category":"StorageWrite","enabled":true}]'
```

3. Upload a blob, then download it to generate logs:
```bash
echo "test" > /tmp/test.txt
az storage blob upload --account-name salab111 --container-name test --name test.txt --file /tmp/test.txt --auth-mode login
az storage blob download --account-name salab111 --container-name test --name test.txt --file /tmp/dl.txt --auth-mode login
```

4. Wait 5-10 minutes, then query in the Log Analytics portal → Logs:
```kql
StorageBlobLogs
| where TimeGenerated > ago(1h)
| project TimeGenerated, OperationName, ObjectKey, CallerIpAddress
```

5. **Teardown:**
```bash
az storage account delete --name salab111 --resource-group rg-lab --yes
az monitor log-analytics workspace delete --resource-group rg-lab --workspace-name lab-workspace --yes
rm /tmp/test.txt /tmp/dl.txt
```

## Detection rules & checklists

```
# Checklist
- [ ] Log Analytics workspace exists and retains >= 90 days
- [ ] Entra ID diagnostic settings ship Sign-in, Audit, and SPN logs
- [ ] Activity Log ships Administrative + Security categories
- [ ] All storage accounts have diagnostic settings (StorageRead + StorageWrite enabled)
- [ ] All Key Vaults have diagnostic settings (AuditEvent enabled)
- [ ] Azure Policy: deployIfNotExists diagnostic settings on all supported types
- [ ] Microsoft Sentinel onboarded with built-in analytics rules activated
- [ ] Custom analytics rules tested with deliberate benign trigger event
- [ ] Sentinel Playbooks created for high-severity incident auto-response
```

## References
- [Azure Monitor diagnostic settings](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings)
- [Microsoft Sentinel documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [KQL quick reference](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [Entra ID diagnostic logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-stream-logs-to-log-analytics)
- [../IAM/authn-flows-and-tokens.md](../IAM/authn-flows-and-tokens.md)
- [../Storage-Data-Security/storage-primitives.md](../Storage-Data-Security/storage-primitives.md)
