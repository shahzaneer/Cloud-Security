# 02 — CloudTrail Activity & Data Events

> **Level:** Intermediate
> **Prereqs:** [The Security Log Mosaic per Cloud](the-security-log-mosaic-per-cloud.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion (T1562.008), Discovery
> **Authorization scope:** Configure CloudTrail only in your own AWS sandbox account. All queries run against your own telemetry.

## What & why

CloudTrail is AWS's immutable audit backbone — every management API call and (when enabled) every data-plane read/write passes through it. Understanding the tiers (Event History, Trail, Lake, Insight) and the cost-coverage tradeoffs maps directly to whether an attacker's S3 `GetObject` or DynamoDB `Scan` becomes a ledger entry or a ghost.

## The OnPrem reality

Linux `auditd` with `audit.rules` trawls every `open()`, `execve()`, `unlink()` syscall matching a filter. Windows Advanced Audit Policy logs file read/write events (SACL on filesystem objects). Both generate extreme volume — the SIEM admin had to toggle rules per-host and accept gaps. CloudTrail's management events are the narrow-focused equivalent, but data events are the per-object analogue that historically no one enabled pre-cloud because the volume was prohibitive.

## Core concepts

### Management vs Data events

| Dimension | Management events | Data events |
|---|---|---|
| What's recorded | Create/Update/Delete on AWS resources | Read/Write to resource *contents* |
| Examples | `RunInstances`, `CreateRole`, `AttachRolePolicy` | `GetObject`, `PutObject`, `DynamoDB.GetItem` |
| Default state | ON (90-day Event History) | OFF — must explicitly enable |
| Volume | Low (admin actions) | High (per-object access) |
| Cost | Free for mgmt, Trail: $0.00 for first copy | $0.10/100k events (after free tier) |
| Attack evasion | Cannot be disabled (StopLogging recorded) | Data events not recorded → blind spot |

### Trail types

| Trail type | Scope | Cost model | Use case |
|---|---|---|---|
| Single-region trail | One region only | One trail in S3 | Legacy accounts |
| Multi-region trail | All regions, one S3 prefix | One trail, all region events | Every account should use this |
| Organization trail | All accounts in AWS Org | One trail in mgmt account; events in member accounts appear | Enterprise baseline |

### CloudTrail Lake — SQL-queryable event store

Lake copies management and data events into a queryable data store (not S3). You define an **event data store** with a retention period (7d to 7y). Lake supports SQL queries over the events with zero S3 copy management — but charges per GB ingested and per GB scanned.

### CloudTrail Insights — anomaly ML

Insights scans management events and surfaces unusual API call patterns — e.g., a sudden spike in `CreateAccessKey` calls from a previously inactive IAM user. It costs $0.35/100k events analyzed. It produces `CloudTrailInsight` events sent to the same S3 bucket as the trail.

### Log file integrity validation

Every CloudTrail log file in S3 includes a SHA-256 hash in the file metadata. A separate digest file chain (`_CloudTrail-Digest_`) contains hourly hashes of all log files, creating a tamper-evident chain. To verify a log file hasn't been altered post-delivery: `aws cloudtrail validate-logs --trail-name org-management-trail --start-time "2026-06-22T00:00:00Z"`.

## AWS

### Create a full organization trail with all bells

```bash
aws cloudtrail create-trail \
  --name org-full-trail \
  --s3-bucket-name cloudtrail-central-111111111111 \
  --is-multi-region-trail \
  --is-organization-trail \
  --enable-log-file-validation \
  --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:111111111111:log-group:cloudtrail:* \
  --cloud-watch-logs-role-arn arn:aws:iam::111111111111:role/CloudTrail-CWLogs \
  --kms-key-id arn:aws:kms:us-east-1:111111111111:key/example-key-id

aws cloudtrail start-logging --name org-full-trail
```

### Add data events for all S3 buckets

```bash
aws cloudtrail put-event-selectors \
  --trail-name org-full-trail \
  --advanced-event-selectors '[
    {
      "Name": "Management selector",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Management"]}
      ]
    },
    {
      "Name": "S3 data selector",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}
      ]
    }
  ]'
```

### Enable CloudTrail Lake

```bash
aws cloudtrail create-event-data-store \
  --name audit-lake-7y \
  --retention-period 2557 \
  --advanced-event-selectors '[
    {
      "Name": "All events",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Management", "Data"]}
      ]
    }
  ]' \
  --multi-region-enabled
```

### Query Lake

```bash
aws cloudtrail start-query \
  --query-statement "SELECT eventTime, eventName, userIdentity.arn, sourceIPAddress FROM event_data_store_id WHERE eventTime > '2026-06-01' AND eventName = 'StopLogging'"
```

## Azure (equivalent capability)

Azure's CloudTrail analogue is the **Activity Log** (ARM-level management operations, default on, 90d retention) + **resource-level diagnostic logs** for data-plane.

### Org-level Activity Log export

```bash
az monitor diagnostic-settings create \
  --name org-activity-export \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000 \
  --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"ServiceHealth","enabled":true}]' \
  --event-hub subscription-logs-eventhub
```

### Data-plane diagnostics (equivalent to S3 data events)

```bash
az monitor diagnostic-settings create \
  --name sa-data-plane \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/saprod111 \
  --logs '[{"category":"StorageRead","enabled":true},{"category":"StorageWrite","enabled":true}]' \
  --workspace central-workspace-id
```

**Gotcha:** Diagnostic settings are **per-resource** in Azure. There is no "all storage accounts in subscription" toggle. Use Azure Policy to enforce at scale.

## GCP (equivalent capability)

GCP's CloudTrail analogue is **Cloud Audit Logs** — split into four types:

| Type | Audited operations | Default | Disable-able |
|---|---|---|---|
| Admin Activity | Create/Update/Delete API calls | ON, forced | **Cannot disable** |
| Data Access | Read/Write to resource contents | OFF | Must enable per-service |
| Policy Denied | Calls rejected by IAM or Org Policy | ON, forced | Cannot disable |
| System Event | Compute Engine non-API events | ON | Cannot disable |

### Enable Data Access on Cloud Storage

```bash
gcloud projects get-iam-policy project-id-111111 --format json > /tmp/policy.json
# Edit policy to add auditConfigs block for storage
# Then:
gcloud projects set-iam-policy project-id-111111 /tmp/policy.json
```

The `auditConfigs` block:
```json
{
  "auditConfigs": [
    {
      "service": "storage.googleapis.com",
      "auditLogConfigs": [
        {"logType": "ADMIN_READ"},
        {"logType": "DATA_READ"},
        {"logType": "DATA_WRITE"}
      ]
    }
  ]
}
```

### BigQuery sink (GCP's "Lake" equivalent)

```bash
gcloud logging sinks create audit-to-bq \
  bigquery.googleapis.com/projects/project-id-111111/datasets/audit_logs \
  --log-filter='logName:"cloudaudit.googleapis.com" AND severity>=DEFAULT'

bq query --use_legacy_sql=false \
  'SELECT timestamp, protoPayload.methodName, protoPayload.authenticationInfo.principalEmail FROM `project-id-111111.audit_logs.cloudaudit_googleapis_com_activity` WHERE timestamp > "2026-06-01"'
```

## OnPrem mapping (auditd equivalent)

```bash
# auditd rule — log all execve calls by non-root
auditctl -a exit,always -F arch=b64 -S execve -F uid>=1000 -k user-exec

# Equivalent CloudTrail mgmt event
# CloudTrail event: eventName=RunInstances
# azure Activity Log: Microsoft.Compute/virtualMachines/write
# GCP: compute.instances.insert
```

| Concern | OnPrem (auditd) | AWS (CloudTrail) | Azure (Activity+Diagnostics) | GCP (Cloud Audit Logs) |
|---|---|---|---|---|
| Admin activity | `execve` filter | Mgmt events, default on | Activity Log — Administrative, default on | Admin Activity, forced on |
| Data access | SACL on inodes | Data events, default off | Storage diagnostics, default off | Data Access, default off per service |
| Policy denied | N/A | AccessDenied logged in CloudTrail | Activity Log 403 entries | Policy Denied, forced on |
| Integrity | aide / tripwire | SHA-256 digest chain in S3 | Immutable Log Analytics tables | Bucket lock on sink |
| Query layer | ausearch / aureport | CloudTrail Lake SQL | KQL in Log Analytics | BigQuery SQL |

## 🔴 Red Team view

### Disabling the trail — attacker TTPs

An attacker who has compromised a principal with `cloudtrail:StopLogging` can suppress future management events before executing high-signal actions.

```bash
aws cloudtrail stop-logging --name org-management-trail
# Alternatively, delete the trail outright:
aws cloudtrail delete-trail --name org-management-trail
```

**There is a window:** `StopLogging` itself is a management event logged by CloudTrail *before* logging stops. The attacker's high-signal actions after `StopLogging` are lost, but the `StopLogging` call is always recorded — unless the attacker deletes the S3 files before they reach durable storage.

**Azure equivalent:** Deleting a diagnostic setting is recorded in Activity Log. But the diagnostic setting disappears and data-plane telemetry stops to the sink.

**GCP equivalent:** Admin Activity logs **cannot be disabled** — a major defensive advantage. But Data Access logs can silently go dark if the `auditConfigs` block is removed from IAM policy.

### Evading detection by targeting the data-plane gap

Even without touching CloudTrail, an attacker evades detection entirely for data theft if data events aren't enabled:

```bash
aws s3 cp s3://prod-db-backups/backup-2026-06-22.enc /tmp/stolen.enc
# 0 log entries if data events not enabled for this bucket.
```

### Artifacts

- `StopLogging` / `DeleteTrail`: recorded in CloudTrail mgmt events (the trail logs its own death).
- `UpdateTrail` with `--no-include-global-service-events`: disables global service event logging silently.
- In GCP: removal of `auditConfigs` block in IAM policy is logged as `SetIamPolicy` with the diff.
- In Azure: `diagnosticSettings/delete` appears in Activity Log at the resource scope.

## 🔵 Blue Team view

### Preventive controls

**AWS SCP — deny StopLogging and DeleteTrail organisation-wide:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::111111111111:role/BreakGlassCloudTrailAdmin"
        }
      }
    },
    {
      "Effect": "Deny",
      "Action": [
        "organizations:LeaveOrganization"
      ],
      "Resource": "*"
    }
  ]
}
```

**Azure Policy — enforce diagnostic settings on all supported resources:**

```json
{
  "policyRule": {
    "if": {
      "field": "type",
      "in": ["Microsoft.Storage/storageAccounts", "Microsoft.KeyVault/vaults", "Microsoft.Network/networkSecurityGroups"]
    },
    "then": {
      "effect": "deployIfNotExists",
      "details": {
        "type": "Microsoft.Insights/diagnosticSettings",
        "existenceCondition": {
          "allOf": [
            {"field": "Microsoft.Insights/diagnosticSettings/logs.enabled", "equals": "true"}
          ]
        },
        "deployment": {
          "properties": {
            "mode": "incremental",
            "template": {
              "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              "resources": [{
                "type": "Microsoft.Insights/diagnosticSettings",
                "apiVersion": "2021-05-01-preview",
                "properties": {
                  "workspaceId": "[parameters('workspaceId')]",
                  "logs": [
                    {"category": "StorageRead", "enabled": true},
                    {"category": "StorageWrite", "enabled": true},
                    {"category": "StorageDelete", "enabled": true}
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

**GCP Org Policy — enforce data access logging:**

> (as of June 2026, the GCP Org Policy constraint to enforce data access audit logging is `constraints/cloud.auditEnableDataAccessLogs`. Verify the current name at [GCP Org Policy constraints](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints).)

### Detection signals

```
# CloudWatch metric alarm on StopLogging
MetricName: StopLogging
Namespace: CloudTrailMetrics
Threshold: >= 1
Period: 300
Statistic: Sum

# CloudWatch Logs Insights query
fields @timestamp, userIdentity.arn, eventName, sourceIPAddress
| filter eventName in ["StopLogging", "DeleteTrail", "UpdateTrail"]
| filter ispresent(userIdentity.arn)

# Azure KQL — log sink tampering
AzureActivity
| where OperationNameValue contains "diagnosticSettings/delete"
   or OperationNameValue contains "diagnosticSettings/write"
| where Properties contains "enabled: false"
| project TimeGenerated, Caller, ResourceId

# GCP Logging — data access log config removed
protoPayload.methodName="SetIamPolicy"
protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE"
protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/logging.configWriter"
```

### Response steps

1. **Isolate:** Attach `DenyAll` inline policy to the principal that called `StopLogging`.
2. **Re-enable:** `aws cloudtrail start-logging --name <trail>`
3. **Assess gap:** Query CloudTrail Event History for all events by that principal in the last hour. Cross-reference with CloudTrail Lake.
4. **Validate integrity:** `aws cloudtrail validate-logs` to ensure log files weren't tampered with post-delivery.
5. **Replicate:** Mirror CloudTrail to a separate security account that the compromised account cannot touch.

## Hands-on lab

1. Check current CloudTrail config:
```bash
aws cloudtrail describe-trails
aws cloudtrail get-event-selectors --trail-name <trail-name>
```

2. If data events are off, enable them on a test S3 bucket:
```bash
aws s3 mb s3://trail-data-test-111111111111
aws cloudtrail put-event-selectors --trail-name <trail> \
  --advanced-event-selectors '[
    {"Name":"S3 data","FieldSelectors":[
      {"Field":"eventCategory","Equals":["Data"]},
      {"Field":"resources.type","Equals":["AWS::S3::Object"]},
      {"Field":"resources.ARN","StartsWith":["arn:aws:s3:::trail-data-test-111111111111"]}
    ]}
  ]'
```

3. Generate a data event:
```bash
echo "audit me" > /tmp/trail-test.txt
aws s3 cp /tmp/trail-test.txt s3://trail-data-test-111111111111/
```

4. Query Event History (wait ~15min for delivery):
```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=PutObject --max-results 3
```

5. **Teardown:**
```bash
aws s3 rm s3://trail-data-test-111111111111/trail-test.txt
aws s3 rb s3://trail-data-test-111111111111
rm /tmp/trail-test.txt
```

## Detection rules & checklists

```
# Sigma rule — CloudTrail StopLogging detected
title: AWS CloudTrail StopLogging Detected
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: StopLogging
  condition: selection
level: high

# Checklist
- [ ] CloudTrail is multi-region and organization-wide
- [ ] SCP denies `cloudtrail:StopLogging` / `DeleteTrail` to all but break-glass role
- [ ] CloudWatch alarm on `StopLogging` events
- [ ] S3 data events enabled on sensitive buckets
- [ ] CloudTrail Lake enabled (or Athena queries over S3) for long-term forensics
- [ ] Digest file validation run monthly
- [ ] Logs replicated to separate security account
- [ ] CloudTrail log file encryption with KMS-CMK (not default S3-SSE)
```

## References
- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [CloudTrail Lake](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html)
- [Azure Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
- [GCP Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [GCP Logging sinks](https://cloud.google.com/logging/docs/export/configure_export_v2)
- [../IAM/permission-boundaries-and-quarantine.md](../IAM/permission-boundaries-and-quarantine.md)
- [../Blue-Team-Defense/blue-team-basics.md](../Blue-Team-Defense/blue-team-basics.md)
