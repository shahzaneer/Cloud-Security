# 01 — The Security Log Mosaic Per Cloud

> **Level:** Fundamental
> **Prereqs:** [Shared Responsibility](../Fundamentals/shared-responsibility.md) (Cloud Architecture & Shared Responsibility)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** see ATT&CK Cloud matrix for Discovery, Defense Evasion
> **Authorization scope:** Enable/disable logs only in your own sandbox accounts. All detection queries run against your own telemetry.

## What & why

Cloud security begins with knowing which log you need and where it's NOT collected by default. Each provider ships a mosaic of control-plane logs, data-plane logs, flow logs, DNS logs, sign-in logs, and threat-detection findings — many default off. If you don't enable the tile, the attacker walks through it silently.

## The OnPrem reality

Pre-cloud, you shipped everything to Splunk: syslog from Linux boxes, `Windows Event Log` from domain controllers, `journald` for systemd services, `auditd` for kernel-level syscall tracing, firewall syslog (ASA/pfSense), and proxy logs. The SIEM admin wrote a `props.conf` and a `transforms.conf` per source type. Cloud replaces 80% of those sources with three API-backed services — but each requires explicit opt-in for its most valuable part.

## Core concepts — the mosaic tile table

| Log tile | AWS | Azure | GCP | OnPrem | Default ON? |
|---|---|---|---|---|---|
| Control-plane mgmt log | CloudTrail (management events) | Activity Log | Cloud Audit Logs — Admin Activity | auditd / sudo log | **Yes** (all three) |
| Data-plane access log | CloudTrail S3 data events / DynamoDB Streams | Storage Logs / Blob diagnostics / Key Vault logs | Cloud Audit Logs — Data Access | File server access audit | **NO** — must enable |
| VPC / network flow log | VPC Flow Logs | NSG Flow Logs / VNet Flow Logs | VPC Flow Logs | NetFlow / sFlow on router | **NO** — must enable |
| DNS query log | Route 53 Resolver Query Logs | Azure DNS query logs / Private DNS | Cloud DNS logging | BIND / Unbound query log | **NO** — must enable |
| IdP / sign-in log | IAM Identity Center logs / AWS SSO | Entra ID Sign-in Logs / Audit Logs | Cloud Identity Login Audit | AD Security log (Event 4624/4625) | **Varies** — Entra Sign-in is P1/P2 licensed |
| Threat detection findings | GuardDuty | Defender for Cloud alerts | SCC — Event Threat Detection | OSSEC / Wazuh alerts | **NO** — must enable service |
| Load-balancer access log | ALB/NLB/CLB Access Logs | App Gateway / LB diagnostics | Cloud Load Balancing logging | HAProxy / Nginx access log | **NO** — must enable |
| API gateway / function log | API Gateway execution logs, Lambda CW logs | APIM logs, Function App logs | API Gateway / Cloud Functions logs | App server access log | **Partial** — execution logs on API Gateway default off |

### The gotcha gap

The three cloud providers ALL log control-plane management API calls by default (who created/updated/deleted what). But data-plane access — who read an S3 object, who listed a Blob container, who `get`'d a secret from Key Vault — is **off by default everywhere**. This is the attacker's silent corridor.

## AWS

### CloudTrail: the backbone

Management events (Create/Delete/Update anything) are recorded in CloudTrail by default for the last 90 days (Event History). For durable, cross-account log storage you must create a **trail**.

**Enable via CLI — management trail to S3:**

```bash
aws cloudtrail create-trail \
  --name org-management-trail \
  --s3-bucket-name cloudtrail-logs-111111111111 \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id arn:aws:kms:us-east-1:111111111111:key/example-key-id
aws cloudtrail start-logging --name org-management-trail
```

**Enable S3 data events (NOT default, costs charge per 100k events):**

```bash
aws cloudtrail put-event-selectors \
  --trail-name org-management-trail \
  --event-selectors '[
    {
      "ReadWriteType": "All",
      "IncludeManagementEvents": true,
      "DataResources": [
        {
          "Type": "AWS::S3::Object",
          "Values": ["arn:aws:s3:::my-bucket/"]
        }
      ]
    }
  ]'
```

### VPC Flow Logs

```bash
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-id vpc-11111111 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name vpc-flow-logs
```

### Route 53 Resolver Query Logs

```bash
aws route53resolver create-resolver-query-log-config \
  --name dns-queries \
  --destination-arn arn:aws:logs:us-east-1:111111111111:log-group:dns-logs
```

## Azure

### Activity Log (default, 90-day retention)

Every ARM-level operation (create/update/delete a resource) appears in the Activity Log automatically. To retain beyond 90 days, export via **diagnostic settings**.

**Export Activity Log to Log Analytics workspace:**

```bash
az monitor diagnostic-settings create \
  --name export-activity-log \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000 \
  --workspace /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-monitor/providers/Microsoft.OperationalInsights/workspaces/central-workspace \
  --logs '[{"category": "Administrative", "enabled": true}, {"category": "Security", "enabled": true}]'
```

### Storage Blob diagnostics (OFF by default)

```bash
az monitor diagnostic-settings create \
  --name blob-diag \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/saprod111 \
  --logs '[{"category": "StorageRead", "enabled": true}, {"category": "StorageWrite", "enabled": true}, {"category": "StorageDelete", "enabled": true}]' \
  --workspace /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-monitor/providers/Microsoft.OperationalInsights/workspaces/central-workspace
```

### NSG Flow Logs

```bash
az network watcher flow-log configure \
  --nsg nsg-prod \
  --resource-group rg-prod \
  --storage-account saflowlogs111 \
  --enabled true \
  --retention 90
```

## GCP

### Cloud Audit Logs — Admin Activity (always ON, cannot disable)

Every `Create`, `Delete`, `Update`, `SetIamPolicy` on any GCP resource is logged. These logs are visible in Cloud Logging under `activity` log type.

### Cloud Audit Logs — Data Access (OFF by default, per-service)

**Data Access must be explicitly enabled per service.** Example — enable DATA_READ for Cloud Storage:

```bash
gcloud logging sinks create gcs-data-access \
  storage.googleapis.com/projects/project-id-111111/locations/global/buckets/audit-logs-111111 \
  --log-filter='logName:"cloudaudit.googleapis.com%2Fdata_access" resource.type:"gcs_bucket"'

gcloud logging read 'logName="projects/project-id-111111/logs/cloudaudit.googleapis.com%2Fdata_access"' --limit 10
```

Alternative via `gcloud services enable` and explicit audit config in IAM policy:

```bash
gcloud projects get-iam-policy project-id-111111 --format json > /tmp/policy.json
# Add auditConfig for DATA_READ/WRITE on storage.googleapis.com
gcloud projects set-iam-policy project-id-111111 /tmp/policy.json
```

### VPC Flow Logs

```bash
gcloud compute networks subnets update subnet-prod \
  --region us-central1 \
  --enable-flow-logs \
  --logging-aggregation-interval interval-5-sec \
  --logging-flow-sampling 1.0
```

### Cloud DNS Logging

```bash
gcloud dns policies create dns-logging-policy \
  --networks default \
  --enable-logging \
  --description "Audit DNS queries"
```

## Terraform mosaic baseline snippet

```hcl
resource "aws_cloudtrail" "org_trail" {
  name                          = "org-management-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  is_organization_trail         = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::${aws_s3_bucket.data.id}/"]
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name               = "activity-to-workspace"
  target_resource_id = "/subscriptions/00000000-0000-0000-0000-000000000000"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.central.id

  log {
    category = "Administrative"
    enabled  = true
  }
  log {
    category = "Security"
    enabled  = true
  }
}

resource "google_logging_project_sink" "audit_to_bq" {
  name        = "audit-to-bq"
  destination = "bigquery.googleapis.com/projects/project-id-111111/datasets/audit_logs"
  filter      = "logName:\"cloudaudit.googleapis.com\""
  unique_writer_identity = true
}
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Management audit | auditd / sudo log | CloudTrail mgmt events | Activity Log (Administrative) | Cloud Audit Logs — Admin Activity |
| Data access audit | File server SACLs | S3 data events (opt-in) | Storage diagnostics (opt-in) | Data Access logs (opt-in per service) |
| Network flow | NetFlow / sFlow | VPC Flow Logs (opt-in) | NSG Flow Logs (opt-in) | VPC Flow Logs (opt-in) |
| DNS queries | BIND query log | Route 53 Resolver Query Logs (opt-in) | Private DNS diagnostics (opt-in) | Cloud DNS logging (opt-in) |
| Sign-in / auth | AD Security log | CloudTrail + IAM reports | Entra ID Sign-in / Audit Logs | Cloud Identity Login Audit |
| Central sink | Splunk / ELK | S3 → Athena / CW Logs | Log Analytics workspace | Cloud Logging → BigQuery |

## 🔴 Red Team view

### The "data-plane gap" — contained demonstration

The most dangerous concealable action in AWS: reading objects from S3 without data events enabled. Only data events capture `GetObject`.

**Before enabling data events** — attacker reads a bucket undetected:

```bash
aws s3 cp s3://my-bucket/customer-data.csv /tmp/exfil.csv
# CloudTrail records: NOTHING for this read.
# GuardDuty records: NOTHING (no anomaly in S3 API patterns without data events as baseline).
```

**After enabling data events** on the same bucket — repeat the read:

```bash
aws s3 cp s3://my-bucket/customer-data.csv /tmp/exfil.csv
# CloudTrail now records:
#   eventName: GetObject
#   eventSource: s3.amazonaws.com
#   sourceIPAddress: x.x.x.x
#   userAgent: aws-cli/2.x
```

**Attackers also target:** `s3:ListObjects` to enumerate bucket contents, `dynamodb:Scan` to exfiltrate tables, `kms:Decrypt` on a data key — all default-off data events.

**Azure equivalent gap:** Without StorageRead diagnostics enabled on a Blob storage account, an attacker with a compromised SAS token can download every blob — and the Activity Log shows zero read operations, only the SAS token generation.

**GCP equivalent gap:** Without Data Access logging enabled on Cloud Storage, `storage.objects.get` produces no audit log entry.

**Artifacts of this technique:** Even without data events, attacker access to S3 still requires an authenticated principal (IAM role, user key, or federated session). The `sts:GetCallerIdentity` call pre-recon and any IAM enumeration calls (`iam:ListRoles`, `iam:ListAttachedUserPolicies`) are management events logged by default. Defense: look for unusual IAM enumeration followed by a quiet period.

## 🔵 Blue Team view

### The full mosaic baseline — one IaC module

Deploy a single Terraform module across every account/project/tenant that forces the following ON:

```
☑ CloudTrail org trail multi-region with S3 data events on all buckets containing sensitive data
☑ CloudTrail Lake copy for SQL queries on raw events
☑ VPC Flow Logs on all VPCs → S3/CloudWatch
☑ Route 53 resolver query logs
☑ GuardDuty at org level (auto-enroll new accounts)
☑ All findings → EventBridge → central SIEM
☑ SCP denying `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail`
```

**Equivalent one-liner audit per cloud:**

```bash
aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`].{Name:Name,S3Bucket:S3BucketName,Logging:IsLogging}' --output table

az monitor diagnostic-settings list --resource /subscriptions/00000000-0000-0000-0000-000000000000 --query 'value[?logs[?category==`Administrative`].enabled]'

gcloud logging logs list --filter='logName:"cloudaudit.googleapis.com%2Fdata_access"' --format 'table(logName)'
```

### Preventive controls

| Control | AWS | Azure | GCP |
|---|---|---|---|
| Prevent log disable | SCP deny `cloudtrail:StopLogging` | Azure Policy `Deny` on diagnostic setting delete | Org policy `storage.googleapis.com` audit logging constraint |
| Prevent log deletion | SCP deny `cloudtrail:DeleteTrail` | Resource lock on Log Analytics workspace | `logging.sinks` IAM restriction |
| Auto-enable new accounts | AWS Organizations auto-enroll | Azure Lighthouse / Policy at MG level | Org policy inheritance |
| Immutable logs | S3 Object Lock on CloudTrail bucket | Immutable storage on Log Analytics (30d+) | Bucket lock on log sink GCS bucket |

### Detection queries

```
# CloudWatch Logs Insights — Check for CloudTrail disabling
fields @timestamp, userIdentity.arn, eventName
| filter eventName in ["StopLogging", "DeleteTrail", "UpdateTrail"]
| stats count() by userIdentity.arn, eventName

# Azure KQL — Diagnostic setting removal
AzureActivity
| where OperationNameValue contains "diagnosticSettings/delete"
| project TimeGenerated, Caller, ResourceId

# GCP Logging — Sink deletion
resource.type="logging_sink"
protoPayload.methodName="google.logging.v2.ConfigServiceV2.DeleteSink"
```

## Hands-on lab

1. In your AWS sandbox, check what's currently logged:
```bash
aws cloudtrail describe-trails --query 'trailList[*].{Name:Name, Selectors:EventSelectors}'
```

2. If no trail exists with data events, create one targeting a test S3 bucket:
```bash
aws s3 mb s3://detection-test-bucket-111111111111
aws cloudtrail put-event-selectors --trail-name <your-trail> \
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::detection-test-bucket-111111111111/"]}]}]'
```

3. Put a test object, then read it:
```bash
echo "test data" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://detection-test-bucket-111111111111/
aws s3 cp s3://detection-test-bucket-111111111111/test.txt /tmp/readback.txt
```

4. Check CloudTrail Event History for `GetObject` event — should now appear.

5. **Teardown:**
```bash
aws s3 rm s3://detection-test-bucket-111111111111/test.txt
aws s3 rb s3://detection-test-bucket-111111111111
rm /tmp/test.txt /tmp/readback.txt
```

## Detection rules & checklists

```
# Cloud Custodian — verify CloudTrail is multi-region and logging
policies:
  - name: cloudtrail-enabled
    resource: cloudtrail
    filters:
      - type: status
        key: IsLogging
        value: false

# Skipped check — alert
- [ ] Multi-region CloudTrail exists and is logging
- [ ] S3 data events enabled on buckets containing PII/secrets
- [ ] VPC Flow Logs enabled on all VPCs
- [ ] NSG Flow Logs enabled (Azure) / Subnet flow logs (GCP)
- [ ] Route 53 / Private DNS logs enabled
- [ ] Entra ID Sign-in logs shipping to Log Analytics (Azure)
- [ ] GuardDuty / Defender for Cloud / SCC Event Threat Detection enabled
- [ ] SCP/Policy denies log disabling by non-admin principals
```

## References
- [AWS CloudTrail Data Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events.html)
- [Azure Monitor diagnostic settings](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings)
- [GCP Cloud Audit Logs overview](https://cloud.google.com/logging/docs/audit)
- [../IAM/identity-primitives-per-cloud.md](../IAM/identity-primitives-per-cloud.md)
- [../Blue-Team-Defense/blue-team-basics.md](../Blue-Team-Defense/blue-team-basics.md)
