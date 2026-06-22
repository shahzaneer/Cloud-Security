# 06 — Audit Log Retention & Immutability

> **Level:** Intermediate–Advanced
> **Prereqs:** [Monitoring Detection SIEM](../Monitoring-Detection-SIEM), [Tabletop Exercise Templates](../IR-Forensics-Cloud/tabletop-exercise-templates.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Impact (log deletion)
> **Authorization scope:** Log retention configuration and Object Lock policies must be tested in your own sandbox accounts. Do not apply to production trails without change control.

## What & why

Logs are the single most important evidence artifact in cloud security. An attacker who obtains `Delete` or `StopLogging` permissions on your log sink can wipe the historical record of every action they took. Long retention + immutability is a defensive perimeter around your audit trail — it means even a fully compromised identity cannot erase the past. Configure retention and immutability *before* you need the logs, because after an incident, it's too late.

## The OnPrem reality

Pre-cloud, log immutability was physical: `chattr +a` on Linux append-only log files, WORM (Write Once Read Many) tape backups, or a central syslog server with disk-level immutability. The syslog server was often the attacker's first target — `rm /var/log/syslog` was the kill switch. The cloud equivalent is Object Lock, immutable blob storage, and cross-account log ingestion so that even the compromised account's administrators cannot destroy evidence.

## Cross-cloud retention & immutability primitives

| Feature | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| **Audit log source** | `auditd`, syslog, Windows Event Log | CloudTrail (mgmt + data events) | Azure Activity Log + resource logs | Cloud Audit Logs (Admin, Data, System, Policy) |
| **Long-retention store** | Elasticsearch ILM → frozen tier | CloudTrail Lake (7-year queryable) | Log Analytics workspace (2yr default, extended), ADX long-term | BigQuery (unlimited, partitioned tables) |
| **Immutability** | `chattr +a`, WORM tape | S3 Object Lock (COMPLIANCE mode) | Immutable Blob Storage with time-based retention policy | GCS Bucket Lock with retention policy |
| **Integrity validation** | `aide` tripwire checksum | CloudTrail log file validation (SHA-256 digest) | Azure Monitor log integrity (AzSecPack) | Cloud Audit Log immutable audit log entry |
| **Cross-account failsafe** | rsyslog relay to separate VLAN | CloudTrail cross-account trail (org trail) | Azure Lighthouse + Log Analytics workspace in separate tenant | Aggregated sinks → separate project |
| **Tamper detection** | `auditd -w` on log dir | CloudTrail `StopLogging` → EventBridge → alert | Activity Log `Delete` on diagnostic setting → alert | `auditLogging.delete` → Pub/Sub → alert |

## AWS — CloudTrail Lake + S3 Object Lock

### Enable CloudTrail Lake (7-year immutable query)

```bash
aws cloudtrail create-event-data-store \
  --name "org-trail-lake-7yr" \
  --retention-period 2557 \
  --multi-region-enabled \
  --organization-enabled \
  --termination-protection-enabled

# Query via CloudTrail Lake
aws cloudtrail start-query \
  --query-statement "SELECT eventTime, eventName, userIdentity.arn, sourceIPAddress \
                     FROM aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
                     WHERE eventTime > '2026-01-01' ORDER BY eventTime DESC LIMIT 100"
```

### S3 trail with Object Lock (Compliance mode)

```hcl
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-logs-111111111111-eu-central-1"
}

resource "aws_s3_bucket_versioning" "trail_versioning" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "trail_lock" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = 7
    }
  }
}

resource "aws_cloudtrail" "org_trail" {
  name                          = "org-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  enable_log_file_validation    = true
  enable_logging                = true
  is_multi_region_trail         = true
  is_organization_trail         = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn
  include_global_service_events = true
}
```

### Log file integrity validation

```bash
# Validate CloudTrail digest files
aws cloudtrail validate-logs \
  --trail-name org-audit-trail \
  --start-time "2026-06-20T00:00:00Z" \
  --end-time "2026-06-21T00:00:00Z"

# Output: Log files delivered between ... are valid (digests match)
```

### Deny CloudTrail deletion via SCP

```json
{
  "Sid": "DenyStopLogging",
  "Effect": "Deny",
  "Action": [
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
    "cloudtrail:DeleteEventDataStore",
    "s3:DeleteObject"
  ],
  "Resource": [
    "arn:aws:cloudtrail:*:111111111111:trail/org-audit-trail",
    "arn:aws:s3:::cloudtrail-logs-111111111111-eu-central-1/*"
  ]
}
```

### Cross-account failsafe — write-only publisher, read-only security

```hcl
# Log bucket in Security account (222222222222) accepts logs from production accounts
data "aws_iam_policy_document" "cross_account_logs" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cross_account_trail.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
  statement {
    effect = "Deny"
    principals { type = "*" }
    actions   = ["s3:DeleteObject", "s3:DeleteBucket"]
    resources = [
      aws_s3_bucket.cross_account_trail.arn,
      "${aws_s3_bucket.cross_account_trail.arn}/*"
    ]
  }
}
```

## Azure — immutable blob + ADX long retention

### Enable immutable blob storage for audit logs

```bash
az storage account create \
  --name auditlogsim00001 \
  --resource-group rg-security \
  --location westeurope \
  --kind StorageV2 \
  --enable-versioning true

az storage container create \
  --name audit-logs \
  --account-name auditlogsim00001

az storage container immutability-policy create \
  --container-name audit-logs \
  --account-name auditlogsim00001 \
  --period 2555  # 7 years in days
```

### Log Analytics workspace long retention

```bash
az monitor log-analytics workspace create \
  --resource-group rg-security \
  --workspace-name law-security-audit-00001 \
  --retention-time 730  # 2 years (max for free tier)

# (as of June 2026, Azure Log Analytics workspace retention can be extended beyond 2 years
# via Data Export rules to Azure Data Explorer (ADX) or storage accounts; interactive retention
# up to 12 years is available on paid tiers)
az monitor log-analytics workspace table update \
  --resource-group rg-security \
  --workspace-name law-security-audit-00001 \
  --name AzureActivity \
  --retention-time 2555
```

### Diagnostic settings — all logs to immutable storage

```bash
az monitor diagnostic-settings create \
  --name audit-all-logs \
  --resource "/subscriptions/00000000-0000-0000-0000-000000000000" \
  --storage-account auditlogsim00001 \
  --logs '[{"category": "Administrative", "enabled": true, "retentionPolicy": {"enabled": true, "days": 2555}}]'
```

### Azure Policy — require diagnostic settings

```hcl
resource "azurerm_policy_definition" "require_diagnostics" {
  name         = "require-resource-diagnostics"
  display_name = "Require diagnostic settings on all resources"
  policy_type  = "Custom"
  mode         = "All"
  policy_rule  = jsonencode({
    if = {
      field = "type"
      notIn = ["Microsoft.Resources/subscriptions/resourceGroups"]
    }
    then = {
      effect = "deployIfNotExists"
      details = {
        type        = "Microsoft.Insights/diagnosticSettings"
        roleDefinitionIds = ["/providers/microsoft.authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"]
        existenceCondition = {
          allOf = [
            { field = "Microsoft.Insights/diagnosticSettings/logs.enabled", equals = "true" }
          ]
        }
      }
    }
  })
}
```

## GCP — BigQuery time travel + bucket lock

### Enable Cloud Audit Logs with default retention

```bash
gcloud services enable logging.googleapis.com --project=sec-audit-project

gcloud logging logs list --project=sec-audit-project

# Log buckets with retention
gcloud logging buckets create audit-logs-bucket \
  --location=us-central1 \
  --retention-days=2555 \
  --project=sec-audit-project

gcloud logging sinks create audit-to-bq \
  bigquery.googleapis.com/projects/sec-audit-project/datasets/audit_logs \
  --log-filter="logName:cloudaudit.googleapis.com" \
  --project=sec-audit-project
```

### GCS bucket lock for log archive

```hcl
resource "google_storage_bucket" "audit_log_archive" {
  name     = "audit-log-archive-000000000000"
  location = "US"
  uniform_bucket_level_access = true

  retention_policy {
    retention_period = 2555 * 86400
    is_locked        = true  # Once locked, can only increase, never decrease or remove
  }

  versioning { enabled = true }
}
```

### BigQuery time travel

```bash
# BigQuery keeps 7 days of time travel by default for accidental deletion
# For longer-term immutability, export snapshots to locked GCS bucket
bq query --use_legacy_sql=false '
  EXPORT DATA OPTIONS(
    uri="gs://audit-log-archive-000000000000/snapshots/2026-Q2/*.parquet",
    format="PARQUET"
  ) AS
  SELECT * FROM `sec-audit-project.audit_logs.cloudaudit_googleapis_com_activity_*`
  WHERE _TABLE_SUFFIX >= "20260401"
'
```

## OnPrem — log immutability

```bash
# Linux: append-only log directory
chattr +a /var/log/audit/

# auditd immutable rules
auditctl -w /etc/shadow -p wa -k identity_modify
auditctl -e 2  # immutable mode — requires reboot to change rules

# Rsyslog relay with TLS to central log server
# /etc/rsyslog.d/50-forward.conf
*.* @@(o)central-logger.example.com:6514
```

## 🔴 Red Team view — "log file deletion is the kill switch"

**Attack narrative:** An attacker who compromises an IAM role with `cloudtrail:StopLogging` can attempt to stop the trail before performing malicious actions. If Object Lock or SCP denies the `StopLogging` call, the attacker must live with the logs being written — they can only evade by blending into the noise immediately after each write.

**Contained exploitation attempts:**

```bash
# Attempt 1: Stop logging — likely denied by SCP or bucket Object Lock
aws cloudtrail stop-logging --name org-audit-trail
# AccessDenied — SCP "DenyStopLogging" blocks it

# Attempt 2: Delete trail
aws cloudtrail delete-trail --name org-audit-trail
# AccessDenied — SCP blocks it

# Attempt 3: Delete log files from S3
aws s3 rm s3://cloudtrail-logs-111111111111-eu-central-1/AWSLogs/111111111111/ --recursive
# AccessDenied — Object Lock in COMPLIANCE mode prevents deletion even for root

# Attempt 4 (advanced): Overwrite log files (historical rewrite)
aws s3 cp forged-log.json.gz \
  s3://cloudtrail-logs-111111111111-eu-central-1/AWSLogs/111111111111/CloudTrail/us-east-1/2026/06/22/log.json.gz
# Succeeds but creates a NEW version (versioning enabled)
# The original log file is preserved as a previous version — not truly overwritten

# Attacker's next move: live inside the noise
# Since logs cannot be stopped or deleted, the attacker:
#   - Spreads actions across many legitimate-looking API calls
#   - Uses assume-role chains to obscure identity
#   - Relies on alert fatigue from high-volume cloud environments
```

**Artifacts left:**
- `AccessDenied` for every `StopLogging`/`DeleteTrail` attempt — these are gold for detection
- Version history on S3 shows attempted overwrites
- Even unsuccessful attempts are logged to the *same* trail (irony)
- CloudTrail log file validation digest would detect any successful corruption

## 🔵 Blue Team view — defense in depth around the audit trail

### Multi-region copy of log bucket

```hcl
resource "aws_s3_bucket_replication_configuration" "log_replication" {
  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "cross-region-logs"
    status = "Enabled"
    destination {
      bucket        = aws_s3_bucket.logs_dr.arn
      storage_class = "STANDARD"
    }
    delete_marker_replication { status = "Disabled" }
  }
}

resource "aws_s3_bucket" "logs_dr" {
  provider = aws.dr_region
  bucket   = "cloudtrail-logs-dr-111111111111-eu-west-1"
}

resource "aws_s3_bucket_object_lock_configuration" "logs_dr_lock" {
  provider = aws.dr_region
  bucket   = aws_s3_bucket.logs_dr.id
  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = 7
    }
  }
}
```

### Cross-account ingestion failsafe

```
Production Account (111111111111)
  CloudTrail
    ├──► S3 in same account (write-only, Object Lock)
    └──► S3 in Security Account (222222222222) — publisher role only, no delete

Security Account (222222222222)
  S3 (cross-account log bucket, Object Lock)
  Only security-auditors can read, NO ONE can delete
```

### Detection: StopLogging attempt

```yaml
title: CloudTrail StopLogging Attempted
id: s7t8o9p0-1000-4000-8000-q1r2s3t4u5v6
status: stable
description: Any attempt to stop CloudTrail logging is critical — even if denied
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: cloudtrail.amazonaws.com
    eventName:
      - StopLogging
      - DeleteTrail
      - UpdateTrail
      - DeleteEventDataStore
  condition: selection
level: critical
```

**AWS CloudWatch Logs Insights — StopLogging attempts (successful or denied):**

```sql
fields @timestamp, userIdentity.arn, eventName, errorCode, sourceIPAddress
| filter eventSource = "cloudtrail.amazonaws.com"
| filter eventName in ["StopLogging", "DeleteTrail", "UpdateTrail", "DeleteEventDataStore"]
| sort @timestamp desc
```

**Azure — diagnostic setting deletion:**

```kql
AzureActivity
| where OperationNameValue == "Microsoft.Insights/diagnosticSettings/delete"
| project TimeGenerated, Caller, OperationNameValue, ResourceId
```

**GCP — audit log sink deletion:**

```bash
gcloud logging logs list --project=sec-audit-project --filter="protoPayload.methodName=google.logging.v2.ConfigServiceV2.DeleteSink"
```

### Alert pipeline — StopLogging → PagerDuty immediately

```hcl
resource "aws_cloudwatch_metric_alarm" "stop_logging" {
  alarm_name  = "CloudTrailStopLoggingAttempt"
  namespace   = "AWS/CloudTrail"
  metric_name = "StopLoggingAttempt"

  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.pagerduty.arn]
}
```

## Hands-on lab — log retention & immutability setup

**Duration:** 15 min. **Cost:** Free-tier S3 + CloudTrail usage.

```bash
# AWS: Create a trail with log validation and object lock bucket
aws s3api create-bucket \
  --bucket trail-test-111111111111-us-east-1 \
  --region us-east-1

aws s3api put-bucket-versioning \
  --bucket trail-test-111111111111-us-east-1 \
  --versioning-configuration Status=Enabled

aws s3api put-object-lock-configuration \
  --bucket trail-test-111111111111-us-east-1 \
  --object-lock-configuration '{"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Years": 1}}}'

aws cloudtrail create-trail \
  --name test-trail \
  --s3-bucket-name trail-test-111111111111-us-east-1 \
  --enable-log-file-validation \
  --no-is-multi-region-trail

aws cloudtrail start-logging --name test-trail

# Generate a log entry
aws s3 ls

# Validate log integrity
aws cloudtrail validate-logs \
  --trail-name test-trail \
  --start-time "2026-06-22T00:00:00Z"

# Teardown
aws cloudtrail stop-logging --name test-trail
aws cloudtrail delete-trail --name test-trail
aws s3 rm s3://trail-test-111111111111-us-east-1/ --recursive
aws s3api delete-bucket --bucket trail-test-111111111111-us-east-1
```

## Detection rules & checklists

```yaml
title: Log Sink Configuration Modified
id: t8u9v0w1-2000-4000-8000-x2y3z4a5b6c7
status: experimental
description: Detects modification or deletion of log export configurations across clouds
# Cross-cloud: covers AWS DeleteTrail/StopLogging, Azure diagnostic setting delete, GCP sink delete
logsource:
  service: cloud_audit
detection:
  aws:
    eventSource: cloudtrail.amazonaws.com
    eventName: ["StopLogging", "DeleteTrail", "UpdateTrail"]
  azure:
    operationName: "Microsoft.Insights/diagnosticSettings/delete"
  gcp:
    methodName: "google.logging.v2.ConfigServiceV2.DeleteSink"
  condition: any of them
level: critical
```

**Log retention & immutability checklist:**

- [ ] CloudTrail/Activity Log/Cloud Audit Log enabled on ALL accounts/projects.
- [ ] Log bucket has Object Lock in COMPLIANCE mode (or equivalent per cloud).
- [ ] SCP/Policy denies `StopLogging` and `DeleteTrail` for all principals except break-glass.
- [ ] Log file validation enabled.
- [ ] Cross-region replication of log bucket.
- [ ] Cross-account log ingestion (publisher ≠ reader account).
- [ ] Alert fires immediately on any `StopLogging`/`DeleteTrail`/delete diagnostic setting.
- [ ] Retention period meets legal/regulatory minimum (typically 1–7 years).
- [ ] Quarterly restore test from log archive proves logs are recoverable.

## References

- [AWS CloudTrail integrity validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [Azure Immutable Blob Storage](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview)
- [GCP Bucket Lock](https://cloud.google.com/storage/docs/bucket-lock)
- [GCP Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- MITRE ATT&CK: T1070 Indicator Removal, T1562.001 Disable or Modify Tools
- Cross-links: [../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md), [../IR-Forensics-Cloud/log-preservation-and-chain-of-custody.md](../IR-Forensics-Cloud/log-preservation-and-chain-of-custody.md)
