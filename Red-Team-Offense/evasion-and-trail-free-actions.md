# 08 — Evasion & Trail-Free Actions

> **Level:** Advanced
> **Prereqs:** [Monitoring Detection SIEM](../Monitoring-Detection-SIEM), [Initial Access Vectors](initial-access-vectors.md) through [Lateral Movement & Pivoting](lateral-movement-and-pivoting.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion (T1562, T1070, T1574, T1535), Discovery
**Authorization scope:** Run only against your own sandbox accounts / sanctioned engagement with written authorization. All trails, logs, and resources below are placeholders.

## What & why
Not every cloud API call generates a management-plane log event by default. Data-plane operations (e.g., S3 `GetObject`, DynamoDB `GetItem`, Azure Storage `GetBlob`) and certain service actions (e.g., SSM Session Manager shell activity) require *opt-in* logging. Attackers exploit these gaps to move, read, and exfiltrate without triggering default detection pipelines.

## The OnPrem reality
On-prem evasion means clearing event logs (`wevtutil cl`), disabling Sysmon, tampering with EDR hooks, or living entirely in memory (fileless malware). The attacker must actively *delete* evidence. In cloud, evasion is often *passive* — you choose actions that never generate logs in the first place.

## Core concepts

### Trail-free action classes

| Class | Description | Default Logged? |
|---|---|---|
| **Data-plane reads** | `s3:GetObject`, `dynamodb:GetItem`, `kms:Decrypt` | No (requires data event trail) |
| **Data-plane writes** | `s3:PutObject`, `sqs:SendMessage` | No (requires data event trail) |
| **Service-internal actions** | SSM session shell commands, ECS container exec | No (separate logging) |
| **Read-only discovery actions** | `sns:ListTopics`, `sqs:ListQueues` | Yes (management plane) |
| **Console-only actions** | Actions taken via the web console | Yes (CloudTrail logs console actions) |
| **Resource policy evaluation** | IAM policy simulation (`SimulatePrincipalPolicy`) | Yes |
| **Cross-service implicit actions** | Lambda invoking S3 internally | Lambda invocation logged; S3 call may not be |

### Default logging coverage by cloud

| Service Action | AWS | Azure | GCP |
|---|---|---|---|
| Object read (`GetObject` / `GetBlob`) | NO by default (needs data event trail) | NO by default (needs storage diagnostic setting) | YES (Admin Activity audit enabled by default; data access needs enabling) |
| Object write (`PutObject`) | NO by default | NO by default | YES (data access audit must be enabled) |
| Database item read (`GetItem`) | NO (DynamoDB data events) | NO (Cosmos DB diagnostic setting) | NO (Firestore audit log config) |
| Secret read (`GetSecretValue`) | NO by default (Secrets Manager data events) | YES (Key Vault audit log enabled by default; as of June 2026, data plane operations are logged to Azure Monitor) | NO (Secret Manager needs data access audit) |
| Queue message receive | NO (SQS data events not available) | NO (Service Bus diagnostic) | NO (Pub/Sub data access) |
| Shell session content (SSM / Cloud Shell) | NO (session content stored separately, off by default) | NO (Cloud Shell not audited for commands) | NO (Cloud Shell `$HOME` persisted, commands not audited) |
| VPC flow logs | NO (opt-in) | NO (NSG flow logs opt-in) | NO (VPC flow logs opt-in) |

## AWS

### Trail-free recon via SNS and SQS enumeration

```bash
# These are MANAGEMENT plane calls — they ARE logged in CloudTrail
aws sns list-topics
aws sqs list-queues
# CloudTrail eventNames: ListTopics, ListQueues

# But reading messages from SQS is a DATA plane action — NOT logged by default
aws sqs receive-message --queue-url https://sqs.us-east-1.amazonaws.com/111111111111/my-queue
# CloudTrail: NO event emitted (data plane, no data event trail available for SQS)
```

### S3 data events — the default blind spot

```bash
# Upload a file to a bucket — management plane: no event
aws s3 cp /tmp/data.txt s3://example-bucket/data.txt
# CloudTrail: NO PutObject event by default

# Read a file from a bucket
aws s3 cp s3://example-bucket/secrets.txt -
# CloudTrail: NO GetObject event by default

# List bucket contents — management plane: YES, logged
aws s3 ls s3://example-bucket/
# CloudTrail: ListBucket event emitted
```

### Enabling S3 data events for detection

```bash
# Create a CloudTrail trail with S3 data events enabled
aws cloudtrail create-trail --name security-data-trail --s3-bucket-name cloudtrail-logs-bucket

aws cloudtrail put-event-selectors --trail-name security-data-trail \
  --event-selectors '[
    {
      "ReadWriteType": "All",
      "IncludeManagementEvents": true,
      "DataResources": [
        {
          "Type": "AWS::S3::Object",
          "Values": ["arn:aws:s3:::example-bucket/"]
        }
      ]
    }
  ]'
# Now all S3 object-level operations generate CloudTrail events
```

### SSM Session Manager — tunnel without SSH logs

```bash
# Start an SSM session to an EC2 instance — management event logged
aws ssm start-session --target i-0abcdef1234567890
# CloudTrail: StartSession event emitted

# Shell commands executed inside the SSM session:
# ls -la /home
# cat /etc/passwd
# These generate NO CloudTrail events by default
# Session content is ONLY logged if you enable S3/CloudWatch logging on the SSM document

# Prevent tunneling abuse:
aws ssm update-document --name SSM-SessionManagerRunShell --content '{
  "schemaVersion":"1.0",
  "inputs":{
    "s3BucketName":"ssm-session-logs-bucket",
    "s3EncryptionEnabled":true,
    "cloudWatchLogGroupName":"/ssm/sessions",
    "cloudWatchEncryptionEnabled":true
  }
}'
```

### Other trail-free or partially-trail-free actions

| Action | Default CloudTrail Coverage | How to Cover |
|---|---|---|
| `s3:GetObject` / `s3:PutObject` | None | Enable data events on bucket |
| `dynamodb:GetItem` / `PutItem` | None | Enable DynamoDB data events |
| `lambda:Invoke` (async) | None | Enable Lambda data events |
| `kms:Decrypt` | Optional data events | Enable KMS data events on key |
| `secretsmanager:GetSecretValue` | None by default | Enable Secrets Manager data events |
| SSM session shell commands | None | Enable session logging to S3/CloudWatch |
| ECS `execute-command` | Start event logged; command output not logged | Enable ECS exec logging |
| `rds:ExecuteStatement` (Data API) | None | Enable RDS Data API logging |
| `s3:GetObject` via pre-signed URL | None (but pre-signed URL creation IS logged) | Enable S3 data events |

## Azure

### Storage account data-plane blind spots

```bash
# Azure Storage data-plane operations are NOT in Activity Log by default
# Activity Log only covers management-plane (create/delete storage account)
# Data plane (read/write blob) requires Azure Storage Analytics or diagnostic settings

# Enable storage logging to capture data-plane operations
az monitor diagnostic-settings create \
  --name storage-data-logs \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example-rg/providers/Microsoft.Storage/storageAccounts/examplestorage \
  --logs '[
    {"category":"StorageRead","enabled":true},
    {"category":"StorageWrite","enabled":true},
    {"category":"StorageDelete","enabled":true}
  ]' \
  --workspace /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example-rg/providers/Microsoft.OperationalInsights/workspaces/example-workspace
```

### Azure Cloud Shell — console without audit

```bash
# Cloud Shell provides a browser-based terminal with:
# - A persistent $HOME directory (5 GB)
# - Pre-authenticated az cli
# - No command-level auditing by default

# Commands run in Cloud Shell use the user's identity
# Activity Log shows the resource changes, not the shell commands themselves
# A user can run arbitrary scripts in Cloud Shell and only the AZURE API calls are logged

# Detection: Enable Cloud Shell diagnostics
az monitor diagnostic-settings create \
  --name cloudshell-logs \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Portal/userSettings/cloudshell \
  --logs '[{"category":"Administrative","enabled":true}]'
```

### Azure resource graph — enumeration without per-resource calls

```bash
# Resource Graph queries across all subscriptions in one call
az graph query -q "resources | project name, type, location, resourceGroup"
# This returns data from 100s of resources in ONE Activity Log entry
# Much lower footprint than individual az resource show calls

# Similarly: az ad user list (lists all users in one call)
az ad user list --query '[].{UPN:userPrincipalName,Enabled:accountEnabled}'
```

## GCP

### GCP audit log types and coverage

GCP has three audit log types, with varying default coverage:

| Log Type | Default? | What It Covers |
|---|---|---|
| **Admin Activity** | **YES** (enabled, cannot disable) | Resource creation, modification, deletion; IAM changes |
| **Data Access** | **NO** (must opt in) | Resource data reads/writes (e.g., reading a GCS object, querying BigQuery) |
| **System Event** | **YES** (cannot disable) | Google-internal actions (e.g., compute instance preemption) |
| **Policy Denied** | **YES** (cannot disable) | Any denied API call |

```bash
# Admin Activity IS logged — good
gcloud compute instances list
# Audit log: methodName="compute.instances.list"

# Data Access is NOT logged by default — blind spot
gsutil cat gs://example-bucket/secrets.txt
# Audit log: NOT emitted unless Data Access audit is enabled

# Enable Data Access audit logs
gcloud logging settings update --organization=000000000000 \
  --enable-data-access-logging

# Or per project:
gcloud logging settings update --project=example-project \
  --enable-data-access-logging
```

### GCP Cloud Shell persistence

```bash
# Cloud Shell provides a browser-based terminal. Its $HOME is persistent (5GB).
# An attacker can:
# - Store scripts in ~/scripts/
# - Set up tmux sessions that persist across browser closes
# - Use gcloud commands that inherit the user's IAM permissions

# Detection: Cloud Shell sessions logged as Admin Activity
gcloud logging read 'protoPayload.methodName="google.cloud.shell.v1.CloudShellService.StartEnvironment"' --limit 10
```

## OnPrem mapping (recap table)

| Evasion Technique | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Delete event logs | `wevtutil cl Security` | `aws cloudtrail delete-trail` (logged) or `StopLogging` (logged) | Delete Log Analytics workspace (logged) | Disable audit log sink (logged) |
| Data-plane blind spots | N/A (all file access via OS, monitorable) | S3/DB data events off by default | Storage data-plane off by default | Data Access audit off by default |
| Tunnel without shell logs | SSH over DNS (iodine) | SSM Session Manager (no shell logging by default) | Cloud Shell (no command audit) | Cloud Shell + IAP tunnel |
| Replay token post-revocation | Pass-the-hash (hash unchanged by password reset) | N/A (STS tokens have definitive expiry) | N/A (refresh token revoked on user revoke) | N/A (OAuth2 token expiry) |
| Living-off-the-land binaries | `certutil`, `bitsadmin`, `mshta` | AWS CLI on EC2 (pre-installed) | `az cli` on Cloud Shell (pre-authenticated) | `gcloud` on Cloud Shell (pre-authenticated) |

## 🔴 Red Team view

### Trail-free recon strategy

An attacker prioritizes actions that minimize log footprint:

1. **Prefer data-plane reads over management-plane lists.** Reading `s3://bucket/iam-export.json` via `GetObject` is trail-free by default, while `aws iam list-roles` generates a CloudTrail event.

2. **Use SSM Session Manager instead of SSH.** No SSH daemon logs, no `auth.log` entries, no `lastlog` record. Only `StartSession` in CloudTrail.

3. **Use pre-signed URLs for exfil.** The URL *generation* is logged (`s3:GetObject` pre-signed), but the actual download from an unrelated IP is a data-plane event — if data events aren't enabled, it's invisible.

4. **Enumerate via resource graph / aggregated APIs.** `az graph query` returns everything in one logged call instead of 50+ individual `az resource show` calls.

5. **Exploit Cloud Shell persistence.** Staging tools in Cloud Shell `$HOME` avoids creating new resources, and the shell itself is an approved administrative pathway.

### What trail-free leaves behind

Even "trail-free" actions leave some artifacts:

| "Trail-Free" Action | Remaining Artifact |
|---|---|
| S3 `GetObject` without data events | S3 server access logs (if enabled separately); VPC Flow Log for the network connection |
| SSM session shell commands | SSM Agent logs on the instance (`/var/log/amazon/ssm/`); shell history files |
| Cloud Shell commands | `$HOME/.bash_history` in the Cloud Shell persistent storage |
| DynamoDB `GetItem` without data events | CloudWatch metrics (read capacity units consumed); application-level logs |
| Pre-signed URL access | S3 access logs (if enabled); CloudFront logs (if behind CDN) |

## 🔵 Blue Team view

### Enabling full coverage

**AWS: Data event trails for all sensitive resources**

```bash
# Enable data events for ALL S3 buckets in the account
aws cloudtrail put-event-selectors --trail-name security-data-trail \
  --advanced-event-selectors '[
    {
      "Name": "S3 data events",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}
      ]
    }
  ]'

# Enable DynamoDB data events
aws cloudtrail put-event-selectors --trail-name security-data-trail \
  --advanced-event-selectors '[
    {
      "Name": "DynamoDB data events",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::DynamoDB::Table"]}
      ]
    }
  ]'

# Enable Lambda data events
# Enable KMS data events on all CMKs
# Enable Secrets Manager data events
```

**Azure: Diagnostic settings for all storage accounts**

```bash
# Enable for all storage accounts in subscription
az storage account list --query '[].id' -o tsv | while read id; do
  az monitor diagnostic-settings create \
    --name "data-plane-logs" \
    --resource "$id" \
    --logs '[
      {"category":"StorageRead","enabled":true},
      {"category":"StorageWrite","enabled":true},
      {"category":"StorageDelete","enabled":true}
    ]' \
    --workspace /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/security/providers/Microsoft.OperationalInsights/workspaces/sentinel-workspace
done
```

**GCP: Enable Data Access audit logs**

```bash
# Enable for all services at org level
gcloud logging settings update --organization=000000000000 \
  --enable-data-access-logging

# Or per project per service:
gcloud logging settings update --project=example-project \
  --service=storage.googleapis.com \
  --enable-data-access-logging
```

### Detection queries

**Detect StopLogging / DeleteTrail — the "loud" evasion:**
```sql
SELECT eventtime, useridentity.arn, eventname, sourceipaddress
FROM cloudtrail_logs
WHERE eventname IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
  AND eventtime > now() - interval '1' day;
```

**Detect SSM sessions from unusual principals:**
```sql
SELECT eventtime, useridentity.arn, requestparameters.target, sourceipaddress
FROM cloudtrail_logs
WHERE eventname = 'StartSession'
  AND useridentity.arn NOT LIKE '%:role/ssm-automation%'
  AND eventtime > now() - interval '1' day;
```

**Detect S3 data events from external IPs:**
```sql
SELECT eventtime, useridentity.arn, eventname, sourceipaddress, requestparameters.bucketname, requestparameters.key
FROM cloudtrail_logs
WHERE eventname IN ('GetObject', 'PutObject')
  AND sourceipaddress NOT IN ('10.0.0.0/8', '172.16.0.0/12') -- not internal
  AND eventtime > now() - interval '1' day;
```

**Detect disable of security services:**
```sql
-- GuardDuty detector deletion
SELECT eventtime, useridentity.arn, eventname
FROM cloudtrail_logs
WHERE eventname IN ('DeleteDetector', 'StopMonitoringMembers')
  AND eventtime > now() - interval '1' day;

-- Azure: Security Center pricing tier downgrade
-- GCP: Security Command Center deactivation
```

### SIEM forwarding

```bash
# AWS: Forward CloudTrail to SIEM via CloudWatch Logs subscription filter
aws logs put-subscription-filter \
  --log-group-name /aws/cloudtrail/security-data-trail \
  --filter-name siem-forwarder \
  --filter-pattern "" \
  --destination-arn arn:aws:lambda:us-east-1:111111111111:function:siem-forwarder

# Azure: Send Activity Log to Sentinel via diagnostic setting
# GCP: Create a log sink to Pub/Sub → SIEM
gcloud logging sinks create siem-sink pubsub.googleapis.com/projects/example-project/topics/siem-topic \
  --log-filter='logName:cloudaudit.googleapis.com'
```

## Hands-on lab

**Objective:** Observe the difference between management-plane and data-plane logging.

1. **Verify current CloudTrail coverage:**
   ```bash
   aws cloudtrail describe-trails --query 'trailList[].{Name:Name,HasCustomEventSelectors:HasCustomEventSelectors}'
   ```

2. **Perform actions and check what's logged:**

   ```bash
   # Action 1: Management plane — WILL be logged
   aws iam list-roles --max-items 5
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=ListRoles --max-results 1
   # Result: Event found

   # Action 2: S3 data plane — MAY NOT be logged (if data events not enabled)
   echo "test" > /tmp/test.txt
   aws s3 cp /tmp/test.txt s3://your-sandbox-bucket/test.txt
   sleep 120
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=PutObject --max-results 1
   # Result: Likely "no events found" unless data events enabled
   ```

3. **Enable data events and re-test:**
   ```bash
   aws cloudtrail put-event-selectors --trail-name <your-trail> \
     --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::your-sandbox-bucket/"]}]}]'

   aws s3 cp /tmp/test2.txt s3://your-sandbox-bucket/test2.txt
   sleep 120
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=PutObject --max-results 1
   # Result: Event found — data events now captured
   ```

4. **Test SSM session logging:**
   ```bash
   aws ssm start-session --target <instance-id> 2>/dev/null || echo "No instance available"
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=StartSession --max-results 1
   ```

**Expected output:** Management events always visible; data events only visible after enabling; SSM `StartSession` visible but shell commands not logged without session logging.

**Teardown:** Clean up uploaded S3 objects.

## Detection rules & checklists

### Sigma rule: Disabling CloudTrail

```yaml
title: CloudTrail Logging Disabled
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName:
      - StopLogging
      - DeleteTrail
      - UpdateTrail
  condition: selection
level: critical
```

### Cloud Custodian: enforce S3 data events on all buckets

```yaml
policies:
  - name: check-s3-data-events-enabled
    resource: aws.cloudtrail
    filters:
      - type: event-selector
        key: DataResources
        value: empty
    actions:
      - type: notify
        template: missing-data-events
```

### Checklist

- [ ] CloudTrail data events enabled for ALL S3 buckets
- [ ] CloudTrail data events enabled for DynamoDB, Lambda, KMS, Secrets Manager
- [ ] SSM session logging enabled (S3 + CloudWatch)
- [ ] GuardDuty enabled in all regions
- [ ] CloudTrail Insights enabled for anomaly detection
- [ ] Azure: Diagnostic settings enabled for all storage accounts
- [ ] Azure: Activity Log exported to Sentinel / Log Analytics continuously
- [ ] GCP: Data Access audit logs enabled for all services
- [ ] GCP: Log sink exporting to SIEM (Pub/Sub → SIEM)
- [ ] Alert on `StopLogging`, `DeleteTrail`, `DeleteDetector`, `DisableSecurityHub`

## References

- [AWS CloudTrail Data Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [AWS SSM Session Manager Logging](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-logging.html)
- [Azure Storage Analytics Logging](https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics-logging)
- [GCP Audit Logs Overview](https://cloud.google.com/logging/docs/audit)
- [GuardDuty Findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html)
- See also: [06-Logging-and-Monitoring/cloudtrail-deep-dive.md](../Monitoring-Detection-SIEM/cloudtrail-deep-dive.md)
- See also: [09-09-collection-data-exfil-channels.md](./collection-data-exfil-channels.md)
