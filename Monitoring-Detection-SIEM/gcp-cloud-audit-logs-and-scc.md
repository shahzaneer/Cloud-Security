# 04 — GCP Cloud Audit Logs & SCC

> **Level:** Intermediate
> **Prereqs:** [The Security Log Mosaic per Cloud](the-security-log-mosaic-per-cloud.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Discovery
> **Authorization scope:** Configure Cloud Audit Logs and SCC in your own GCP project. Queries run against your own project's telemetry.

## What & why

GCP splits audit logs into four types: Admin Activity (forced on), Data Access (per-service opt-in), Policy Denied (forced on), and System Events (forced on). Security Command Center (SCC) sits on top as the vulnerability-threat-posture management plane. Together they form GCP's security telemetry backbone — but the gap between what's forced and what's optional is where attackers operate.

## The OnPrem reality

Debian/Ubuntu `auditd` with custom `audit.rules` shipped to each host via config management. Every `-S execve` and `-S open` had to be reasoned about. GCP's Admin Activity is the zero-config equivalent — every GCP API call that changes state is recorded without you lifting a finger. The challenge is the *Data Access* tier, which remains opt-in, exactly like file SACLs on Windows.

## Core concepts

### The four audit log types

| Log type | Scope | Default | Can attacker disable? | Example events |
|---|---|---|---|---|
| Admin Activity | Create/Update/Delete API calls | **ON, forced** | No — cannot be disabled | `compute.instances.insert`, `storage.buckets.create`, `SetIamPolicy` |
| Data Access | Read/Write to resource contents | **OFF per service** | Can be removed from `auditConfigs` | `storage.objects.get`, `bigquery.tables.getData` |
| Policy Denied | Access denied by IAM or Org Policy | **ON, forced** | No | IAM deny, Org Policy violation |
| System Event | Non-human GCP internal events | **ON** | N/A | Compute Engine host maintenance, preemptible instance termination |

### Cloud Audit Logs → Pub/Sub → BigQuery pipeline

The canonical ingestion pipeline for GCP security telemetry:

```
[Admin Activity] ──┐
[Data Access] ─────┤──> Cloud Logging ──> Log Sink ──> Pub/Sub ──> BigQuery / Dataflow ──> dashboards
[Policy Denied] ───┘                         │
                                             └──> Cloud Function (real-time alerting)
```

### Security Command Center (SCC)

| Tier | Features | Cost |
|---|---|---|
| Standard (default) | Asset inventory, basic IAM analysis, container threat detection | Free |
| Premium | Event Threat Detection, Security Health Analytics, web security scanner, container threat detection, VM threat detection | ~$0.03/hour per project or subscription |

**Key SCC capabilities:**
- **Event Threat Detection:** ML-based log anomaly detection over Cloud Audit Logs, Cloud DNS, and Cloud NAT logs
- **Security Health Analytics:** Misconfiguration scanners (public buckets, open firewalls, unencrypted disks)
- **Container Threat Detection:** Runtime anomaly detection on GKE
- **VM Threat Detection:** Scans volume snapshots for cryptominers, web shells, malware

## GCP

### Step 1: Enable Data Access logging on Cloud Storage & BigQuery

Data Access must be set in the project's IAM policy via `auditConfigs`:

```bash
gcloud projects get-iam-policy project-id-111111 --format json > /tmp/policy.json
```

Edit `/tmp/policy.json` to add:

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
    },
    {
      "service": "bigquery.googleapis.com",
      "auditLogConfigs": [
        {"logType": "DATA_READ"},
        {"logType": "DATA_WRITE"}
      ]
    },
    {
      "service": "secretmanager.googleapis.com",
      "auditLogConfigs": [
        {"logType": "DATA_READ"},
        {"logType": "DATA_WRITE"}
      ]
    }
  ]
}
```

```bash
gcloud projects set-iam-policy project-id-111111 /tmp/policy.json
```

### Step 2: Create a log sink to BigQuery

```bash
bq mk --dataset --location=US project-id-111111:audit_logs

gcloud logging sinks create audit-to-bq \
  bigquery.googleapis.com/projects/project-id-111111/datasets/audit_logs \
  --log-filter='logName:"cloudaudit.googleapis.com" severity>=DEFAULT' \
  --project project-id-111111

gcloud logging sinks describe audit-to-bq --project project-id-111111
```

Note the `writerIdentity` from the sink description — grant it `roles/bigquery.dataEditor` on the dataset.

```bash
gcloud projects add-iam-policy-binding project-id-111111 \
  --member "serviceAccount:p111111111111-xxxxxx@gcp-sa-logging.iam.gserviceaccount.com" \
  --role roles/bigquery.dataEditor
```

### Step 3: Query audit logs in BigQuery

```sql
SELECT
  timestamp,
  protoPayload.methodName,
  protoPayload.authenticationInfo.principalEmail,
  protoPayload.requestMetadata.callerIp
FROM `project-id-111111.audit_logs.cloudaudit_googleapis_com_activity`
WHERE timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
  AND protoPayload.methodName LIKE "%.setIamPolicy"
ORDER BY timestamp DESC;
```

### Step 4: Enable SCC Premium & notification to Pub/Sub

```bash
gcloud scc notifications create scc-findings-notify \
  --organization organizations/111111111111 \
  --pubsub-topic projects/project-id-111111/topics/scc-findings \
  --filter "state=\"ACTIVE\""

gcloud scc services enable \
  --organization organizations/111111111111 \
  --service SECURITY_COMMAND_CENTER
```

### Step 5: Create a Cloud Function to process SCC findings

```bash
gcloud functions deploy scc-finding-handler \
  --runtime python310 \
  --trigger-topic scc-findings \
  --entry-point process_finding \
  --source ./function-src
```

Minimal handler:

```python
import base64
import json

def process_finding(event, context):
    pubsub_message = base64.b64decode(event['data']).decode('utf-8')
    finding = json.loads(pubsub_message)
    category = finding.get('finding', {}).get('category', 'unknown')
    resource = finding.get('finding', {}).get('resourceName', 'unknown')
    severity = finding.get('finding', {}).get('severity', 'LOW')
    print(f"SCC finding: {category} on {resource} severity={severity}")
```

## AWS (equivalent capability)

AWS equivalent audit model:
- Management events = `Admin Activity` (default on)
- S3 data events = `Data Access` (must enable per-bucket via event selectors)
- `AccessDenied` = `Policy Denied` (logged in CloudTrail)
- GuardDuty = `SCC Event Threat Detection`
- Security Hub = `SCC Security Health Analytics`

## Azure (equivalent capability)

Azure equivalent:
- Activity Log = `Admin Activity`
- Resource diagnostics = `Data Access`
- Entra ID sign-in denied = `Policy Denied` equivalent
- Microsoft Sentinel analytics rules = `SCC Event Threat Detection`
- Defender for Cloud recommendations = `SCC Security Health Analytics`

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Admin audit (forced) | auditd `execve` | CloudTrail mgmt events | Activity Log | Admin Activity |
| Data access audit | File SACLs (per-file) | S3 data events (per-bucket) | Diagnostics (per-resource) | Data Access (per-service, per-logType) |
| Policy denied | `-EACCES` in auditd | CloudTrail `AccessDenied` | Activity Log 403 | Policy Denied (forced on) |
| Central sink | Splunk | S3 → Athena | Log Analytics workspace | BigQuery dataset |
| Threat detection | OSSEC / Wazuh | GuardDuty | Defender for Cloud | SCC Event Threat Detection |
| Misconfig scan | OpenSCAP / Lynis | Security Hub / Config | Defender for Cloud | SCC Security Health Analytics |

## 🔴 Red Team view

### Data Access gap — the GCP attacker's silent corridor

Admin Activity cannot be disabled — every `SetIamPolicy`, `storage.buckets.create`, `compute.instances.insert` is recorded permanently. But **Data Access logs are only enabled if you explicitly turn them on per service**. An attacker who reads data from GCS or queries BigQuery tables operates entirely outside the audit trail unless the defender enabled Data Access on those services.

```bash
# Attacker lists all objects in a GCS bucket — invisible if DATA_READ not on:
gsutil ls gs://prod-data-111111/

# Attacker downloads a sensitive file — invisible if DATA_READ not on:
gsutil cp gs://prod-data-111111/customer-dump.csv /tmp/exfil.csv

# In BigQuery, attacker runs:
bq query "SELECT * FROM \`project-id-111111.prod_dataset.credit_cards\`"
# Zero audit log entries if DATA_READ not enabled on bigquery.googleapis.com
```

**The enumerable blind spot:** The attacker's initial recon — `gsutil ls` listing buckets, `bq ls` listing datasets — is also Data Access and therefore silent. The attack's only logged footprint is the initial `gcloud auth login` or `sts:GetCallerIdentity` (if via federation), which is merely a single auth event.

**Azure equivalent:** Without `StorageRead` diagnostic, `GetBlob` in StorageBlobLogs produces nothing.

**AWS equivalent:** Without S3 data events, `GetObject` and `ListObjects` produce nothing in CloudTrail.

### Artifacts

- `SetIamPolicy` removing `auditConfigs` block: recorded in Admin Activity — the defender's last signal before data-plane blindness.
- `gcloud services disable logging.googleapis.com`: also an Admin Activity event.
- Attacker's `gcloud compute ssh` or `gcloud container clusters get-credentials`: logged as Admin Activity (resource-level access for orchestration actions).

## 🔵 Blue Team view

### Org Policy — force Data Access logging

> (as of June 2026, the constraint `constraints/cloud.auditEnableDataAccessLogs` enforces Data Access logging at the org/folder/project level. Verify the current name at [GCP Org Policy constraints](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints).)

```bash
gcloud org-policies set-policy /tmp/force-data-access.yaml \
  --organization organizations/111111111111
```

Example policy YAML to enforce Data Access logging on GCS and BigQuery:
```yaml
constraint: constraints/gcp.resourceLocations
listPolicy:
  allValues: ALLOW
---
# Custom org policy constraint (must be created as custom constraint first)
# Enforces that auditConfigs includes DATA_READ + DATA_WRITE for storage + bigquery
```

Alternative: **Custom constraint** via `gcloud org-policies custom-constraints`:

```bash
gcloud org-policies custom-constraints create enable-audit-configs-custom \
  --organization organizations/111111111111 \
  --resource-types projects \
  --method-types UPDATE \
  --condition "resource.auditConfigs.exists(c, c.service=='storage.googleapis.com' && c.auditLogConfigs.exists(l, l.logType=='DATA_READ'))"
```

### Detection queries

```
# GCP Logging — Data Access logs explicitly disabled (auditConfigs removed)
protoPayload.methodName="SetIamPolicy"
protoPayload.serviceData.policyDelta.auditConfigDeltas.action="REMOVE"

# GCP Logging — Admin attempted to disable Data Access on GCS
protoPayload.methodName="SetIamPolicy"
resource.type="project"
NOT protoPayload.serviceData.policyDelta.auditConfigDeltas.service="storage.googleapis.com"
# (alert if SetIamPolicy results in no storage auditConfigs)

# GCP BigQuery — query for IAM changes that reduce audit coverage
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail,
  protoPayload.serviceData.policyDelta
FROM `project-id-111111.audit_logs.cloudaudit_googleapis_com_activity`
WHERE protoPayload.methodName = "SetIamPolicy"
  AND REGEXP_CONTAINS(TO_JSON_STRING(protoPayload.serviceData.policyDelta), 'REMOVE')
ORDER BY timestamp DESC;

# AWS CloudWatch — CloudTrail stop logging
fields @timestamp, userIdentity.arn
| filter eventName = "StopLogging"

# Azure KQL — diagnostic setting deleted
AzureActivity
| where OperationNameValue contains "diagnosticSettings/delete"
```

### Preventive controls

| Control | GCP | AWS | Azure |
|---|---|---|---|
| Force admin audit | Admin Activity cannot be disabled | SCP deny `cloudtrail:StopLogging` | Azure Policy deny diagnostic setting delete |
| Force data audit | Org policy + custom constraint on auditConfigs | SCP deny trail update without data events | Azure Policy deployIfNotExists diagnostic settings |
| Immutable logs | Bucket lock on sink GCS bucket | S3 Object Lock | Immutable storage on Log Analytics tables |
| Findings forwarding | SCC → Pub/Sub → Cloud Function | GuardDuty → EventBridge → Lambda | Defender → Logic Apps / Sentinel Playbooks |

### Response steps

1. **Audit config removed:** Immediately re-add `auditConfigs` for all critical services. Block the principal that made the change.
2. **Data exfil suspected:** Query Admin Activity for the principal's `storage.objects.get` calls (if Data Access was enabled). Cross-reference with Cloud NAT logs for volume spikes.
3. **Replicate:** Set up a parallel log sink to a separate GCP project that the compromised project's principals cannot touch.

## Hands-on lab

1. Check current audit config for your project:
```bash
gcloud projects get-iam-policy project-id-111111 --format json | jq '.auditConfigs'
```

2. If empty or no Data Access for storage, enable it:
```bash
gcloud projects get-iam-policy project-id-111111 --format json > /tmp/policy.json
# Edit policy.json to add auditConfigs for storage DATA_READ + DATA_WRITE
gcloud projects set-iam-policy project-id-111111 /tmp/policy.json
```

3. Upload and read an object to generate a data access log:
```bash
gsutil mb gs://audit-test-bucket-111111
echo "test" > /tmp/gcp-test.txt
gsutil cp /tmp/gcp-test.txt gs://audit-test-bucket-111111/
gsutil cp gs://audit-test-bucket-111111/gcp-test.txt /tmp/readback.txt
```

4. Query for the data access log (may take minutes to appear):
```bash
gcloud logging read 'logName="projects/project-id-111111/logs/cloudaudit.googleapis.com%2Fdata_access" resource.type="gcs_bucket"' --limit 5
```

5. **Teardown:**
```bash
gsutil rm gs://audit-test-bucket-111111/gcp-test.txt
gsutil rb gs://audit-test-bucket-111111
rm /tmp/policy.json /tmp/gcp-test.txt /tmp/readback.txt
```

## Detection rules & checklists

```
# Sigma rule — GCP audit config removed
title: GCP Cloud Audit Logs AuditConfig Removed
status: experimental
logsource:
  product: gcp
  service: cloudaudit
detection:
  selection:
    protoPayload.methodName: SetIamPolicy
    protoPayload.serviceData.policyDelta.auditConfigDeltas.action: REMOVE
  condition: selection
level: high

# Checklist
- [ ] Admin Activity enabled (always on — verify not bypassed via org)
- [ ] Data Access enabled on: Cloud Storage, BigQuery, Secret Manager, Cloud SQL, GKE
- [ ] Policy Denied logs visible in Log Explorer
- [ ] Log sink to BigQuery with 365+ day retention
- [ ] SCC Standard or Premium enabled
- [ ] SCC notifications to Pub/Sub configured
- [ ] Org Policy or custom constraint enforces Data Access logging
- [ ] Separate security project owns the BigQuery log sink
- [ ] Cloud Function / Cloud Run processes high-severity SCC findings to Slack/PagerDuty
```

## References
- [GCP Cloud Audit Logs overview](https://cloud.google.com/logging/docs/audit)
- [GCP Security Command Center](https://cloud.google.com/security-command-center/docs/concepts-security-command-center-overview)
- [GCP Org Policy constraints](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints)
- [GCP Log sinks](https://cloud.google.com/logging/docs/export)
- [../IAM/identity-primitives-per-cloud.md](../IAM/identity-primitives-per-cloud.md)
- [../Storage-Data-Security/storage-primitives.md](../Storage-Data-Security/storage-primitives.md)
