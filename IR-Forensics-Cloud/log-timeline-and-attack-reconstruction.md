# 07 — Log Timeline and Attack Reconstruction

> **Level:** Advanced
> **Prereqs:** [06-Monitoring](../Monitoring-Detection-SIEM/), [11-01](./ir-runbook-cloud-aware.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** All (reconstruction of full kill chain)
> **Authorization scope:** Run only in your own sandbox account; all example account IDs are placeholders (`111111111111`, `00000000-0000-0000-0000-000000000000`).

## What & why

Post-incident, reconstruct the attacker's full kill-chain timeline across cloud services: what was accessed, when, from where, and what was the blast radius. This requires joining CloudTrail/Admin Activity logs with VPC Flow logs, GuardDuty/Sentinel/SCC findings, and data-plane access logs — across a window that spans initial access through detection to containment.

## The OnPrem reality

On-prem timeline reconstruction used a SIEM (Splunk, Elastic) ingesting syslog, Windows Event Log, auditd, firewall logs, and EDR telemetry. An analyst would pivot on hostname or username, manually correlating events across log silos in a timeline view.

## Core concepts

### Timeline construction loop

```
1. Identify "ground zero" — the first GuardDuty/Sentinel/SCC finding, or the highest-severity alert
2. Extract identity (principalId / UserPrincipalName / serviceAccount)
3. Extract source IP
4. Query all log sources for that identity ± source IP in a ±6h window around ground zero
5. Join: CloudTrail + VPC Flow + Config + GuardDuty + Data Events (S3/DynamoDB)
6. Build adjacency graph: resource touched → resource touched next
7. Mark blast radius: every resource the identity touched post-compromise
```

### Log source matrix

| Log type | AWS | Azure | GCP |
|----------|-----|-------|-----|
| Control-plane API | CloudTrail | Azure Activity Log | Cloud Audit Logs (Admin Activity) |
| Data-plane access | CloudTrail Data Events (S3, DynamoDB, Lambda) | Azure Diagnostic Settings (Storage, Key Vault) | Cloud Audit Logs (Data Access) |
| Network flows | VPC Flow Logs | NSG Flow Logs | VPC Flow Logs |
| Threat detection | GuardDuty | Microsoft Defender for Cloud / Sentinel | Security Command Center |
| Config drift | AWS Config | Azure Policy / Resource Graph | Cloud Asset Inventory |
| IAM authentication | CloudTrail (AssumeRole, GetCallerIdentity) | Azure AD Sign-in Logs | Cloud Audit Logs (auth) |
| Container / K8s | EKS audit logs → CloudWatch | AKS diagnostics → Log Analytics | GKE audit logs → Cloud Logging |

## AWS

**Timeline query (CloudTrail Lake):**

```sql
SELECT
    eventTime,
    eventName,
    eventSource,
    userIdentity.arn AS principal,
    sourceIPAddress,
    userAgent,
    errorCode,
    requestParameters
FROM cloudtrail_events
WHERE userIdentity.arn = 'arn:aws:sts::111111111111:assumed-role/ProdAppRole/session-abc'
  AND eventTime BETWEEN '2026-06-22T10:00:00Z' AND '2026-06-22T16:00:00Z'
ORDER BY eventTime ASC
```

**VPC Flow Log + CloudTrail join (Athena):**

```sql
WITH trail AS (
    SELECT eventtime, eventname, sourceipaddress, useragent, useridentity.arn
    FROM cloudtrail_logs
    WHERE useridentity.arn = 'arn:aws:sts::111111111111:assumed-role/ProdAppRole/session-abc'
      AND eventtime BETWEEN timestamp '2026-06-22 10:00:00' AND timestamp '2026-06-22 16:00:00'
),
flows AS (
    SELECT timestamp, srcaddr, dstaddr, dstport, action, bytes, packets
    FROM vpc_flow_logs
    WHERE srcaddr = '203.0.113.42'  -- attacker's IP
      AND timestamp BETWEEN timestamp '2026-06-22 10:00:00' AND timestamp '2026-06-22 16:00:00'
)
SELECT t.eventtime, t.eventname, t.sourceipaddress, f.dstaddr, f.dstport, f.bytes
FROM trail t
LEFT JOIN flows f ON t.sourceipaddress = f.srcaddr
  AND ABS(to_unixtime(t.eventtime) - to_unixtime(f.timestamp)) < 60
ORDER BY t.eventtime ASC
```

**Consolidated timeline export script:**

```bash
#!/bin/bash
INCIDENT_ID="inc-1719000000"
PRINCIPAL="arn:aws:sts::111111111111:assumed-role/ProdAppRole/session-abc"
SOURCE_IP="203.0.113.42"
START="2026-06-22T10:00:00Z"
END="2026-06-22T16:00:00Z"

echo "=== CloudTrail Events ==="
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=$PRINCIPAL \
    --start-time "$(date -d $START +%s)" \
    --end-time "$(date -d $END +%s)" \
    --output json > timeline_${INCIDENT_ID}_cloudtrail.json

echo "=== GuardDuty Findings ==="
aws guardduty list-findings --detector-id detector-abc \
    --finding-criteria "Criterion={service.archived={Eq=[false]},updatedAt={Gte=$(date -d $START +%s)000}}" \
    --output json > timeline_${INCIDENT_ID}_guardduty.json

echo "=== S3 Data Events ==="
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
    --start-time "$(date -d $START +%s)" \
    --end-time "$(date -d $END +%s)" \
    --output json > timeline_${INCIDENT_ID}_s3.json

echo "=== Config Changes ==="
aws configservice get-resource-config-history \
    --resource-type AWS::EC2::SecurityGroup \
    --resource-id sg-0a1b2c3d4e5f67890 \
    --later-time "$(date -d $END +%s)" \
    --earlier-time "$(date -d $START +%s)" > timeline_${INCIDENT_ID}_config.json

jq -s 'add' timeline_${INCIDENT_ID}_*.json > timeline_${INCIDENT_ID}_merged.json
```

## Azure

```kql
// Sentinel / Log Analytics KQL: full timeline for compromised identity
let compromised = "operator@example.com";
let start = datetime(2026-06-22T10:00:00Z);
let end = datetime(2026-06-22T16:00:00Z);
union
    (SigninLogs | where UserPrincipalName == compromised | project TimeGenerated, Source="SignIn", Event="SignIn", IP=IPAddress, Detail=ResultType),
    (AzureActivity | where Caller == compromised | project TimeGenerated, Source="Activity", Event=OperationName, IP=CallerIpAddress, Detail=Properties_d),
    (StorageBlobLogs | where AuthenticationType != "" and AuthenticationId has compromised | project TimeGenerated, Source="Storage", Event=OperationName, IP=CallerIpAddress, Detail=ObjectKey),
    (SecurityAlert | where Entities has compromised | project TimeGenerated, Source="Sentinel", Event=AlertName, IP="", Detail=Description)
| order by TimeGenerated asc
```

**Export timeline via Azure CLI:**

```bash
az monitor log-analytics query \
    --workspace $(az monitor log-analytics workspace show \
        -g security-rg -n sentinel-ws --query customerId -o tsv) \
    --analytics-query "
    union
    SigninLogs | where UserPrincipalName == 'operator@example.com' and TimeGenerated between(datetime(2026-06-22T10:00:00Z) .. datetime(2026-06-22T16:00:00Z)),
    AzureActivity | where Caller == 'operator@example.com' and TimeGenerated between(datetime(2026-06-22T10:00:00Z) .. datetime(2026-06-22T16:00:00Z))
    | order by TimeGenerated asc
    " -o json > timeline_inc.json
```

## GCP

```sql
-- BigQuery: join Cloud Audit + VPC Flow + SCC findings
WITH admin_logs AS (
    SELECT timestamp, protopayload_auditlog.methodName AS method,
           protopayload_auditlog.authenticationInfo.principalEmail AS principal,
           protopayload_auditlog.requestMetadata.callerIp AS ip
    FROM `project.dataset.cloudaudit_googleapis_com_activity`
    WHERE protopayload_auditlog.authenticationInfo.principalEmail = 'sa-compromised@project.iam.gserviceaccount.com'
      AND timestamp BETWEEN '2026-06-22T10:00:00Z' AND '2026-06-22T16:00:00Z'
),
data_logs AS (
    SELECT timestamp, protopayload_auditlog.methodName AS method,
           protopayload_auditlog.authenticationInfo.principalEmail AS principal,
           protopayload_auditlog.requestMetadata.callerIp AS ip,
           protopayload_auditlog.resourceName AS resource
    FROM `project.dataset.cloudaudit_googleapis_com_data_access`
    WHERE protopayload_auditlog.authenticationInfo.principalEmail = 'sa-compromised@project.iam.gserviceaccount.com'
      AND timestamp BETWEEN '2026-06-22T10:00:00Z' AND '2026-06-22T16:00:00Z'
)
SELECT timestamp, method, principal, ip, 'admin' AS log_type FROM admin_logs
UNION ALL
SELECT timestamp, method, principal, ip, 'data' AS log_type FROM data_logs
ORDER BY timestamp ASC
```

**Export via gcloud:**

```bash
gcloud logging read \
    'protoPayload.authenticationInfo.principalEmail="sa-compromised@project.iam.gserviceaccount.com" AND timestamp>="2026-06-22T10:00:00Z" AND timestamp<="2026-06-22T16:00:00Z"' \
    --format=json --limit=10000 > timeline_inc.json
```

## OnPrem mapping (recap table)

| Reconstruction step | OnPrem | AWS | Azure | GCP |
|--------------------|--------|-----|-------|-----|
| Identity pivot | Splunk search by `UserName` | CloudTrail Lake query by `userIdentity.arn` | Sentinel KQL by `UserPrincipalName` | BigQuery by `principalEmail` |
| Network flow join | Firewall logs + NetFlow | VPC Flow Log + CloudTrail in Athena | NSG Flow Log + Activity in Log Analytics | VPC Flow Log + Audit in BigQuery |
| Data access track | File server audit (Event 4663) | S3 Data Events in CloudTrail | Storage Blob Logs in Diagnostic Settings | Data Access audit logs |
| Config drift | RANCID / config backups | AWS Config timeline | Azure Resource Graph change history | Cloud Asset Inventory change history |
| Blast radius map | AD group membership mapping | IAM policy simulation + `GetResourcesForUser` | `az role assignment list --assignee` | `gcloud asset search-all-iam-policies` |
| Export format | CSV from SIEM export | `aws cloudtrail lookup-events --output json` | `az monitor log-analytics query -o json` | `gcloud logging read --format=json` |

## 🔴 Red Team view

Sophisticated attackers attempt to manipulate or evade the log timeline:

**CloudTrail/Admin Activity cannot be deleted by the attacker.** AWS, Azure, and GCP admin activity logs are managed service logs — even an attacker with full admin privileges cannot delete or modify them. `cloudtrail:StopLogging` stops *new* events from being recorded, but events before the stop call persist. `cloudtrail:DeleteTrail` deletes the trail configuration but not the S3 logs (if S3 lifecycle doesn't purge them).

**What attackers CAN do:**
- Call `cloudtrail:StopLogging` / disable Azure Diagnostic Settings / disable GCP audit log sink — creates a gap from the stop time forward.
- Fill the log gap with noise: after re-enabling logging, flood `List*` / `Describe*` calls to bury the malicious activity in volume.
- Use `aws s3 rm s3://cloudtrail-bucket/` if the role has S3 permissions — deletes historical log files (but the attacker must find the bucket ARN first).
- Exploit the fact that data-plane logging (S3 Data Events, Storage diagnostic logs) is often not enabled by default — no record of data exfiltration exists.

**"The logs that existed before the attacker disabled logging persist on disk"** — and the attacker may not know that a separate organization trail or cross-account log sink is still operational. Organizations can deploy a management-account trail that member-account admins cannot disable.

**Artifacts:**
- `cloudtrail:StopLogging` event itself — the last event in the trail before the gap.
- `cloudtrail:DeleteTrail` — rare event, high signal.
- S3 bucket access logs showing `s3:DeleteObject` on `.json.gz` files in a CloudTrail bucket prefix.
- Azure Activity Log showing `Microsoft.Insights/diagnosticSettings/delete`.
- GCP Audit Log showing `google.logging.v2.ConfigServiceV2.DeleteSink`.

## 🔵 Blue Team view

### Organization trail (AWS) — defense against trail deletion

```bash
aws cloudtrail create-trail \
    --name org-forensic-trail \
    --s3-bucket-name org-forensic-bucket \
    --is-organization-trail \
    --is-multi-region-trail \
    --enable-log-file-validation

aws cloudtrail put-event-selectors \
    --trail-name org-forensic-trail \
    --event-selectors '[{
        "ReadWriteType": "All",
        "IncludeManagementEvents": true,
        "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::"]}]
    }]'
```

### Sentinel cross-tactic timeline (Azure)

```kql
// Multi-tactic blast radius: everything a compromised SP touched
let compromised_sp = "00000000-0000-0000-0000-000000000000";
AzureActivity
| where Caller == compromised_sp
| extend Tactic = case(
    OperationName has "write" and OperationName has "firewallRules", "DefenseEvasion",
    OperationName has "listKeys", "CredentialAccess",
    OperationName has "export", "Exfiltration",
    "Execution"
)
| project TimeGenerated, OperationName, Tactic, ResourceGroup, CallerIpAddress
| order by TimeGenerated asc
```

### Timeline sanity check

Before declaring the incident "closed," verify:

```python
def validate_timeline(timeline):
    gaps = []
    for i in range(1, len(timeline)):
        gap = timeline[i]['time'] - timeline[i-1]['time']
        if gap > timedelta(minutes=30):
            gaps.append({
                'start': timeline[i-1]['time'],
                'end': timeline[i]['time'],
                'duration_minutes': gap.total_seconds() / 60
            })
    if gaps:
        print(f"⚠️ {len(gaps)} timeline gaps > 30 min detected — possible log stoppage")
    return gaps
```

### Multi-cloud blast radius script

```python
def compute_blast_radius(principal, start, end):
    # AWS
    aws_resources = query_cloudtrail_lake(principal, start, end)
    # Azure
    azure_resources = query_sentinel(principal, start, end)
    # GCP
    gcp_resources = query_bigquery(principal, start, end)

    return {
        'iam_roles_assumed': dedupe([r['role'] for r in aws_resources if r['event'] == 'AssumeRole']),
        's3_buckets_accessed': dedupe([r['bucket'] for r in aws_resources if r['event'] == 'GetObject']),
        'db_instances_queried': dedupe([r['instance'] for r in all_resources if r['event'] == 'Query']),
        'all_resources_touched': dedupe(aws_resources + azure_resources + gcp_resources)
    }
```

## Hands-on lab

1. In sandbox, run 15-20 varied API calls (assume role, list buckets, describe instances, get object) to simulate attacker behavior.
2. Query CloudTrail Lake / Log Analytics / BigQuery with the identity and ±6h window.
3. Export to CSV and build a chronological timeline using `jq` or Python pandas.
4. Identify: first action, last action, total resources touched, any S3 objects accessed.
5. Validate the timeline has no gaps > 30 min.
6. Teardown: no persistent resources.

## Detection rules & checklists

```yaml
title: CloudTrail Logging Stopped or Trail Deleted
logsource:
  product: aws
  service: cloudtrail
detection:
  select_stop:
    eventSource: cloudtrail.amazonaws.com
    eventName: StopLogging
  select_delete:
    eventSource: cloudtrail.amazonaws.com
    eventName: DeleteTrail
  condition: select_stop or select_delete
  severity: critical
```

```yaml
title: Azure Diagnostic Setting Deleted
logsource:
  product: azure
  service: activitylog
detection:
  selection:
    operationName: Microsoft.Insights/diagnosticSettings/delete
  condition: selection
  severity: critical
```

```yaml
title: GCP Log Sink Deleted
logsource:
  product: gcp
  service: cloudaudit
detection:
  selection:
    protoPayload.methodName: google.logging.v2.ConfigServiceV2.DeleteSink
  condition: selection
  severity: critical
```

- [ ] Organization trail enabled (AWS) / management-group diagnostic setting (Azure) / org-level log sink (GCP).
- [ ] S3 Data Events, Storage diagnostic logs, and Data Access audit logs enabled for all production resources.
- [ ] Timeline gap-detection script included in post-incident SOP.
- [ ] Blast radius report auto-generated from timeline at incident close.

## References

- [CloudTrail Lake queries](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-query.html)
- [Sentinel hunting queries](https://learn.microsoft.com/en-us/azure/sentinel/hunting)
- [GCP log query language](https://cloud.google.com/logging/docs/view/logging-query-language)
- [AWS VPC Flow Logs + Athena](https://docs.aws.amazon.com/athena/latest/ug/vpc-flow-logs.html)
- See ATT&CK Cloud matrix for all tactics (reconstruction)
