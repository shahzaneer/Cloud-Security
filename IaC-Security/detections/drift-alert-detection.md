# Detection 01 — Drift Alert: Manual Cloud Changes Outside Terraform

> **Type:** Sigma-style detection rule
> **Clouds:** AWS · Azure · GCP
> **Target:** Resources mutated without the Terraform/IaC user-agent, indicating manual console/CLI changes or attacker persistence
> **Severity:** High
> **Authorization scope:** Run detection queries against your own cloud accounts only.

## What this detects

Resources in Terraform-managed infrastructure that are created, updated, or deleted by a principal whose `userAgent` does not contain `HashiCorp-Terraform` (or the known IaC deployer identity). This catches:
- Emergency console fixes (authorized but unrecorded drift)
- Attacker persistence (IAM users, backdoor security groups)
- Accidental changes by engineers with overly broad console access
- Resources created by legacy scripts/other automation that bypass IaC

## Detection logic (pseudo-rule)

```
IF resource.mutation.eventTime within [last 24h]
AND resource.tags contains "ManagedBy" = "Terraform"
AND userAgent does NOT match "HashiCorp-Terraform*"
AND userIdentity.arn is NOT the known deployer role
THEN ALERT "Manual change outside IaC — possible drift or persistence"
```

---

## AWS — CloudTrail + CloudWatch Logs

### Log source

- **Service:** AWS CloudTrail (management events)
- **Log group:** `aws-cloudtrail-logs-111111111111-*` (or centralized S3 bucket)
- **Key fields:** `eventName`, `userAgent`, `userIdentity.arn`, `sourceIPAddress`, `requestParameters`

### Detection query (CloudWatch Logs Insights)

```
fields @timestamp, eventName, userIdentity.arn, userAgent, sourceIPAddress,
       requestParameters, resources.0.arn as resourceArn
| filter eventName not in ("Describe*", "Get*", "List*")
| filter ispresent(resourceArn)
| filter userAgent not like "HashiCorp-Terraform"
| filter userAgent not like "terraform"
| filter userIdentity.arn not like "arn:aws:sts::111111111111:assumed-role/terraform-deploy"
| filter userIdentity.arn not like "arn:aws:sts::111111111111:assumed-role/terraform-plan"
| filter userIdentity.arn not like "arn:aws:sts::111111111111:assumed-role/github-actions-apply"
| sort @timestamp desc
| limit 100
```

### Event exclusions (reduce noise)

Common AWS services that legitimately mutate resources without Terraform user-agent:

| Excluded userAgent prefix | Reason |
|---|---|
| `console.amazonaws.com` | Console changes — these are the drift you want to find, so do NOT exclude unless you allow break-glass |
| `cloudformation.amazonaws.com` | CloudFormation stacks — separate IaC pipeline |
| `config.amazonaws.com` | AWS Config remediation |
| `health.amazonaws.com` | AWS Health events (no mutation) |
| `signin.amazonaws.com` | Login events (filtered by eventName already) |

### Alert severity

| EventName pattern | Severity | Rationale |
|---|---|---|
| `*SecurityGroup*`, `*NetworkAcl*` | CRITICAL | Network perimeter change |
| `*IAM*`, `CreateUser`, `CreateAccessKey`, `AttachUserPolicy` | CRITICAL | Identity persistence |
| `PutBucketPolicy`, `PutBucketAcl` | HIGH | Data exposure |
| `*DBInstance*`, `ModifyDBInstance` | HIGH | Production data tier change |
| `RunInstances`, `TerminateInstances` | MEDIUM | Compute lifecycle — may be auto-scaling |
| `Create*`, `Delete*` (not above) | MEDIUM | Resource creation/deletion outside IaC |

### Sample alert payload (Slack / PagerDuty)

```json
{
  "title": "DRIFT: Manual change outside Terraform",
  "severity": "HIGH",
  "resource": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0a1b2c3d",
  "event": "AuthorizeSecurityGroupIngress",
  "user": "arn:aws:iam::111111111111:user/jane.eng",
  "sourceIp": "203.0.113.45",
  "userAgent": "console.amazonaws.com",
  "time": "2026-06-22T14:32:00Z",
  "remediation": "Review and either 'terraform import' or revert via 'terraform apply'"
}
```

---

## Azure — Activity Log + Log Analytics

### Log source

- **Service:** Azure Activity Log (subscription-level)
- **Workspace:** Log Analytics workspace linked to Sentinel / diagnostic settings
- **Key fields:** `OperationName`, `Caller`, `CallerIpAddress`, `Claims`, `Properties`

### Detection query (KQL — Azure Sentinel / Log Analytics)

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue !startswith "MICROSOFT.INSIGHTS"
| where OperationNameValue contains "write"
| where Caller !has "terraform-deploy"
| where Caller !has "github-actions-apply"
| where Caller !has "azure-pipelines-deploy"
| extend UserAgent = tostring(parse_json(Claims).user_agent)
| where UserAgent !contains "HashiCorp-Terraform"
| where UserAgent !contains "terraform"
| where UserAgent !contains "AzurePipelines"
| project TimeGenerated, OperationNameValue, Caller, CallerIpAddress,
          ResourceId, UserAgent, ResourceGroup
| order by TimeGenerated desc
```

### Event exclusions (Azure)

| Excluded Caller pattern | Reason |
|---|---|
| `*terraform-deploy*` | Known Terraform deployer SP |
| `*github-actions-apply*` | Known CI runner SP |
| `AzureBackup` | Backup service — not drift |
| `AzureSecurityCenter` | ASC / Defender — remediation actions |
| `Microsoft.Advisor` | Advisor recommendations — no mutation |
| `WindowsAzureMSI` | Managed Identity token refresh |

### Sentinel analytics rule template

```json
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "Azure resource mutation outside IaC pipeline",
    "description": "Detects write operations on Azure resources not originating from Terraform or known CI/CD pipeline identities",
    "severity": "High",
    "query": "AzureActivity | where OperationNameValue contains 'write' | where Caller !has 'terraform-deploy' | where Caller !has 'github-actions' | summarize count() by bin(TimeGenerated, 1h), Caller, ResourceGroup",
    "queryFrequency": "1h",
    "queryPeriod": "1h",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "tactics": ["Persistence", "DefenseEvasion"],
    "techniques": ["T1578"]
  }
}
```

### Alert severity mapping (Azure)

| OperationName pattern | Severity |
|---|---|
| `MICROSOFT.NETWORK/*/write` | CRITICAL |
| `MICROSOFT.AUTHORIZATION/roleAssignments/write` | CRITICAL |
| `MICROSOFT.STORAGE/storageAccounts/*/write` | HIGH |
| `MICROSOFT.KEYVAULT/vaults/secrets/write` | HIGH |
| `MICROSOFT.COMPUTE/virtualMachines/write` | MEDIUM |

---

## GCP — Cloud Audit Logs + Log Analytics / SCC

### Log source

- **Service:** Cloud Audit Logs (Admin Activity)
- **Log sink:** Pub/Sub → SIEM, or log bucket for log analytics
- **Key fields:** `protoPayload.methodName`, `protoPayload.authenticationInfo.principalEmail`, `protoPayload.requestMetadata.callerIp`, `protoPayload.requestMetadata.requestAttributes.userAgent`

### Detection query (BigQuery / Log Analytics)

```sql
SELECT
  timestamp,
  protoPayload.methodName,
  protoPayload.authenticationInfo.principalEmail,
  protoPayload.requestMetadata.callerIp,
  protoPayload.requestMetadata.requestAttributes.userAgent,
  resource.labels.project_id,
  protoPayload.resourceName
FROM
  `project-id.dataset.cloudaudit_googleapis_com_activity`
WHERE
  timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
  AND protoPayload.methodName NOT LIKE '%.get'
  AND protoPayload.methodName NOT LIKE '%.list'
  AND protoPayload.authenticationInfo.principalEmail NOT LIKE 'terraform-deploy@%'
  AND protoPayload.authenticationInfo.principalEmail NOT LIKE 'github-actions@%'
  AND protoPayload.requestMetadata.requestAttributes.userAgent NOT LIKE '%HashiCorp-Terraform%'
  AND protoPayload.requestMetadata.requestAttributes.userAgent NOT LIKE '%terraform%'
  AND protoPayload.requestMetadata.requestAttributes.userAgent NOT LIKE '%ConfigConnector%'
ORDER BY timestamp DESC
LIMIT 100
```

### Event exclusions (GCP)

| Excluded principalEmail pattern | Reason |
|---|---|
| `terraform-deploy@*` | Known Terraform deployer SA |
| `github-actions@*` | Known CI runner SA |
| `config-connector@*` | GCP Config Connector controller |
| `*@cloudbuild.gserviceaccount.com` | Cloud Build — separate pipeline |
| `*@gcp-sa-*.iam.gserviceaccount.com` | GCP internal service agents |
| `system:*` | Google internal systems |

### Alert severity mapping (GCP)

| methodName pattern | Severity |
|---|---|
| `*.firewalls.*`, `*.networks.*` | CRITICAL |
| `iam.serviceAccounts.*Key*` | CRITICAL |
| `*.buckets.setIamPolicy`, `*.buckets.update` | HIGH |
| `secretmanager.versions.add` | HIGH |
| `compute.instances.insert`, `compute.instances.delete` | MEDIUM |

---

## Cross-cloud comparison

| Dimension | AWS | Azure | GCP |
|---|---|---|---|
| Log source | CloudTrail | Activity Log (+ diagnostic settings on resources) | Cloud Audit Logs (Admin Activity) |
| User-agent field | `userAgent` in CloudTrail event | `user_agent` in Claims (parse_json) | `protoPayload.requestMetadata.requestAttributes.userAgent` |
| Identity field | `userIdentity.arn` | `Caller` (UPN or SP name) | `protoPayload.authenticationInfo.principalEmail` |
| Query engine | CloudWatch Logs Insights / Athena | Log Analytics (KQL) / Sentinel | BigQuery / Log Analytics |
| Native alert | CloudWatch Alarm + SNS | Sentinel analytics rule / Alert rule | SCC findings / Log-based alerting policy |
| Time to detect | ~5 min (CloudTrail delivery) + query interval | ~5–15 min (Activity Log latency) | ~1–5 min (near real-time) |

## Reducing false positives

Common legitimate mutators NOT going through Terraform:

| Scenario | AWS example | Azure example | GCP example |
|---|---|---|---|
| Auto-scaling | `ec2:RunInstances` from `autoscaling.amazonaws.com` | VMSS scale-out (`Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write`) | MIG auto-scaling |
| Backup/DR restoration | `rds:RestoreDBInstanceFromSnapshot` from `rds.amazonaws.com` | Azure Backup restore | — |
| Break-glass console changes | `ec2:ModifyInstanceAttribute` from `console.amazonaws.com` with tag `BreakGlass=true` | Portal changes with `BreakGlass` tag queryable via Resource Graph | Console changes with `BreakGlass` label |
| Third-party SaaS integrations | Datadog creating monitors via API key | AppInsights, monitoring agents | Cloud Monitoring, managed services |

**Recommended whitelist approach:**
1. Tag all IaC-managed resources with `ManagedBy=Terraform` (or equivalent).
2. Alert only on tagged resources — avoids noise on auto-scaling groups, backup-restored instances, and SaaS-managed resources.
3. Allow a "break-glass" tag (`BreakGlass=true`) with 24h auto-expiry alert.

## Remediation response

When this alert fires:

1. **Verify:** Is the change authorized? Check the ticket system for a break-glass request.
2. **If authorized:** Ensure the change is back-ported to IaC within 24h: `terraform import <resource_type>.<name> <resource_id>`.
3. **If unauthorized:** Immediately revoke the credential that made the change. Revert via `terraform apply` to restore desired state.
4. **Forensics:** Query CloudTrail/Activity Log for all actions by the same principal in the last 7 days.
5. **Rotate:** If a human user credential was used, rotate their access key / force MFA re-auth.

## References

- [08-07 — Drift Detection & Reconciliation](../drift-detection-and-reconciliation.md)
- [06-02 — CloudTrail Activity & Data Events](../../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md)
- [06-07 — Detection as Code: Sigma & Cloud Custodian](../../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md)
- AWS: [CloudTrail Log Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-event-reference.html)
- Azure: [Activity Log Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema)
- GCP: [Cloud Audit Logs Event Reference](https://cloud.google.com/logging/docs/audit)
