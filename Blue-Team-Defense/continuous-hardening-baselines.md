# 07 — Continuous Hardening Baselines

> **Level:** Intermediate
> **Prereqs:** [Drift Detection & Reconciliation](../IaC-Security/drift-detection-and-reconciliation.md), [Blast Radius Reduction Patterns](blast-radius-reduction-patterns.md), [Posture Management per Cloud](../Compliance-Audit-Gov/posture-management-per-cloud.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Persistence, Initial Access
> **Authorization scope:** Deploy and scan baselines only in your own sandbox accounts.

## What & why

Hardening is not a one-time pass. Continuous hardening means: baseline-as-code, drift detection, automated compliance reporting, and automatic issue creation for non-compliant resources. Without continuous monitoring, a resource created outside the IaC pipeline (click-ops, emergency fix) stays misconfigured until the next annual audit.

## The OnPrem reality

CIS benchmarks were applied via Ansible playbooks or Group Policy, then checked monthly with Nessus/Qualys scans. Drift — a server patched to CIS Level 1 but then a developer runs a script that changes registry settings — was caught at the next scheduled scan, often weeks later. Cloud continuous hardening checks drift in near-real-time via native scanning services.

## Cross-cloud comparison

| Provider | Baseline tool | Baseline format | Drift detection | Compliance reporting |
|---|---|---|---|---|
| AWS | Security Hub + AWS Config Conformance Packs | `AWS-Foundational-Security-Best-Practices` (pre-built) | Config rules evaluate continuously on resource change | Security Hub dashboard + custom reports |
| AWS | AWS Config custom rules | Lambda-based or managed AWS Config rules | Trigger on resource creation/change/periodic | Aggregated to Security Hub + S3 bucket |
| Azure | Defender for Cloud + Azure Policy | Regulatory Compliance dashboard (CIS, NIST, PCI) | Azure Policy evaluates on resource lifecycle | Secure Score + compliance dashboard |
| Azure | Azure Policy initiatives | JSON definition with `audit`/`deny`/`deployIfNotExists` | Continuous evaluation | Compliance percentage by subscription |
| GCP | Security Command Center (SCC) Premium | Security Health Analytics (built-in detectors) | Scans daily + on resource change | SCC dashboard + Compliance Reports |
| GCP | SCC Custom modules | YAML-based custom detector definitions | Scheduled scan | Integrated into SCC findings |
| OnPrem | Nessus/Qualys + Ansible | CIS benchmark YAML/playbook | Scheduled scans (weekly) | Central console + PDF export |

## AWS

**Enable Security Hub with foundational best-practices:**

```bash
aws securityhub enable-security-hub \
  --enable-default-standards

aws securityhub batch-enable-standards \
  --standards-subscription-requests '[
    {
      "StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
    },
    {
      "StandardsArn": "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"
    }
  ]'

aws securityhub create-members \
  --account-details '[{"AccountId": "222222222222"}, {"AccountId": "333333333333"}]'

aws securityhub invite-members --account-ids '["222222222222","333333333333"]'
```

**Deploy Conformance Pack for S3 baseline:**

```yaml
Resources:
  S3BucketPublicReadProhibited:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-public-read-prohibited
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_PUBLIC_READ_PROHIBITED
  S3BucketPublicWriteProhibited:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-public-write-prohibited
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_PUBLIC_WRITE_PROHIBITED
  S3BucketServerSideEncryptionEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-server-side-encryption-enabled
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
  S3BucketSSLRequestsOnly:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-ssl-requests-only
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_SSL_REQUESTS_ONLY
```

**Terraform — Security Hub delegated administrator:**

```hcl
resource "aws_securityhub_organization_admin_account" "main" {
  admin_account_id = "555555555555"
}

resource "aws_securityhub_organization_configuration" "main" {
  auto_enable           = true
  auto_enable_standards = "DEFAULT"
}
```

**Drift detection — custom Config rule for non-standard ports:**

```bash
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "restricted-ssh-rule",
    "Source": {"Owner": "AWS", "SourceIdentifier": "INCOMING_SSH_DISABLED"},
    "Scope": {"ComplianceResourceTypes": ["AWS::EC2::SecurityGroup"]}
  }'

aws configservice start-config-rules-evaluation \
  --config-rule-names restricted-ssh-rule
```

**Slack notification for new Security Hub findings:**

```bash
aws events put-rule --name SecurityHubFindings \
  --event-pattern '{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
      "findings": {
        "Compliance": {
          "Status": ["FAILED"]
        },
        "RecordState": ["ACTIVE"],
        "Workflow": {"Status": ["NEW"]}
      }
    }
  }'

aws events put-targets --rule SecurityHubFindings \
  --targets "Id=1,Arn=arn:aws:lambda:us-east-1:111111111111:function:SecHubSlackNotifier"
```

## Azure

**Enable Defender for Cloud with continuous assessment:**

```bash
az security pricing create --name VirtualMachines --tier Standard
az security pricing create --name StorageAccounts --tier Standard
az security pricing create --name SqlServers --tier Standard

az security workspace-setting create \
  --name default \
  --workspace-id /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-security/providers/Microsoft.OperationalInsights/workspaces/sentinel-workspace
```

**Assign CIS Azure Foundations initiative:**

```bash
az policy set-definition list \
  --query "[?displayName=='CIS Microsoft Azure Foundations Benchmark v1.4.0']"

az policy assignment create \
  --name cis-azure-foundations \
  --policy-set-definition /providers/Microsoft.Authorization/policySetDefinitions/1a45cbf3-194e-4a60-8c25-b28cca396e3f \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

**View compliance — identify drift:**

```bash
az policy state list \
  --query "[?complianceState=='NonCompliant'].[displayName, resourceId, policyAssignmentName]" \
  --output table

az security secure-score-controls list \
  --query "[?currentScore < maxScore].[controlName, currentScore, maxScore]" \
  --output table
```

**Custom Azure Policy — detect VMs without Azure Monitor agent:**

```json
{
  "if": {
    "allOf": [
      {"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
      {
        "anyOf": [
          {"field": "Microsoft.Compute/virtualMachines/extensions.type", "notEquals": "AzureMonitorLinuxAgent"},
          {"field": "Microsoft.Compute/virtualMachines/extensions.provisioningState", "notEquals": "Succeeded"}
        ]
      }
    ]
  },
  "then": {"effect": "audit"}
}
```

## GCP

**Enable Security Command Center Premium:**

```bash
gcloud services enable securitycenter.googleapis.com --project org-admin-111111

gcloud scc settings describe --organization 000000000000

gcloud scc settings update \
  --organization=000000000000 \
  --enable-asset-discovery=true \
  --asset-discovery-config-file=asset_discovery.json
```

**Enable built-in detectors (Security Health Analytics):**

SHA detectors automatically scan for: public buckets, open firewall rules, unencrypted disks, legacy service accounts, exposed GKE dashboard, KMS key rotation, and ~150 more.

**View non-compliant findings:**

```bash
gcloud scc findings list organizations/000000000000/sources/- \
  --filter='state="ACTIVE" AND severity="HIGH" OR severity="CRITICAL"' \
  --format='table(finding.name, resourceName, category, severity)'
```

**Custom SCC module — detect public Cloud SQL instances:**

```yaml
name: organizations/000000000000/securityHealthAnalyticsSettings/customModules/public_sql_instance
displayName: Public Cloud SQL Instance Detector
description: Detects Cloud SQL instances with authorized network 0.0.0.0/0
customConfig:
  predicate:
    expression: |
      resource.type == "cloudsql.googleapis.com/Instance"
      && resource.properties.settings.ipConfiguration.authorizedNetworks.any(
        net, net.value == "0.0.0.0/0"
      )
  resourceSelector:
    resourceTypes:
    - cloudsql.googleapis.com/Instance
  severity: HIGH
```

**Audit Log export for continuous compliance:**

```bash
gcloud logging sinks create compliance-logs \
  storage.googleapis.com/compliance-audit-bucket \
  --log-filter='severity>=WARNING AND resource.type!="audited_resource"'
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Baseline standard | CIS Benchmark (OS/app) | AWS Foundational Best Practices + CIS | CIS Azure Foundations + Defender for Cloud | CIS GCP Benchmark + SHA detectors |
| Drift engine | Nessus/Qualys scheduled scans | AWS Config rules (continuous trigger) | Azure Policy (continuous evaluation) | SCC Security Health Analytics (daily + on-change) |
| Dashboard | Tenable/Qualys console | Security Hub | Defender for Cloud | SCC dashboard |
| Alerting | SMTP/SIEM integration | EventBridge → SNS/Slack | Logic App / Action Group | Pub/Sub → Cloud Function → Slack |
| Auto-remediation | Ansible playbook on schedule | AWS Config auto-remediation | Azure Policy `deployIfNotExists` | SCC Recommendations API |
| Custom detection | Nessus compliance checks (audit files) | Custom Config rules (Lambda) | Custom Azure Policy definitions | Custom SCC modules (YAML) |

## 🔴 Red Team view

**Baseline drift is the attacker's strongest signal — new accounts without coverage.**

**Narrative (contained):**

A company's Terraform pipeline auto-enables Security Hub and Config rules when `CreateAccount` events fire. An engineer manually creates an emergency "hotfix" account via the AWS Console instead of the Terraform pipeline:

```bash
aws organizations create-account --account-name "Prod-Hotfix" --email "aws-hotfix@example.com"
```

The account is created. But the `CreateAccount` EventBridge rule's Lambda was deleted by a CI/CD misconfiguration 3 weeks ago — nobody noticed. The hotfix account has:

- No Security Hub enabled.
- No SCPs attached (default no-OU state in Organizations).
- No CloudTrail trail.
- Default VPC with `0.0.0.0/0` inbound rules (auto-created by AWS).

An attacker discovers this account via `organizations:ListAccounts` (a read-only action allowed in many IAM roles). The attacker finds the account has no trail, no guardrails, and proceeds to use it as a persistence pivot — deploying cryptomining instances with no detection coverage.

**How coverage gaps appear:**

| Gap type | Root cause | Attacker exploit |
|---|---|---|
| New account not in baseline scope | Account created manually, outside IaC pipeline | Account has zero detection; attacker uses it as persistence |
| Config rule deleted | CI/CD pipeline error / human error | Non-compliant resources accumulate without alerting |
| Security Hub disabled | Cost optimization during budget cycle | Detection blind for weeks |
| Region not in Config scope | Config recorder limited to specific regions | Attacker deploys in non-monitored region |
| Baseline outdated | CIS benchmark upgraded but Policy set not updated | New attack vectors not covered by old checks |

**Artifacts:**
- CloudTrail: `CreateAccount` without corresponding `EnableSecurityHub` event within 30 minutes.
- `ListAccounts` from unusual source IP (attacker reconnaissance).
- New instance `RunInstances` in a non-monitored region with no Flow Logs.

## 🔵 Blue Team view

**Account-birth hooks — baseline auto-apply on new accounts/projects.**

**AWS EventBridge → Step Functions account-birth baseline:**

```json
{
  "detail-type": ["AWS Service Event via CloudTrail"],
  "source": ["aws.organizations"],
  "detail": {
    "eventSource": ["organizations.amazonaws.com"],
    "eventName": ["CreateManagedAccount"]
  }
}
```

Step Functions state machine:
1. Wait 60 seconds (account provisioning delay).
2. `EnableSecurityHub` + `EnableAwsServiceAccess` for Config.
3. `PutConfigRule` for foundational rules.
4. `AttachPolicy` (SCP attach to default OU).
5. `CreateTrail` (multi-region, management events, log validation).
6. `PutMetricFilter` + `PutMetricAlarm` (baseline alarm setup).
7. Publish SNS: "New account XXXX baselined."

**Terraform module — account baseline as code:**

```hcl
module "account_baseline" {
  source = "github.com/example/terraform-aws-account-baseline"

  account_id = "222222222222"

  enable_cloudtrail    = true
  enable_config        = true
  enable_security_hub  = true
  enable_guardduty     = true

  scp_policy_arns = [
    aws_organizations_policy.deny_public_s3.arn,
    aws_organizations_policy.deny_iam_user_create.arn
  ]
}
```

**Detect account-birth failures — the Lambda that didn't fire:**

```
SELECT eventTime, requestParameters.accountName, requestParameters.accountId
FROM cloudtrail_111111111111
WHERE eventName = 'CreateManagedAccount'
  AND eventTime > now() - interval '1' day

-- Then, for each new account, check if SecurityHub was enabled within 1h:
SELECT eventTime, eventName, requestParameters.accountId
FROM cloudtrail_111111111111
WHERE eventName = 'EnableSecurityHub'
  AND eventTime BETWEEN '2026-06-22T02:00:00Z' AND '2026-06-22T03:00:00Z'
```

**Continuous monitoring cron — check all accounts daily:**

```bash
#!/usr/bin/env bash

ACCOUNTS=$(aws organizations list-accounts --query 'Accounts[].Id' --output text)

for ACCT in $ACCOUNTS; do
  echo "Checking account $ACCT..."
  
  TRAIL=$(aws cloudtrail describe-trails --region us-east-1 \
    --query "trailList[?IsMultiRegionTrail==\`true\`].Name" --output text 2>/dev/null)
  if [ -z "$TRAIL" ]; then
    curl -X POST "$SLACK_WEBHOOK" -d "{\"text\":\"ACCOUNT $ACCT HAS NO ORG TRAIL\"}"
  fi
  
  SH=$(aws securityhub describe-hub --region us-east-1 2>/dev/null)
  if [ $? -ne 0 ]; then
    curl -X POST "$SLACK_WEBHOOK" -d "{\"text\":\"ACCOUNT $ACCT HAS NO SECURITY HUB\"}"
  fi
done
```

**Checklist:**
- [ ] Security Hub / Defender for Cloud / SCC Premium enabled in all accounts/subscriptions/projects.
- [ ] All Security Hub standards / Azure Policy initiatives / SHA detectors are active.
- [ ] Account-birth automation is deployed and tested monthly.
- [ ] Daily cron verifies no account has lost its baseline coverage.
- [ ] Drift detection findings feed into the SOC ticket queue automatically.

Cross-link: [08-07 Drift Detection & Reconciliation](../IaC-Security/drift-detection-and-reconciliation.md), [10-02 Preventive Guardrails](preventive-guardrails-as-code.md), [06-05 Native Threat Detection](../Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md).

## Hands-on lab

Enable Security Hub and Config in your sandbox account and run compliance checks:

```bash
aws securityhub enable-security-hub
aws configservice describe-compliance-by-config-rule
aws securityhub get-findings --max-items 10
```

Review findings, note any non-compliant resources, and remediate.

## Detection rules & checklists

**Cloud Custodian — find accounts without Security Hub:**

```yaml
policies:
  - name: accounts-without-security-hub
    resource: account
    filters:
      - type: security-hub
        key: hub.enabled
        value: false
```

**Sigma rule — baseline removal:**

```yaml
title: Security Hub Disabled
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: DisableSecurityHub
  condition: selection
level: high
```

## References
- [AWS Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)
- [Azure Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
- [GCP Security Command Center](https://cloud.google.com/security-command-center/docs/concepts-security-command-center-overview)
- [CIS Benchmarks — Cloud](https://www.cisecurity.org/benchmark/)
- [MITRE ATT&CK — Disable or Modify Tools (T1562.001)](https://attack.mitre.org/techniques/T1562/001/)
