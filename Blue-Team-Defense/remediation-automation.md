# 08 — Remediation Automation

> **Level:** Advanced
> **Prereqs:** [Break Glass & Emergency Procedures](break-glass-and-emergency-procedures.md), [IaC Supply Chain & Provider Trust](../IaC-Security/iac-supply-chain-and-provider-trust.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Persistence
> **Authorization scope:** Deploy remediation automation only in your own sandbox accounts. Never auto-remediate production data-plane resources without human approval.

## What & why

Auto-remediation closes findings without human intervention for high-confidence, low-risk issues. The rule: never auto-remediate production data-plane resources (databases, compute instances), but auto-close IAM, network misconfigurations, and public-access findings. Manual remediation should be the exception, not the rule, for infrastructure safety nets.

## The OnPrem reality

On-prem "auto-remediation" was a helpdesk ticket queue: compliance scan finds host missing a patch → ticket created → L2 engineer validates → applies patch during change window. SLAs were measured in days. Cloud auto-remediation shrinks the window to seconds for well-understood issues like "S3 bucket went public."

## Cross-cloud comparison

| Provider | Auto-remediation service | Trigger | Safe categories to auto-remediate | Manual categories |
|---|---|---|---|---|
| AWS | AWS Config rules + `AWSConfigRemediation` | Config compliance change → SSM Automation | S3 public access, SG open ports, EBS encryption, IAM password policy | EC2 instance operations, RDS modifications, IAM role deletion |
| AWS | Security Hub custom actions → Lambda | Security Hub finding → EventBridge | GuardDuty low-severity network findings | GuardDuty high-severity credential exfiltration |
| Azure | Azure Policy `deployIfNotExists` | Resource creation / update | Diagnostic settings, VM extensions, tag enforcement | Data-plane operations, key rotation |
| Azure | Sentinel Playbook (Logic App) | Sentinel alert → Logic App trigger | Block IP via NSG, disable user, revoke session | VM deletion, DB modifications |
| GCP | SCC Recommendations API → Cloud Function | SCC finding → Pub/Sub | Public bucket, open firewall, disable SA key | Instance deletion, IAM policy changes, project deletion |
| GCP | OS Config `guestPolicy` → Patch compliance | Scheduled / on-demand | Package installation, config file enforcement | Kernel updates, service restarts |

## AWS

**AWS Config auto-remediation — fix public S3 bucket:**

```bash
aws configservice put-remediation-configurations \
  --remediation-configurations '[{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "TargetType": "SSM_DOCUMENT",
    "TargetId": "AWS-ConfigureS3BucketPublicAccessBlock",
    "Parameters": {
      "AutomationAssumeRole": {"StaticValue": {"Values": ["arn:aws:iam::111111111111:role/ConfigRemediationRole"]}},
      "BlockPublicAcls": {"StaticValue": {"Values": ["true"]}},
      "BlockPublicPolicy": {"StaticValue": {"Values": ["true"]}},
      "IgnorePublicAcls": {"StaticValue": {"Values": ["true"]}},
      "RestrictPublicBuckets": {"StaticValue": {"Values": ["true"]}},
      "BucketName": {"ResourceValue": {"Value": "RESOURCE_ID"}}
    },
    "Automatic": true,
    "MaximumAutomaticAttempts": 3,
    "RetryAttemptSeconds": 60
  }]'
```

**Auto-remediate open Security Group (0.0.0.0/0 on SSH):**

```bash
aws ssm create-document \
  --name "RemediateOpenSSH" \
  --document-type "Automation" \
  --content '{
    "description": "Revoke SSH from 0.0.0.0/0",
    "schemaVersion": "0.3",
    "assumeRole": "{{AutomationAssumeRole}}",
    "parameters": {
      "GroupId": {"type": "String"},
      "AutomationAssumeRole": {"type": "String"}
    },
    "mainSteps": [{
      "name": "RevokeSSH",
      "action": "aws:executeAwsApi",
      "inputs": {
        "Service": "ec2",
        "Api": "RevokeSecurityGroupIngress",
        "GroupId": "{{GroupId}}",
        "IpPermissions": [{
          "IpProtocol": "tcp",
          "FromPort": 22,
          "ToPort": 22,
          "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }]
      }
    }]
  }'
```

**Remediation role — least-privilege for the auto-remediation engine:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutPublicAccessBlock",
        "s3:PutBucketAcl",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:CreateFlowLogs",
        "iam:UpdateAccountPasswordPolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

**Dangerous patterns to NOT auto-remediate:**

| Finding type | Why manual | Safe alternative |
|---|---|---|
| GuardDuty `CredentialExfiltration` | Could be false-positive; disabling credentials breaks prod | Auto-apply `Deny *` SCP to account, page SOC |
| RDS public access | Auto-modifying RDS security group may break app connectivity | Auto-tag `NeedsRemediation`, notify DBA team |
| Root user activity | Root is legitimate for rare billing/closing-account actions | Alert + page SOC; do not auto-disable root |
| IAM policy attachment | Could break application functionality | Alert + quarantine, human-approve policy change |

## Azure

**Azure Policy `deployIfNotExists` — auto-remediate diagnostic settings:**

```json
{
  "if": {
    "field": "type",
    "equals": "Microsoft.Compute/virtualMachines"
  },
  "then": {
    "effect": "deployIfNotExists",
    "details": {
      "type": "Microsoft.Insights/diagnosticSettings",
      "deploymentScope": "resourceGroup",
      "roleDefinitionIds": [
        "/providers/Microsoft.Authorization/roleDefinitions/00000000-0000-0000-0000-000000000000"
      ],
      "existenceCondition": {
        "field": "Microsoft.Insights/diagnosticSettings/logs.enabled",
        "equals": "true"
      },
      "deployment": {
        "properties": {
          "mode": "incremental",
          "template": {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [{
              "type": "Microsoft.Insights/diagnosticSettings",
              "apiVersion": "2021-05-01-preview",
              "name": "[concat('diag-', parameters('vmName'))]",
              "properties": {
                "workspaceId": "[parameters('workspaceId')]",
                "logs": [{
                  "category": "Administrative",
                  "enabled": true
                }]
              }
            }]
          }
        }
      }
    }
  }
}
```

**Sentinel Playbook — auto-block malicious IP:**

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "triggers": {
      "When_a_Sentinel_alert_is_triggered": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "host": {
            "connection": { "name": "azuresentinel" }
          },
          "body": {
            "callback_url": "@{listCallbackUrl()}"
          }
        }
      }
    },
    "actions": {
      "Add_IP_to_NSG_deny_rule": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": { "name": "azurenetworksecuritygroups" }
          },
          "method": "put",
          "path": "/subscriptions/@{triggerBody()?['WorkspaceSubscriptionId']}/resourceGroups/rg-security/providers/Microsoft.Network/networkSecurityGroups/nsg-quarantine/securityRules/deny-malicious-ip",
          "body": {
            "properties": {
              "priority": 100,
              "direction": "Inbound",
              "access": "Deny",
              "protocol": "*",
              "sourceAddressPrefix": "@{triggerBody()?['ExtendedProperties']?['SourceIP']}"
            }
          }
        }
      }
    }
  }
}
```

## GCP

**SCC Recommendation → Cloud Function auto-remediate public bucket:**

```python
import functions_framework
from google.cloud import storage

@functions_framework.cloud_event
def remediate_public_bucket(cloud_event):
    finding = cloud_event.data
    resource_name = finding.get('resourceName', '')

    if 'storage.googleapis.com/Bucket' not in resource_name:
        return

    bucket_name = resource_name.split('/')[-1]
    client = storage.Client()
    bucket = client.get_bucket(bucket_name)

    bucket.iam_configuration.uniform_bucket_level_access_enabled = True
    bucket.iam_configuration.public_access_prevention = 'enforced'
    bucket.patch()

    print(f"Remediated public bucket: {bucket_name}")
```

**Deploy as Cloud Function triggered by Pub/Sub:**

```bash
gcloud functions deploy remediate-public-bucket \
  --runtime python312 \
  --trigger-topic scc-findings \
  --entry-point remediate_public_bucket \
  --region us-east1 \
  --service-account remediator-sa@project-id-111111.iam.gserviceaccount.com
```

**Remediation SLO — monitor how fast findings close:**

```
SELECT
  category,
  AVG(TIMESTAMP_DIFF(closeTime, createTime, MINUTE)) AS avg_remediation_minutes,
  COUNT(*) AS total_findings
FROM scc_findings_000000000000
WHERE closeTime IS NOT NULL
  AND createTime > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
GROUP BY category
ORDER BY avg_remediation_minutes DESC
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Auto-fix public access | Firewall script via SIEM webhook | Config auto-remediation (SSM doc) | Policy `deployIfNotExists` | SCC Recommendation → Cloud Function |
| Auto-patch | SCCM / Ansible scheduled job | Systems Manager Patch Manager | Azure Automation Update Management | OS Config `guestPolicy` |
| Remediation engine | Rundeck / StackStorm | SSM Automation / Lambda | Logic App / Automation Account | Cloud Functions / Workflows |
| Approval gate | ServiceNow change approval | Step Functions wait-for-approval task | Logic App approval action | Cloud Workflows conditional step |
| False-positive guard | Runbook test before production | Remediation action in audit mode first | Policy `audit` before `deployIfNotExists` | SCC mute rules for known patterns |
| Remediation SLO | Weekly compliance scan closure | Days (MTTR measured per finding) | Secure Score trending | SCC finding age dashboard |

## 🔴 Red Team view

**Attackers exploit remediation failure modes.**

**Narrative — auto-remediation fails open (contained):**

A production S3 bucket has auto-remediation configured: Config rule detects public access → SSM document applies `PutPublicAccessBlock=true`. During Black Friday, the auto-remediation hits an API throttle limit (`TooManyRequestsException`). The retry logic:

```
Attempt 1: Throttled (API limit reached during Black Friday traffic spike)
Attempt 2: Throttled (back-off 60s)
Attempt 3: Throttled (back-off 120s)
→ MaximumAutomaticAttempts=3 reached → Finding marked FAILED → No further automatic attempts
```

The bucket stays public. The Finding is in Security Hub at `FAILED` state — but the SOC assumes auto-remediation handles it and no human looks. An attacker discovers the bucket 2 hours later and exfiltrates the data.

**Narrative — auto-remediation rollback (contained):**

An auto-remediation function applies `PutPublicAccessBlock=true` to a bucket used by an internal application. The application breaks — it relied on public-read access for a specific path. The ops team manually reverts the `PublicAccessBlock` to `false` at 3 AM during the incident. The revert triggers another Config compliance check, auto-remediation fires again, and the cycle repeats ("flip-flop remediation").

**Artifacts:**
- CloudTrail: alternating `PutPublicAccessBlock` (block true → false → true → false) within a short time window.
- Config: recurring compliance changes for the same resource.
- The bucket stays public during the flip-flop windows.

## 🔵 Blue Team view

**Safe auto-remediation patterns:**

| Pattern | Implementation | Why safe |
|---|---|---|
| One-way toggle | `PutPublicAccessBlock=true` only; never auto-set to false | No flip-flop; human must reopen if needed |
| Tag-based exclusion | Add tag `RemediationExempt=true` before manual revert | Config rule scoped to exclude tagged resources |
| Audit-first deployment | First month: Config rule in `audit` mode; observe false positive rate | Validate before enabling auto-remediation |
| Business-hours gating | Step Function checks `IsBusinessHours` before proceeding | Avoid auto-fix breaking production during critical periods |
| Human-approval for high-risk | Step Functions `waitForTaskToken` → Slack approval button | Data-plane changes get human sign-off |
| Daily reconciliation | Cron checks: "Did any auto-remediated resource get manually reverted within 24h?" | Detect flip-flop pattern, page SOC |

**Human-approval workflow (Step Functions):**

```json
{
  "Comment": "Auto-remediate S3 public access with approval if tag critical=true",
  "StartAt": "CheckCriticalTag",
  "States": {
    "CheckCriticalTag": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.details.resourceTag.critical",
          "StringEquals": "true",
          "Next": "WaitForApproval"
        }
      ],
      "Default": "ApplyPublicAccessBlock"
    },
    "WaitForApproval": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
      "Parameters": {
        "FunctionName": "SlackApprovalLambda",
        "Payload": {
          "message": "Bucket $.details.bucketName is public and tagged critical. Approve remediation?",
          "taskToken.$": "$$.Task.Token"
        }
      },
      "Next": "ApplyPublicAccessBlock"
    },
    "ApplyPublicAccessBlock": {
      "Type": "Task",
      "Resource": "arn:aws:states:::aws-sdk:s3:putPublicAccessBlock",
      "End": true
    }
  }
}
```

**Daily flip-flop detection:**

```
SELECT eventTime, eventName, requestParameters.bucketName,
       requestParameters.publicAccessBlockConfiguration
FROM cloudtrail_111111111111
WHERE eventName IN ('PutPublicAccessBlock', 'DeletePublicAccessBlock')
  AND eventTime > now() - interval '1' day
ORDER BY bucketName, eventTime
```

**Checklist:**
- [ ] Auto-remediation covers S3 public access, SG open ports, EBS encryption only.
- [ ] Auto-remediation NEVER modifies data-plane resources (RDS, DynamoDB, EC2 terminate).
- [ ] All auto-remediation has a maximum retry count and dead-letter queue for failures.
- [ ] `RemediationExempt` tag mechanism is documented and SOC can query exempted resources.
- [ ] Monthly test: create a public bucket, verify it's auto-remediated within 5 minutes.

Cross-link: [10-05 Auto-Response Isolate](auto-response-isolate-and-quarantine.md), [08-07 Drift Detection](../IaC-Security/drift-detection-and-reconciliation.md), [09-08 Evasion & Trail-Free Actions](../Red-Team-Offense/evasion-and-trail-free-actions.md).

## Hands-on lab

See [labs/landing-zone-mini-lab.md](labs/landing-zone-mini-lab.md) — includes SCP testing which is the preventive companion to auto-remediation.

## Detection rules & checklists

**Cloud Custodian — auto-remediate without action:**

```yaml
policies:
  - name: auto-fix-public-s3
    resource: s3
    filters:
      - type: bucket-policy
        key: "Statement[].Principal"
        op: contains
        value: "*"
    actions:
      - type: set-public-access-block
        state: true
```

## References
- [AWS Config Remediation](https://docs.aws.amazon.com/config/latest/developerguide/remediation.html)
- [Azure Policy Remediation](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources)
- [GCP SCC Finding Remediation](https://cloud.google.com/security-command-center/docs/how-to-remediate-findings)
- [MITRE ATT&CK — Disable or Modify Tools (T1562.001)](https://attack.mitre.org/techniques/T1562/001/)
