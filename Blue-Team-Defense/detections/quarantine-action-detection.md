# Detection — Quarantine Action Detection

> **Module:** 10-05 Auto-Response: Isolate and Quarantine
> **Clouds:** AWS · Azure · GCP · OnPrem
> **Authorization scope:** Audit queries for your own environments.

## Purpose

Detect when any quarantine or isolation action is executed — whether triggered by automated playbook or manual SOC intervention. These actions are high-confidence indicators of active incident response and should be:
1. Auditable (what was quarantined, when, by whom, why).
2. Monitored (if too many quarantine actions fire, the auto-response may be in a flip-flop cycle).
3. Alerted (if quarantine actions fire outside business hours or without a corresponding incident ticket).

---

## AWS

### Detection 1 — EC2 instance quarantined (SG swap)

```
SELECT eventTime, eventName, userIdentity.arn,
       requestParameters.instanceId,
       requestParameters.groupId
FROM cloudtrail_111111111111
WHERE eventName = 'ModifyInstanceAttribute'
  AND requestParameters.groupId IN ('sg-0quarantinexxxxxxxx', 'sg-0quarantineyyyyyyyy')
ORDER BY eventTime DESC
```

### Detection 2 — IAM role inline deny policy applied (identity quarantine)

```
SELECT eventTime, eventName, userIdentity.arn,
       requestParameters.roleName, requestParameters.policyName
FROM cloudtrail_111111111111
WHERE eventName = 'PutRolePolicy'
  AND requestParameters.policyName LIKE '%Quarantine%'
ORDER BY eventTime DESC
```

### Detection 3 — EC2 instance stopped by auto-response

```
SELECT eventTime, eventName, userIdentity.arn,
       requestParameters.instanceId
FROM cloudtrail_111111111111
WHERE eventName = 'StopInstances'
  AND userIdentity.arn LIKE '%:role/AutoResponseExecutionRole'
ORDER BY eventTime DESC
```

### Detection 4 — SSM Automation quarantine document executed

```
SELECT eventTime, eventName, userIdentity.arn,
       requestParameters.documentName
FROM cloudtrail_111111111111
WHERE eventName = 'StartAutomationExecution'
  AND requestParameters.documentName IN (
    'AWS-DetachIamRoleFromInstance',
    'AWS-StopEC2Instance',
    'AWS-QuarantineInstance'
  )
ORDER BY eventTime DESC
```

### Detection 5 — SCP Deny * attached (account-level quarantine)

```
SELECT eventTime, eventName, userIdentity.arn,
       requestParameters.policyId, requestParameters.targetId
FROM cloudtrail_111111111111
WHERE eventName = 'AttachPolicy'
  AND requestParameters.policyId IN (
    SELECT id FROM s3_guardrail_policies WHERE name = 'QuarantineDenyAll'
  )
ORDER BY eventTime DESC
```

### AWS Config rule — detect instances not in quarantine SG during incident

```json
{
  "ConfigRuleName": "quarantine-sg-enforcement",
  "Source": {"Owner": "AWS", "SourceIdentifier": "EC2_SECURITY_GROUP_ATTACHED_TO_ENI"},
  "Scope": {"ComplianceResourceTypes": ["AWS::EC2::Instance"]},
  "InputParameters": "{\"groupId\": \"sg-0quarantinexxxxxxxx\"}"
}
```

---

## Azure

### Detection 1 — VM stopped via Sentinel Playbook

```kusto
AzureActivity
| where OperationNameValue == "Microsoft.Compute/virtualMachines/deallocate/action"
| where Caller contains "SentinelPlaybook" or Caller contains "LogicApp"
| project TimeGenerated, Caller, ResourceId, CorrelationId
```

### Detection 2 — User disabled (identity quarantine)

```kusto
AuditLogs
| where OperationName == "Update user"
| where TargetResources[0].modifiedProperties[0].newValue == "false"
| where TargetResources[0].modifiedProperties[0].displayName == "AccountEnabled"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].userPrincipalName
```

### Detection 3 — User sessions revoked

```kusto
AuditLogs
| where OperationName == "Revoke sign-in sessions"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].userPrincipalName
```

### Detection 4 — NSG rule added (network quarantine)

```kusto
AzureActivity
| where OperationNameValue == "Microsoft.Network/networkSecurityGroups/securityRules/write"
| where Properties contains "Quarantine" or Properties contains "DenyAll"
| project TimeGenerated, Caller, ResourceId
```

### Detection 5 — Conditional Access block applied

```kusto
SigninLogs
| where ResultType == "53003"  // Blocked by Conditional Access
| where ConditionalAccessStatus == "failure"
| project TimeGenerated, UserPrincipalName, IPAddress, UserAgent
```

---

## GCP

### Detection 1 — Compute instance stopped via Cloud Function

```
SELECT timestamp, resource.labels.instance_id,
       protoPayload.authenticationInfo.principalEmail
FROM cloudaudit_000000000000
WHERE protoPayload.methodName = "v1.compute.instances.stop"
  AND protoPayload.authenticationInfo.principalEmail LIKE "%quarantine%"
  OR protoPayload.authenticationInfo.principalEmail LIKE "%auto-response%"
ORDER BY timestamp DESC
```

### Detection 2 — Service account key deleted (identity quarantine)

```
SELECT timestamp, protoPayload.resourceName,
       protoPayload.authenticationInfo.principalEmail
FROM cloudaudit_000000000000
WHERE protoPayload.methodName = "google.iam.admin.v1.DeleteServiceAccountKey"
  OR protoPayload.methodName = "DisableServiceAccountKey"
ORDER BY timestamp DESC
```

### Detection 3 — IAM policy binding removed (identity quarantine)

```
SELECT timestamp,
       protoPayload.request.bindings,
       protoPayload.authenticationInfo.principalEmail
FROM cloudaudit_000000000000
WHERE protoPayload.methodName = "SetIamPolicy"
  AND protoPayload.request.policy.bindings IS NULL
ORDER BY timestamp DESC
```

### Detection 4 — Firewall rule inserted (network quarantine)

```
SELECT timestamp, resource.labels.firewall_name,
       protoPayload.authenticationInfo.principalEmail
FROM cloudaudit_000000000000
WHERE protoPayload.methodName = "v1.compute.firewalls.insert"
  AND (protoPayload.request.name LIKE "%quarantine%"
    OR protoPayload.request.denied IS NOT NULL)
ORDER BY timestamp DESC
```

### Detection 5 — Org policy deny-all applied (folder/project quarantine)

```
SELECT timestamp, protoPayload.resourceName,
       protoPayload.authenticationInfo.principalEmail
FROM cloudaudit_000000000000
WHERE protoPayload.methodName = "SetOrgPolicy"
  AND protoPayload.request.constraint CONTAINS "deny"
ORDER BY timestamp DESC
```

---

## OnPrem

### Sigma rule — AD account disabled

```yaml
title: Active Directory Account Disabled During Incident
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4725
    TargetUserName|contains: quarantine
  condition: selection
level: high
```

### Sigma rule — firewall rule added

```yaml
title: Firewall Deny Rule Added
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4950
    RuleName|contains: "block" or "deny" or "quarantine"
  condition: selection
level: medium
```

---

## Correlation query — did quarantine fire outside incident context?

This detects quarantine actions without a corresponding incident ticket or during unexpected hours. High-confidence indication of either a false-positive auto-response or an attacker testing the quarantine playbook.

### AWS — quarantine without incident context

```
SELECT q.eventTime AS quarantine_time, q.eventName, q.userIdentity.arn,
       q.requestParameters.instanceId,
       i.eventTime AS incident_time, i.eventName AS incident_event
FROM cloudtrail_111111111111 q
LEFT JOIN cloudtrail_111111111111 i
  ON i.requestParameters.instanceId = q.requestParameters.instanceId
  AND i.eventName IN ('GuardDutyFinding', 'SecurityHubFinding')
  AND ABS(DATETIME_DIFF(q.eventTime, i.eventTime, MINUTE)) < 30
WHERE q.eventName IN ('ModifyInstanceAttribute', 'StopInstances', 'PutRolePolicy')
  AND q.requestParameters.groupId = 'sg-0quarantinexxxxxxxx'
  AND i.eventTime IS NULL
ORDER BY q.eventTime DESC
```

### Azure — quarantine actions count per hour (detect flip-flop)

```kusto
AzureActivity
| where OperationNameValue in (
    "Microsoft.Compute/virtualMachines/deallocate/action",
    "Microsoft.Network/networkSecurityGroups/securityRules/write"
)
| where Caller contains "Playbook" or Caller contains "LogicApp"
| summarize Count = count() by bin(TimeGenerated, 1h), OperationNameValue
| where Count > 5
| project TimeGenerated, OperationNameValue, Count
```

---

## Alert configuration

### AWS EventBridge rule — any quarantine action

```json
{
  "source": ["aws.ec2", "aws.iam", "aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "ModifyInstanceAttribute",
      "StopInstances",
      "PutRolePolicy",
      "StartAutomationExecution"
    ],
    "requestParameters": {
      "groupName": [{"prefix": "quarantine"}]
    }
  }
}
```

### Azure Activity Log alert — any quarantine playbook run

```bash
az monitor activity-log alert create \
  --name "QuarantinePlaybookAlert" \
  --condition "category=Administrative and operationName=Microsoft.Compute/virtualMachines/deallocate/action" \
  --action-group /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-security/providers/Microsoft.Insights/actionGroups/secops \
  --resource-group rg-security
```

### GCP Log-based alert — quarantine actions

```bash
gcloud alpha monitoring policies create \
  --policy-from-file quarantine-alert-policy.yaml
```

---

## Response runbook

| Alert | Immediate action | Investigation follow-up |
|---|---|---|
| Quarantine playbook executed | Verify the playbook fired because of a real GuardDuty/Defender/SCC finding, not a test | Check the correlated finding for severity and source IP |
| Multiple quarantines in < 1 hour | Pause the auto-response playbook. Check for flip-flop pattern. | Investigate rate of findings; possible attacker causing repeated violations |
| Quarantine outside business hours | Page on-call SOC immediately | Treat as potential real incident until proven otherwise |
| Quarantine without upstream finding | The playbook was either manually triggered or incorrectly configured | Audit who ran it; check CI/CD logs |
| Quarantine action then immediate revert | Attacker may be testing rollback. Page SOC. | Review CloudTrail for the principal who reverted the quarantine |

---

## References
- [10-05 Auto-Response Isolate and Quarantine](../auto-response-isolate-and-quarantine.md)
- [06-02 CloudTrail Activity Events](../../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md)
- [06-03 Azure Log Analytics & Sentinel](../../Monitoring-Detection-SIEM/azure-log-analytics-and-sentinel.md)
- [06-04 GCP Cloud Audit Logs & SCC](../../Monitoring-Detection-SIEM/gcp-cloud-audit-logs-and-scc.md)
