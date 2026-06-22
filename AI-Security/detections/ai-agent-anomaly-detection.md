# Detection 01 — AI Agent Anomaly Detection

> **Level:** Advanced
> **Prereqs:** `../agentic-ai-threat-model.md`, `../ai-agent-hardening-guardrails.md`
> **Clouds:** AWS · Azure · GCP · OnPrem
> **Authorization scope:** Deploy detection rules against your own sandbox telemetry. Test by simulating agent actions (or benign equivalents) in your own accounts (`111111111111`, `00000000-0000-0000-0000-000000000000`, `example-project`).

## 🔴 Red Team view — how attackers trigger these detections

**Rule 1 (Agent IAM writes):** Attacker injects a prompt that causes the agent to call `iam:CreateUser`, `iam:CreateAccessKey`, or `iam:AddUserToGroup`. The detection fires because the agent's IAM role has never (or rarely) performed IAM write operations in baseline. The attacker may try to blend by adding a benign IAM read (`iam:ListUsers`) before the write, but the write itself is the signal.

**Rule 2 (Unknown tool API):** Attacker uses a tool-confusion technique where the agent calls `lambda:CreateFunction` even though the agent's tool list only defines `s3:GetObject` and `dynamodb:Query`. The detection fires on any API call not in the agent's approved tool list. Attackers may try to camouflage by calling an API with a similar name (`s3:PutObject` instead of `s3:GetObject`) — the detection matches against an explicit allowlist.

**Rule 3 (Guardrail bypass pattern):** Attacker's prompt is blocked by guardrails. Within 5 minutes, the same session/user-agent retries with semantically similar but lexically different phrasing. The detection correlates guardrail denial logs with subsequent allowed actions from the same session. Attackers may attempt to evade by waiting longer than the correlation window, or by switching sessions — but the *intent* remains detectable through semantic similarity across prompts.

## 🔵 Blue Team view — detection engineering rationale

Rule 1 is the highest-priority signal. An agent performing any IAM write operation is a near-certain indicator of either misconfiguration (agent shouldn't have that permission) or compromise (prompt injection succeeded). Rule 2 catches tool misuse that may not trigger IAM-specific alerts — e.g., an agent invoking Lambda when it should only read S3. Rule 3 catches attackers probing guardrails, which is a precursor to a successful bypass. All three rules should ship to PagerDuty with immediate response SLA.

## Rule 1 — AI Agent IAM Write Operations

### Sigma rule

```yaml
title: AI Agent Performs IAM Write Operation
id: c1d2e3f4-8001-4001-8001-a1b2c3d4e5f6
status: experimental
description: |
  Detects when an AI agent's IAM role or service account performs an IAM write
  operation (CreateUser, CreateAccessKey, AddUserToGroup, AttachUserPolicy,
  CreateRole, PutRolePolicy, UpdateAssumeRolePolicy, etc.).
  AI agents should not have IAM write permissions — this is either a configuration
  error or a successful prompt injection.
author: ai-security-detection-team
date: 2026-06-22
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_agent:
    userIdentity.sessionContext.sessionIssuer.userName|contains:
      - 'Agent'
      - 'agent'
      - 'OpsAgent'
      - 'BedrockAgent'
    # Alternative: match on userAgent containing 'bedrock' or 'langchain'
  selection_iam_write:
    eventSource: iam.amazonaws.com
    eventName:
      - CreateUser
      - CreateAccessKey
      - CreateLoginProfile
      - AddUserToGroup
      - AttachUserPolicy
      - AttachRolePolicy
      - PutUserPolicy
      - PutRolePolicy
      - CreateRole
      - UpdateAssumeRolePolicy
      - CreatePolicy
      - CreatePolicyVersion
      - SetDefaultPolicyVersion
      - DeleteUser
      - DeleteRole
      - DeletePolicy
      - RemoveUserFromGroup
      - DetachUserPolicy
      - UpdateUser
  condition: selection_agent and selection_iam_write
level: critical
tags:
  - attack.privilege_escalation
  - attack.t1078
  - attack.t1098
  - ai_agent
  - prompt_injection
falsepositives:
  - Legitimate IAM automation (not AI agents) using similar role naming
  - Agent role name contains 'Agent' but is a CI/CD runner, not an LLM agent
```

### AWS — CloudTrail Lake query

```sql
SELECT
  eventTime,
  eventName,
  userIdentity.arn,
  userIdentity.sessionContext.sessionIssuer.userName,
  sourceIPAddress,
  userAgent,
  requestParameters,
  errorCode
FROM aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN (
    'CreateUser', 'CreateAccessKey', 'CreateLoginProfile',
    'AddUserToGroup', 'AttachUserPolicy', 'AttachRolePolicy',
    'PutUserPolicy', 'PutRolePolicy', 'CreateRole',
    'UpdateAssumeRolePolicy', 'CreatePolicy', 'DeleteUser',
    'DeleteRole', 'DeletePolicy'
  )
  AND (
    userIdentity.sessionContext.sessionIssuer.userName LIKE '%Agent%'
    OR userIdentity.arn LIKE '%:role/BedrockAgent%'
    OR userIdentity.arn LIKE '%:role/Agent%'
    OR userAgent LIKE '%bedrock%'
    OR userAgent LIKE '%langchain%'
  )
  AND eventTime > date_add('hour', -1, current_timestamp)
ORDER BY eventTime DESC
```

### AWS — CloudWatch Logs Insights query

```sql
fields @timestamp, eventName, userIdentity.arn,
       sourceIPAddress, userAgent, requestParameters
| filter eventSource = "iam.amazonaws.com"
| filter eventName in [
    "CreateUser", "CreateAccessKey", "CreateLoginProfile",
    "AddUserToGroup", "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutRolePolicy", "CreateRole",
    "UpdateAssumeRolePolicy"
  ]
| filter userIdentity.arn like /Agent/ or userAgent like /bedrock/
| sort @timestamp desc
```

### Azure — KQL (Sentinel)

```kql
// Agent managed identity or service principal performing IAM writes
let AgentIdentities = (
    IdentityInfo
    | where TimeGenerated > ago(30d)
    | where DisplayName has_any ("ai-agent", "copilot-agent", "bedrock-agent")
    | distinct AccountObjectId
);
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName has_any (
    "Add member to role",
    "Add member to group",
    "Create user",
    "Update user",
    "Add owner to group",
    "Add directory role member"
)
| where InitiatedBy.user.id in (AgentIdentities)
    or InitiatedBy.app.displayName has_any ("ai-agent", "copilot-agent")
| project TimeGenerated, OperationName, InitiatedBy,
          TargetResources, Result
| order by TimeGenerated desc
```

```kql
// Alternative: Azure Activity Log — agent permission changes
AzureActivity
| where TimeGenerated > ago(1h)
| where Caller has_any ("ai-agent", "managed-identity-agent")
| where OperationNameValue has_any (
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write"
)
| project TimeGenerated, Caller, OperationNameValue,
          ResourceId, CallerIpAddress, Properties
```

### GCP — Cloud Logging query (BigQuery)

```sql
SELECT
  timestamp,
  protopayload_auditlog.methodName,
  protopayload_auditlog.authenticationInfo.principalEmail,
  protopayload_auditlog.requestMetadata.callerIp,
  protopayload_auditlog.requestMetadata.callerSuppliedUserAgent,
  protopayload_auditlog.resourceName
FROM `example-project.logs.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.authenticationInfo.principalEmail LIKE '%agent-sa@%'
  AND protopayload_auditlog.methodName IN (
    'google.iam.admin.v1.CreateServiceAccount',
    'google.iam.admin.v1.CreateServiceAccountKey',
    'google.iam.admin.v1.SetIamPolicy',
    'google.iam.admin.v1.CreateRole',
    'google.iam.admin.v1.UpdateRole',
    'google.iam.admin.v1.DeleteServiceAccount',
    'google.iam.admin.v1.DeleteServiceAccountKey'
  )
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
ORDER BY timestamp DESC
```

### OnPrem — grep + jq on local audit log

```bash
grep 'iam\.CreateUser\|iam\.CreateAccessKey\|iam\.AddUserToGroup' /var/log/agent/agent-audit.log \
  | jq 'select(.approved_by == "auto" or .approved_by == null)'
```

## Rule 2 — AI Agent Invoking API Not in Known Tool List

### Sigma rule

```yaml
title: AI Agent Invokes API Outside Approved Tool List
id: d2e3f4a5-9002-4002-8002-b2c3d4e5f6a7
status: experimental
description: |
  Detects when an AI agent's IAM role calls an AWS API that is not in its
  pre-approved tool list. Each agent should have a finite, explicit list of
  APIs its tools can call. Any API call outside this list indicates either
  a tool-confusion attack or an agent misconfiguration.
author: ai-security-detection-team
date: 2026-06-22
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_agent:
    userIdentity.sessionContext.sessionIssuer.arn|contains:
      - ':role/OpsAgent'
      - ':role/BedrockAgent'
      - ':role/AIAgent'
  selection_api:
    eventName|notcontains:
      # KNOWN TOOL LIST — update per agent's actual approved APIs
      - GetObject
      - ListBucket
      - GetItem
      - Query
      - Scan
      - DescribeInstances
      - DescribeRegions
      - GetCallerIdentity
      - SendEmail
      - PublishTopic
      - GetMetricStatistics
      - ListMetrics
  condition: selection_agent and selection_api
level: high
tags:
  - attack.execution
  - attack.t1059
  - ai_agent
  - tool_confusion
  - prompt_injection
falsepositives:
  - New tool added to agent without updating detection allowlist
  - Agent role used by non-agent process (IAM role reuse)
```

### AWS — CloudTrail Lake query

```sql
SELECT
  eventTime, eventName, eventSource, userIdentity.arn,
  sourceIPAddress, userAgent, requestParameters
FROM aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
WHERE userIdentity.sessionContext.sessionIssuer.arn LIKE '%:role/OpsAgent%'
  AND eventName NOT IN (
    'GetObject', 'ListBuckets', 'ListObjects', 'ListObjectsV2',
    'GetItem', 'Query', 'Scan',
    'DescribeInstances', 'DescribeRegions', 'DescribeAvailabilityZones',
    'GetCallerIdentity', 'GetMetricStatistics', 'ListMetrics'
    -- UPDATE: add all APIs from the agent's approved tool OpenAPI spec
  )
  AND eventTime > date_add('hour', -1, current_timestamp)
  AND errorCode IS NULL  -- only successful calls count
ORDER BY eventTime DESC
```

### Azure — KQL (Sentinel)

```kql
// Agent performing Azure operations outside known tool list
let KnownActions = dynamic([
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "Microsoft.Insights/Metrics/Read",
    "Microsoft.Web/sites/functions/listKeys/action"
    // UPDATE: per agent's approved Azure role actions
]);
AzureActivity
| where TimeGenerated > ago(1h)
| where Caller has_any ("ai-agent", "agent-identity")
| where OperationNameValue !in (KnownActions)
| where ActivityStatus == "Succeeded"
| project TimeGenerated, Caller, OperationNameValue,
          ResourceId, CallerIpAddress, Properties
| order by TimeGenerated desc
```

### GCP — Cloud Logging query (BigQuery)

```sql
-- Agent SA calling APIs outside tool list
SELECT
  timestamp,
  protopayload_auditlog.methodName,
  protopayload_auditlog.serviceName,
  protopayload_auditlog.authenticationInfo.principalEmail
FROM `example-project.logs.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.authenticationInfo.principalEmail = 'vertex-agent-sa@example-project.iam.gserviceaccount.com'
  AND protopayload_auditlog.methodName NOT IN (
    'storage.objects.get',
    'storage.objects.list',
    'bigquery.jobs.query',
    'bigquery.tables.getData',
    'monitoring.timeSeries.list',
    'logging.logEntries.list'
    -- UPDATE: per agent's approved tool APIs
  )
  AND protopayload_auditlog.authorizationInfo[0].granted = true
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
ORDER BY timestamp DESC
```

## Rule 3 — Guardrail Bypass Pattern (Blocked → Retried with Different Phrasing)

### Sigma rule

```yaml
title: AI Agent Prompt Blocked by Guardrail Then Retried Within 5 Minutes
id: e3a4b5c6-0003-4003-8003-c3d4e5f6a7b8
status: experimental
description: |
  Detects when an agent prompt is blocked by content guardrails (Bedrock Guardrails,
  Azure AI Content Safety, Vertex Safety Filters, or guardrails-ai) and then
  within 5 minutes the same session attempts the same underlying action with
  different phrasing. This is a strong indicator of an attacker probing guardrails.
  The correlation requires guardrail logs joined to agent invocation logs.
author: ai-security-detection-team
date: 2026-06-22
logsource:
  product: aws
  service: cloudtrail
detection:
  guardrail_block:
    eventSource: bedrock.amazonaws.com
    eventName: GuardrailIntervention
    guardrailAction: BLOCKED
    # Timeframe: within 5 minutes of subsequent allowed invocation
  subsequent_invoke:
    eventSource: bedrock.amazonaws.com
    eventName: InvokeAgent
    # Same sessionId as guardrail_block
  # Requires session correlation:
  # guardrail_block.sessionId == subsequent_invoke.sessionId
  # AND subsequent_invoke.eventTime - guardrail_block.eventTime < 300 seconds
  timeframe: 5m
  condition: guardrail_block | near subsequent_invoke
level: high
tags:
  - attack.reconnaissance
  - attack.t1592
  - ai_agent
  - guardrail_bypass
  - defense_evasion
falsepositives:
  - User legitimately rephrased after unintentional block
  - Multiple users sharing an agent session (unlikely but possible)
```

### AWS — Correlation query (Athena / CloudTrail Lake)

```sql
-- Requires guardrail logs in CloudWatch joined with CloudTrail
-- Guardrail blocks in CloudWatch
WITH guardrail_blocks AS (
  SELECT
    timestamp AS block_time,
    JSON_EXTRACT_SCALAR(log, '$.sessionId') AS session_id,
    JSON_EXTRACT_SCALAR(log, '$.prompt') AS blocked_prompt,
    JSON_EXTRACT_SCALAR(log, '$.blockedTopic') AS blocked_topic
  FROM cloudwatch_guardrail_logs
  WHERE JSON_EXTRACT_SCALAR(log, '$.decision') = 'BLOCKED'
    AND timestamp > date_add('hour', -1, current_timestamp)
),
-- Subsequent agent invocations in CloudTrail
agent_invocations AS (
  SELECT
    eventTime AS invoke_time,
    requestParameters.sessionId AS session_id,
    requestParameters.promptText AS retry_prompt,
    userIdentity.arn
  FROM aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
  WHERE eventName = 'InvokeAgent'
    AND eventTime > date_add('hour', -1, current_timestamp)
)
SELECT
  g.block_time,
  a.invoke_time,
  g.session_id,
  g.blocked_prompt,
  a.retry_prompt,
  g.blocked_topic,
  a.userIdentity.arn
FROM guardrail_blocks g
JOIN agent_invocations a ON g.session_id = a.session_id
WHERE a.invoke_time BETWEEN g.block_time AND (g.block_time + INTERVAL '5' MINUTE)
ORDER BY g.block_time DESC
```

### Azure — KQL (Log Analytics / Sentinel)

```kql
let guardrailDenials = (
    AIServiceGuardrailLogs
    | where TimeGenerated > ago(1h)
    | where Action == "Blocked"
    | project DenialTime=TimeGenerated, SessionId, BlockedPrompt=PromptText,
              BlockedTopic=Category, UserId
);
let subsequentRequests = (
    AIAgentInvocationLogs
    | where TimeGenerated > ago(1h)
    | where Status == "Success"
    | project InvokeTime=TimeGenerated, SessionId, PromptText,
              UserId, AgentId, ToolCalled
);
guardrailDenials
| join kind=inner (
    subsequentRequests
    | where InvokeTime between (guardrailDenials.DenialTime .. (guardrailDenials.DenialTime + 5m))
) on SessionId
| extend 
    TimeGapSeconds = datetime_diff('second', InvokeTime, DenialTime)
| where TimeGapSeconds <= 300
| project 
    DenialTime, InvokeTime, TimeGapSeconds, SessionId, UserId,
    BlockedPrompt, RetryPrompt=PromptText, BlockedTopic, ToolCalled
| order by DenialTime desc
```

### GCP — Cloud Logging query (BigQuery)

```sql
-- Guardrail block events from Vertex AI Safety Filters
WITH safety_blocks AS (
  SELECT
    timestamp AS block_time,
    JSON_EXTRACT_SCALAR(protopayload_auditlog.metadataJson, '$.session_id') AS session_id,
    JSON_EXTRACT_SCALAR(protopayload_auditlog.metadataJson, '$.prompt_text') AS blocked_prompt,
    JSON_EXTRACT_SCALAR(protopayload_auditlog.metadataJson, '$.safety_category') AS blocked_category
  FROM `example-project.logs.cloudaudit_googleapis_com_activity`
  WHERE protopayload_auditlog.methodName = 'google.cloud.aiplatform.v1.SafetyFilter.Intervention'
    AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
),
-- Subsequent agent actions
agent_actions AS (
  SELECT
    timestamp AS invoke_time,
    JSON_EXTRACT_SCALAR(protopayload_auditlog.metadataJson, '$.session_id') AS session_id,
    JSON_EXTRACT_SCALAR(protopayload_auditlog.metadataJson, '$.prompt_text') AS retry_prompt,
    protopayload_auditlog.methodName AS action
  FROM `example-project.logs.cloudaudit_googleapis_com_activity`
  WHERE protopayload_auditlog.methodName LIKE 'google.cloud.aiplatform.v1.Agent%'
    AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
)
SELECT
  s.block_time,
  a.invoke_time,
  s.session_id,
  s.blocked_prompt,
  a.retry_prompt,
  s.blocked_category,
  a.action,
  TIMESTAMP_DIFF(a.invoke_time, s.block_time, SECOND) AS retry_delay_seconds
FROM safety_blocks s
JOIN agent_actions a ON s.session_id = a.session_id
WHERE a.invoke_time BETWEEN s.block_time AND TIMESTAMP_ADD(s.block_time, INTERVAL 5 MINUTE)
ORDER BY s.block_time DESC
```

### Python — batch correlation script

```python
#!/usr/bin/env python3
"""detect_guardrail_bypass.py — Correlate guardrail blocks with retry attempts"""

import json, sys, os
from datetime import datetime, timedelta

GUARDRAIL_LOG = os.environ.get("GUARDRAIL_LOG", "/tmp/agent-guardrail.log")
WINDOW_MINUTES = 5

def load_entries(logfile: str) -> list:
    entries = []
    with open(logfile) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError:
                continue
    return entries

def find_bypass_attempts(entries: list) -> list:
    blocks = [e for e in entries if e.get("decision") == "BLOCKED"]
    allowed = [e for e in entries if e.get("decision") == "ALLOWED"]

    findings = []
    for block in blocks:
        block_time = datetime.strptime(block["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
        for allow in allowed:
            allow_time = datetime.strptime(allow["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
            if block_time < allow_time <= block_time + timedelta(minutes=WINDOW_MINUTES):
                if block.get("tool") == allow.get("tool") or block.get("session_id") == allow.get("session_id"):
                    findings.append({
                        "block_time": block["timestamp"],
                        "retry_time": allow["timestamp"],
                        "blocked_tool": block.get("tool"),
                        "blocked_reason": block.get("reason"),
                        "retry_prompt": allow.get("prompt"),
                        "severity": "HIGH"
                    })
    return findings

if __name__ == "__main__":
    entries = load_entries(GUARDRAIL_LOG)
    findings = find_bypass_attempts(entries)
    if findings:
        print(f"ALERT: {len(findings)} guardrail bypass attempts detected:")
        for f in findings:
            print(f"  Blocked at {f['block_time']}, retried at {f['retry_time']}")
            print(f"  Tool: {f['blocked_tool']}, Reason: {f['blocked_reason']}")
        sys.exit(1)
    else:
        print("No guardrail bypass patterns detected.")
        sys.exit(0)
```

## Helper — Agent approval fatigue detection

### Azure — KQL

```kql
// Detect approval fatigue: >10 approvals in 10 minutes from same agent-user
let ApprovalEvents = (
    ApprovalWorkflows_CL
    | where TimeGenerated > ago(1h)
    | extend Approver = tostring(parse_json(Response_s).approved_by)
    | where Approver != ""
);
ApprovalEvents
| summarize ApprovalCount = count(),
            FirstApproval = min(TimeGenerated),
            LastApproval = max(TimeGenerated)
          by Approver, bin(TimeGenerated, 10m)
| where ApprovalCount > 10
| project Approver, ApprovalCount, FirstApproval, LastApproval,
          ApprovalRate = ApprovalCount / 10.0
| order by ApprovalCount desc
```

### GCP — Cloud Logging query

```sql
-- Agent approval fatigue: >10 approvals in 10 min from same approver
SELECT
  JSON_EXTRACT_SCALAR(protopayload_auditlog.metadataJson, '$.approved_by') AS approver,
  COUNT(*) AS approval_count,
  MIN(timestamp) AS first_approval,
  MAX(timestamp) AS last_approval
FROM `example-project.logs.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName = 'google.cloud.workflows.v1.ApprovalGranted'
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
GROUP BY approver, TIMESTAMP_TRUNC(timestamp, MINUTE, 10)
HAVING approval_count > 10
ORDER BY approval_count DESC
```

## Deployment guide

| Rule | SIEM | AWS Native | Azure Native | GCP Native | Response |
|---|---|---|---|---|---|
| Agent IAM writes (Rule 1) | Elastic / Splunk / Sentinel | EventBridge → Lambda → SNS → PagerDuty | Sentinel alert → Logic Apps → Teams | Log-based metric → Pub/Sub → Cloud Function → PagerDuty | Immediate: revoke agent role, rotate creds |
| Unknown tool API (Rule 2) | Elastic / Splunk | CloudWatch alarm on metric filter | Sentinel scheduled query rule | Alert policy on log metric | Investigate: validate agent tool list, check for prompt injection |
| Guardrail bypass (Rule 3) | Splunk correlation search | CloudWatch Insights scheduled query → SNS | Sentinel scheduled query rule (KQL) | BigQuery scheduled query → Pub/Sub | Investigate: analyze retry prompts, rate-limit session |
| Approval fatigue | Splunk / Sentinel UEBA | Custom CloudWatch metric | Sentinel UEBA anomaly | BigQuery scheduled query | Enforce cooldown, require re-auth |

### AWS EventBridge rule template (Rule 1)

```hcl
resource "aws_cloudwatch_event_rule" "agent_iam_write" {
  name        = "agent-iam-write-detection"
  description = "Triggers when an AI agent performs IAM write operations"
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "CreateUser", "CreateAccessKey", "CreateLoginProfile",
        "AddUserToGroup", "AttachUserPolicy", "AttachRolePolicy"
      ]
      userIdentity = {
        sessionContext = {
          sessionIssuer = {
            userName = [{ "prefix": "OpsAgent" }]
          }
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "agent_iam_alert" {
  rule = aws_cloudwatch_event_rule.agent_iam_write.name
  arn  = aws_lambda_function.agent_alert_lambda.arn
}
```

### Alert routing matrix

| Signal | Severity | Recipient | Response SLA |
|---|---|---|---|
| Agent IAM write (Rule 1) | Critical | Cloud security on-call + AI engineering lead | Immediate (< 5 min) |
| Agent API outside tool list (Rule 2) | High | Cloud security team | Investigate within 30 min |
| Guardrail bypass pattern (Rule 3) | High | AI security team + Detection engineering | Investigate within 1h |
| Approval fatigue (>10/min) | Medium | AI engineering lead | Review approval patterns within 24h |

### Test the detections (sandbox only)

```bash
# Test Rule 1: Trigger a simulated agent IAM write
# (In sandbox agent, send prompt that would cause IAM write)
python3 sandbox_agent.py <<EOF
create_iam_user test-detection-user
yes
EOF

# Verify guardrail log appears
cat /tmp/agent-guardrail.log

# Test Rule 3: Block-then-retry pattern
# 1. Send prompt that gets blocked
# 2. Re-send semantically similar prompt within 5 minutes
# 3. Run correlation script
python3 detect_guardrail_bypass.py
```

## References

- [AWS CloudTrail event reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [Azure Sentinel KQL](https://learn.microsoft.com/en-us/azure/sentinel/kusto-overview)
- [GCP Cloud Logging query syntax](https://cloud.google.com/logging/docs/view/logging-query-language)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [MITRE ATLAS](https://atlas.mitre.org/)
- Cross-link: `../agentic-ai-threat-model.md` — threat model these rules defend against
- Cross-link: `../ai-agent-hardening-guardrails.md` — hardening patterns to reduce alert volume
