# Detection 01 — Admin AssumeRole Detection via CloudTrail

> **Detection type:** Sigma rules + CloudTrail Lake queries
> **Target events:** `sts:AssumeRole`, `sts:AssumeRoleWithSAML`, `sts:AssumeRoleWithWebIdentity`
> **Log source:** AWS CloudTrail (management events), Azure Activity Log, GCP Cloud Audit Logs
> **MITRE ATT&CK (tactics):** Persistence, Privilege Escalation, Defense Evasion

---

## Overview

Detecting privileged role assumption by distinguishing **manual** (interactive) from **programmatic** (automated) assume-role patterns. Manual assume-role events — especially from unusual User-Agents, outside business hours, or chained across multiple roles — are high-fidelity signals of attacker lateral movement or persistence.

## Sigma Rules

### Sigma Rule 1 — Manual AssumeRole Detected (Non-Console, Non-SDK)

```yaml
title: Manual AssumeRole with Unusual User-Agent
id: detect-01-manual-assume-role
status: experimental
description: Detects AssumeRole API calls from User-Agents not matching known automation patterns (aws-cli, Terraform, CloudFormation, SDKs).
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sts.amazonaws.com
    eventName: AssumeRole
  filter_automation:
    userAgent|contains:
      - 'aws-cli'
      - 'aws-sdk'
      - 'Boto3'
      - 'APN/1.0 HashiCorp'
      - 'cloudformation.amazonaws.com'
      - 'signin.amazonaws.com'
      - 'console.amazonaws.com'
      - 'lambda.amazonaws.com'
      - 'GitHub-Hookshot'
      - 'Azure-DevOps'
  filter_legit_services:
    userAgent|contains:
      - 'ec2.amazonaws.com'
      - 'ecs.amazonaws.com'
      - 'eks.amazonaws.com'
  condition: selection and not (filter_automation or filter_legit_services)
level: high
falsepositives:
  - New CI/CD tool with custom User-Agent
  - Third-party SaaS integration (validate User-Agent)
  - Security tool performing authorized assume-role testing
```

### Sigma Rule 2 — Chained AssumeRole (A → B → C within 5 Minutes)

```yaml
title: Chained AssumeRole Cascade Within Short Window
id: detect-02-chained-assume-role
status: experimental
description: Detects an AssumedRole principal performing another AssumeRole call, indicating a privilege chain.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sts.amazonaws.com
    eventName: AssumeRole
    userIdentity.type: AssumedRole
  filter_approved_chains:
    roleSessionName|contains: 'ApprovedChain'
  condition: selection and not filter_approved_chains
  timeframe: 5m
level: high
falsepositives:
  - Cross-account audit tooling (add roleSessionName filter)
  - Multi-hop pipeline with documented chain
  - Lambda execution role assuming another role
```

### Sigma Rule 3 — AssumeRole from Unusual TLS Fingerprint (JA3 / JA4)

```yaml
title: AssumeRole from Unusual TLS Client
id: detect-03-tls-fingerprint-assume-role
status: experimental
description: Detects AssumeRole events where the TLS JA3 or JA4 fingerprint doesn't match known automation binaries. Requires CloudTrail Lake with enhanced delivery (TLS metadata).
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sts.amazonaws.com
    eventName: AssumeRole
  filter_expected_ja4:
    tlsDetails.tlsClientHello.fingerprint|contains:
      - 'ja4_hash_aws_cli_v2'
      - 'ja4_hash_terraform_v1_6'
      - 'ja4_hash_boto3_latest'
  condition: selection and not filter_expected_ja4
level: medium
falsepositives:
  - Custom automation tool with unique TLS stack
  - New SDK version not yet in baseline
```

> (as of June 2026, JA4 hash values vary per CLI/SDK version; TLS fingerprint metadata availability depends on CloudTrail Lake enhanced delivery. Baseline your own known-good JA4 fingerprints for the AWS CLI, Terraform, and boto3 versions in use.)

### Sigma Rule 4 — AssumeRole with Suspicious RoleSessionName

```yaml
title: Suspicious RoleSessionName Patterns
id: detect-04-session-name-patterns
status: experimental
description: Detects AssumeRole calls with roleSessionName matching pentesting tool conventions or lacking organization naming standards.
logsource:
  product: aws
  service: cloudtrail
detection:
  keywords:
    - 'Pacu'
    - 'pacu_session'
    - 'ScoutSuite'
    - 'prowler'
    - 'enumerate'
    - 'recon'
    - 'test'
  selection:
    eventSource: sts.amazonaws.com
    eventName: AssumeRole
    requestParameters.roleSessionName|contains:
      - 'Pacu'
      - 'pacu'
      - 'test'
      - 'hack'
      - 'exploit'
      - 'backdoor'
  condition: selection
level: high
falsepositives:
  - Legitimate security team using the term "test" in session names
```

## CloudTrail Lake SQL Queries

### Query 1 — Detect manual assume-role (programmatic exclusion)

```sql
SELECT
  eventTime,
  userIdentity.arn AS callerArn,
  requestParameters.roleArn AS targetRole,
  requestParameters.roleSessionName,
  sourceIPAddress,
  userAgent,
  tlsDetails.clientHello.cipherSuites AS tlsCipher
FROM
  "<event-data-store-id>"
WHERE
  eventName = 'AssumeRole'
  AND eventTime > now() - interval '1' day
  AND userAgent NOT LIKE '%aws-cli%'
  AND userAgent NOT LIKE '%aws-sdk%'
  AND userAgent NOT LIKE '%Boto3%'
  AND userAgent NOT LIKE '%Terraform%'
  AND userAgent NOT LIKE '%console.amazonaws.com%'
  AND userAgent NOT LIKE '%signin.amazonaws.com%'
ORDER BY
  eventTime DESC
```

### Query 2 — Chained assume-role detection

```sql
WITH role_chains AS (
  SELECT
    eventTime,
    userIdentity.arn AS fromRole,
    requestParameters.roleArn AS toRole,
    sourceIPAddress,
    userAgent,
    LAG(toRole_string) OVER (
      PARTITION BY sourceIPAddress
      ORDER BY eventTime
    ) AS previous_target_role
  FROM
    "<event-data-store-id>"
  WHERE
    eventName = 'AssumeRole'
    AND userIdentity.type = 'AssumedRole'
    AND eventTime > now() - interval '1' day
)
SELECT *
FROM role_chains
WHERE previous_target_role IS NOT NULL
ORDER BY eventTime DESC
```

### Query 3 — Geo-anomalous assume-role

```sql
SELECT
  eventTime,
  userIdentity.arn,
  requestParameters.roleArn,
  sourceIPAddress,
  userAgent,
  awsRegion
FROM
  "<event-data-store-id>"
WHERE
  eventName = 'AssumeRole'
  AND eventTime > now() - interval '1' day
  AND sourceIPAddress NOT LIKE '192.0.2.%'  -- Replace with your corporate egress
  AND awsRegion NOT IN ('us-east-1', 'eu-west-1')  -- Replace with approved regions
ORDER BY
  eventTime DESC
```

### Query 4 — AssumeRole volume anomaly (potential enumeration)

```sql
SELECT
  date_trunc('hour', eventTime) AS hour_bin,
  sourceIPAddress,
  COUNT(*) AS assume_count,
  array_agg(DISTINCT requestParameters.roleArn) AS roles_targeted
FROM
  "<event-data-store-id>"
WHERE
  eventName = 'AssumeRole'
  AND errorCode IS NULL  -- Successful only
  AND eventTime > now() - interval '1' day
GROUP BY
  date_trunc('hour', eventTime),
  sourceIPAddress
HAVING
  COUNT(*) > 5
ORDER BY
  assume_count DESC
```

## Azure Equivalent Queries

### Azure Activity Log — detect role assignment to unusual service principal

```kusto
AzureActivity
| where OperationNameValue contains "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where Caller contains "spn:" or Caller contains "appid:"
| join kind=inner (
    SigninLogs
    | where AppId !in ("797f4846-ba00-4fd7-ba43-dac1f8f63013", "1950a258-227b-4e31-a9cf-717495945fc2")
) on $left.Caller == $right.AppId
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, Properties
```

### Azure — detect PIM activation outside business hours

```kusto
AuditLogs
| where ActivityDisplayName == "Add member to role completed (PIM activation)"
| where hourofday(ActivityDateTime) < 7 or hourofday(ActivityDateTime) > 19
| project ActivityDateTime, InitiatedBy.user.userPrincipalName, TargetResources[0].modifiedProperties[0].newValue
```

## GCP Equivalent Queries

### GCP Cloud Audit Logs — detect SA impersonation chain

```sql
SELECT
  timestamp,
  protopayload_auditlog.authenticationInfo.principalEmail AS impersonator,
  protopayload_auditlog.authenticationInfo.serviceAccountDelegationInfo AS delegation_chain,
  protopayload_auditlog.requestMetadata.callerIp
FROM
  `<project-id>`.cloudaudit_googleapis_com_activity_*
WHERE
  protopayload_auditlog.methodName = 'google.iam.credentials.v1.IAMCredentials.GenerateAccessToken'
  AND ARRAY_LENGTH(protopayload_auditlog.authenticationInfo.serviceAccountDelegationInfo) > 1
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
```

### GCP — detect service account key creation

```sql
SELECT
  timestamp,
  protopayload_auditlog.authenticationInfo.principalEmail,
  protopayload_auditlog.requestMetadata.callerIp,
  protopayload_auditlog.request.name AS target_sa
FROM
  `<project-id>`.cloudaudit_googleapis_com_activity_*
WHERE
  protopayload_auditlog.methodName = 'google.iam.admin.v1.CreateServiceAccountKey'
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
```

## Alert Routing

### AWS — EventBridge rule for manual AssumeRole

```json
{
  "source": ["aws.sts"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["sts.amazonaws.com"],
    "eventName": ["AssumeRole"],
    "userAgent": [
      { "anything-but": {
        "prefix": ["aws-cli", "aws-sdk", "Boto3", "APN/1.0 HashiCorp", "console.amazonaws.com"]
      }}
    ]
  }
}
```

```bash
aws events put-rule \
  --name ManualAssumeRoleAlert \
  --event-pattern file://event-pattern.json

aws events put-targets \
  --rule ManualAssumeRoleAlert \
  --targets "Id=1,Arn=arn:aws:sns:us-east-1:111111111111:SecurityAlerts"
```

## Detection Coverage Matrix

| Technique | AWS Detection | Azure Detection | GCP Detection |
|---|---|---|---|
| Manual assume-role | Sigma Rule 1 + CloudTrail Lake Q1 | SigninLogs + Activity Log | Cloud Audit Logs delegation chain |
| Role chaining (A→B→C) | Sigma Rule 2 + CloudTrail Lake Q2 | AuditLogs PIM activation + role assignment | IAMCredentials.GenerateAccessToken chain length |
| TLS fingerprint anomaly | Sigma Rule 3 (CloudTrail Lake enhanced) | Conditional Access device compliance | Context-aware access (device trust) |
| Session name abnormality | Sigma Rule 4 | AuditLogs initiatedBy inspection | Audit log principalEmail pattern |
| Enumeration / volume | CloudTrail Lake Q4 | Identity Protection risk detection | SCC anomaly detection |
| Geo-anomaly | CloudTrail Lake Q3 | SigninLogs impossible travel | Context-aware access location |

## Tuning & Exclusion Guidelines

Add explicit exclusions in detection rules for:
- **Authorized security tools:** Add their specific `userAgent` string or `roleSessionName` prefix to the exclusion list (e.g., `roleSessionName|startswith: 'SecurityAudit-'`).
- **Change windows:** Time-based exclusion (`eventTime` between `02:00`–`04:00` UTC on Saturdays, if that's the maintenance window).
- **Break-glass roles:** Exclude specific role ARNs (break-glass roles have their own dedicated alerting — see [just-in-time-and-break-glass.md](../just-in-time-and-break-glass.md)).

## References

- [AWS CloudTrail Lake SQL reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-limitations-sql.html)
- [Sigma rules for cloud](https://github.com/SigmaHQ/sigma/tree/master/rules/cloud)
- [CloudTrail event reference — AssumeRole](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)
- [MITRE ATT&CK — Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)
