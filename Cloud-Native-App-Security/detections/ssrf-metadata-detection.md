# Detection — SSRF Metadata Credential Usage Outside VPC

> **Prereqs:** `../ssrf-and-cloud-metadata-from-app.md`, `../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md`
> **MITRE ATT&CK:** T1522 (Cloud Instance Metadata API), T1078.004 (Cloud Accounts)
> **Scope:** Apply these detections in your own cloud accounts only.

## Overview

This detection identifies when cloud instance/function/service credentials are used **from outside the expected VPC/network boundary** within a short time window after an application-level HTTP request — the hallmark of an SSRF → metadata → credential-exfiltration chain.

## Sigma rule (cross-cloud)

```yaml
title: Cloud Credentials Used From External IP Within 10 Minutes of App Subnet Request
id: 7b1c9a3e-4d5f-6a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: >
  Detects cloud API calls using an application's IAM role from a source IP
  that is NOT in the VPC, occurring within 10 minutes of an HTTP request
  to the application's webhook/API endpoint. This is the signature of
  SSRF-to-metadata credential exfiltration.
author: Cloud Security Curriculum
date: 2026-06-22
tags:
  - attack.t1522
  - attack.t1078.004
  - attack.credential_access
logsource:
  category: cloud_audit
  product: multiple
detection:
  selection_credential_use:
    eventName:
      - GetCallerIdentity
      - ListBuckets
      - DescribeInstances
      - GetObject
      - ListObjects
    sourceIPAddress|re: '^(?!10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.).*'  # Not RFC 1918
  selection_app_role:
    userIdentity.type: 'AssumedRole'
    userIdentity.sessionContext.sessionIssuer.arn|contains: ':role/'
  timeframe: 10m
  condition: selection_credential_use and selection_app_role
falsepositives:
  - Legitimate multi-region deployment using the same role from different regions
  - Developer running local tooling with assumed role (should use separate dev roles)
  - CI/CD pipeline with dynamic IPs (whitelist pipeline IP ranges)
level: high
```

## AWS — CloudTrail query (Athena / CloudTrail Lake)

```sql
-- Find application-role API calls from external IPs within a 10-minute window
-- after any HTTP request to the app's ALB/API Gateway

WITH app_http_requests AS (
    SELECT DISTINCT
        CAST(FROM_UNIXTIME(timestamp/1000) AS TIMESTAMP) AS request_time,
        client_ip
    FROM alb_access_logs
    WHERE request_time >= date_add('minute', -10, current_timestamp)
      AND target_group_arn LIKE '%app-target-group%'
      AND client_ip LIKE '198.51.100.%'   -- Replace with your app subnet CIDR
),
external_credential_use AS (
    SELECT
        eventTime,
        eventName,
        sourceIPAddress,
        userAgent,
        userIdentity.arn AS role_arn,
        userIdentity.sessionContext.sessionIssuer.arn AS issuer_arn,
        requestParameters
    FROM cloudtrail_logs
    WHERE eventSource IN ('sts.amazonaws.com', 's3.amazonaws.com', 'ec2.amazonaws.com')
      AND eventName IN ('GetCallerIdentity', 'ListBuckets', 'DescribeInstances', 'GetObject')
      AND userIdentity.type = 'AssumedRole'
      AND userIdentity.arn LIKE '%:role/app-role%'  -- Replace with your app's role name
      AND NOT regexp_like(sourceIPAddress, '^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.')
      AND eventTime >= date_add('day', -1, current_timestamp)
)
SELECT
    e.eventTime,
    e.eventName,
    e.sourceIPAddress,
    e.role_arn,
    e.userAgent,
    a.request_time,
    TIMESTAMPDIFF(MINUTE, a.request_time, CAST(e.eventTime AS TIMESTAMP)) AS minutes_after_app_request
FROM external_credential_use e
LEFT JOIN app_http_requests a
    ON CAST(e.eventTime AS TIMESTAMP) >= a.request_time
    AND CAST(e.eventTime AS TIMESTAMP) <= date_add('minute', 10, a.request_time)
ORDER BY e.eventTime DESC
```

## AWS — CloudWatch Logs Insights (Lambda/App-level)

```
# Detect metadata endpoint access from application code
fields @timestamp, @message
| filter @message like /169\.254\.169\.254/
| filter @logStream like /app-lambda/
| stats count() by bin(5m)
| sort @timestamp desc
```

## Azure — Log Analytics / Sentinel

```kql
// Detect managed identity token usage from unexpected IP
let KnownAppIPs = dynamic(["10.0.1.0/24", "10.0.2.0/24"]);
let AppManagedIdentity = "app-function-mi";  // Replace with your managed identity name
IdentityLogonEvents
| where TimeGenerated > ago(1h)
| where Identity == AppManagedIdentity
| where ipv4_is_in_range(IPAddress, "10.0.0.0/8") == false
    and ipv4_is_in_range(IPAddress, "172.16.0.0/12") == false
    and ipv4_is_in_range(IPAddress, "192.168.0.0/16") == false
| project TimeGenerated, IPAddress, Resource, OperationName, UserAgent
| order by TimeGenerated desc
```

```kql
// Correlate: App Function HTTP request followed by unusual Resource Manager call
let AppRequests = AppServiceHTTPLogs
    | where TimeGenerated > ago(1h)
    | where _ResourceId contains "vulnerable-app"
    | project TimeGenerated, CsUriStem, CIp;
let SuspiciousRMCalls = AzureActivity
    | where TimeGenerated > ago(1h)
    | where Caller contains "app-function-mi"
    | where not(ipv4_is_private(CallerIpAddress))
    | project TimeGenerated, OperationName, CallerIpAddress, Caller;
AppRequests
| join kind=inner (SuspiciousRMCalls) on $left.CIp == $right.CallerIpAddress
| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) <= 10
| project AppRequestTime=TimeGenerated, AppEndpoint=CsUriStem,
          SrcIP=CIp, RMOperation=OperationName, RMTime=TimeGenerated1
```

## GCP — Cloud Logging / BigQuery

```sql
-- Detect service account token used from external IP
-- (useful for Cloud Run / GCE metadata SSRF follow-on)
SELECT
  timestamp,
  protopayload_auditlog.authenticationInfo.principalEmail AS sa_email,
  protopayload_auditlog.requestMetadata.callerIp AS caller_ip,
  protopayload_auditlog.methodName AS method,
  protopayload_auditlog.serviceName AS service
FROM `example-project.logs.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.authenticationInfo.principalEmail LIKE 'app-sa@%'
  AND NOT (
    protopayload_auditlog.requestMetadata.callerIp LIKE '10.%'
    OR protopayload_auditlog.requestMetadata.callerIp LIKE '35.%'  -- GCP private access
  )
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
ORDER BY timestamp DESC
```

## OnPrem / Generic — SIEM correlation rule

```
// Pseudocode for correlation engine (Splunk / Elastic / QRadar)
Event A: HTTP request to app endpoint from attacker IP (from ALB/Nginx access log)
Event B: Cloud API call using app role from same attacker IP (from CloudTrail/Syslog)
Condition: Event B occurs within 600 seconds of Event A
           AND source_ip matches
           AND Event B.role matches app-role pattern
Action: Create high-severity alert
```

## Cloud Custodian policy (preventive)

```yaml
# AWS — deny S3 access from non-VPC for app role
policies:
  - name: block-app-role-external-s3
    resource: aws.s3
    mode:
      type: cloudtrail
      role: arn:aws:iam::111111111111:role/CustodianRole
    filters:
      - type: event
        key: "userIdentity.sessionContext.sessionIssuer.arn"
        value: "arn:aws:iam::111111111111:role/app-role"
        op: regex
      - not:
          - type: event
            key: "sourceIPAddress"
            value: "10.0.0.0/8"
            op: cidr
    actions:
      - type: notify
        template: default
        subject: "App role used from outside VPC"
        to:
          - security@example.com
```

## OPA / Rego rule (preventive)

```rego
# Deny IAM policies that allow app-role to be used without VPC endpoint condition
package cloud.security

deny[msg] {
    role := input.iam_roles[_]
    role.name == "app-role"
    policy := role.policies[_]
    not has_vpc_condition(policy)
    msg := sprintf("app-role policy %q must include aws:SourceVpce condition", [policy.name])
}

has_vpc_condition(policy) {
    policy.Statement[_].Condition.StringEquals["aws:SourceVpce"]
}
```

## Tuning and false positives

| Scenario | Mitigation |
|---|---|
| CI/CD pipeline uses app-role from dynamic IPs | Whitelist pipeline IP ranges (GitHub Actions, GitLab CI CIDRs) |
| Multi-region deployment uses same role from different VPCs | Add `aws:SourceVpc` or VPC endpoint condition to IAM policy |
| Developer testing with local AWS CLI + assume-role | Use separate dev roles with different naming patterns |
| Lambda@Edge or CloudFront function — runs at edge locations | These will have non-VPC IPs by design; exclude Lambda@Edge from alert |

## Response playbook

1. **Confirm the alert** — check if the external IP correlates to a known service (CI/CD, developer VPN).
2. **Identify the vulnerable app endpoint** — cross-reference ALB/API Gateway access logs at the same minute.
3. **Revoke active sessions** — use `RevokeSession` on the IAM role or disable the managed identity temporarily.
4. **Rotate credentials** — force instance/function restart to pick up new temporary credentials.
5. **Patch the SSRF** — add URL allowlist validation to the vulnerable endpoint.
6. **Enforce IMDSv2** — if running on EC2, require `HttpTokens=required`.
7. **Add preventive controls** — deploy the Cloud Custodian or OPA policy above.

## References

- Sigma HQ rule repository: https://github.com/SigmaHQ/sigma
- Cloud Custodian: https://cloudcustodian.io/
- OPA (Open Policy Agent): https://www.openpolicyagent.org/
- Full lesson: `../ssrf-and-cloud-metadata-from-app.md`
- Lab: `../labs/ssrf-to-imds-lab.md`
- Network-level defense: `../../Network-Security/ssrf-and-imds-pivots.md`
- SIEM patterns: `../../Monitoring-Detection-SIEM/ingestion-pipeline-siem-patterns.md`
