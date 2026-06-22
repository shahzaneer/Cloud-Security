# Detection 01 — Cloud Tuxy Baseline Detections

> **Level:** Intermediate–Advanced
> **Prereqs:** 09-01..09-11
> **Clouds:** AWS · Azure · GCP
**Authorization scope:** Detection rules for use in your own security operations. All account IDs, tenant GUIDs, and project IDs are placeholders.

## Overview

A cross-cloud detection baseline covering the five most common cloud attack signals:
1. Anomalous `List*` API storms (reconnaissance)
2. New IAM access key created for a human IAM user (persistence)
3. Public S3 ACL / Azure SAS grant / GCS public IAM binding (data exposure)
4. Lambda/Function created outside CI/CD pipeline (persistence / privesc)
5. Privileged action from a new ASN or geographic region (credential theft)

All rules use Sigma-style YAML with provider-specific adaptations. Placeholder account IDs and regex patterns must be replaced with your org's values.

---

## Rule 1: Reconnaissance — Anomalous List API Burst

### AWS (Sigma)

```yaml
title: Cloud Reconnaissance List API Burst
id: cloud-tuxy-001
status: experimental
description: Detects a single principal making >30 List/Describe calls within 5 minutes
author: cloud-tuxy
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource:
      - iam.amazonaws.com
      - ec2.amazonaws.com
      - s3.amazonaws.com
      - organizations.amazonaws.com
    eventName|startswith:
      - 'List'
      - 'Describe'
      - 'GetAccount'
  filter_ci:
    userIdentity.arn|contains: 'ci-role'
  filter_tf:
    userIdentity.arn|contains: 'terraform'
  filter_cfn:
    userIdentity.invokedBy: 'cloudformation.amazonaws.com'
  timeframe: 5m
  condition: selection | count() by userIdentity.arn > 30
  filters: [filter_ci, filter_tf, filter_cfn]
falsepositives:
  - CloudFormation stack drift detection
  - Security auditing tools (ScoutSuite, Prowler)
  - CI/CD pipeline resource enumeration
level: medium
tags:
  - attack.t1590
  - attack.t1526
```

### Azure (KQL — Sentinel)

```kusto
// cloud-tuxy-001-azure: Reconnaissance List API Storm
let timeframe = 5m;
let threshold = 30;
ActivityLog
| where TimeGenerated > ago(timeframe)
| where OperationNameValue startswith "List" or OperationNameValue startswith "Get"
| where Caller !contains "terraform" and Caller !contains "devops"
| summarize Count = count() by Caller, bin(TimeGenerated, 1m)
| where Count > threshold
| project TimeGenerated, Caller, Count, OperationNameValue
```

### GCP (Logging query)

```bash
# cloud-tuxy-001-gcp: Reconnaissance List API Burst
gcloud logging read '
  logName="projects/example-project/logs/cloudaudit.googleapis.com%2Factivity"
  protoPayload.methodName=~"List.*|Describe.*|GetIamPolicy"
  timestamp >= "$(date -v-5M -u +%Y-%m-%dT%H:%M:%SZ)"
  protoPayload.authenticationInfo.principalEmail!~"terraform|ci"
' --format='table(timestamp, protoPayload.methodName, protoPayload.authenticationInfo.principalEmail)' --limit 100
```

---

## Rule 2: New Access Key for Human IAM User

### AWS (Sigma)

```yaml
title: New Access Key Created for Human IAM User
id: cloud-tuxy-002
status: experimental
description: Alerts when a new access key is created for an IAM user (not a machine role)
author: cloud-tuxy
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateAccessKey
  filter_service_role:
    userIdentity.type: 'AssumedRole'
    userIdentity.arn|contains: 'aws-service-role'
  filter_ci:
    userIdentity.arn|contains: 'ci-'
  condition: selection and not filter_service_role and not filter_ci
level: high
tags:
  - attack.t1098
  - attack.t1136
```

### Azure (KQL — Sentinel)

```kusto
// cloud-tuxy-002-azure: New Service Principal Credential Added
AuditLogs
| where Category == "ApplicationManagement"
| where ActivityDisplayName in ("Add service principal credentials", "Add application password")
| where InitiatedBy.app != "Microsoft Azure AD Internal" // not system-generated
| where InitiatedBy.user.userPrincipalName !contains "serviceaccount"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName, ActivityDisplayName
```

### GCP (Logging query)

```bash
# cloud-tuxy-002-gcp: New Service Account Key Created
gcloud logging read '
  logName="projects/example-project/logs/cloudaudit.googleapis.com%2Factivity"
  protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
  timestamp >= "$(date -v-24H -u +%Y-%m-%dT%H:%M:%SZ)"
' --format='table(timestamp, protoPayload.request.name, protoPayload.authenticationInfo.principalEmail)'
```

---

## Rule 3: Public S3 ACL / Blob Container / GCS Bucket

### AWS (Sigma)

```yaml
title: S3 Bucket Made Public
id: cloud-tuxy-003
status: experimental
description: Detects when an S3 bucket ACL or policy grants access to AllUsers or AuthenticatedUsers
author: cloud-tuxy
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_acl:
    eventSource: s3.amazonaws.com
    eventName: PutBucketAcl
    requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI:
      - 'http://acs.amazonaws.com/groups/global/AllUsers'
      - 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
  selection_policy:
    eventSource: s3.amazonaws.com
    eventName: PutBucketPolicy
    requestParameters.bucketPolicy.Statement.Principal: '*'
  condition: selection_acl or selection_policy
level: high
tags:
  - attack.t1530
```

### Azure (KQL — Sentinel)

```kusto
// cloud-tuxy-003-azure: Storage Account Public Access Enabled
ActivityLog
| where OperationNameValue == "Microsoft.Storage/storageAccounts/write"
| where Properties contains "allowBlobPublicAccess" and Properties contains "true"
| project TimeGenerated, Caller, ResourceId
```

### GCP (Logging query)

```bash
# cloud-tuxy-003-gcp: GCS Bucket Made Public
gcloud logging read '
  logName="projects/example-project/logs/cloudaudit.googleapis.com%2Factivity"
  protoPayload.methodName="storage.setIamPermissions"
  protoPayload.request.bindings.members="allUsers"
  timestamp >= "$(date -v-24H -u +%Y-%m-%dT%H:%M:%SZ)"
' --format='table(timestamp, resource.labels.bucket_name, protoPayload.authenticationInfo.principalEmail)'
```

---

## Rule 4: Lambda / Function Created Outside CI/CD

### AWS (Sigma)

```yaml
title: Lambda Function Created Outside CI Pipeline
id: cloud-tuxy-004
status: experimental
description: Detects Lambda function creation by a principal not in the CI/CD role list
author: cloud-tuxy
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: lambda.amazonaws.com
    eventName: CreateFunction20150331
  filter_ci:
    userIdentity.arn|contains:
      - 'ci-deploy-role'
      - 'terraform-role'
      - 'cdk-role'
      - 'cloudformation'
  filter_cfn:
    userIdentity.invokedBy: 'cloudformation.amazonaws.com'
  condition: selection and not filter_ci and not filter_cfn
level: high
tags:
  - attack.t1574
  - attack.t1205
```

### Azure (KQL — Sentinel)

```kusto
// cloud-tuxy-004-azure: Azure Function App Created Outside DevOps
ActivityLog
| where OperationNameValue contains "Microsoft.Web/sites/write"
| where Properties contains '"kind":"functionapp"'
| where Caller !contains "devops" and Caller !contains "terraform"
| project TimeGenerated, Caller, ResourceId, ResourceGroup
```

### GCP (Logging query)

```bash
# cloud-tuxy-004-gcp: Cloud Function Deployed Outside CI
gcloud logging read '
  logName="projects/example-project/logs/cloudaudit.googleapis.com%2Factivity"
  protoPayload.methodName=("google.cloud.functions.v1.CloudFunctionsService.CreateFunction" OR "google.cloud.functions.v1.CloudFunctionsService.UpdateFunction")
  protoPayload.authenticationInfo.principalEmail!~"cloudbuild|terraform"
  timestamp >= "$(date -v-24H -u +%Y-%m-%dT%H:%M:%SZ)"
' --format='table(timestamp, resource.labels.function_name, protoPayload.authenticationInfo.principalEmail)'
```

---

## Rule 5: Privileged Action from New ASN / Geo

### AWS (Sigma)

```yaml
title: Privileged Action from New Geographic Region or ASN
id: cloud-tuxy-005
status: experimental
description: Detects high-privilege API calls (CreateUser, AttachRolePolicy, StopLogging) from an IP not seen in 30-day baseline
author: cloud-tuxy
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName:
      - CreateUser
      - DeleteUser
      - AttachRolePolicy
      - PutRolePolicy
      - StopLogging
      - DeleteTrail
      - UpdateAssumeRolePolicy
      - CreateAccessKey
  filter_corp_asn:
    sourceIPAddress|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  filter_corp_geo:
    sourceIPAddress|geo: 'US'
  timeframe: 24h
  condition: selection and not filter_corp_asn and not filter_corp_geo
level: high
tags:
  - attack.t1078
  - attack.t1098
```

### Azure (KQL — Sentinel)

```kusto
// cloud-tuxy-005-azure: Privileged Operation from New Location
SigninLogs
| where TimeGenerated > ago(1d)
| where RiskLevelDuringSignIn in ("high", "medium")
| where AppDisplayName == "Microsoft Azure Management"
| join kind=inner (
    ActivityLog
    | where OperationNameValue in ("Microsoft.Authorization/roleAssignments/write", "Microsoft.Storage/storageAccounts/listKeys/action")
) on $left.UserPrincipalName == $right.Caller
| project TimeGenerated, UserPrincipalName, IPAddress, Location, OperationNameValue, RiskDetail
```

### GCP (Logging query)

```bash
# cloud-tuxy-005-gcp: Privileged Action from New Location
gcloud logging read '
  logName="projects/example-project/logs/cloudaudit.googleapis.com%2Factivity"
  protoPayload.methodName=~"SetIamPolicy|CreateServiceAccount|CreateServiceAccountKey|DeleteServiceAccount"
  protoPayload.request.policy.bindings.role=~"roles/owner"
  timestamp >= "$(date -v-24H -u +%Y-%m-%dT%H:%M:%SZ)"
' --format='table(timestamp, protoPayload.methodName, protoPayload.authenticationInfo.principalEmail)'
```

---

## Deployment Guide

### AWS: Deploy as CloudWatch Logs Metric Filters

```bash
# Example: deploy rule cloud-tuxy-002 (CreateAccessKey alert)
LOG_GROUP=$(aws cloudtrail describe-trails --query 'trailList[0].CloudWatchLogsLogGroupArn' --output text)

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "cloud-tuxy-002-CreateAccessKey" \
  --filter-pattern '{($.eventSource = "iam.amazonaws.com") && ($.eventName = "CreateAccessKey")}' \
  --metric-transformations 'metricName=CreateAccessKey,metricNamespace=CloudTuxy,metricValue=1'

aws cloudwatch put-metric-alarm \
  --alarm-name "cloud-tuxy-002-CreateAccessKey" \
  --metric-name CreateAccessKey \
  --namespace CloudTuxy \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:111111111111:security-alerts
```

### Azure: Deploy to Sentinel Analytics Rules

Export each KQL query as a Scheduled Query Rule in Sentinel:
1. Navigate to Sentinel → Analytics → Create → Scheduled query rule
2. Paste the KQL query
3. Set run frequency: 5 minutes
4. Map entity fields (Account: Caller, IP: CallerIpAddress)
5. Create incident for alerts

### GCP: Deploy as Log-Based Metrics + Alerting Policies

```bash
# Create a log-based metric
gcloud logging metrics create cloud-tuxy-002-sa-key-create \
  --description="Counts CreateServiceAccountKey events" \
  --log-filter='protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"'

# Create an alerting policy
gcloud alpha monitoring policies create \
  --notification-channels=projects/example-project/notificationChannels/000000000 \
  --condition-display-name="SA Key Created" \
  --condition-filter='metric.type="logging.googleapis.com/user/cloud-tuxy-002-sa-key-create" AND resource.type="global"' \
  --condition-threshold-value=1 \
  --condition-threshold-duration=300s
```

---

## False Positive Tuning Guide

| Rule | Common False Positive | Tuning Action |
|---|---|---|
| cloud-tuxy-001 (List burst) | CI/CD pipeline scanning resources | Add CI role ARNs to filter_ci |
| cloud-tuxy-001 (List burst) | CloudFormation drift detection | Add `invokedBy: cloudformation.amazonaws.com` filter |
| cloud-tuxy-002 (CreateAccessKey) | Automated key rotation script | Add rotation role ARN to filter |
| cloud-tuxy-002 (CreateAccessKey) | New employee onboarding (legitimate) | Correlate with HR system (new hire ticket) |
| cloud-tuxy-003 (Public bucket) | Static website hosting bucket | Add tag exception: `tag:website=true` |
| cloud-tuxy-004 (Lambda outside CI) | Ad-hoc admin-created utility Lambda | Require justification tag on admin-created functions |
| cloud-tuxy-005 (Priv action new geo) | Employee traveling | Add corporate VPN ASN to filter; require MFA for all privileged ops |

---

## Cross-Cloud Correlation

For multi-cloud environments, normalize event schemas before correlation:

```
Normalized Event Schema:
{
  "detection_id": "cloud-tuxy-002",
  "cloud": "aws|azure|gcp",
  "event_time": "ISO8601",
  "principal": "arn or UPN or email",
  "action": "CreateAccessKey|AddPasswordCredential|CreateServiceAccountKey",
  "target": "username or SP name or SA email",
  "source_ip": "x.x.x.x",
  "user_agent": "tool string"
}
```

Export all cloud logs to a centralized SIEM/SOAR. Correlate events across clouds using the normalized schema to detect attackers pivoting across providers.

## References

- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [AWS CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [Azure Activity Log Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema)
- [GCP Audit Log Reference](https://cloud.google.com/logging/docs/audit)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Cloud Custodian](https://cloudcustodian.io/)
