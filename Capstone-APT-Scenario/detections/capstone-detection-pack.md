# 01 — Capstone Detection Pack

> **Level:** Advanced
> **Prereqs:** 13-03, 13-04; Modules 06-07, 06-02, 06-03, 06-04
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Reconnaissance, Initial Access, Privilege Escalation, Persistence, Lateral Movement, Collection, Impact
**Authorization scope:** Capstone labs are to be run only against learner-owned sandbox accounts. Placeholder accounts are used in all queries. No live attack surfaces.

## What & why

One detection rule per red stage from [13-03 Red Variant Walkthrough](../Capstone-APT-Scenario/red-variant-walkthrough.md). Each rule includes: Sigma YAML (vendor-agnostic), AWS CloudWatch Logs Insights query, Azure KQL (Sentinel/Log Analytics), GCP Logging query, and Cloud Custodian/OPA policy (where applicable). Deploy all rules before running the blue lab.

---

## CAP-RECON-01 — Reconnaissance via Public Bucket Enumeration

**Red stage ref:** Stage 1 — Recon ([09-02](../Red-Team-Offense/recon-osint-and-fingerprint.md))
**MITRE tactic:** Reconnaissance
**MITRE technique:** see ATT&CK Cloud matrix — Active Scanning (T1595)

### Sigma YAML

```yaml
title: Capstone — Public Bucket Enumeration from External IP
id: cap-recon-01
status: experimental
author: capstone-learner
date: 2025-01-01
tags:
  - attack.reconnaissance
  - attack.t1595
logsource:
  product: aws
  service: cloudtrail
  category: data_events
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: ListObjects
    userIdentity.type: AWSAccount  # unauthenticated or external
  filter_trusted_ip:
    sourceIPAddress|startswith:
      - '10.'
      - '172.'
      - '192.168.'
  condition: selection and not filter_trusted_ip
falsepositives:
  - Legitimate public bucket access from customers/partners
  - Security scanner (e.g., prowler) run from CI — add CI egress IP to allowlist
level: low
```

### AWS CloudWatch Logs Insights

```sql
filter eventSource = "s3.amazonaws.com"
  and eventName = "ListObjects"
  and userIdentity.type = "AWSAccount"
| filter sourceIPAddress not like "10." and sourceIPAddress not like "172." and sourceIPAddress not like "192.168."
| fields @timestamp, sourceIPAddress, requestParameters.bucketName, userIdentity.accountId
| sort @timestamp desc
| limit 50
```

### Azure KQL (Sentinel)

```kusto
StorageBlobLogs
| where OperationName == "ListBlobs"
| where AuthenticationType == "Anonymous"
| where CallerIpAddress !startswith "10." and CallerIpAddress !startswith "172." and CallerIpAddress !startswith "192.168."
| project TimeGenerated, AccountName, OperationName, CallerIpAddress, UserAgentHeader
```

### GCP Logging query

```sql
logName:"cloudaudit.googleapis.com%2Fdata_access"
protoPayload.methodName="storage.objects.list"
protoPayload.authenticationInfo.principalEmail="allUsers"
protoPayload.requestMetadata.callerIp!="10.*" AND protoPayload.requestMetadata.callerIp!="172.*" AND protoPayload.requestMetadata.callerIp!="192.168.*"
```

### Cloud Custodian (honey-token check)

```yaml
policies:
  - name: capstone-honey-token-hit
    resource: aws.s3
    mode:
      type: cloudtrail
      events:
        - event: GetObject
          ids: requestParameters.key
    filters:
      - type: event
        key: "requestParameters.key"
        value: "honey-token.txt"
        op: eq
    actions:
      - type: notify
        to: [security@example.com]
        subject: "HONEYTOKEN HIT — Reconnaissance detected"
```

---

## CAP-IA-01 — Initial Access via SSRF → IMDS Credential Theft

**Red stage ref:** Stage 2 — Initial Access ([09-03](../Red-Team-Offense/initial-access-vectors.md))
**MITRE tactic:** Credential Access
**MITRE technique:** Unsecured Credentials: Cloud Instance Metadata API (T1552.005)

### Sigma YAML

```yaml
title: Capstone — SSRF to IMDS Credential Exfiltration
id: cap-ia-01
status: experimental
author: capstone-learner
date: 2025-01-01
tags:
  - attack.credential_access
  - attack.t1552.005
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: GetCallerIdentity
  filter_trusted_ip:
    sourceIPAddress|contains: '<trusted-cidr>'  # learner fills in sandbox range
  timewindow: 5m
  condition: selection and not filter_trusted_ip
falsepositives:
  - Legitimate cross-region API call from a new region
  - DevOps accessing from coffee shop — consider VPN requirement
level: medium
```

### AWS CloudWatch Logs Insights

```sql
filter eventName = "GetCallerIdentity"
| filter sourceIPAddress not in ("<trusted-eip>", "<vpn-cidr>")
| stats count() as call_count by sourceIPAddress, userIdentity.arn
| filter call_count = 1  -- first-time caller from this IP
| sort call_count desc
```

### AWS GuardDuty native (auto-detected)

```
Finding type: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.Custom
Severity: High
Description: EC2 instance credentials were used from an IP address not
  associated with the EC2 instance that owns the credentials.
Resource: arn:aws:ec2:us-east-1:111111111111:instance/i-0abcdef1234567890
Action: The IAM credentials for instance i-0abcdef... were used from IP 198.51.100.77.
```

### Azure KQL (Sentinel)

```kusto
AzureActivity
| where OperationNameValue == "Microsoft.Compute/virtualMachines/retrieveMetadata/action"
| where CallerIpAddress !startswith "10."
| project TimeGenerated, Caller, CallerIpAddress, Resource
```

### GCP Logging query

```sql
protoPayload.methodName="compute.instances.getMetadata"
protoPayload.requestMetadata.callerIp!="10.*"
resource.type="gce_instance"
protoPayload.authenticationInfo.principalEmail!=protoPayload.resourceName
-- (caller not the instance itself — credentials used externally)
```

---

## CAP-IA-02 — Initial Access via Leaked CI Credentials

**Red stage ref:** Stage 2 — Initial Access ([09-03](../Red-Team-Offense/initial-access-vectors.md), Path B)
**MITRE tactic:** Initial Access
**MITRE technique:** Valid Accounts (T1078)

### Sigma YAML

```yaml
title: Capstone — Leaked CI Key Used from External IP
id: cap-ia-02
status: experimental
author: capstone-learner
date: 2025-01-01
tags:
  - attack.initial_access
  - attack.t1078
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.userName: ci-deployer
  filter_ci_pipeline_ip:
    sourceIPAddress:
      - '34.200.0.0/16'   # placeholder CI CIDR — learner replaces
      - '52.200.0.0/16'
  condition: selection and not filter_ci_pipeline_ip
falsepositives:
  - Developer using ci-deployer key from home — this IS the incident
  - Key rotation by DevOps team — ensure rotation is done from CI runner
level: high
```

### AWS CloudWatch Logs Insights

```sql
filter userIdentity.userName = "ci-deployer"
  and eventName not in ("GetCallerIdentity")
  and sourceIPAddress not in ("<ci-runner-eip>")
| fields @timestamp, eventName, sourceIPAddress, userAgent, requestParameters
| sort @timestamp desc
| limit 100
```

### Azure KQL (Sentinel)

```kusto
SigninLogs
| where AppId == "<ci-deployer-app-id>"  -- learner replaces
| where Location != "US"  -- learner replaces with trusted geo
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail
```

### GCP Logging query

```sql
protoPayload.authenticationInfo.principalEmail="ci-deployer@example-project.iam.gserviceaccount.com"
protoPayload.requestMetadata.callerIp!="<ci-runner-external-ip>"
protoPayload.methodName=~"google.*"
severity!="DEFAULT"
```

---

## CAP-PE-01 — Privilege Escalation via PassRole

**Red stage ref:** Stage 3 — Privilege Escalation ([09-05](../Red-Team-Offense/privilege-escalation-catalogue.md))
**MITRE tactic:** Privilege Escalation
**MITRE technique:** Valid Accounts (T1078), see ATT&CK Cloud — Cloud Accounts (T1078.004)

### Sigma YAML

```yaml
title: Capstone — PassRole + CreateFunction Privilege Escalation
id: cap-pe-01
status: experimental
author: capstone-learner
date: 2025-01-01
tags:
  - attack.privilege_escalation
  - attack.t1078.004
logsource:
  product: aws
  service: cloudtrail
detection:
  passrole:
    eventName: PassRole
    requestParameters.roleName: ProdLambdaExecRole
  create_function:
    eventName: CreateFunction20150331
  timeframe: 5m
  condition: passrole and create_function
falsepositives:
  - CI pipeline creating Lambda with a well-known role — add CI role ARN to filter
  - Infrastructure provisioning via Terraform (same role) — check userAgent
level: high
```

### AWS CloudWatch Logs Insights (paired events)

```sql
fields @timestamp, eventName, userIdentity.arn, requestParameters.roleName
| filter eventName in ("PassRole", "CreateFunction")
| stats list(eventName) as events, list(requestParameters.roleName) as roles by userIdentity.arn
| filter events = ["PassRole", "CreateFunction"]  -- both events from same principal
  or events = ["CreateFunction", "PassRole"]
```

### AWS GuardDuty native

```
Finding type: PrivilegeEscalation:IAMUser/AdministrativePermissions
Severity: Medium/High
Description: An IAM principal demonstrated a combination of permissions
  indicative of privilege escalation.
Resource: arn:aws:iam::111111111111:role/ProdLambdaExecRole
```

### Azure KQL (Sentinel)

```kusto
AzureActivity
| where OperationNameValue == "Microsoft.Authorization/roleAssignments/write"
| where Properties_d contains "Owner"
| join (AzureActivity | where OperationNameValue == "Microsoft.Web/sites/functions/write") on Caller
| project TimeGenerated, Caller, OperationNameValue, Properties_d
```

### GCP Logging query

```sql
protoPayload.methodName=("iam.serviceAccounts.getAccessToken" OR "iam.serviceAccounts.signBlob" OR "google.iam.admin.v1.CreateServiceAccountKey")
protoPayload.authenticationInfo.principalEmail!=protoPayload.request.name
-- (principal calling != the SA they are accessing — indicative of tokenCreator abuse)
```

---

## CAP-PER-01 — Persistence via Unauthorized CreateAccessKey

**Red stage ref:** Stage 4 — Persistence ([09-07](../Red-Team-Offense/persistence-techniques-in-cloud.md))
**MITRE tactic:** Persistence
**MITRE technique:** Create Account (T1136), see ATT&CK Cloud — Cloud Account (T1136.003)

### Sigma YAML

```yaml
title: Capstone — Unauthorized CreateAccessKey Outside CI Window
id: cap-per-01
status: experimental
author: capstone-learner
date: 2025-01-01
tags:
  - attack.persistence
  - attack.t1136.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: CreateAccessKey
  filter_ci_role:
    userIdentity.sessionContext.sessionIssuer.userName: '<ci-role-name>'  # learner fills
  condition: selection and not filter_ci_role
falsepositives:
  - On-call creating emergency access key — should go through break-glass process
  - Automated key rotation — filter on known rotation role
level: high
```

### AWS CloudWatch Logs Insights

```sql
filter eventName = "CreateAccessKey"
| filter userIdentity.arn not like "%<ci-role-name>%"
| fields @timestamp, userIdentity.arn, requestParameters.userName, sourceIPAddress
| sort @timestamp desc
```

### AWS honey-token variant

```sql
-- Alert if the canary key (never used legitimately) is touched
filter eventName = "GetCallerIdentity"
  and userIdentity.accessKeyId = "<honey-user-canary-key-id>"
| fields @timestamp, sourceIPAddress
-- This should NEVER fire — if it does, attacker is using the honey-token key
```

### Azure KQL (Sentinel)

```kusto
AuditLogs
| where OperationName == "Add service principal credentials"
| where TargetResources[0].displayName != "<trusted-sp-names>"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName
```

### GCP Logging query

```sql
protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
protoPayload.authenticationInfo.principalEmail!="ci-deployer@example-project.iam.gserviceaccount.com"
severity!="DEFAULT"
```

---

## CAP-PER-02 — Persistence via New Privileged Account Creation

**Red stage ref:** Stage 4 — Persistence ([09-07](../Red-Team-Offense/persistence-techniques-in-cloud.md))
**MITRE tactic:** Persistence
**MITRE technique:** Create Account: Cloud Account (T1136.003)

### Sigma YAML

```yaml
title: Capstone — New IAM User Created + AdministratorAccess Attached
id: cap-per-02
status: experimental
author: capstone-learner
date: 2025-01-01
tags:
  - attack.persistence
  - attack.t1136.003
logsource:
  product: aws
  service: cloudtrail
detection:
  create_user:
    eventName: CreateUser
  attach_admin:
    eventName: AttachUserPolicy
    requestParameters.policyArn: arn:aws:iam::aws:policy/AdministratorAccess
  timeframe: 10m
  condition: create_user and attach_admin
falsepositives:
  - DevOps creating emergency admin user — should use PIM/JIT (Module 02-07)
  - Account factory creating new accounts — filter on automation userAgent
level: critical
```

### AWS CloudWatch Logs Insights

```sql
filter eventName in ("CreateUser", "AttachUserPolicy")
| filter requestParameters.policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
   or eventName = "CreateUser"
| stats list(eventName) as events, list(requestParameters.userName) as users by userIdentity.arn
| filter events = ["CreateUser", "AttachUserPolicy"]
```

### Azure KQL (Sentinel)

```kusto
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties[0].newValue == "Owner"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName
```

### GCP Logging query

```sql
protoPayload.methodName="google.iam.admin.v1.CreateServiceAccount"
protoPayload.response.bindings.member=~"serviceAccount:*"
protoPayload.response.bindings.role="roles/owner"
```

---

## CAP-LM-01 — Lateral Movement via AssumeRole Chain

**Red stage ref:** Stage 5 — Lateral Movement ([09-06](../Red-Team-Offense/lateral-movement-and-pivoting.md))
**MITRE tactic:** Lateral Movement
**MITRE technique:** Use Alternate Authentication Material (T1550)

### Sigma YAML

```yaml
title: Capstone — Cross-Account AssumeRole Chain
id: cap-lm-01
status: experimental
author: capstone-learner
date: 2025-01-01
tags:
  - attack.lateral_movement
  - attack.t1550
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AssumeRole
  filter_same_account:
    userIdentity.accountId: requestParameters.roleArn|re: 'arn:aws:iam::([0-9]{12}):role/.*'
  timeframe: 30m
  condition: |
    selection
    and not (
      userIdentity.accountId = '111111111111' and requestParameters.roleArn contains '111111111111'
    )
  aggregation: count() by sourceIPAddress >= 2
falsepositives:
  - Cross-account automation (e.g., centralized logging) — exclude known automation roles
  - CloudFormation StackSets deploying across accounts — filter on userAgent
level: high
```

### AWS CloudWatch Logs Insights (multi-hop detection)

```sql
filter eventName = "AssumeRole"
| parse @message '"roleArn":"arn:aws:iam::*:/role/*"' as targetAccount, targetRole
| parse @message '"callerArn":"arn:aws:iam::*:user/*"' as sourceAccount
| filter sourceAccount != targetAccount  -- cross-account
| stats count() as hop_count, list(targetAccount) as target_accounts by sourceIPAddress
| filter hop_count >= 2  -- 2+ distinct accounts from same IP in 30 min
```

### Azure KQL (Sentinel)

```kusto
AzureActivity
| where OperationNameValue == "Microsoft.Authorization/roleAssignments/write"
| extend TargetSub = tostring(Properties_d.scope)
| extend CallerSub = SubscriptionId
| where TargetSub != CallerSub  -- cross-subscription
| project TimeGenerated, Caller, CallerSub, TargetSub
```

### GCP Logging query

```sql
protoPayload.methodName="google.iam.admin.v1.SetIamPolicy"
resource.name!="projects/example-project"  -- IAM change in a different project
protoPayload.authenticationInfo.principalEmail=~"*@example-project.iam.gserviceaccount.com"
```

### Cloud Custodian (trust graph alert)

```yaml
policies:
  - name: capstone-anomalous-assume-role-chain
    resource: aws.iam-role
    mode:
      type: cloudtrail
      events:
        - event: AssumeRole
          ids: requestParameters.roleArn
    filters:
      - type: event
        key: "userIdentity.accountId"
        value: "111111111111"  # production account
      - type: event
        key: "requestParameters.roleArn"
        op: regex
        value: "arn:aws:iam::(?!111111111111)"  # NOT production — lateral hop
    actions:
      - type: notify
        to: [security@example.com]
        subject: "CAP-LM-01: Cross-account AssumeRole detected"
```

---

## CAP-COLL-01 — Collection / Data Staging via High-Volume GetObject

**Red stage ref:** Stage 6 — Collection ([09-09](../Red-Team-Offense/collection-data-exfil-channels.md))
**MITRE tactic:** Collection
**MITRE technique:** Data from Cloud Storage (T1530)

### Sigma YAML

```yaml
title: Capstone — High-Volume S3 GetObject Storm
id: cap-coll-01
status: experimental
author: capstone-learner
date: 2025-01-01
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
  category: data_events
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: GetObject
  timeframe: 5m
  condition: selection | count() by userIdentity.arn > 50
falsepositives:
  - CI artifact download — exclude CI role
  - Legitimate bulk data processing job — exclude known processing role
  - Backup restoration — schedule-based exclusion
level: high
```

### AWS CloudWatch Logs Insights

```sql
filter eventSource = "s3.amazonaws.com" and eventName in ("ListObjects", "GetObject")
| stats count() as GetCount by eventName, userIdentity.arn, bin(5m)
| filter eventName = "GetObject" and GetCount > 50
-- and filter (max by GetCount where eventName = "GetObject") > 10 * (max by GetCount where eventName = "ListObjects")
```

### Azure KQL (Sentinel)

```kusto
StorageBlobLogs
| where OperationName == "GetBlob"
| summarize GetCount = count() by CallerIpAddress, bin(TimeGenerated, 5m)
| where GetCount > 100
| project TimeGenerated, CallerIpAddress, GetCount
```

### GCP Logging query

```sql
protoPayload.methodName="storage.objects.get"
resource.labels.bucket_name="capstone-data-example-project"
severity="NOTICE"
-- Aggregate: count > 100 in 5 min window
```

### Cloud Custodian (List/Get ratio policy)

```yaml
policies:
  - name: capstone-s3-get-storm
    resource: aws.s3
    mode:
      type: cloudtrail
      events:
        - event: GetObject
    filters:
      - type: event
        key: "eventName"
        value: "GetObject"
      - type: metric
        name: GetObjectCount
        op: ge
        value: 50
        window: 5
    actions:
      - type: notify
        to: [security@example.com]
        subject: "CAP-COLL-01: High-volume GetObject storm detected"
```

---

## CAP-IMP-01 — Impact via Attempted Delete on WORM-Protected Object

**Red stage ref:** Stage 7 — Impact ([09-09](../Red-Team-Offense/collection-data-exfil-channels.md))
**MITRE tactic:** Impact
**MITRE technique:** Data Destruction (T1485)

### Sigma YAML

```yaml
title: Capstone — DeleteObject Denied by Object Lock Retention
id: cap-imp-01
status: experimental
author: capstone-learner
date: 2025-01-01
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
  category: data_events
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: DeleteObject
    errorCode: AccessDenied
    errorMessage|contains: Object Lock
  condition: selection
falsepositives:
  - Very low — legitimate automation rarely attempts deletion of Object-Locked blobs
  - Misconfigured lifecycle policy — check the calling user/role
level: critical
```

### AWS CloudWatch Logs Insights

```sql
filter eventName = "DeleteObject" and errorCode = "AccessDenied"
| filter errorMessage like /Object Lock/
| fields @timestamp, userIdentity.arn, requestParameters.bucketName,
    requestParameters.key, sourceIPAddress, errorMessage
| sort @timestamp desc
```

### Azure KQL (Sentinel)

```kusto
StorageBlobLogs
| where OperationName == "DeleteBlob"
| where StatusCode == 403
| where AdditionalInfo contains "ImmutabilityPolicy"
| project TimeGenerated, AccountName, ObjectKey, CallerIpAddress, UserAgentHeader
```

### GCP Logging query

```sql
protoPayload.methodName="storage.objects.delete"
protoPayload.status.code=7  -- PERMISSION_DENIED
protoPayload.status.message=~"retention"
resource.labels.bucket_name="capstone-worm-example-project"
```

### Cloud Custodian (WORM-tamper alert)

```yaml
policies:
  - name: capstone-worm-tamper-alert
    resource: aws.s3
    mode:
      type: cloudtrail
      events:
        - event: DeleteObject
          ids: requestParameters.key
    filters:
      - type: event
        key: "errorCode"
        value: "AccessDenied"
      - type: event
        key: "errorMessage"
        value: "Object Lock"
        op: regex
    actions:
      - type: notify
        to: [security@example.com, compliance@example.com]
        subject: "CAP-IMP-01: WORM-Protected Object Delete Attempted — HIGH CONFIDENCE"
```

---

## CAP-EVASION-01 — Attempted GuardDuty/IP/Log Evasion

> (as of June 2026, GuardDuty finding coverage evolves with each release; check the [GuardDuty findings documentation](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html) for current coverage of evasion techniques.)

**Red stage ref:** [09-08 Evasion & Trail-Free Actions](../Red-Team-Offense/evasion-and-trail-free-actions.md)
**MITRE tactic:** Defense Evasion
**MITRE technique:** Disable or Modify Tools (T1562.001), Impair Defenses (T1562)

### Sigma YAML

```yaml
title: Capstone — CloudTrail or GuardDuty Disable Attempt
id: cap-evasion-01
status: experimental
author: capstone-learner
date: 2025-01-01
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  product: aws
  service: cloudtrail
detection:
  stop_logging:
    eventName: StopLogging
  delete_trail:
    eventName: DeleteTrail
  guardduty_disable:
    eventSource: guardduty.amazonaws.com
    eventName: DeleteDetector
  condition: stop_logging or delete_trail or guardduty_disable
falsepositives:
  - Scheduled trail recreation by platform team — alert anyway, verify
  - GuardDuty detector migration — alert anyway, verify
level: critical
```

### AWS CloudWatch Logs Insights

```sql
filter eventName in ("StopLogging", "DeleteTrail", "DeleteDetector")
  or (eventSource = "guardduty.amazonaws.com" and eventName in ("DeleteDetector", "StopMonitoringMembers"))
| fields @timestamp, eventName, eventSource, userIdentity.arn, sourceIPAddress
| sort @timestamp desc
```

### Azure KQL (Sentinel)

```kusto
AzureActivity
| where OperationNameValue in (
    "Microsoft.Security/securityContacts/delete",
    "Microsoft.Insights/diagnosticSettings/delete",
    "Microsoft.OperationsManagement/solutions/delete")
| project TimeGenerated, Caller, OperationNameValue, Resource
```

### GCP Logging query

```sql
protoPayload.methodName=("google.logging.v2.ConfigServiceV2.DeleteSink"
  OR "google.logging.v2.ConfigServiceV2.UpdateSink" -- changing destination
  OR "logging.sinks.delete"
  OR "securitycenter.findings.mute")
severity!="DEFAULT"
```

---

## Deployment checklist

| Rule ID | Sigma YAML | CloudWatch Insights | Azure KQL | GCP Logging | Custodian | Test pass? |
|---|---|---|---|---|---|---|
| CAP-RECON-01 | [x] | [x] | [x] | [x] | [x] | |
| CAP-IA-01 | [x] | [x] | [x] | [x] | — | |
| CAP-IA-02 | [x] | [x] | [x] | [x] | — | |
| CAP-PE-01 | [x] | [x] | [x] | [x] | — | |
| CAP-PER-01 | [x] | [x] | [x] | [x] | — | |
| CAP-PER-02 | [x] | [x] | [x] | [x] | — | |
| CAP-LM-01 | [x] | [x] | [x] | [x] | [x] | |
| CAP-COLL-01 | [x] | [x] | [x] | [x] | [x] | |
| CAP-IMP-01 | [x] | [x] | [x] | [x] | [x] | |
| CAP-EVASION-01 | [x] | [x] | [x] | [x] | — | |

## References

- [13-03 — Red Variant Walkthrough](../Capstone-APT-Scenario/red-variant-walkthrough.md)
- [13-04 — Blue Variant Walkthrough](../Capstone-APT-Scenario/blue-variant-walkthrough.md)
- [06-07 — Detection-as-Code Sigma & Custodian](../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md)
- [06-02 — CloudTrail Activity & Data Events](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md)
- [06-03 — Azure Log Analytics & Sentinel](../Monitoring-Detection-SIEM/azure-log-analytics-and-sentinel.md)
- [06-04 — GCP Cloud Audit Logs & SCC](../Monitoring-Detection-SIEM/gcp-cloud-audit-logs-and-scc.md)
- [06-05 — Native Threat Detection](../Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md)
