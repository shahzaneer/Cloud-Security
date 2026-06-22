# Detection 01 — Compliance Drift Detection

> **Level:** Intermediate
> **Prereqs:** 12-03, 06-07
> **Clouds:** AWS · Azure · GCP
> **Authorization scope:** Apply detection rules against your own sandbox telemetry. Test by deliberately making a test resource noncompliant, waiting for evaluation, then remediating — observe both alerts.

## 🔴 Red Team view — how attackers trigger these detections

**Drift exploitation (Rule 1):** An attacker who knows the compliance scan schedule modifies a resource (e.g., removes S3 public access block) immediately *after* the periodic scan. The resource is flagged noncompliant at the next scan, but the attacker has already staged exfil data in the newly-public bucket and deleted it before anyone investigates. The drift signal — "was compliant, now noncompliant" — is the detection that catches this before data loss.

**Evidence tampering (Rule 2):** An attacker with write access to the evidence bucket overwrites noncompliant findings with forged compliant JSON *outside* the quarterly assessment window when no legitimate evidence generation is running. The `PutObject` event timestamp falling outside January/April/July/October 1–3 is the tell.

## 🔵 Blue Team view — detection engineering rationale

Rule 1 is high-priority because a *new* noncompliance on a previously-compliant resource is more urgent than chronic noncompliance — it indicates an active configuration change, not legacy drift. Rule 2 is critical because evidence bucket modifications outside the scheduled quarterly window have no legitimate purpose and strongly suggest tampering. Both rules ship findings directly to the security team's PagerDuty escalation path.

## Rule 1 — Resource falls into noncompliant posture after being compliant within 24 hours

### Sigma rule

```yaml
title: Resource Falls Into Noncompliant Posture After Being Compliant
id: a1b2c3d4-6001-4001-8001-e5f6a7b8c9d0
status: experimental
description: |
  Detects when a resource transitions from COMPLIANT to NON_COMPLIANT within 24 hours.
  This is a "drift signal" — someone or something changed the resource configuration
  away from the compliance baseline. High priority because a known-compliant resource
  becoming noncompliant is more urgent than a resource that was always noncompliant.
author: compliance-detection-team
date: 2026-06-22
logsource:
  product: aws
  service: config
detection:
  current:
    eventName: complianceChange
    complianceType: NON_COMPLIANT
  # Requires correlation: same resourceId was COMPLIANT within previous 24h
  # (as of June 2026, implement stateful correlation via Elastic ML job anomalies
  # or Splunk transaction command across 24h windows)
  timeframe: 24h
  condition: current
level: high
tags:
  - attack.defense_evasion
  - attack.t1562
  - compliance_drift
```

### Backend 1: AWS CloudWatch Logs Insights

```sql
-- Find resources that went from COMPLIANT to NON_COMPLIANT today
fields @timestamp, configurationItem.resourceId, configurationItem.resourceType,
       configurationItem.configuration, configurationItemRelationships
| filter eventName = "configurationItemChange"  -- (as of June 2026, verify this is the exact AWS Config event name; may be `configurationItemChange` or `ConfigurationItemChange` depending on Config recorder setup)
| filter configurationItem.configurationItemStatus = "OK"
| sort @timestamp desc
| stats latest(@timestamp) as lastChange by configurationItem.resourceId
-- Correlate with current NON_COMPLIANT state from describe-compliance-by-config-rule
```

### Backend 2: AWS Config advanced query — current noncompliant snapshot

```sql
SELECT
  resourceId,
  resourceType,
  awsRegion,
  configuration,
  supplementaryConfiguration
WHERE resourceType IN (
  'AWS::S3::Bucket',
  'AWS::IAM::User',
  'AWS::EC2::SecurityGroup',
  'AWS::RDS::DBInstance'
)
AND configuration.complianceType = 'NON_COMPLIANT'
```

### Backend 3: Azure Sentinel KQL — compliance drift

```kql
// Resources that were compliant yesterday but noncompliant today
// Uses Azure Resource Graph change history (sent via diagnostic settings)
let yesterday = datetime(2026-06-21);
let today = datetime(2026-06-22);
let compliant_yesterday = (
    AzureActivity
    | where TimeGenerated between (startofday(yesterday) .. endofday(yesterday))
    | where OperationNameValue has "write"
    | where ResourceGroup != ""
    | summarize by ResourceId
);
let noncompliant_today = (
    SecurityResources
    | where TimeGenerated > ago(1d)
    | where AssessmentStatus == "Unhealthy"
    | project ResourceId, AssessmentName, Severity
);
noncompliant_today
| where ResourceId in (compliant_yesterday)
| project TimeGenerated, ResourceId, AssessmentName, Severity
| order by TimeGenerated desc
```

### Backend 4: GCP Cloud Logging query — SCC finding transition

```sql
-- SCC findings that went from INACTIVE to ACTIVE (or newly created)
SELECT
  resource.name,
  finding.category,
  finding.severity,
  finding.state,
  finding.createTime,
  finding.eventTime
FROM securitycenter.findings
WHERE finding.state = "ACTIVE"
  AND finding.createTime >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
ORDER BY finding.createTime DESC
```

### Complete detection pipeline

```python
#!/usr/bin/env python3
"""compliance-drift-detector.py — Check for resources that drifted from compliant to noncompliant"""

import boto3, json, datetime, os
from decimal import Decimal

dynamodb = boto3.resource("dynamodb")
config = boto3.client("config")
sns = boto3.client("sns")

SNAPSHOT_TABLE = os.environ.get("SNAPSHOT_TABLE", "compliance-snapshots")
ALERT_TOPIC = os.environ.get("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-1:111111111111:compliance-drift")

# Get current noncompliant resources
response = config.describe_compliance_by_resource(
    ComplianceTypes=["NON_COMPLIANT"],
    Limit=100
)

current_noncompliant = {}
for item in response["ComplianceByResources"]:
    resource_id = item["ResourceId"]
    current_noncompliant[resource_id] = {
        "resource_type": item["ResourceType"],
        "last_checked": datetime.datetime.utcnow().isoformat()
    }

# Compare against yesterday's snapshot in DynamoDB
table = dynamodb.Table(SNAPSHOT_TABLE)
yesterday = datetime.datetime.utcnow() - datetime.timedelta(days=1)
yesterday_key = yesterday.strftime("%Y-%m-%d")

try:
    yesterday_item = table.get_item(Key={"snapshot_date": yesterday_key})
    yesterday_snapshot = yesterday_item.get("Item", {}).get("compliant_resources", [])
except Exception:
    yesterday_snapshot = []

# Find newly noncompliant resources (were compliant yesterday)
yesterday_set = set(yesterday_snapshot)
today_set = set(current_noncompliant.keys())
newly_noncompliant = today_set - yesterday_set

if newly_noncompliant:
    message = f"ALERT: {len(newly_noncompliant)} resources became noncompliant in the last 24h:\n"
    for resource_id in newly_noncompliant:
        message += f"  - {resource_id} ({current_noncompliant[resource_id]['resource_type']})\n"

    sns.publish(
        TopicArn=ALERT_TOPIC,
        Subject=f"[HIGH] Compliance Drift — {len(newly_noncompliant)} resources noncompliant",
        Message=message
    )
    print(message)
else:
    print("No compliance drift detected.")

# Save today's snapshot for tomorrow's comparison
today_key = datetime.datetime.utcnow().strftime("%Y-%m-%d")
table.put_item(Item={
    "snapshot_date": today_key,
    "compliant_resources": list(current_noncompliant.keys()),
    "total_resources": len(current_noncompliant),
    "timestamp": datetime.datetime.utcnow().isoformat()
})
```

## Rule 2 — Evidence bucket modifications outside assessment period

### Sigma rule

```yaml
title: Evidence Bucket Modified Outside Quarterly Assessment Window
id: b2c3d4e5-7002-4002-8002-f6a7b8c9d0e1
status: experimental
description: |
  Detects PutObject or DeleteObject operations on the compliance evidence bucket
  that occur outside the scheduled quarterly assessment windows.
  Windows: Jan 1-3, Apr 1-3, Jul 1-3, Oct 1-3 (first 3 days of each quarter).
  Outside these windows, any write to the evidence bucket is suspect.
author: compliance-detection-team
date: 2026-06-22
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName:
      - PutObject
      - DeleteObject
      - DeleteObjects
    requestParameters.bucketName: compliance-evidence-
  # Time filter: NOT in assessment windows (Jan 1-3, Apr 1-3, Jul 1-3, Oct 1-3)
  # (as of June 2026, implement calendar-based inclusion/exclusion logic in SIEM
  # using lookup tables or cron-scheduled filter updates)
  timeframe: outside_assessment_windows
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1070
  - attack.t1565
  - evidence_tampering
```

### Backend 1: AWS CloudWatch Logs Insights

```sql
-- Evidence bucket modifications outside Q1 window (Jan 1-3, 2026)
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, requestParameters.key
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutObject", "DeleteObject", "DeleteObjects"]
| filter requestParameters.bucketName like /compliance-evidence-/
| filter @timestamp not like /2026-0[147]-0[1-3]/  -- Q1: Jan, Apr, Jul, Oct days 1-3
| sort @timestamp desc
```

### Backend 2: AWS CloudTrail Lake query

```sql
SELECT
  eventTime,
  eventName,
  userIdentity.arn,
  sourceIPAddress,
  requestParameters.bucketName,
  requestParameters.key,
  errorCode
FROM aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee  -- event data store ID
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutObject', 'DeleteObject', 'DeleteObjects')
  AND requestParameters.bucketName LIKE 'compliance-evidence-%'
  AND NOT (
    (EXTRACT(MONTH FROM eventTime) IN (1, 4, 7, 10))
    AND EXTRACT(DAY FROM eventTime) BETWEEN 1 AND 3
  )
ORDER BY eventTime DESC
LIMIT 100
```

### Backend 3: Azure Sentinel KQL

```kql
// Evidence container writes outside assessment windows
let assessment_months = dynamic([1, 4, 7, 10]);
let assessment_days = dynamic([1, 2, 3]);
StorageBlobLogs
| where AccountName startswith "complianceevidence"
| where OperationName in ("PutBlob", "DeleteBlob")
| extend m = datetime_part("Month", TimeGenerated)
| extend d = datetime_part("Day", TimeGenerated)
| where not (m in (assessment_months) and d in (assessment_days))
| project TimeGenerated, CallerIpAddress, AccountName, ObjectKey, OperationName, UserAgentHeader
| order by TimeGenerated desc
```

### Backend 4: GCP Cloud Logging query

```sql
-- Evidence bucket writes outside assessment windows
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail,
  protoPayload.requestMetadata.callerIp,
  resource.labels.bucket_name,
  protoPayload.resourceName
FROM `sec-audit-project.audit_logs.cloudaudit_googleapis_com_data_access_*`
WHERE protoPayload.methodName IN (
  "storage.objects.insert",
  "storage.objects.delete",
  "storage.objects.update"
)
AND resource.labels.bucket_name LIKE "compliance-evidence-%"
AND NOT (
  EXTRACT(MONTH FROM timestamp) IN (1, 4, 7, 10)
  AND EXTRACT(DAY FROM timestamp) BETWEEN 1 AND 3
)
ORDER BY timestamp DESC
```

### Python detection script — evidence bucket tamper alert

```python
#!/usr/bin/env python3
"""evidence-bucket-guard.py — Alert on evidence bucket modifications outside windows"""

import boto3, datetime

s3 = boto3.client("s3")
sns = boto3.client("sns")
bucket = "compliance-evidence-111111111111-us-east-1"
alert_topic = "arn:aws:sns:us-east-1:111111111111:evidence-tamper-alerts"

today = datetime.datetime.utcnow()
month = today.month
day = today.day

# Assessment windows: first 3 days of Jan, Apr, Jul, Oct
in_window = (month in [1, 4, 7, 10]) and (1 <= day <= 3)

if not in_window:
    # Check for recent object modifications (last 1 hour)
    # Use S3 server access logs or CloudTrail
    pass  # CloudTrail-based detection preferred (see SQL above)

    # Simplified: check if any object has LastModified outside the window
    paginator = s3.get_paginator("list_objects_v2")
    recent_modifications = []

    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            last_mod = obj["LastModified"].replace(tzinfo=None)
            hours_ago = (today.replace(tzinfo=None) - last_mod).total_seconds() / 3600
            if hours_ago < 1:  # modified in last hour
                recent_modifications.append(f"  {obj['Key']} — modified {last_mod.isoformat()}")

    if recent_modifications:
        message = (
            f"EVIDENCE TAMPER ALERT: {len(recent_modifications)} objects modified "
            f"outside quarterly assessment window (today: month={month}, day={day}):\n"
            + "\n".join(recent_modifications)
        )
        sns.publish(
            TopicArn=alert_topic,
            Subject=f"[CRITICAL] Evidence Bucket Modified Outside Assessment Window",
            Message=message
        )
        print(message)
    else:
        print(f"No evidence modifications in last hour (month={month}, day={day}, in_window={in_window})")
else:
    print(f"Inside assessment window (month={month}, day={day}) — modifications expected.")
```

## Alert routing matrix

| Signal | Severity | Recipient | Response SLA |
|---|---|---|---|
| Resource became noncompliant within 24h (Rule 1) | High | Security team PagerDuty | Investigate within 2h |
| Evidence bucket modified outside window (Rule 2) | Critical | CISO + security team on-call | Investigate within 15 min |
| Evidence bucket manifest hash mismatch | Critical | CISO + audit lead + security team | Investigate within 15 min |
| StopLogging / DeleteTrail attempt | Critical | Security team PagerDuty | Immediate page |
| Finding suppressed < 1h after creation | Medium | Detection engineering team | Investigate within 24h |

## Test the detections (sandbox only)

```bash
# Test Rule 1: Make a resource noncompliant
# 1. Ensure a test S3 bucket has public access block
aws s3api create-bucket --bucket drift-test-111111111111-us-east-1
aws s3api put-public-access-block \
  --bucket drift-test-111111111111-us-east-1 \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# 2. Wait for Config rule to evaluate as COMPLIANT
aws configservice start-config-rules-evaluation \
  --config-rule-names s3-bucket-public-read-prohibited

# 3. Drift the resource — remove public access block
aws s3api delete-public-access-block \
  --bucket drift-test-111111111111-us-east-1

# 4. Re-evaluate Config rule — now NON_COMPLIANT
aws configservice start-config-rules-evaluation \
  --config-rule-names s3-bucket-public-read-prohibited

# 5. Verify the drift detector script fires (Rule 1)
python3 compliance-drift-detector.py

# Test Rule 2: Write to evidence bucket outside window
# (If today is NOT Jan 1-3, Apr 1-3, Jul 1-3, or Oct 1-3)
aws s3 cp /tmp/test-file.txt \
  s3://compliance-evidence-111111111111-us-east-1/outside-window-test.txt
python3 evidence-bucket-guard.py

# Cleanup
aws s3 rm s3://drift-test-111111111111-us-east-1 --recursive
aws s3api delete-bucket --bucket drift-test-111111111111-us-east-1
aws s3 rm s3://compliance-evidence-111111111111-us-east-1/outside-window-test.txt
```

## Deploy as scheduled Lambda

```hcl
resource "aws_cloudwatch_event_rule" "drift_detection" {
  name                = "compliance-drift-detection"
  description         = "Run compliance drift detection every 6 hours"
  schedule_expression = "rate(6 hours)"
}

resource "aws_cloudwatch_event_target" "drift_detection_lambda" {
  rule = aws_cloudwatch_event_rule.drift_detection.name
  arn  = aws_lambda_function.drift_detector.arn
}

resource "aws_lambda_function" "drift_detector" {
  filename      = "compliance-drift-detector.zip"
  function_name = "compliance-drift-detector"
  role          = aws_iam_role.drift_detector.arn
  handler       = "compliance-drift-detector.lambda_handler"
  runtime       = "python3.12"
  timeout       = 300

  environment {
    variables = {
      SNAPSHOT_TABLE  = aws_dynamodb_table.compliance_snapshots.name
      ALERT_TOPIC_ARN = aws_sns_topic.compliance_drift.arn
    }
  }
}
```

## References

- [AWS Config compliance change events](https://docs.aws.amazon.com/config/latest/developerguide/notifications-for-AWS-Config.html)
- [Azure Policy compliance data](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data)
- [GCP SCC API](https://cloud.google.com/security-command-center/docs/reference/rest)
- MITRE ATT&CK: T1562 Impair Defenses, T1070 Indicator Removal, T1565 Data Manipulation
- Cross-links: [../evidence-automation.md](evidence-automation.md), [../audit-log-retention-and-immutability.md](audit-log-retention-and-immutability.md)
