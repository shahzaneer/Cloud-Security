# Detection Rule — IR Snapshot Evidence Trigger

> **Level:** Intermediate
> **Clouds:** AWS · Azure · GCP
> **Purpose:** Trigger forensic preservation when a high-confidence threat detection fires, with a sidecar alert if the snapshot takes too long.
> **Authorization scope:** Deploy only in your own sandbox account. All account IDs are placeholders (`111111111111`, `00000000-0000-0000-0000-000000000000`).

## Rule 1 — AWS: GuardDuty Finding → Invoke IR Lambda

### EventBridge rule

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{"numeric": [">=", 5]}],
    "type": [
      "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
      "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
      "UnauthorizedAccess:EC2/SSHBruteForce",
      "UnauthorizedAccess:EC2/RDPBruteForce",
      "Persistence:IAMUser/AnomalousBehavior",
      "PrivilegeEscalation:IAMUser/AnomalousBehavior",
      "CredentialAccess:IAMUser/AnomalousBehavior",
      "Impact:EC2/AbusedDomainReputation",
      "DefenseEvasion:IAMUser/AnomalousBehavior"
    ]
  }
}
```

Target: Lambda function that executes the preservation runbook ([ir-runbook-cloud-aware.md](./ir-runbook-cloud-aware.md) Phase 1-5).

### Lambda execution role policy (minimum)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:CreateSnapshots",
        "ec2:CreateTags",
        "ec2:ModifyInstanceAttribute",
        "ec2:StopInstances",
        "ec2:DescribeInstances",
        "ec2:DescribeSnapshots",
        "ec2:DisassociateIamInstanceProfile",
        "ec2:DescribeIamInstanceProfileAssociations",
        "iam:PutRolePolicy",
        "iam:UpdateAccessKey",
        "iam:ListAccessKeys",
        "ssm:SendCommand",
        "s3:PutObject"
      ],
      "Resource": "*"
    }
  ]
}
```

## Rule 2 — Sidecar alert: Snapshot took > 120 seconds

### CloudWatch Metric Filter

**Log group:** `/aws/lambda/ir-forensic-preservation`

**Filter pattern:**

```
{ ($.eventName = "CreateSnapshots") && ($.duration_ms > 120000) }
```

### CloudWatch Alarm

```bash
aws cloudwatch put-metric-alarm \
    --alarm-name "IR-Snapshot-Slow" \
    --alarm-description "Forensic snapshot creation exceeded 120 seconds" \
    --metric-name SnapshotDuration \
    --namespace IR-Forensics \
    --statistic Maximum \
    --period 300 \
    --threshold 120000 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 1 \
    --alarm-actions "arn:aws:sns:us-east-1:111111111111:ir-oncall"
```

### Sigma-style rule

```yaml
title: GuardDuty Medium+ Finding — IR Snapshot Not Initiated Within 60s
id: ir-snapshot-missed
status: stable
description: |
  When GuardDuty fires a Medium-or-higher finding, a forensic snapshot
  should be created within 60 seconds. If no CreateSnapshots event follows,
  the automated preservation chain failed.
logsource:
  product: aws
  service: cloudtrail
detection:
  guardduty_finding:
    eventSource: guardduty.amazonaws.com
    eventName: CreateFindings
  no_snapshot:
    timeframe: 120s
    condition: not
      next_event:
        eventSource: ec2.amazonaws.com
        eventName: CreateSnapshots
        attribute: "instance-specification"  # or any matching instance ID
  condition: guardduty_finding and no_snapshot
severity: critical
falsepositives:
  - GuardDuty findings on Fargate/Lambda resources (no EBS volumes to snapshot)
  - Findings on terminated instances
```

## Rule 3 — Sidecar alert: Forensic tagging took > 300 seconds

### Sigma-style rule

```yaml
title: IR Evidence Tagging Delayed Beyond 300 Seconds
id: ir-tagging-slow
status: stable
description: |
  After a GuardDuty finding triggers IR, the compromised instance should
  be tagged `forensic=true` within 300 seconds. Delays indicate tooling
  failure, SSM agent downtime, or an attacker blocking the automation.
logsource:
  product: aws
  service: cloudtrail
detection:
  guardduty_finding:
    eventSource: guardduty.amazonaws.com
    eventName: CreateFindings
  no_tagging:
    timeframe: 300s
    condition: not
      next_event:
        eventSource: ec2.amazonaws.com
        eventName: CreateTags
        requestParameters.tagSet: [{key: forensic, value: "true"}]
  condition: guardduty_finding and no_tagging
severity: high
```

## Rule 4 — Azure: Microsoft Defender → Logic App Trigger

### Azure Monitor alert rule

```json
{
  "location": "global",
  "properties": {
    "scopes": ["/subscriptions/00000000-0000-0000-0000-000000000000"],
    "criteria": {
      "allOf": [
        {
          "name": "SecurityAlert",
          "metricName": "SecurityAlert",
          "dimensions": [
            {
              "name": "Severity",
              "operator": "Include",
              "values": ["High", "Medium"]
            }
          ],
          "timeAggregation": "Count",
          "operator": "GreaterThan",
          "threshold": 0
        }
      ],
      "windowSize": "PT5M",
      "evaluationFrequency": "PT1M"
    },
    "actions": {
      "actionGroups": [{
        "actionGroupId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/ir-rg/providers/Microsoft.Insights/actionGroups/IR-Forensics"
      }]
    }
  }
}
```

Action Group → Logic App that calls `az vm deallocate`, `az snapshot create`, and `az role assignment delete`.

### Sentinel Analytics Rule (KQL)

```kql
// Sentinel Analytics: IR Snapshot Trigger
let finding_window = 1h;
SecurityAlert
| where TimeGenerated > ago(finding_window)
| where Severity in ("High", "Medium")
| where AlertName contains "UnauthorizedAccess"
      or AlertName contains "Malicious"
      or AlertName contains "Anomalous"
      or AlertName contains "BruteForce"
| join kind=leftanti (
    AzureActivity
    | where TimeGenerated > ago(finding_window)
    | where OperationNameValue has "snapshot"
    | where ActivityStatusValue == "Succeeded"
) on $left.ResourceId == $right._ResourceId
| project AlertName, Severity, TimeGenerated, ResourceId, Entities
```

## Rule 5 — GCP: SCC Finding → Cloud Function Trigger

### Pub/Sub topic filter

```yaml
notificationConfig:
  pubsubTopic: projects/project-id/topics/scc-findings
  streamingConfig:
    filter: 'state="ACTIVE" AND (severity="HIGH" OR severity="CRITICAL") AND (findingClass="THREAT" OR findingClass="VULNERABILITY")'
```

### Cloud Function (2nd gen) trigger

```python
def scc_to_snapshot(event, context):
    finding = event['finding']
    resource_name = finding['resourceName']

    if 'compute.googleapis.com/Instance' in resource_name:
        instance = resource_name.split('/')[-1]
        zone = extract_zone(resource_name)
        subprocess.run([
            'gcloud', 'compute', 'disks', 'snapshot', instance,
            f'--zone={zone}',
            f'--snapshot-names=snap-scc-{context.timestamp}',
            '--labels=forensic=true'
        ])
        subprocess.run([
            'gcloud', 'compute', 'instances', 'stop',
            instance, f'--zone={zone}'
        ])
```

### Log-based metric: snapshot delay

```bash
gcloud logging metrics create ir-snapshot-delay \
    --description="Time between SCC finding and disk snapshot" \
    --log-filter='
        resource.type="gce_disk"
        AND protoPayload.methodName="v1.compute.snapshots.insert"
        AND protoPayload.request.@type="type.googleapis.com/compute.snapshots.insert"
    '
```

## Deployment validation

### AWS

```bash
# Deploy EventBridge rule
aws events put-rule \
    --name "IR-GuardDuty-To-Snapshot" \
    --event-pattern '{
        "source": ["aws.guardduty"],
        "detail-type": ["GuardDuty Finding"],
        "detail": {"severity": [{"numeric": [">=", 5]}]}
    }'

aws events put-targets \
    --rule "IR-GuardDuty-To-Snapshot" \
    --targets "Id=1,Arn=arn:aws:lambda:us-east-1:111111111111:function:ir-forensic-preservation"

# Trigger a test finding
aws guardduty create-sample-findings \
    --detector-id <detector-id> \
    --finding-types "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"

# Verify Lambda execution
aws logs tail /aws/lambda/ir-forensic-preservation --follow
```

### Azure

```bash
az monitor metrics alert create \
    --name "IR-Defender-To-Snapshot" \
    --resource-group ir-rg \
    --scopes "/subscriptions/00000000-0000-0000-0000-000000000000" \
    --condition "count SecurityAlert > 0 where Severity includes High" \
    --window-size 5m \
    --evaluation-frequency 1m \
    --action "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/ir-rg/providers/Microsoft.Logic/workflows/ir-forensics"
```

### GCP

```bash
gcloud pubsub subscriptions create ir-scc-to-snapshot \
    --topic=scc-findings \
    --push-endpoint="https://us-central1-project-id.cloudfunctions.net/ir-forensics" \
    --push-auth-service-account="ir-forensics-sa@project-id.iam.gserviceaccount.com"
```

## False positive handling

| False positive | Mitigation |
|---------------|-----------|
| GuardDuty Fargate finding — no EBS to snapshot | Lambda checks resource type before snapshotting; skip if `resourceType` is `Instance` but no `instanceDetails` |
| GuardDuty Medium on a terminated instance | Filter out instances with `State.Name` = `terminated` before snapshotting |
| Sentinel SecurityAlert on PaaS (no VM) | Logic App checks resource type; only snapshot `Microsoft.Compute/virtualMachines` |
| SCC finding on deleted GCE instance | Cloud Function checks `gcloud compute instances describe` before snapshot |

## References

- [AWS EventBridge event patterns](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html)
- [Azure Monitor alert rules](https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-overview)
- [GCP Pub/Sub notifications for SCC](https://cloud.google.com/security-command-center/docs/how-to-notifications)
- See [ir-runbook-cloud-aware.md](./ir-runbook-cloud-aware.md) for the full Lambda/Logic App/Cloud Function runbook code
