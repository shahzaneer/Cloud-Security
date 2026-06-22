# Labs 01 — Add One Detection

> **Level:** Intermediate
> **Prereqs:** 06-01, 06-07 (Sigma basics)
> **Clouds:** AWS (primary) · Azure · GCP
> **Authorization scope:** Run only in your own sandbox account. You will deliberately grant yourself `AdministratorAccess` — this is intentional and reversible.

## Objective

Write one Sigma detection rule, convert it to a cloud-native backend query, trigger the event in your sandbox, observe the log line, and optionally post it to a webhook.

## Pre-lab

### Tools required
- `python3` with `pip`
- `aws` CLI configured for your sandbox account
- A test IAM user to grant admin to (create during lab)

### Install Sigma CLI

```bash
pip install sigma-cli pysigma
sigma plugin install insight-connect
```

### Verify

```bash
sigma --version
```

## Step 1: Write the Sigma rule

Create a file `detection-adminaccess.yml`:

```yaml
title: IAM User Granted AdministratorAccess Policy
id: 6a84b985-d4bf-4ce1-bf36-1bb3b24a4ace
status: experimental
description: Detects when the AWS managed AdministratorAccess policy is attached to an IAM user
author: lab-user
date: 2026-06-22
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AttachUserPolicy
    requestParameters.policyArn|endswith: AdministratorAccess
  condition: selection
falsepositives:
  - Authorized admin grant during account setup
  - Break-glass procedure
level: high
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1098
```

### Cross-cloud variants

**Azure variant** (`detection-adminaccess-azure.yml`):

```yaml
title: Role Assignment of Owner or User Access Administrator
id: a1b2c3d4-e5f6-7890-abcd-ef123456789a
status: experimental
description: Detects assignment of high-privilege Azure RBAC roles
logsource:
  product: azure
  service: activity
detection:
  selection:
    operationName: Microsoft.Authorization/roleAssignments/write
    properties.requestbody.properties.roleDefinitionId|endswith: 8e3af657-a8ff-443c-a75c-2fe8c4bcb635
  condition: selection
falsepositives:
  - PIM activation (not a direct role assignment)
level: high
```

> `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` = Owner role definition ID.

**GCP variant** (`detection-adminaccess-gcp.yml`):

```yaml
title: Project IAM Binding to roles/owner
id: b2c3d4e5-f6a7-8901-bcde-f123456789b0
status: experimental
description: Detects assignment of roles/owner to a user or service account in GCP
logsource:
  product: gcp
  service: cloudaudit
detection:
  selection:
    protoPayload.methodName: SetIamPolicy
    protoPayload.serviceData.policyDelta.bindingDeltas.action: ADD
    protoPayload.serviceData.policyDelta.bindingDeltas.role: roles/owner
  condition: selection
falsepositives:
  - Authorized project-level admin grants
level: high
```

## Step 2: Convert Sigma to backend query

### Convert to AWS CloudWatch Logs Insights

```bash
sigma convert -t logsource -p aws detection-adminaccess.yml
```

Expected output:

```
fields @timestamp, eventName, userIdentity.arn, requestParameters.userName, requestParameters.policyArn
| filter eventName = "AttachUserPolicy"
| filter requestParameters.policyArn like /AdministratorAccess/
```

### Convert to Azure Sentinel KQL

```bash
sigma convert -t sentinel-rule -p azure detection-adminaccess-azure.yml
```

### Convert to GCP Logging query

```bash
sigma convert -t chronicle -p gcp detection-adminaccess-gcp.yml
```

## Step 3: Trigger the detection in AWS

### Create a test IAM user

```bash
aws iam create-user --user-name lab-detection-test-user
```

### Attach AdministratorAccess to the test user

```bash
aws iam attach-user-policy \
  --user-name lab-detection-test-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

This action is the event your Sigma rule should detect.

### Verify the policy is attached

```bash
aws iam list-attached-user-policies --user-name lab-detection-test-user
```

## Step 4: Observe the matching log line

### Query CloudTrail Event History

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
  --max-results 5 \
  --query 'Events[?Username==`lab-detection-test-user`].{Time:EventTime,Event:EventName,UserName:Username,Policy:CloudTrailEvent}' \
  --output text
```

### If using CloudTrail Lake

```bash
aws cloudtrail start-query \
  --query-statement "SELECT eventTime, eventName, userIdentity.arn, requestParameters.policyArn FROM <event-data-store-id> WHERE eventName='AttachUserPolicy' AND requestParameters.policyArn LIKE '%AdministratorAccess%'"
```

### CloudWatch Logs Insights (if CloudTrail trails forward to CW Logs)

Navigate to CloudWatch → Logs Insights and run the Sigma-generated query:

```
fields @timestamp, eventName, userIdentity.arn, requestParameters.userName, requestParameters.policyArn
| filter eventName = "AttachUserPolicy"
| filter requestParameters.policyArn like /AdministratorAccess/
| sort @timestamp desc
| limit 20
```

## Step 5 (Optional): Post via webhook to Slack

If you have a Slack incoming webhook or Discord channel, wrap the detection in a Lambda:

```python
import json
import urllib.request

def handler(event, context):
    cloudtrail_event = json.loads(event['Records'][0]['Sns']['Message'])
    detail = cloudtrail_event.get('detail', {})

    if detail.get('eventName') == 'AttachUserPolicy' and 'AdministratorAccess' in detail.get('requestParameters', {}).get('policyArn', ''):
        slack_msg = {
            "text": f":rotating_light: *AdminAccess Granted*",
            "attachments": [{
                "color": "danger",
                "fields": [
                    {"title": "User", "value": detail['requestParameters']['userName'], "short": True},
                    {"title": "By", "value": detail['userIdentity']['arn'], "short": True},
                    {"title": "IP", "value": detail.get('sourceIPAddress', 'unknown'), "short": True}
                ]
            }]
        }
        req = urllib.request.Request(
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX",
            data=json.dumps(slack_msg).encode(),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req)

    return {"statusCode": 200}
```

Deploy via EventBridge rule:

```bash
aws events put-rule \
  --name attach-adminaccess-alert \
  --event-pattern '{"source":["aws.iam"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventName":["AttachUserPolicy"]}}'

aws events put-targets --rule attach-adminaccess-alert \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:111111111111:function:slack-adminaccess-alert"
```

Trigger a test event:

```bash
aws events put-events \
  --entries '[{"Source":"aws.iam","DetailType":"AWS API Call via CloudTrail","Detail":"{\"eventName\":\"AttachUserPolicy\",\"requestParameters\":{\"userName\":\"lab-detection-test-user\",\"policyArn\":\"arn:aws:iam::aws:policy/AdministratorAccess\"},\"userIdentity\":{\"arn\":\"arn:aws:iam::111111111111:user/admin\"},\"sourceIPAddress\":\"203.0.113.42\"}"}]'
```

## Cross-cloud alternatives

### Azure — trigger the detection

```bash
az role assignment create \
  --assignee "lab-user@example.com" \
  --role Owner \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

Query Activity Log:

```bash
az monitor activity-log list \
  --resource-group rg-lab \
  --query "[?authorization.action=='Microsoft.Authorization/roleAssignments/write']" \
  -o table
```

### GCP — trigger the detection

```bash
gcloud projects add-iam-policy-binding project-id-111111 \
  --member user:lab-user@example.com \
  --role roles/owner
```

Query audit logs:

```bash
gcloud logging read 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner"' --limit 5
```

## 🔴 Red Team view

Attackers often grant themselves `AdministratorAccess` after compromising a lower-privileged principal — this is a pure persistence and privilege escalation play. The `AttachUserPolicy` call is a management event and is always logged by CloudTrail, but the defender must have a rule watching for it. Without a Sigma rule or equivalent, this action looks identical to a legitimate admin grant and the attacker achieves admin without alerting.

**Artifacts:** `AttachUserPolicy` on `arn:aws:iam::aws:policy/AdministratorAccess` in CloudTrail, caller identity, source IP, user agent. The attached policy persists until explicitly detached — giving the attacker persistent admin even if the original compromise vector is closed.

## 🔵 Blue Team view

This detection is a Tier-1 SOC rule — it has very few legitimate uses and every hit demands investigation. Deploy the Sigma rule converted to your SIEM backend, tune out known service accounts used for automated admin grants (e.g., a break-glass role), and route hits to PagerDuty with a 15-minute SLA. Pair with a Cloud Custodian policy that automatically detaches `AdministratorAccess` unless granted by an approved break-glass principal.

## Teardown

### AWS teardown

```bash
aws iam detach-user-policy \
  --user-name lab-detection-test-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws iam delete-user --user-name lab-detection-test-user

rm detection-adminaccess.yml

# Remove Lambda + EventBridge rule (if created in Step 5)
aws events remove-targets --rule attach-adminaccess-alert --ids 1
aws events delete-rule --name attach-adminaccess-alert
aws lambda delete-function --function-name slack-adminaccess-alert
```

### Azure teardown

```bash
az role assignment delete \
  --assignee "lab-user@example.com" \
  --role Owner \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

### GCP teardown

```bash
gcloud projects remove-iam-policy-binding project-id-111111 \
  --member user:lab-user@example.com \
  --role roles/owner
```

## Expected output

After Step 4, you should see a CloudTrail event similar to:

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::111111111111:user/your-admin-user",
    "accountId": "111111111111",
    "userName": "your-admin-user"
  },
  "eventTime": "2026-06-22T12:00:00Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "AttachUserPolicy",
  "sourceIPAddress": "203.0.113.42",
  "requestParameters": {
    "userName": "lab-detection-test-user",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
  },
  "responseElements": null
}
```

The Sigma rule matches because:
- `eventName` == `"AttachUserPolicy"` ✓
- `requestParameters.policyArn` ends with `"AdministratorAccess"` ✓

## References
- [SigmaHQ rules repository](https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws)
- [PySigma backends](https://github.com/SigmaHQ/pySigma-backend-insight-connect)
- [../detection-as-code-sigma-and-custodian.md](../detection-as-code-sigma-and-custodian.md)
- [../IAM/permission-boundaries-and-quarantine.md](../IAM/permission-boundaries-and-quarantine.md)
