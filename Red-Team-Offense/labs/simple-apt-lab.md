# Lab 02 — Simple APT Lab: Full Chain + Honeytoken + SOC Dashboard

> **Level:** Advanced
> **Prereqs:** 09-01..09-11, labs/linchpin-lab.md
> **Clouds:** AWS (primary)
**Authorization scope:** Run only in your own sandbox AWS account. All resources, ARNs, and account IDs are placeholders. This is scaffolding and educational narrative — no operational binaries.

## Overview

This lab extends the linchpin chain from Lab 01 with:
1. A pre-set **honeytoken** IAM access key as bait — watch CloudTrail detect any use
2. A **Slack-style SOC dashboard** using EventBridge + Lambda → localhost webhook that alerts when a detection rule fires
3. Full artifact verification and teardown

## Architecture

```
                         ┌─────────────────────────────┐
                         │     SOC Dashboard            │
                         │  (Lambda → localhost:9999)   │
                         └──────────▲──────────────────┘
                                    │ webhook POST
                         ┌──────────┴──────────────────┐
                         │   Detection Lambda          │
                         │   (EventBridge trigger)     │
                         └──────────▲──────────────────┘
                                    │ CloudTrail event
┌──────────────────────────────────────────────────────────┐
│                Your Sandbox (111111111111)                │
│                                                          │
│  ┌─────────────────┐   ┌───────────────────────────┐    │
│  │ honey-user      │   │ Attack Chain:             │    │
│  │ AKIAIOSFODNN7EX │   │ linchpin-vuln-role →      │    │
│  │ (honeytoken)    │   │ linchpin-lambda-admin →   │    │
│  └─────────────────┘   │ linchpin-backdoor          │    │
│                        └───────────────────────────┘    │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │ CloudTrail → CloudWatch Logs → EventBridge Rule  │   │
│  └──────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
```

## Pre-requisites

- Completed Lab 01 (linchpin chain)
- AWS sandbox account
- `python3`, `jq`, `curl`
- A terminal that can listen on `localhost:9999` (for the webhook receiver)

## Step 1: Deploy the Honeytoken

Create a fake "production admin" user with an access key that looks real but has zero permissions. Any use of this key is definitively malicious.

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# Create a honey-user with a tempting name
aws iam create-user --user-name prod-deployment-admin --tags Key=honeytoken,Value=true

# Create an access key — this is the honeytoken
HONEY_KEY=$(aws iam create-access-key --user-name prod-deployment-admin)

echo "=== HONEYTOKEN CREATED ==="
echo "Access Key ID: $(echo $HONEY_KEY | jq -r '.AccessKey.AccessKeyId')"
echo "Secret Key:    $(echo $HONEY_KEY | jq -r '.AccessKey.SecretAccessKey')"
echo ""
echo "Store these somewhere an attacker might find them (e.g., a test repo, CI log, or pastebin-like location)."
echo "But do NOT push to a real public repo — use a local 'leaked' file for testing."

# Attach NO permissions — zero policies. The user exists purely for detection.
# Any AccessDenied or API call using this key is a high-fidelity alert.

# Verify the user has no permissions
aws iam list-attached-user-policies --user-name prod-deployment-admin
# Output: {"AttachedPolicies": []}

aws iam list-user-policies --user-name prod-deployment-admin
# Output: {"PolicyNames": []}
```

## Step 2: Test Honeytoken Detection

```bash
# Simulate an attacker finding and using the honeytoken
export AWS_ACCESS_KEY_ID=$(echo $HONEY_KEY | jq -r '.AccessKey.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $HONEY_KEY | jq -r '.AccessKey.SecretAccessKey')

# Any API call should fail (AccessDenied) since the user has no permissions
aws sts get-caller-identity 2>&1
# Expected: AccessDenied — but the attempt IS logged in CloudTrail

# Try enumerating
aws iam list-roles 2>&1
# Expected: AccessDenied

# Try accessing S3
aws s3 ls 2>&1
# Expected: AccessDenied

# Unset the honeytoken
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

sleep 120
echo "=== Check CloudTrail for honeytoken usage ==="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$(echo $HONEY_KEY | jq -r '.AccessKey.AccessKeyId') \
  --max-results 10 \
  --query 'Events[].{Time:EventTime,Event:EventName,Error:ErrorMessage}' \
  --output table

# Every AccessDenied from this key is a high-fidelity alert.
# This key should NEVER be used by any legitimate process.
```

## Step 3: Build the SOC Dashboard

Create a simple detection pipeline: CloudTrail → CloudWatch Logs → EventBridge Rule → Lambda → localhost webhook.

### 3a: Create the SNS topic for alerts

```bash
aws sns create-topic --name security-alerts

# Subscribe your email for real notifications (optional)
# aws sns subscribe --topic-arn arn:aws:sns:us-east-1:${ACCOUNT_ID}:security-alerts \
#   --protocol email --notification-endpoint you@example.com
```

### 3b: Create the detection Lambda

```bash
mkdir -p /tmp/detection-lambda
cat > /tmp/detection-lambda/index.py << 'PYEOF'
import json
import urllib3
import os

WEBHOOK_URL = os.environ.get('WEBHOOK_URL', 'http://localhost:9999/alert')
http = urllib3.PoolManager()

def handler(event, context):
    alerts = []

    for record in event.get('Records', []):
        cloudtrail_event = json.loads(record.get('Sns', {}).get('Message', '{}'))
        detail = cloudtrail_event.get('detail', {})

        event_name = detail.get('eventName', 'Unknown')
        user_arn = detail.get('userIdentity', {}).get('arn', 'Unknown')
        source_ip = detail.get('sourceIPAddress', 'Unknown')
        error = detail.get('errorMessage', '')

        # Detection rule 1: Honeytoken key used
        if event_name in ('GetCallerIdentity', 'ListRoles', 'ListUsers'):
            alerts.append({
                'rule': 'HONEYTOKEN_USED',
                'severity': 'CRITICAL',
                'event': event_name,
                'principal': user_arn,
                'source_ip': source_ip,
                'error': error,
                'summary': f'Honeytoken key used for {event_name} from {source_ip}'
            })

        # Detection rule 2: CreateAccessKey on IAM user
        if event_name == 'CreateAccessKey':
            alerts.append({
                'rule': 'PERSISTENCE_KEY_CREATED',
                'severity': 'HIGH',
                'event': event_name,
                'principal': user_arn,
                'source_ip': source_ip,
                'summary': f'New access key created by {user_arn}'
            })

        # Detection rule 3: Lambda created with admin role
        if event_name == 'CreateFunction20150331':
            role = detail.get('requestParameters', {}).get('role', '')
            if 'Admin' in role:
                alerts.append({
                    'rule': 'LAMBDA_ADMIN_ROLE',
                    'severity': 'HIGH',
                    'event': event_name,
                    'principal': user_arn,
                    'role': role,
                    'summary': f'Lambda created with admin role: {role}'
                })

        # Detection rule 4: AssumeRole without MFA
        if event_name == 'AssumeRole':
            mfa = detail.get('additionalEventData', {}).get('MFAUsed', 'No')
            if mfa == 'No':
                alerts.append({
                    'rule': 'ASSUME_ROLE_NO_MFA',
                    'severity': 'MEDIUM',
                    'event': event_name,
                    'principal': user_arn,
                    'summary': f'AssumeRole without MFA by {user_arn}'
                })

    if alerts:
        payload = json.dumps({'alerts': alerts, 'count': len(alerts)})

        try:
            response = http.request('POST', WEBHOOK_URL,
                                     body=payload,
                                     headers={'Content-Type': 'application/json'})
            print(f"Sent {len(alerts)} alerts to webhook. Status: {response.status}")
        except Exception as e:
            print(f"Failed to send webhook: {e}")
            print(f"Alerts that would have been sent: {payload}")

        # Also log to CloudWatch
        for alert in alerts:
            print(json.dumps(alert))

    return {'statusCode': 200, 'alerts': len(alerts)}
PYEOF

cd /tmp/detection-lambda && zip -r /tmp/detection-lambda.zip index.py
```

### 3c: Create the IAM role for the detection Lambda

```bash
aws iam create-role \
  --role-name detection-lambda-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy \
  --role-name detection-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Allow publishing to SNS topic
aws iam put-role-policy \
  --role-name detection-lambda-role \
  --policy-name sns-publish \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Action\": \"sns:Publish\",
      \"Resource\": \"arn:aws:sns:us-east-1:${ACCOUNT_ID}:security-alerts\"
    }]
  }"
```

### 3d: Deploy the detection Lambda

```bash
aws lambda create-function \
  --function-name soc-detector \
  --runtime python3.9 \
  --role arn:aws:iam::${ACCOUNT_ID}:role/detection-lambda-role \
  --handler index.handler \
  --zip-file fileb:///tmp/detection-lambda.zip \
  --timeout 30 \
  --environment "Variables={WEBHOOK_URL=http://localhost:9999/alert}"
```

### 3e: Create CloudWatch Logs subscription for CloudTrail

```bash
# Find your CloudTrail log group
LOG_GROUP=$(aws cloudtrail describe-trails --query 'trailList[0].CloudWatchLogsLogGroupArn' --output text)

if [ -z "$LOG_GROUP" ] || [ "$LOG_GROUP" = "None" ]; then
  echo "CloudTrail not sending to CloudWatch Logs. Creating a trail with CloudWatch Logs..."
  # This step varies by setup; for lab purposes, we use EventBridge directly
fi

# Alternative: Use EventBridge rule that triggers on CloudTrail events
aws events put-rule \
  --name soc-detection-rule \
  --event-pattern '{
    "source": ["aws.iam", "aws.lambda", "aws.sts"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["CreateAccessKey", "CreateUser", "CreateFunction", "AssumeRole", "GetCallerIdentity"]
    }
  }'

aws events put-targets \
  --rule soc-detection-rule \
  --targets "Id=1,Arn=arn:aws:lambda:us-east-1:${ACCOUNT_ID}:function:soc-detector"

# Add permission for EventBridge to invoke the Lambda
aws lambda add-permission \
  --function-name soc-detector \
  --statement-id eventbridge-invoke \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:us-east-1:${ACCOUNT_ID}:rule/soc-detection-rule
```

## Step 4: Set Up the Local Webhook Receiver

In a separate terminal, start a simple HTTP server to receive alerts:

```bash
# Terminal 2: Start the webhook receiver
python3 -c '
import http.server
import json

class AlertHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        body = self.rllib.parse.unquote(self.rfile.read(content_length).decode())
        alerts = json.loads(body)
        print(f"\n=== SOC ALERT [{alerts.get(\"count\", 0)} alerts] ===")
        for alert in alerts.get("alerts", []):
            print(f"  [{alert[\"severity\"]}] {alert[\"rule\"]}: {alert[\"summary\"]}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass  # suppress log noise

server = http.server.HTTPServer(("localhost", 9999), AlertHandler)
print("SOC Dashboard listening on http://localhost:9999/alert ...")
server.serve_forever()
'
```

Leave this running. Keep Terminal 2 visible — it's your "SOC dashboard."

## Step 5: Trigger the Full Chain and Watch the SOC

### 5a: Run the linchpin attack (reuse from Lab 01)

In Terminal 1:

```bash
# Repeat the assume-role + Lambda escalation from Lab 01
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::${ACCOUNT_ID}:role/linchpin-vuln-role \
  --role-session-name lab2-attack \
  --query 'Credentials' --output json)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.SessionToken')

aws lambda invoke --function-name linchpin-lambda /tmp/output.txt
# Creates the backdoor user again
```

### 5b: Use the honeytoken

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# Use the honeytoken credentials
export AWS_ACCESS_KEY_ID=$(echo $HONEY_KEY | jq -r '.AccessKey.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $HONEY_KEY | jq -r '.AccessKey.SecretAccessKey')

aws sts get-caller-identity 2>&1
# AccessDenied — but triggers the SOC dashboard

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```

### 5c: Check the SOC dashboard (Terminal 2)

Within 1–5 minutes, you should see output like:

```
=== SOC ALERT [3 alerts] ===
  [MEDIUM] ASSUME_ROLE_NO_MFA: AssumeRole without MFA by arn:aws:iam::111111111111:role/linchpin-vuln-role
  [HIGH] LAMBDA_ADMIN_ROLE: Lambda created with admin role: arn:aws:iam::111111111111:role/linchpin-lambda-admin
  [CRITICAL] HONEYTOKEN_USED: Honeytoken key used for GetCallerIdentity from 198.51.100.10
```

## Step 6: Verification

```bash
# Check CloudWatch Logs for the detection Lambda
aws logs filter-log-events \
  --log-group-name /aws/lambda/soc-detector \
  --filter-pattern '"alert"' \
  --query 'events[].message' --output text | head -20

# Check EventBridge rule invocations
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -v-1H -u +%s)" --max-results 5

# Verify honeytoken key usage is logged
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$(echo $HONEY_KEY | jq -r '.AccessKey.AccessKeyId') \
  --max-results 5 --query 'Events[].EventTime' --output table
```

## Step 7: Teardown

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# Delete the SOC dashboard components
aws events remove-targets --rule soc-detection-rule --ids 1
aws events delete-rule --name soc-detection-rule
aws lambda delete-function --function-name soc-detector
aws iam delete-role-policy --role-name detection-lambda-role --policy-name sns-publish
aws iam detach-role-policy --role-name detection-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam delete-role --role-name detection-lambda-role

# Delete honeytoken user
HONEY_KEY_ID=$(echo $HONEY_KEY | jq -r '.AccessKey.AccessKeyId')
aws iam delete-access-key --user-name prod-deployment-admin --access-key-id "$HONEY_KEY_ID" 2>/dev/null
aws iam delete-user --user-name prod-deployment-admin 2>/dev/null

# Delete SNS topic
aws sns delete-topic --topic-arn arn:aws:sns:us-east-1:${ACCOUNT_ID}:security-alerts

# Delete linchpin resources (from Lab 01)
BACKDOOR_KEY=$(aws iam list-access-keys --user-name linchpin-backdoor --query 'AccessKeyMetadata[0].AccessKeyId' --output text 2>/dev/null)
if [ -n "$BACKDOOR_KEY" ] && [ "$BACKDOOR_KEY" != "None" ]; then
  aws iam delete-access-key --user-name linchpin-backdoor --access-key-id "$BACKDOOR_KEY"
fi
aws iam delete-user --user-name linchpin-backdoor 2>/dev/null
aws lambda delete-function --function-name linchpin-lambda 2>/dev/null
aws iam delete-role-policy --role-name linchpin-vuln-role --policy-name vuln-policy 2>/dev/null
aws iam delete-role --role-name linchpin-vuln-role 2>/dev/null
aws iam detach-role-policy --role-name linchpin-lambda-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null
aws iam delete-role --role-name linchpin-lambda-admin 2>/dev/null

# Clean temp files
rm -rf /tmp/detection-lambda /tmp/detection-lambda.zip /tmp/output.txt

echo "=== Verification: no resources remain ==="
aws iam list-users --query "Users[?contains(UserName,'linchpin') || contains(UserName,'prod-deployment')].UserName"
aws lambda list-functions --query "Functions[?contains(FunctionName,'linchpin') || contains(FunctionName,'soc-detector')].FunctionName"
aws events list-rules --query "Rules[?contains(Name,'soc')].Name"
# All should return empty lists
```

Press Ctrl+C in Terminal 2 to stop the webhook receiver.

## Lessons Learned

1. **Honeytokens work.** The `prod-deployment-admin` key is definitively malicious — no legitimate user or service ever uses it. Any CloudTrail event with that `AccessKeyId` is a critical alert.

2. **Real-time detection is achievable.** EventBridge → Lambda → webhook provides near-real-time alerting using only AWS-native services. This same pattern can be extended to Slack, PagerDuty, or a SIEM.

3. **The full chain IS detectable.** From `AssumeRole` (without MFA) to `CreateFunction` (with admin role) to `CreateAccessKey` (on a human user), every step emits a CloudTrail event with a distinct `eventName`.

4. **Correlation is the gap.** Each individual event can be benign (admins assume roles, CI creates functions). Correlating them in sequence from the same principal reveals the attack. This is where SIEM/SOAR adds value beyond individual alert rules.

## References

- [09-11-building-a-simple-apt.md](../building-a-simple-apt.md)
- [labs/linchpin-lab.md](./linchpin-lab.md)
- [AWS EventBridge Event Patterns](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html)
- [Canarytokens](https://canarytokens.org/)
- [AWS Honeytoken Strategy](https://docs.aws.amazon.com/security-hub/latest/userguide/securityhub-standards-fsbp-controls.html)
