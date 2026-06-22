# Lab — Honey Token Lab

> **Module:** 10-04 Deception: Honeytokens
> **Approx. time:** 20 minutes
> **Cost:** Free tier (IAM user + access key + S3 bucket + CloudTrail metric filter — all free/negligible)
> **Authorization scope:** Run only in your own AWS sandbox account.

## Objective

Create a full honey-token pipeline:
1. Create a fake IAM user with a `Deny *` policy and an access key.
2. Plant the key in a sandbox git repo.
3. Run `gitleaks` to detect the planted key (validates that secret scanners find it).
4. Set up CloudTrail metric filter + CloudWatch alarm for any `AccessDenied` from the honey user.
5. Simulate an attacker using the key → verify alarm fires.
6. Teardown.

## Prerequisites

- AWS sandbox account with `iam:CreateUser`, `iam:CreateAccessKey`, `iam:PutUserPolicy`, `logs:PutMetricFilter`, `cloudwatch:PutMetricAlarm`, `sns:CreateTopic`.
- `git`, `gitleaks` (or `truffleHog`), `python3`, `jq` installed locally.
- AWS CLI configured.

## Step 1 — Create the honey user and key

```bash
aws iam create-user --user-name honey-devops-readonly

aws iam put-user-policy \
  --user-name honey-devops-readonly \
  --policy-name HoneyTokenDenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }'

aws iam create-access-key --user-name honey-devops-readonly | tee /tmp/honey-key.json

HONEY_KEY_ID=$(jq -r .AccessKey.AccessKeyId /tmp/honey-key.json)
HONEY_SECRET_KEY=$(jq -r .AccessKey.SecretAccessKey /tmp/honey-key.json)

echo "Honey key created: $HONEY_KEY_ID"
```

## Step 2 — Ensure CloudTrail is enabled (for metric filter)

```bash
aws cloudtrail describe-trails --query "trailList[?IsMultiRegionTrail==\`true\`].TrailARN" --output text

CLOUDTRAIL_LOG_GROUP=$(aws cloudtrail describe-trails \
  --query "trailList[0].CloudWatchLogsLogGroupArn" --output text)
```

If you don't have a CloudTrail trail with a CloudWatch Log Group, create one:

```bash
aws logs create-log-group --log-group-name CloudTrail/HoneyTokenLogs

aws cloudtrail create-trail \
  --name HoneyTokenTrail \
  --s3-bucket-name your-existing-cloudtrail-bucket \
  --is-multi-region-trail \
  --enable-log-file-validation

aws cloudtrail update-trail \
  --name HoneyTokenTrail \
  --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:$(aws sts get-caller-identity --query Account --output text):log-group:CloudTrail/HoneyTokenLogs:* \
  --cloud-watch-logs-role-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/CloudTrail_CloudWatchLogs_Role

aws cloudtrail start-logging --name HoneyTokenTrail
```

## Step 3 — Create CloudWatch metric filter for honey-token access

```bash
aws logs put-metric-filter \
  --log-group-name CloudTrail/HoneyTokenLogs \
  --filter-name HoneyTokenAccessDenied \
  --filter-pattern '{ ($.userIdentity.arn = "arn:aws:iam::'$(aws sts get-caller-identity --query Account --output text)':user/honey-devops-readonly") && ($.errorCode = "AccessDenied") }' \
  --metric-transformations \
    metricName=HoneyTokenTrigger,metricNamespace=HoneyTokens,metricValue=1
```

## Step 4 — Create SNS topic and CloudWatch alarm

```bash
SNS_TOPIC_ARN=$(aws sns create-topic --name HoneyTokenAlert --output text --query TopicArn)

aws sns subscribe \
  --topic-arn $SNS_TOPIC_ARN \
  --protocol email \
  --notification-endpoint security-alerts@example.com

aws cloudwatch put-metric-alarm \
  --alarm-name HoneyTokenUsed \
  --alarm-description "Honey token IAM user was accessed" \
  --metric-name HoneyTokenTrigger \
  --namespace HoneyTokens \
  --statistic Sum \
  --period 60 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions $SNS_TOPIC_ARN
```

## Step 5 — Plant the honey key in a sandbox git repo

```bash
mkdir /tmp/honey-repo && cd /tmp/honey-repo && git init

cat > config.json <<EOF
{
  "aws_access_key_id": "$HONEY_KEY_ID",
  "aws_secret_access_key": "$HONEY_SECRET_KEY",
  "region": "us-east-1"
}
EOF

git add config.json && git commit -m "Add AWS config"
echo "Honey key planted in /tmp/honey-repo/config.json"
```

## Step 6 — Run gitleaks to detect the planted key

```bash
gitleaks detect --source /tmp/honey-repo --no-git --verbose 2>&1 | tee /tmp/gitleaks-output.txt
```

**Expected output:** `gitleaks` should find the `AKIA*` pattern in `config.json` and report it as a credential leak.

This validates: your honey key would be caught by automated secret scanners if it were pushed to a real repo. The honey-token defense pipeline (scanner alert → SOC → investigate) mirrors this flow.

## Step 7 — Simulate an attacker using the honey key

```bash
export AWS_ACCESS_KEY_ID=$HONEY_KEY_ID
export AWS_SECRET_ACCESS_KEY=$HONEY_SECRET_KEY

aws sts get-caller-identity 2>&1
```

**Expected output:** `An error occurred (AccessDenied) when calling the GetCallerIdentity operation: ... denied`

Now wait ~60 seconds and check the CloudWatch alarm:

```bash
aws cloudwatch describe-alarms --alarm-names HoneyTokenUsed \
  --query "MetricAlarms[0].StateValue" --output text
```

**Expected output:** `ALARM`

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```

## Step 8 — Verify the metric data point

```bash
aws cloudwatch get-metric-statistics \
  --namespace HoneyTokens \
  --metric-name HoneyTokenTrigger \
  --start-time "$(date -u -v-5M +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 60 \
  --statistics Sum
```

**Expected output:** At least one data point with `Sum: 1` confirming the honey-token access was recorded.

## Step 9 — Local webhook alert (optional, Python)

```python
#!/usr/bin/env python3
# honey_listener.py — Run before the simulated attack
import http.server
import json

class HoneyHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = json.loads(self.rfile.read(content_length))
        print(f"HONEY TOKEN ALERT: {json.dumps(body, indent=2)}")
        self.send_response(200)
        self.end_headers()

server = http.server.HTTPServer(('localhost', 8888), HoneyHandler)
print("Honey token listener on http://localhost:8888")
server.serve_forever()
```

In a real deployment, the `SNS → Lambda → Slack/PagerDuty` chain replaces this local listener.

## Step 10 — Teardown

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

aws cloudwatch delete-alarms --alarm-names HoneyTokenUsed

aws logs delete-metric-filter \
  --log-group-name CloudTrail/HoneyTokenLogs \
  --filter-name HoneyTokenAccessDenied

aws sns unsubscribe --subscription-arn \
  $(aws sns list-subscriptions-by-topic --topic-arn $SNS_TOPIC_ARN \
    --query "Subscriptions[0].SubscriptionArn" --output text)

aws sns delete-topic --topic-arn $SNS_TOPIC_ARN

aws iam delete-access-key \
  --user-name honey-devops-readonly \
  --access-key-id $HONEY_KEY_ID

aws iam delete-user-policy \
  --user-name honey-devops-readonly \
  --policy-name HoneyTokenDenyAll

aws iam delete-user --user-name honey-devops-readonly

aws cloudtrail delete-trail --name HoneyTokenTrail 2>/dev/null
aws logs delete-log-group --log-group-name CloudTrail/HoneyTokenLogs 2>/dev/null

rm /tmp/honey-key.json /tmp/gitleaks-output.txt
rm -rf /tmp/honey-repo
```

## Expected output summary

| Step | Expected result |
|---|---|
| Create honey user + key | IAM user created with `Deny *` policy |
| `gitleaks` scan | Finds `AKIA*` in `config.json` — alerts on key leak |
| `aws sts get-caller-identity` with honey key | `AccessDenied` error |
| CloudWatch alarm state after 60s | `ALARM` |
| Metric data point | `Sum: 1` for `HoneyTokenTrigger` |

## Alert pipeline flowchart (what you just built)

```
Honey key planted in git repo
        │
        ▼
gitleaks/truffleHog detects leak ──► alert (CI pipeline or pre-commit hook)
        │
        ▼
Attacker finds key elsewhere (public repo, pastebin, CI log)
        │
        ▼
Attacker uses key: aws sts get-caller-identity
        │
        ▼
CloudTrail logs: GetCallerIdentity + AccessDenied + source IP/userAgent
        │
        ▼
CloudWatch Logs metric filter matches honey user ARN
        │
        ▼
CloudWatch Alarm: ALARM state
        │
        ▼
SNS → Lambda → Slack channel / PagerDuty
        │
        ▼
SOC acknowledges: investigate source IP, correlate with other events
```

## Cost note

- IAM user + access key: Free.
- CloudTrail trail: Free (management events). Additional cost if data events enabled.
- CloudWatch Logs: Ingestion cost for the AccessDenied event (~$0.50/GB ingested — negligible for single event).
- CloudWatch Alarm: $0.10/month per alarm.
- SNS: First 1,000 email notifications free per month.

## References
- [10-04 Deception: Honeytokens](../deception-honeytokens.md)
- [AWS CloudTrail metric filters](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-metric-filters.html)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [Canarytokens.org](https://canarytokens.org/)
