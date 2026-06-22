# 07 — Log Redaction & Leakage Detection

> **Level:** Intermediate
> **Prereqs:** [05-05 — Env Vars vs Mounted Secrets](./env-vars-vs-mounted-secrets.md); ties with [06-* — Monitoring, Detection & SIEM](../Monitoring-Detection-SIEM/)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Collection
> **Authorization scope:** Run only against your own log streams in sandbox accounts.

## What & why

Logs are a secret sink equally dangerous as git history. Structured logging without scrubbing has shipped AWS secret keys to Datadog, database passwords to CloudWatch, and JWT tokens to ELK. Once a secret lands in a log aggregator, it is effectively public to anyone with log-read access — which is often every developer and every monitoring tool. Redaction at the log-emission point is the only reliable defense.

## The OnPrem reality

A sysadmin ran `grep -i password /var/log/syslog` and found every failed login attempt with the password typed into the username field. Application debug logs included full HTTP request bodies containing API keys. The centralized log server (Graylog, ELK) had weaker access controls than the production database. Nobody knew what was in the logs until the first PCI audit.

```bash
# OnPrem: finding secrets in logs (reactive, manual)
grep -RP '(password|secret|token|key)\s*[=:]\s*\S+' /var/log/ --include="*.log"

# Common places secrets appear in OnPrem logs:
# - /var/log/syslog (failed SSH with password in username field)
# - /var/log/apache2/error.log (env dump on 500 errors)
# - /var/log/mysql/error.log (connection strings with credentials)
# - Core dumps in /var/crash/
# - ~/.bash_history (accidentally typed password as command)
```

## Core concepts

```
Application emits log ──▶ Log framework (structured/unstructured)
                               │
                               ├── Redaction filter (drop/redact sensitive keys)
                               │
                               ▼
                         Log stream (CloudWatch / Azure Monitor / Cloud Logging)
                               │
                               ├── Subscription filter (pattern match)
                               │
                               ▼
                         Log aggregator (Datadog / Splunk / ELK)
                               │
                               └── ⚠️ Secret now in index — searchable by all log-readers
```

## Cross-cloud logging pipeline comparison

| Layer | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Log emission | CloudWatch Logs agent, Lambda `console.log` | Azure Monitor agent, App Insights SDK | Cloud Logging agent, structured logging | syslog, journald, Vector |
| Redaction (pre-write) | Lambda extension / log formatter | Azure Function proxy / App Insights telemetry initializer | Cloud Functions middleware / logging handler | Fluent Bit `Modify` filter / Vector `remap` |
| Stream filtering | CloudWatch Subscription Filter → Lambda | Diagnostic settings → Event Hub → Function | Logging sink → Pub/Sub → Dataflow | Fluentd `rewrite_tag_filter` |
| Secret detection (post-write) | CloudWatch Logs Insights pattern scan | Azure Sentinel KQL scan | Cloud Logging log metric + alert | Custom grep + cron |

## AWS

**Subscription Filter + Lambda redaction:**

```bash
# 1. Create a Lambda that scans log events for secret patterns
# 2. Attach it as a subscription filter on the log group

aws logs put-subscription-filter \
  --log-group-name "/aws/lambda/app-processor" \
  --filter-name "SecretRedactionFilter" \
  --filter-pattern "" \
  --destination-arn "arn:aws:lambda:us-east-1:111111111111:function:LogRedacter" \
  --region us-east-1
```

```python
# Lambda: LogRedacter — masks secrets before forwarding to aggregator
import base64, json, gzip, re, os

SECRET_PATTERNS = [
    (r'(aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[=:]\s*([A-Za-z0-9/+]{40})',
     r'\1=REDACTED'),
    (r'(AKIA[A-Z0-9]{16})', 'AKIAREDACTEDPLACEHOLDER'),
    (r'(Authorization:\s*Bearer\s+)([A-Za-z0-9\-._~+/]+=*)', r'\1REDACTED'),
    (r'(password[=:]\s*)([^\s,}]+)', r'\1REDACTED'),
]

def redact(text):
    for pattern, replacement in SECRET_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text

def handler(event, context):
    output = []
    for record in event['records']:
        data = json.loads(gzip.decompress(base64.b64decode(record['data'])))
        for log_event in data['logEvents']:
            log_event['message'] = redact(log_event['message'])
        output_record = {
            'recordId': record['recordId'],
            'result': 'Ok',
            'data': base64.b64encode(
                gzip.compress(json.dumps(data).encode())
            ).decode()
        }
        output.append(output_record)
    return {'records': output}
```

**CloudWatch Logs Insights — detect AWS secret key pattern in existing logs:**

```
fields @timestamp, @message
| filter @message like /AKIA[A-Z0-9]{16}/
| stats count() by @logStream, bin(1h)
```

## Azure

**Diagnostic settings + transformation KQL:**

```bash
# Azure Monitor diagnostic setting routes logs to Log Analytics workspace
az monitor diagnostic-settings create \
  --name security-logs \
  --resource "/subscriptions/.../resourceGroups/security-lab/providers/Microsoft.Web/sites/app-processor" \
  --workspace "/subscriptions/.../resourcegroups/security-lab/providers/microsoft.operationalinsights/workspaces/security-workspace" \
  --logs '[{"category":"AppServiceAppLogs","enabled":true}]'
```

```kql
// KQL query: detect potential Azure storage key patterns in app logs
AppServiceAppLogs
| where ResultDescription matches regex @"DefaultEndpointsProtocol=.*AccountKey="
| project TimeGenerated, OperationName, ResultDescription
```

**App Insights Telemetry Initializer (redaction at emission):**

```csharp
// C# — App Insights telemetry initializer that strips secrets
public class SecretRedactionInitializer : ITelemetryInitializer
{
    public void Initialize(ITelemetry telemetry)
    {
        if (telemetry is TraceTelemetry trace)
        {
            trace.Message = Regex.Replace(trace.Message,
                @"(AccountKey=)[A-Za-z0-9+/=]{88}",
                "$1REDACTED");
        }
    }
}
```

## GCP

**Logging sink + Dataflow redaction:**

```bash
# Create a Pub/Sub topic as sink destination
gcloud pubsub topics create log-redaction-topic

# Create sink routing specific log types to Pub/Sub
gcloud logging sinks create redaction-sink \
  pubsub.googleapis.com/projects/my-project/topics/log-redaction-topic \
  --log-filter 'resource.type="cloud_function" AND severity>=INFO'

# Dataflow job subscribes to Pub/Sub, redacts, writes to BigQuery
# (Dataflow job code — Python Apache Beam)

# Simplified Python redaction snippet (applicable in Cloud Functions too):
import re, logging
from google.cloud import logging as cloud_logging

class SecretFilter(logging.Filter):
    PATTERNS = [
        (r'(password|secret|token|key)\s*[=:]\s*[\S]+', r'\1=REDACTED'),
        (r'(AIza[0-9A-Za-z\-_]{35})', 'AIzaREDACTEDPLACEHOLDER000'),
    ]

    def filter(self, record):
        msg = record.getMessage()
        for pattern, repl in self.PATTERNS:
            msg = re.sub(pattern, repl, msg, flags=re.IGNORECASE)
        record.msg = msg
        return True

logger = logging.getLogger('app')
logger.addFilter(SecretFilter())
```

**GCP Log Explorer — detect GCP API key patterns:**

```
resource.type="cloud_function"
textPayload=~"AIza[0-9A-Za-z\\-_]{35}"
severity>=DEFAULT
```

## OnPrem

**Fluent Bit / Vector redaction filters:**

```ini
# fluent-bit.conf — Modify filter to redact secrets in log stream
[INPUT]
    Name  tail
    Path  /var/log/app/*.log

[FILTER]
    Name  modify
    Match *
    Condition Key_Value_Matches message ^.*password.*$
    Set    message LOG_REDACTED_BY_FILTER

[OUTPUT]
    Name  stdout
    Match *
```

```yaml
# Vector remap — more sophisticated redaction
# vector.toml
[sources.app_logs]
type = "file"
include = ["/var/log/app/*.log"]

[transforms.redact]
type = "remap"
inputs = ["app_logs"]
source = '''
  .message = replace!(.message, r'(password[=:]\s*)\S+', "$1REDACTED")
  .message = replace!(.message, r'AKIA[A-Z0-9]{16}', "AKIAREDACTED00000")
  .message = replace!(.message, r'AIza[0-9A-Za-z\-_]{35}', "AIzaREDACTED00000")
'''

[sinks.elasticsearch]
type = "elasticsearch"
inputs = ["redact"]
endpoint = "http://elastic.internal.example.com:9200"
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Log collection | Vector / Fluent Bit | CloudWatch agent | Azure Monitor agent | Cloud Logging agent |
| Pre-write redaction | Fluent Bit `Modify` filter | Lambda extension / log formatter | App Insights initializer | `logging.Filter` in Python |
| Stream filtering | Fluentd `rewrite_tag_filter` | Subscription Filter | Diagnostic settings | Logging sink |
| Pattern detection | grep / custom script | CloudWatch Logs Insights | Azure Sentinel KQL | Log Explorer |
| Pipeline redaction | Vector `remap` | Lambda in subscription | Event Hub + Function | Dataflow job |
| Machine data | Graylog / ELK | OpenSearch | Sentinel / Data Explorer | BigQuery |

## 🔴 Red Team view

**SSRF bombing makes the application log a full ID token, then read via an observed error endpoint.**

An attacker exploits an SSRF vulnerability to make the application fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS IMDS). The application's error handler logs the full HTTP response body, which contains temporary IAM credentials. The attacker then triggers the application's log-viewing endpoint (or waits for logs to ship to a less-secured aggregator) and extracts the credentials.

```javascript
// Vulnerable Express service (localhost lab only — NOT production code)
const express = require('express');
const axios = require('axios');
const app = express();

app.get('/fetch', async (req, res) => {
  try {
    const url = req.query.url;  // No validation — SSRF vector
    const response = await axios.get(url);
    res.send(response.data);
  } catch (err) {
    // DANGER: err object includes full response from SSRF target
    console.error(`Fetch failed: ${JSON.stringify(err)}`);
    // Logs: "Fetch failed: {config:{...}, response:{data:'{"AccessKeyId":"ASIA..."...', status:200}}”
    res.status(500).send('Error — check logs');
  }
});

app.listen(3001);
```

```bash
# Attacker triggers SSRF to IMDS:
curl "http://localhost:3001/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Server logs contain the full IMDS response including temporary creds
# Application logs are shipped to CloudWatch / Datadog — now searchable by anyone with log access
```

**Defensive pair — log scrubbing middleware:**

```javascript
// Middleware that redacts secrets from error objects before logging
app.use((err, req, res, next) => {
  const safe = { ...err };
  if (safe.response && safe.response.data) {
    safe.response.data = '[REDACTED_RESPONSE_BODY]';
  }
  if (safe.config && safe.config.headers) {
    safe.config.headers = '[REDACTED_HEADERS]';
  }
  console.error(JSON.stringify(safe));
  next(err);
});
```

**Artifacts left by exfil via logs:**
- CloudWatch Logs: `console.error` with IMDS credentials
- Log aggregator: indexed `AccessKeyId` entries from the app's log stream
- CloudTrail: `GetCallerIdentity` using the leaked temporary credentials (visible after the fact)

## 🔵 Blue Team view

**Pre-ship linter for IaC & infra logs:**

```yaml
# .gitleaks.toml — custom rules for log patterns
[[rules]]
id = "aws-secret-key-in-logs"
description = "AWS Secret Access Key in log output"
regex = '''(aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*([A-Za-z0-9\/+]{40})'''
tags = ["aws", "log"]

[[rules]]
id = "gcp-api-key"
description = "GCP API Key pattern"
regex = '''AIza[0-9A-Za-z\-_]{35}'''
tags = ["gcp", "log"]
```

**CloudWatch alert — secrets detected in trailing 5-minute window:**

```
fields @timestamp, @message, @logStream
| filter @message like /AKIA[A-Z0-9]{16}/
  or @message like /AIza[0-9A-Za-z\-_]{35}/
  or @message like /ghp_[A-Za-z0-9]{36}/
| stats count() by bin(5m)
| filter count > 0
```

```bash
# Create metric filter for secret pattern in CloudWatch
aws logs put-metric-filter \
  --log-group-name "/aws/lambda/app-processor" \
  --filter-name "SecretKeyInLogs" \
  --filter-pattern "AKIA" \
  --metric-transformations \
    "metricName=SecretKeyDetected,metricNamespace=Security/Secrets,metricValue=1"

# Alarm on any occurrence
aws cloudwatch put-metric-alarm \
  --alarm-name secret-key-in-logs \
  --metric-name SecretKeyDetected \
  --namespace Security/Secrets \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:111111111111:security-alerts
```

**Preventive controls:**
1. Standardize on a logging library that auto-redacts (e.g., `python-redactor`, `winston` with custom formatter)
2. Log `JSON.stringify` of objects at `DEBUG` only — never `ERROR` with full request/response bodies
3. IMDSv2 on all EC2 instances (requires session token, blocks unauthenticated SSRF)
4. CloudWatch subscription filter with Lambda redaction on ALL production log groups
5. Least-privilege log access: developers can read `INFO` but not `DEBUG`/`ERROR` log streams

## Hands-on lab

```bash
# 1. Write a Python log redaction module (python-redactor)
cat > /tmp/redact_test.py << 'PYEOF'
import re, logging, json

SENSITIVE_PATTERNS = {
    r'(aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[=:]\s*([A-Za-z0-9/+]{40})': r'\1=REDACTED',
    r'(AKIA[A-Z0-9]{16})': 'AKIAREDACTEDPLACEHOLDER',
    r'(AIza[0-9A-Za-z\-_]{35})': 'GCP_KEY_REDACTED',
    r'(password|passwd|pwd)[=:]\s*([^\s,}]+)': r'\1=REDACTED',
    r'(ghp_[A-Za-z0-9]{36})': 'GH_TOKEN_REDACTED',
}

class RedactFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        for pattern, repl in SENSITIVE_PATTERNS.items():
            msg = re.sub(pattern, repl, msg, flags=re.IGNORECASE)
        record.msg = msg
        return True

logger = logging.getLogger('test')
logger.addFilter(RedactFilter())
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Test: log statements that WOULD leak secrets
logger.info("DB connection: password=super-secret-123, user=admin")
logger.info("AWS key: AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
logger.info("GCP API key: AIzaSyDfakeKeyForIllustrationPurposesABCXYZ")
logger.info("GitHub token: ghp_fakeTokenThatWouldLeakFromLogfilesABC123")

print("--- Expected: all sensitive values replaced with REDACTED ---")
PYEOF
python3 /tmp/redact_test.py

# 2. CloudWatch Logs Insights quick scan (AWS sandbox)
# Paste into CloudWatch Logs Insights:
# fields @timestamp, @message
# | filter @message like /password\s*[=:]\s*\S+/
# | limit 20

# Teardown
rm /tmp/redact_test.py
```

## Detection rules & checklists

```yaml
# Sigma-style: secret patterns in cloud logs
title: Credential Pattern in Application Logs
logsource:
  service: cloudwatch_logs
detection:
  selection:
    - '@message|re': 'AKIA[A-Z0-9]{16}'
    - '@message|re': 'AIza[0-9A-Za-z\-_]{35}'
    - '@message|re': 'ghp_[A-Za-z0-9]{36}'
    - '@message|re': 'sk_live_[A-Za-z0-9]{24}'
    - '@message|re': '-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'
  condition: selection
  severity: critical
```

```bash
# CLI audit: check all Lambda log groups for subscription filters
aws logs describe-log-groups --region us-east-1 --query "logGroups[].logGroupName" --output text | \
  while read lg; do
    FILTERS=$(aws logs describe-subscription-filters --log-group-name "$lg" --region us-east-1 --query "subscriptionFilters")
    if [ "$FILTERS" = "[]" ]; then
      echo "MISSING REDACTION: $lg (no subscription filter)"
    fi
  done

# Azure: check Log Analytics workspaces for KQL alert rules containing secret patterns
az monitor scheduled-query list --resource-group security-lab -o table

# GCP: list logging sinks and verify redaction pipelines
gcloud logging sinks list
```

## References

- [AWS CloudWatch Logs Subscription Filters](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html)
- [Azure Monitor Logs data security](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-security)
- [GCP Cloud Logging sinks](https://cloud.google.com/logging/docs/export/configure_export_v2)
- [Fluent Bit Modify Filter](https://docs.fluentbit.io/manual/pipeline/filters/modify)
- [Vector Remap Language](https://vector.dev/docs/reference/vrl/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- Cross-link: [06-* — Monitoring, Detection & SIEM](../Monitoring-Detection-SIEM/)
