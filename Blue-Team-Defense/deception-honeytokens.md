# 04 — Deception: Honeytokens

> **Level:** Advanced
> **Prereqs:** [Pre Signed Urls & Tokenized Access](../Storage-Data-Security/pre-signed-urls-and-tokenized-access.md), [Cloudtrail Activity & Data Events](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md), [Native Threat Detection Guardduty Defender Scc](../Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Discovery, Collection
> **Authorization scope:** Deploy honeytokens only in your own sandbox accounts. Never plant honeytokens in production resources not under your direct administrative control.

## What & why

Honeytokens are fake credentials, resources, or data artifacts planted to detect unauthorized access. They are one of the highest signal-to-noise defenses available: no legitimate user should ever touch them. When touched, they produce certainty-of-breach alerts. They cost pennies and produce near-zero false positives.

## The OnPrem reality

On-prem honeypots included: fake AD user accounts with login monitoring, fake file shares (`\\server\Payroll`) with file-audit alerts, canary files on workstations monitored by tripwire, and fake database tables (`credit_cards_backup`) with SELECT triggers. The limitation: on-prem honeypots were heavy to deploy and maintain across thousands of endpoints. Cloud honeytokens are lightweight — create a fake key, a fake bucket, a fake DB row, set an alert, done.

## Cross-cloud comparison

| Provider | Honeytoken type | Creation method | Alert mechanism | Detection artifact |
|---|---|---|---|---|
| AWS | Fake IAM access key | `aws iam create-access-key` for honey user | CloudTrail `AccessDenied` when used → EventBridge → SNS | `GetCallerIdentity` from unusual IP/user-agent |
| AWS | Fake S3 bucket | `aws s3 mb s3://honey-finance-reports` + bucket policy deny | S3 access logs or CloudTrail data events | `GetObject` attempts on planted bucket |
| AWS | Fake EC2 key pair | EC2 key pair with honey name `backup-admin-key` | CloudTrail `ImportKeyPair` event | Unusual key import in security account |
| Azure | Honey Service Principal | `az ad sp create-for-rbac --name honey-sp` with no RBAC grants | Azure AD sign-in logs + Activity Log | `ServicePrincipalSignIn` from unknown IP |
| Azure | Fake Storage Account container | `az storage container create --name payroll-backup` | Storage analytics logs + Sentinel | `ListBlobs` / `GetBlob` from unusual principal |
| Azure | Fake Key Vault secret | `az keyvault secret set --name honey-master-key` | Key Vault diagnostics logs | `SecretGet` event from unapproved identity |
| GCP | Fake Service Account key | `gcloud iam service-accounts keys create` for honey SA | Cloud Audit Log `ServiceAccountKey*` | `GenerateAccessToken` from external IP |
| GCP | Fake GCS bucket | `gsutil mb gs://honey-customer-data` + IAM deny | Cloud Audit Log data access | `storage.objects.get` on honey bucket |
| GCP | Fake BigQuery table | Table `honey_credit_cards` with audit logging | BigQuery audit logs | `jobs.query` referencing honey table |
| OnPrem | Fake AD user + canary file | Created via `New-ADUser -Name honey_admin` | Windows Event ID 4624/4663 | Logon event from non-IT subnet |

## AWS

**Create a honey IAM user with disabled policy — any usage = compromise signal:**

```bash
aws iam create-user --user-name honey-devops-readonly

aws iam put-user-policy --user-name honey-devops-readonly \
  --policy-name HoneyTokenPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

aws iam create-access-key --user-name honey-devops-readonly
```

The key `AKIAIOSFODNN7EXAMPLE` is a known AWS documentation example key. An attacker finding this key in a git repo, pastebin, or leaked credential dump will try to use it. The `Deny *` policy ensures every call fails — but the `GetCallerIdentity` event fires in CloudTrail, triggering the alert.

**CloudTrail metric filter for honey-token usage:**

```bash
aws logs put-metric-filter \
  --log-group-name CloudTrail/HoneyTokenLogs \
  --filter-name HoneyTokenAccessDenied \
  --filter-pattern '{ ($.userIdentity.arn = "arn:aws:iam::111111111111:user/honey-devops-readonly") && ($.errorCode = "AccessDenied") }' \
  --metric-transformations \
    metricName=HoneyTokenTrigger,metricNamespace=HoneyTokens,metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name HoneyTokenUsed \
  --metric-name HoneyTokenTrigger \
  --namespace HoneyTokens \
  --statistic Sum \
  --period 60 \
  --threshold 1 \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:111111111111:SecOpsAlert
```

**EventBridge rule — honey-token alert:**

```json
{
  "source": ["aws.sts"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "userIdentity": {"arn": [{"prefix": "arn:aws:iam::111111111111:user/honey"}]}
  }
}
```

Target: Lambda → Slack/PagerDuty webhook.

**Honey S3 bucket — bait for data discovery:**

```bash
aws s3 mb s3://honey-customer-db-backup-2026
aws s3api put-bucket-policy --bucket honey-customer-db-backup-2026 --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::honey-customer-db-backup-2026", "arn:aws:s3:::honey-customer-db-backup-2026/*"],
    "Condition": {"StringNotEquals": {"aws:PrincipalArn": "arn:aws:iam::111111111111:role/BreakGlassRole"}}
  }]
}'

aws s3api put-bucket-notification-configuration --bucket honey-customer-db-backup-2026 \
  --notification-configuration '{
    "LambdaFunctionConfigurations": [{
      "LambdaFunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:HoneyTokenAlert",
      "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
    }]
  }'
```

## Azure

**Honey Service Principal with no permissions:**

```bash
az ad sp create-for-rbac \
  --name honey-ml-engineer \
  --years 1

az ad sp update --id 00000000-0000-0000-0000-000000000000 \
  --set appRoleAssignmentRequired=true
```

**Sentinel alert rule — honey SP sign-in:**

```kusto
SigninLogs
| where AppId == "00000000-0000-0000-0000-000000000000"
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress, UserAgent, ResultDescription
```

**Honey Key Vault secret:**

```bash
az keyvault create --name honey-vault-001 --resource-group rg-honey
az keyvault secret set --vault-name honey-vault-001 \
  --name "prod-db-connection-string" \
  --value "Server=fake-prod-db.example.com;User Id=admin;Password=FAKE_HONEY_PASSWORD_123!"

az monitor diagnostic-settings create \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-honey/providers/Microsoft.KeyVault/vaults/honey-vault-001 \
  --name honey-vault-diag \
  --workspace /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-security/providers/Microsoft.OperationalInsights/workspaces/sentinel-workspace \
  --logs '[{"category": "AuditEvent", "enabled": true}]'
```

## GCP

**Honey Service Account with no IAM bindings:**

```bash
gcloud iam service-accounts create honey-data-analyst \
  --display-name "Honey Data Analyst"

gcloud iam service-accounts keys create honey-key.json \
  --iam-account honey-data-analyst@project-id-111111.iam.gserviceaccount.com

gcloud iam service-accounts add-iam-policy-binding \
  honey-data-analyst@project-id-111111.iam.gserviceaccount.com \
  --member "allAuthenticatedUsers" \
  --role roles/iam.serviceAccountTokenCreator \
  --condition='expression=request.time < timestamp("2000-01-01T00:00:00Z"),title=expired' \
  --condition-from-file condition.yaml
```

**Cloud Audit Log alert — honey SA activity:**

```bash
gcloud logging sinks create honey-token-alerts \
  pubsub.googleapis.com/projects/project-id-111111/topics/honey-alerts \
  --log-filter='protoPayload.authenticationInfo.principalEmail:"honey-data-analyst"'
```

**Honey GCS bucket:**

```bash
gsutil mb -p project-id-111111 -l us-east1 gs://honey-credit-card-exports

gsutil iam ch -d allUsers gs://honey-credit-card-exports
gsutil iam ch -d allAuthenticatedUsers gs://honey-credit-card-exports

gsutil logging set/gcs enable \
  -b gs://log-archive-bucket \
  -o honey-bucket-access gs://honey-credit-card-exports
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Honey identity | AD user with logon audit | IAM user with Deny * policy + dead key | Service Principal with no RBAC grants | SA with no IAM bindings + dead key |
| Honey storage | Canary file on file share | S3 bucket with bucket-policy deny | Storage Account container with no RBAC | GCS bucket with no IAM grants |
| Honey secret | Fake password in password vault | Fake IAM access key in git/CI | Fake Key Vault secret | Fake SA key JSON in repo |
| Alert mechanism | Event ID 4624/4663 + SIEM query | CloudTrail + EventBridge/Lambda → SNS | Sentinel scheduling rule + Logic App | Log sink + Pub/Sub → Cloud Function |
| Canary service | thinkst Canary on-prem appliance | Native CloudTrail + canarytokens.org | canarytokens.org webhook | canarytokens.org webhook |

## 🔴 Red Team view

**How attackers probe and attempt to bypass honeytokens.**

**Narrative (contained):**

An attacker finds a GitHub repo with an AWS access key. Before using it, they test with a lightweight call:

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws sts get-caller-identity 2>&1
```

Result: `AccessDenied`. The attacker now knows:
1. The key is valid (not expired/deleted) — IAM recognized it but denied the action.
2. The key belongs to a dead/disabled user or has a Deny policy — it's likely a honeytoken.

The attacker abandons the key. **But the signal has already been produced.** The `GetCallerIdentity` event fires in CloudTrail before the deny — the metadata (source IP, user-agent, timestamp) is captured.

**Evasion technique — error-code oracle:** An attacker with a large dump of keys may test each key once, checking error codes. `AccessDenied` from `GetCallerIdentity` (user exists, denied) vs `InvalidClientTokenId` (key doesn't exist) — the attacker can triage honeytokens by error type and skip the "exists but denied" keys without further calls.

**Artifacts:**
- CloudTrail: `GetCallerIdentity` event with `errorCode: AccessDenied` from source IP `198.51.100.10`.
- No `GetSessionToken` or `AssumeRole` events from the same key — it was probed once, then abandoned.
- GitHub/Pastebin: the key string appears in public code search results.

## 🔵 Blue Team view

**Honeydash — monitor all honey-token usage:**

```bash
# AWS Lambda — HoneyTokenAlert function (Python)
def lambda_handler(event, context):
    detail = event['detail']
    user = detail.get('userIdentity', {}).get('arn', 'unknown')
    ip = detail.get('sourceIPAddress', 'unknown')
    ua = detail.get('userAgent', 'unknown')
    event_name = detail.get('eventName', 'unknown')

    alert = {
        "text": f"HONEY TOKEN TOUCHED:\nUser: {user}\nAction: {event_name}\nIP: {ip}\nUA: {ua}"
    }

    import json, urllib.request
    req = urllib.request.Request(
        "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
        data=json.dumps(alert).encode(),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req)
```

**CloudTrail Lake query — find all honey-token accesses:**

```
SELECT eventTime, eventName, sourceIPAddress, userAgent, errorCode, errorMessage
FROM "111111111111"."cloudtrail_111111111111"
WHERE userIdentity.arn LIKE '%honey-%'
  AND eventTime > now() - interval '30' day
ORDER BY eventTime DESC
```

**False-positive control:** Legitimate CI/CD scanners (e.g., `truffleHog`, `gitleaks`) may test discovered keys. Allow-list known scanner IPs and user-agents in the alert rule:

```json
{
  "detail": {
    "sourceIPAddress": [{"anything-but": ["10.0.1.50", "10.0.1.51"]}],
    "userAgent": [{"anything-but": [{"prefix": "truffleHog/"}, {"prefix": "gitleaks/"}]}]
  }
}
```

**Response runbook — honey-token alert:**
1. Identify the source IP and user-agent from the alert.
2. Check if the IP corresponds to an internal CI/CD scanner (allow-list check).
3. If external/unexpected: page on-call security engineer.
4. Correlate the source IP with other CloudTrail events in the same time window.
5. If the honey token was found in a public repo: initiate key rotation for all non-honey keys in the affected repo.
6. Block the source IP in WAF/NSG/NGFW.

Cross-link: [06-05 Native Threat Detection](../Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md), [06-02 CloudTrail Activity Events](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md), [04-07 Storage Data Security](../Storage-Data-Security/07-*-data-security.md).

## Hands-on lab

See [`labs/honey-token-lab.md`](labs/honey-token-lab.md).

## Detection rules & checklists

**Cloud Custodian — audit that honey users exist and are monitored:**

```yaml
policies:
  - name: honey-user-monitors
    resource: log-group
    filters:
      - type: value
        key: retentionInDays
        value: 3653
      - type: metric-filter
        key: filterName
        value: HoneyTokenAccessDenied
```

**Checklist:**
- [ ] At least 3 honey IAM users with `Deny *` policies deployed per account.
- [ ] Honey keys are planted in internal git repos, CI logs, and shared wikis.
- [ ] Each honey token has a CloudWatch Metric Filter or EventBridge rule.
- [ ] Honey-token alert is wired to PagerDuty with a 5-minute response SLO.
- [ ] Monthly honey-token drill: SOC member touches a honey token intentionally to validate the alert pipeline.
- [ ] All honey-token resources are tagged `Purpose=HoneyToken` and excluded from auto-remediation (don't auto-delete unused keys).

## References
- [Canarytokens.org](https://canarytokens.org/) — free cross-cloud honeytoken generator
- [AWS — CloudTrail metric filters](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-metric-filters.html)
- [Azure Sentinel — scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)
- [GCP Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [MITRE ATT&CK — Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006/)
