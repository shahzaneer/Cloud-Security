# 07 — Access Reviews & Certification

> **Level:** Intermediate
> **Prereqs:** [IAM](../IAM), [Compliance Audit Gov](.)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Persistence, Privilege Escalation, Credential Access
> **Authorization scope:** Access review scripts must be run in your own sandbox accounts and organizations. All user/principal names are placeholders.

## What & why

Quarterly access reviews are both an audited artifact (SOC 2 CC6.1–CC6.3, ISO 27001 A.9.2.5, PCI DSS 7.1.2) and an actual defense against standing privilege accumulation. The goal: pull the list of every human identity with elevated access, present it to their manager, get an attestation (or revocation), and archive the evidence. Without mechanization, this is the task that eats a senior engineer for two weeks every quarter. With automation, it's a scheduled script + JIRA workflow + auto-revoke.

## The OnPrem reality

Access reviews were a CSV dump from Active Directory (`Get-ADUser -Filter * | Export-Csv`), emailed to department heads with a "please reply by Friday" subject line. Managers ignored it. Revoked access was delayed because the helpdesk ticket for account disablement had a 5-day SLA. Dormant accounts accumulated for years.

## Access review lifecycle

```
Pull effective
permissions
     │
     ▼
Filter human users
with elevated access
     │
     ▼
Generate review
package (CSV/HTML)
     │
     ▼
Manager attestation
(approve/revoke)
     │
     ▼
Auto-revoke
unattested access
after 14 days
     │
     ▼
Archive evidence
to immutable bucket
```

## Cross-cloud access review tooling

| Capability | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| **Identity inventory** | `Get-ADUser`, LDAP query | IAM Access Analyzer, `aws iam list-users` | Microsoft Graph, `az ad user list` | Cloud Identity API, `gcloud identity` |
| **Effective permissions** | ADUC Effective Permissions tab | Access Analyzer policy generation, `simulate-principal-policy` | Entra ID access reviews (P2), PIM eligible assignments | IAM Recommender, `gcloud asset analyze-iam-policy` |
| **Last-used access** | AD lastLogonTimestamp | Access Advisor (service last accessed), Access Key last-used | Sign-in logs (last interactive + non-interactive) | IAM Recommender role insights |
| **Dormant identity detection** | `Search-ADAccount -AccountInactive -TimeSpan 90` | IAM credential report + Access Advisor | Entra ID access review "inactive users" | Recommender `hasNotUsedPermissionsIn` |
| **Automated revocation** | PowerShell `Disable-ADAccount` | Lambda → `iam:DeleteAccessKey`, `iam:DetachUserPolicy` | Logic App → remove role assignment | Cloud Function → `gcloud projects remove-iam-policy-binding` |
| **Evidence export** | CSV + email | Audit Manager + S3 | Graph API → JSON → immutable blob | Asset Inventory → BigQuery → GCS locked bucket |

## AWS — access review automation

### Pull humans with admin-equivalent roles

```bash
# Get users with AdministratorAccess or PowerUserAccess
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d > cred_report.csv

# List users with policies granting admin-equivalent access
aws iam list-entities-for-policy \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --entity-filter User \
  --query "PolicyUsers[*].UserName"

# Check access key last used
aws iam get-access-key-last-used --access-key-id AKIAIOSFODNN7EXAMPLE

# List users whose access keys haven't been rotated in >90 days
aws iam get-account-authorization-details \
  --filter User \
  --query "UserDetailList[?UserPolicyList[?PolicyName=='AdministratorAccess']].{User:UserName, Keys:AccessKeyMetadata[?CreateDate<'$(date -v-90d +%Y-%m-%d)']}"
```

### Python script — evidence pack generator for access review

```python
import boto3, csv, json, datetime

iam = boto3.client("iam")
today = datetime.datetime.utcnow()

report = []
cred_report = iam.get_credential_report()["Content"].decode("utf-8")
reader = csv.DictReader(cred_report.split("\n"))

for row in reader:
    if row["user"] == "<root_account>":
        continue
    key1_last = row.get("access_key_1_last_used_date", "N/A")
    key2_last = row.get("access_key_2_last_used_date", "N/A")

    # Flag dormant: no key used in 60+ days
    dormant = True
    for last in [key1_last, key2_last]:
        if last != "N/A" and last != "no_information":
            try:
                last_date = datetime.datetime.strptime(last, "%Y-%m-%dT%H:%M:%S+00:00")
                if (today - last_date).days < 60:
                    dormant = False
            except ValueError:
                pass

    report.append({
        "user": row["user"],
        "arn": row["arn"],
        "password_enabled": row["password_enabled"],
        "mfa_active": row["mfa_active"],
        "access_key_1_active": row["access_key_1_active"],
        "access_key_1_last_used": key1_last,
        "access_key_2_active": row["access_key_2_active"],
        "access_key_2_last_used": key2_last,
        "dormant": dormant,
        "review_period": "2026-Q2",
        "generated_at": today.isoformat() + "Z"
    })

# Write evidence pack
with open(f"access-review-2026-Q2-{today.strftime('%Y%m%d')}.json", "w") as f:
    json.dump(report, f, indent=2)

# Upload to evidence bucket
s3 = boto3.client("s3")
s3.put_object(
    Bucket="compliance-evidence-111111111111-us-east-1",
    Key=f"2026-Q2/access-review-{today.strftime('%Y%m%d')}.json",
    Body=json.dumps(report, indent=2, default=str)
)
```

### Access Advisor — which services each user actually uses

```bash
aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::111111111111:user/alice

aws iam get-service-last-accessed-details \
  --job-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
  --query "ServicesLastAccessed[].{Service:ServiceName, LastAccessed:LastAuthenticated}"
```

## Azure — access reviews (Entra ID P2 required)

### Pull eligible privileged role assignments

```bash
az role assignment list --include-classic-administrators \
  --query "[?principalType=='User'].{principalName:principalName, role:roleDefinitionName, scope:scope}" -o table

# Entra ID PIM — list eligible assignments
az rest --method get \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?api-version=2024-03-31-preview"

# Access reviews setup (Entra ID P2)
az rest --method post \
  --uri "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions" \
  --body '{
    "displayName": "Quarterly Admin Access Review",
    "scope": {
      "query": "/v1.0/roleManagement/directory/roleDefinitions?$filter=isPrivileged eq true",
      "type": "directoryRoles"
    },
    "reviewers": [{"query": "/v1.0/users/manager", "type": "manager"}],
    "settings": {
      "mailNotificationsEnabled": true,
      "reminderNotificationsEnabled": true,
      "justificationRequiredOnApproval": true,
      "recurrence": {"range": {"type": "numbered", "numberOfOccurrences": 0, "startDate": "2026-07-01"}, "pattern": {"type": "absoluteMonthly", "interval": 3}},
      "autoApplyDecisionsEnabled": true
    }
  }'
```

### Graph API — list users with privileged roles and sign-in activity

```kql
// KQL via Log Analytics — privileged role assignments
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].type == "User"
| extend user = TargetResources[0].userPrincipalName
| project TimeGenerated, user, ActivityDisplayName

// List users who haven't signed in for >60 days with privileged roles
SigninLogs
| where TimeGenerated > ago(90d)
| summarize LastSignIn = max(TimeGenerated) by UserPrincipalName
| where LastSignIn < ago(60d)
| project UserPrincipalName, LastSignIn, DormantDays = datetime_diff('day', now(), LastSignIn)
```

### Evidence export

```bash
az role assignment list --all \
  --include-inherited \
  --query "[?principalType=='User'].{user:principalName, role:roleDefinitionName, scope:scope}" \
  --output json > azure-role-assignments-2026-Q2.json

az storage blob upload \
  --container-name evidence-2026-q2 \
  --file azure-role-assignments-2026-Q2.json \
  --name access-review/azure-role-assignments-2026-Q2.json \
  --account-name complianceevidencellllllll
```

## GCP — access review automation

### IAM Recommender — idle role removal

```bash
# List role recommendations (permissions not used in 90 days)
gcloud recommender recommendations list \
  --project=production-project \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --format="table(recommendation.content.operationGroups[].operations[])"

# Analyze IAM policy for a project
gcloud asset analyze-iam-policy \
  --organization=000000000000 \
  --full-resource-name="//cloudresourcemanager.googleapis.com/projects/production-project" \
  --format="json" > iam-analysis.json
```

### Identify human users with elevated roles

```bash
gcloud projects get-iam-policy production-project \
  --format="table(bindings.role, bindings.members)" \
  | grep -E "user:|roles/owner|roles/editor|roles/iam.securityAdmin"

# List service account keys older than 90 days
gcloud iam service-accounts keys list \
  --iam-account=sa-name@production-project.iam.gserviceaccount.com \
  --managed-by=user \
  --format="table(name, validAfterTime)"
```

### Service account key rotation check

```bash
gcloud iam service-accounts keys list \
  --iam-account="svc-terraform@production-project.iam.gserviceaccount.com" \
  --managed-by="user" \
  --format="json" | jq '.[] | select(.validAfterTime < "2026-03-22T00:00:00Z")'
```

## OnPrem — AD access review

```bash
# Dump AD users with admin-equivalent group membership
Get-ADGroupMember -Identity "Domain Admins" | Export-Csv domain-admins.csv
Get-ADGroupMember -Identity "Enterprise Admins" | Export-Csv enterprise-admins.csv
Get-ADGroupMember -Identity "Schema Admins" | Export-Csv schema-admins.csv

# List inactive accounts (>90 days)
Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly | Export-Csv inactive-users.csv
```

## 🔴 Red Team view — dormant identity takeover

**Attack vector:** A dormant IAM user with `AdministratorAccess` and an access key that hasn't been rotated in 2 years. The user belongs to a former employee who still has an active account because the offboarding ticket was closed without verifying access key deletion. An attacker phishes the former employee's personal email and recovers the AWS access key from a personal laptop backup.

**Contained exploitation:**

```bash
# Step 1: Attacker discovers the dormant key via credential dump or phishing
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Step 2: Verify access still works (Access Advisor would show this service accessed)
aws sts get-caller-identity
# { "Arn": "arn:aws:iam::111111111111:user/former-employee", "Account": "111111111111" }

# Step 3: Attacker creates a new access key for persistence
aws iam create-access-key --user-name former-employee
# Now has two key pairs — the original + new attacker's key

# Step 4: Lateral movement — assume privileged roles
aws sts assume-role \
  --role-arn arn:aws:iam::222222222222:role/ProductionAdmin \
  --role-session-name legit-session

# The dormant identity allows silent takeover because:
#   - No MFA on the user
#   - Key not rotated >90 days
#   - No recent login — manager flagged it "still needed" in last review without checking
```

**Artifacts left:**
- CloudTrail `CreateAccessKey` for a user with `access_key_1_last_used` > 90d ago
- `AssumeRole` from a user whose `password_last_used` is "no_information"
- IAM credential report now shows 2 active keys for the user
- Access Advisor shows new service access patterns for previously dormant user

## 🔵 Blue Team view — mechanized quarterly access review

### IaC for auto-revocation of unattested access

```python
# Lambda scheduled quarterly: revoke access not attested within 14 days
import boto3, json, datetime

iam = boto3.client("iam")
s3 = boto3.client("s3")
sns = boto3.client("sns")

REVIEW_BUCKET = "compliance-evidence-111111111111-us-east-1"
ATTESTATION_KEY = "2026-Q2/access-review/attestations.json"

def lambda_handler(event, context):
    # Load attestation results
    resp = s3.get_object(Bucket=REVIEW_BUCKET, Key=ATTESTATION_KEY)
    attestations = json.loads(resp["Body"].read())

    # Find users not attested within 14 days of review window
    cutoff = datetime.datetime(2026, 4, 14)

    for user_arn, attest in attestations.items():
        if not attest.get("approved") and attest.get("reminder_count", 0) >= 2:
            username = user_arn.split("/")[-1]

            # Revoke: delete access keys, detach admin policies
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                iam.delete_access_key(UserName=username, AccessKeyId=key["AccessKeyId"])

            iam.put_user_policy(
                UserName=username,
                PolicyName="AccessRevoked-ReviewOverdue",
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
                })
            )

            sns.publish(
                TopicArn="arn:aws:sns:us-east-1:111111111111:access-review-alerts",
                Subject=f"Access Revoked: {username}",
                Message=f"Access revoked for {username} — quarterly review not attested by {cutoff}."
            )
```

### Detection — dormant identity suddenly active

```yaml
title: Dormant IAM Identity Suddenly Active
id: u9v0w1x2-3000-4000-8000-y3z4a5b6c7d8
status: experimental
description: An IAM principal with no recent activity suddenly performs actions
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.type: IAMUser
  condition: selection and lastActivity > 60d ago
level: high
```

**CloudWatch Logs Insights — dormant user activity:**

```sql
fields @timestamp, userIdentity.arn, eventName, sourceIPAddress
| filter userIdentity.type = "IAMUser"
| sort @timestamp desc
-- Pair with credential report data for last-used timestamps
```

**Azure Sentinel — dormant privileged sign-in:**

```kql
let dormant_users = (
    SigninLogs
    | summarize LastSignIn = max(TimeGenerated) by UserPrincipalName
    | where LastSignIn < ago(60d)
);
SigninLogs
| where UserPrincipalName in (dormant_users)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType
```

### Orphan key auto-detect

```python
# Detect IAM user access keys not rotated in >90 days
import boto3, csv, datetime

iam = boto3.client("iam")
report = iam.get_credential_report()["Content"].decode("utf-8")
reader = csv.DictReader(report.split("\n"))

threshold = datetime.datetime.utcnow() - datetime.timedelta(days=90)
orphaned = []

for row in reader:
    for key_num in ["1", "2"]:
        key_active = row[f"access_key_{key_num}_active"]
        last_rotated = row[f"access_key_{key_num}_last_rotated"]
        if key_active == "true" and last_rotated:
            if datetime.datetime.fromisoformat(last_rotated) < threshold:
                orphaned.append({
                    "user": row["user"],
                    "key": f"access_key_{key_num}",
                    "last_rotated": last_rotated
                })

print(json.dumps(orphaned, indent=2))
```

## Hands-on lab — access review evidence pack

**Duration:** 20 min. **Cost:** Free-tier IAM + S3.

```bash
# AWS: Generate credential report and filter for admin users
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --query Content --output text | base64 -d > cred_report.csv

# Find users with password enabled but no MFA
cat cred_report.csv | grep "true" | grep "false" # (password_enabled=true, mfa_active=false)

# Azure: List users with Owner role
az role assignment list --include-classic-administrators \
  --query "[?contains(roleDefinitionName, 'Owner')].principalName" -o table

# GCP: List IAM recommendations
gcloud recommender recommendations list \
  --project="$PROJECT_ID" \
  --recommender=google.iam.policy.Recommender \
  --location=global
```

## Detection rules & checklists

**Access review quarterly checklist:**

- [ ] Credential report / identity inventory pulled for all accounts/projects.
- [ ] Human users with admin-equivalent roles identified.
- [ ] Users with unrotated keys > 90 days flagged.
- [ ] Dormant identities (no sign-in/key-use > 60 days) flagged.
- [ ] Review sent to managers with 14-day response window.
- [ ] Unattested access auto-revoked after 14 days + 2 reminders.
- [ ] Evidence archive (credential report + attestations) written to immutable bucket.
- [ ] Service accounts reviewed separately (different lifecycle).
- [ ] Break-glass accounts verified (excluded from auto-revoke, documented).

**Sigma rule — review-attested identity suddenly grants new permission:**

```yaml
title: Access Review-Certified User Creates New Privileged Access
id: e9f0a1b2-4000-4000-8000-c3d4e5f6a7b8
status: experimental
description: User whose access was recently attested grants themselves new elevated permissions
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName:
      - AttachUserPolicy
      - AttachRolePolicy
      - CreateAccessKey
    requestParameters.policyArn|contains: AdministratorAccess
  condition: selection
level: high
```

## References

- [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [Azure Entra ID Access Reviews](https://learn.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview)
- [GCP IAM Recommender](https://cloud.google.com/recommender/docs/recommenders)
- [AWS Access Advisor](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html)
- MITRE ATT&CK: T1078 Valid Accounts, T1098 Account Manipulation, T1136 Create Account
- Cross-links: [../IAM/permission-boundaries-and-scps.md](../IAM/permission-boundaries-and-scps.md), [../Blue-Team-Defense/continuous-hardening-baselines.md](../Blue-Team-Defense/continuous-hardening-baselines.md)
