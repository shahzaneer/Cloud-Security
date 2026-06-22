# 03 — Assume-Role Chains & Trust Graphs

> **Level:** Advanced
> **Prereqs:** [Identity Primitives per Cloud](identity-primitives-per-cloud.md) (Identity Primitives), [Authn Flows & Tokens](authn-flows-and-tokens.md) (AuthN Flows & Tokens)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Lateral Movement, Privilege Escalation
> **Authorization scope:** Identity attacks only in your own sandbox accounts / sanctioned targets.

## What & why

An assume-role chain is a privilege graph: identity A can become identity B, which can become identity C. Each hop may add or subtract permissions. Cross-account chains expand blast radius beyond a single AWS account boundary, and chained escalation paths (A→B→C→admin) are the cloud privilege escalation path.

## The OnPrem reality

Unconstrained Kerberos delegation: a front-end web server (IIS) configured with "Trust this computer for delegation to any service" could impersonate any user to any backend service. An attacker who compromised that server possessed the TGTs of every user who authenticated through it — a single-hop privilege graph to domain admin. Constrained delegation (Windows 2012+) limits which backend services a principal can delegate to, analogous to an AWS trust policy's `Principal` and `Condition` blocks.

## Core concepts

| Concept | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Trust primitive | IAM Role trust policy (`sts:AssumeRole`) | RBAC with `Microsoft.Authorization/roleAssignments` + Managed Identity delegation | SA impersonation via `roles/iam.serviceAccountTokenCreator` | Constrained Delegation (S4U2Self/S4U2Proxy) |
| Anti-confused-deputy | `sts:ExternalId` | Cross-tenant app consent prompts | GCP Workload Identity Federation `attribute.condition` | SPN lockdown + selective auth |
| Chain depth limit | 12h max session across all hops | No hard depth limit; token serialization depth | 1h per impersonation chain, 12h max | Delegation hops limited by forest trust |
| Graph enumeration | `ListRoles` + `AssumeRole` trust doc loop | `az role assignment list` + cross-tenant app search | `gcloud iam service-accounts get-iam-policy` | BloodHound AD graph |
| Trust condition | `aws:PrincipalArn`, `aws:SourceArn` | `condition` field in role assignment | IAM Conditions on impersonation binding | `AllowedToDelegateTo` SPN list |

### How chains work (AWS model)

```
Account-A (111111111111)          Account-B (222222222222)          Account-C (333333333333)
┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│ Role: AuditorRO      │───▶│ Role: AuditorRW      │───▶│ Role: AuditorAdmin    │
│ Trust: user bob      │    │ Trust: 111111111111: │    │ Trust: 222222222222:  │
│                      │    │   role/AuditorRO     │    │   role/AuditorRW      │
│ Policies: ReadOnly   │    │ Policies: Read+Write │    │ Policies: Admin       │
└──────────────────────┘    └──────────────────────┘    └──────────────────────┘
```

Each arrow requires: (a) the source role/user has `sts:AssumeRole` permission for the target role's ARN, and (b) the target role's trust policy allows the source principal. Breaking either link breaks the chain.

## AWS

**Build a 3-account chain:**

```bash
# In Account A (111111111111): bob assumes AuditorRO
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/AuditorRO \
  --role-session-name ChainHop1

# Export the temporary creds from the output, then:
# At hop 1, AuditorRO (A) assumes AuditorRW (B)
aws sts assume-role \
  --role-arn arn:aws:iam::222222222222:role/AuditorRW \
  --role-session-name ChainHop2 \
  --external-id "cross-account-audit-22222"

# At hop 2, AuditorRW (B) assumes AuditorAdmin (C)
aws sts assume-role \
  --role-arn arn:aws:iam::333333333333:role/AuditorAdmin \
  --role-session-name ChainHop3 \
  --external-id "cross-account-audit-33333"

# Verify final identity
aws sts get-caller-identity
```

**Trust policies for each role:**

```json
// Role AuditorRW in Account 222222222222 — trust policy
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::111111111111:role/AuditorRO"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {"sts:ExternalId": "cross-account-audit-22222"}
    }
  }]
}
```

**Visualizing the trust graph — conceptual CLI script:**

```bash
#!/bin/bash
ACCOUNTS=$(aws organizations list-accounts --query "Accounts[].Id" --output text)

for account in $ACCOUNTS; do
  # Assume org-reader role into each account (or use delegated admin)
  ROLES=$(aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[].Principal.AWS].RoleName" --output text)
  for role in $ROLES; do
    TRUSTED=$(aws iam get-role --role-name "$role" \
      --query "Role.AssumeRolePolicyDocument.Statement[].Principal.AWS" --output text)
    echo "$account/$role <-- $TRUSTED"
  done
done
```

**Gotcha:** `MaxSessionDuration` on each intermediate role compounds. If Role A allows 43200s (12h), Role B allows 3600s (1h), the session for Role B times out after 1h — the chain breaks.

## Azure

Azure doesn't use the "assume role" terminology. Instead, it chains through RBAC role assignments on Managed Identities and cross-tenant app registrations.

**Managed Identity chain (same tenant):**

MI-Reader on VM-A is granted `Owner` on Subscription-B. An attacker on VM-A can create a new Managed Identity, grant it higher privileges, and pivot.

```bash
# From VM-A with system-assigned MI-Reader
TOKEN=$(curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com&api-version=2018-02-01" \
  | jq -r .access_token)

# The MI-Reader has Owner on sub B — create a new MI with elevated rights
curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-admin?api-version=2023-01-31" \
  -d '{"location": "eastus"}'

# Assign Owner to the new MI
az role assignment create \
  --assignee <new-mi-principal-id> \
  --role Owner \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

**Cross-tenant app chain:**

An app registration in Tenant-A is consented to in Tenant-B as a service principal. The service principal in Tenant-B can be assigned RBAC roles.

```bash
# List cross-tenant service principals (attacker enumeration)
az ad sp list --all --query "[?appOwnerOrganizationId != null].{DisplayName:displayName,AppOwnerTenant:appOwnerOrganizationId}" -o table
```

**Gotcha:** Managed Identities are always in the same tenant — cross-tenant chaining requires multi-tenant app registrations + admin consent. The admin consent grant (`Directory.Read.All` etc.) is itself a privilege path.

## GCP

GCP uses service account impersonation. The chain is: identity → `roles/iam.serviceAccountTokenCreator` on SA-A → SA-A's IAM policy allows the impersonator → get SA-A's token → repeat to SA-B.

```bash
# Grant impersonation permission
gcloud iam service-accounts add-iam-policy-binding \
  sa-reader@project-a-111111.iam.gserviceaccount.com \
  --member "serviceAccount:sa-initial@project-a-111111.iam.gserviceaccount.com" \
  --role roles/iam.serviceAccountTokenCreator

# Impersonate SA-A, then impersonate SA-B from SA-A's context
gcloud auth activate-service-account \
  sa-initial@project-a-111111.iam.gserviceaccount.com \
  --key-file=sa-initial-key.json

gcloud auth print-access-token \
  --impersonate-service-account sa-reader@project-a-111111.iam.gserviceaccount.com

# Chain to SA-B if sa-reader can impersonate sa-admin
gcloud auth print-access-token \
  --impersonate-service-account sa-admin@project-b-222222.iam.gserviceaccount.com
```

**GCP impersonation check:**

```bash
# Enumerate which SAs can be impersonated by the current identity
gcloud iam service-accounts get-iam-policy \
  sa-target@project-id-111111.iam.gserviceaccount.com \
  --format json | jq '.bindings[] | select(.role=="roles/iam.serviceAccountTokenCreator")'
```

**Gotcha:** GCP impersonation chains are limited by the same org constraints as AWS. The `roles/iam.serviceAccountTokenCreator` role must be granted at the target SA level. Cross-project impersonation requires org-level IAM bindings or explicit cross-project SA IAM policy.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Trust primitive | Kerberos constrained delegation | `sts:AssumeRole` in trust policy | RBAC role assignment delegation | `roles/iam.serviceAccountTokenCreator` |
| Chain enumeration tool | BloodHound (AD) | Cartography / CloudMapper | AzureHound / ROADtools | custom SA IAM policy crawler |
| Anti-confusion mechanism | SPN lockdown + selective authentication | `sts:ExternalId` | Multi-tenant app consent | `attribute.condition` in WIF |
| Max chain depth | Forest trust hop limit (~3-5) | 12h total session duration | No explicit limit | 12h total session duration |
| Hardening control | Protected Users group, SID filtering | SCP `Deny` on `sts:AssumeRole` for cross-account | Azure Policy deny cross-tenant | Org Policy `iam.disableServiceAccountCreation` |

## 🔴 Red Team view

**Building a privilege graph from a read-only role.** Given a read-only role, the attacker enumerates every role the current principal can assume, then recursively walks trust policies to find escalation endpoints.

**Conceptual walk-through (no live tooling):**

```python
# Pseudocode: enumerate all reachable roles from current identity
# Run only in your own sandbox AWS account.
known_roles = [current_role_arn]
visited = set()
escalation_paths = []

while known_roles:
    role_arn = known_roles.pop()
    if role_arn in visited:
        continue
    visited.add(role_arn)

    # Get the trust policy for this role
    trust_doc = get_role_trust_policy(role_arn)

    for statement in trust_doc["Statement"]:
        if "Principal" in statement and "AWS" in statement["Principal"]:
            trusted_principal = statement["Principal"]["AWS"]

            # Check if the trusted principal is a role we can assume
            can_assume = check_sts_assume_role(role_arn)

            if can_assume:
                escalation_paths.append((trusted_principal, "→", role_arn))

                # Check if this role has administrative policies
                admin_policies = [
                    "AdministratorAccess",
                    "AmazonS3FullAccess",
                    "IAMFullAccess"
                ]
                attached = get_attached_policies(role_arn)
                if any(p in admin_policies for p in attached):
                    print(f"ESCALATION: {trusted_principal} → {role_arn} = ADMIN")

            known_roles.append(trusted_principal)
```

**Enumerate manually via CLI (sandbox only):**

```bash
# Given current identity, list all roles in the account
aws iam list-roles --query "Roles[].{Name:RoleName,Arn:Arn,Trust:AssumeRolePolicyDocument}" \
  --output json | jq '.[] | select(.Trust.Statement[].Principal.AWS != null) | {Name,TrustPrincipal: .Trust.Statement[].Principal.AWS}'

# For each role, test assume-role (will fail if not authorized — no harm)
ROLE_ARN="arn:aws:iam::111111111111:role/TargetRole"
aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name Probe 2>/dev/null && \
  echo "CAN ASSUME $ROLE_ARN" || echo "DENIED: $ROLE_ARN"
```

**Artifacts:** Every `AssumeRole` API call is logged in CloudTrail with `eventName: "AssumeRole"`. The `sourceIPAddress`, `roleSessionName` (from the `--role-session-name` flag), and `userAgent` are recorded. A spike of denied `AssumeRole` calls with varying `--role-session-name` values from a single IP is a reliable detection pattern.

**Defensive pairing:** The `sts:ExternalId` condition forces the caller to provide a secret value known only to the trust relationship establisher. Without it, the `AssumeRole` call fails even if the trust policy's `Principal` matches.

## 🔵 Blue Team view

**Hardening trust policies:**

1. **Always use ExternalId for cross-account trust:**
```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::111111111111:role/SourceRole"},
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "placeholder-external-id-12345"
    }
  }
}
```

2. **Restrict by source ARN and source IP:**
```json
{
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "placeholder-external-id-12345",
      "aws:PrincipalArn": "arn:aws:iam::111111111111:role/SourceRole"
    },
    "IpAddress": {
      "aws:SourceIp": "192.0.2.0/24"
    }
  }
}
```

3. **SCP to block cross-account role assumptions from unapproved accounts:**
```json
{
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:RequestedRegion": ["us-east-1", "eu-west-1"]
    }
  }
}
```

**Visualize blast radius:**

Use Cartography (open-source graph tool) to map IAM trust relationships:
```bash
# cartography ingest into Neo4j, then query:
# MATCH (r:AWSRole)-[:TRUSTS]->(p:AWSPrincipal) RETURN r.name, p.name
```

**OPA rule restricting chain depth (as of June 2026, example Rego pattern for trust chain analysis):**

```rego
package iam.trust_chain

deny[msg] {
    role := input.roles[_]
    count(walk_chain(role, [])) > 3
    msg := sprintf("Role %s exceeds max trust chain depth of 3", [role.name])
}

walk_chain(role, visited) = chain {
    trusted := role.assume_role_policy.Statement[_].Principal.AWS
    not visited[role.arn]
    chain := [role.arn | walk_chain(trusted, visited + {role.arn})]
}
```

**Detection queries:**

```
-- CloudTrail Lake: AssumeRole chain detection (chained events within 60s)
SELECT eventTime, userIdentity.arn, requestParameters.roleArn,
       requestParameters.roleSessionName, sourceIPAddress
FROM cloudtrail_111111111111
WHERE eventName = 'AssumeRole'
  AND userIdentity.type = 'AssumedRole'
  AND userIdentity.arn LIKE '%role/%'
ORDER BY eventTime ASC

-- Identify denied AssumeRole probes (enumeration attempt)
SELECT COUNT(*) as denials, sourceIPAddress, userAgent
FROM cloudtrail_111111111111
WHERE eventName = 'AssumeRole'
  AND errorMessage IS NOT NULL
  AND eventTime > now() - interval '1' hour
GROUP BY sourceIPAddress, userAgent
HAVING COUNT(*) > 10
```

## Hands-on lab

**Build a deliberate 3-role escalation chain in your AWS sandbox, capture CloudTrail, then break it.**

> **Cost risk:** Free-tier eligible. AWS STS is free; IAM is free.

**Step 1 — Create three roles with ascending privileges:**

```bash
# Role-A: ReadOnlyAccess (can assume Role-B)
aws iam create-role --role-name ChainLab-RoleA --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::'$(aws sts get-caller-identity --query Account --output text)':user/lab-admin"},
    "Action": "sts:AssumeRole"
  }]
}'
aws iam attach-role-policy --role-name ChainLab-RoleA --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Role-B: PowerUserAccess (can assume Role-C), trusts Role-A
aws iam create-role --role-name ChainLab-RoleB --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::'$(aws sts get-caller-identity --query Account --output text)':role/ChainLab-RoleA"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "chain-lab-b"}}
  }]
}'
aws iam attach-role-policy --role-name ChainLab-RoleB --policy-arn arn:aws:iam::aws:policy/PowerUserAccess

# Role-C: AdministratorAccess (trusts Role-B)
aws iam create-role --role-name ChainLab-RoleC --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::'$(aws sts get-caller-identity --query Account --output text)':role/ChainLab-RoleB"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "chain-lab-c"}}
  }]
}'
aws iam attach-role-policy --role-name ChainLab-RoleC --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

**Step 2 — Walk the chain:**

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Hop 1: lab-admin → Role-A
CREDS_A=$(aws sts assume-role --role-arn arn:aws:iam::$ACCOUNT_ID:role/ChainLab-RoleA --role-session-name Hop1)

export AWS_ACCESS_KEY_ID=$(echo $CREDS_A | jq -r .Credentials.AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_A | jq -r .Credentials.SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS_A | jq -r .Credentials.SessionToken)
aws sts get-caller-identity

# Hop 2: Role-A → Role-B
CREDS_B=$(aws sts assume-role --role-arn arn:aws:iam::$ACCOUNT_ID:role/ChainLab-RoleB --role-session-name Hop2 --external-id chain-lab-b)

export AWS_ACCESS_KEY_ID=$(echo $CREDS_B | jq -r .Credentials.AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_B | jq -r .Credentials.SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS_B | jq -r .Credentials.SessionToken)
aws sts get-caller-identity

# Hop 3: Role-B → Role-C (AdministratorAccess)
CREDS_C=$(aws sts assume-role --role-arn arn:aws:iam::$ACCOUNT_ID:role/ChainLab-RoleC --role-session-name Hop3 --external-id chain-lab-c)
aws sts get-caller-identity --profile-from-creds "$CREDS_C"
```

**Step 3 — Check CloudTrail:**

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole --max-results 10 | jq '.Events[].CloudTrailEvent | fromjson | {time: .eventTime, role: .requestParameters.roleArn, session: .requestParameters.roleSessionName}'
```

**Step 4 — Break the chain by removing ExternalId:**

```bash
# Update Role-B trust policy to remove ExternalId requirement
aws iam update-assume-role-policy --role-name ChainLab-RoleB --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::'$(aws sts get-caller-identity --query Account --output text)':role/ChainLab-RoleA"},
    "Action": "sts:AssumeRole"
  }]
}'

# Retry Hop 2 without ExternalId — it should now succeed
```

**Step 5 — Re-add ExternalId and test break by using wrong ID:**

```bash
# Restore ExternalId condition
aws iam update-assume-role-policy --role-name ChainLab-RoleB --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::'$(aws sts get-caller-identity --query Account --output text)':role/ChainLab-RoleA"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "chain-lab-b"}}
  }]
}'

# Try with wrong ExternalId — should fail with AccessDenied
aws sts assume-role --role-arn arn:aws:iam::$ACCOUNT_ID:role/ChainLab-RoleB \
  --role-session-name TestWrong --external-id WRONG-ID
```

**Expected output:** The wrong ExternalId produces an `AccessDenied` error, demonstrating ExternalId as an anti-confused-deputy control.

**Teardown:**
```bash
for role in ChainLab-RoleA ChainLab-RoleB ChainLab-RoleC; do
  aws iam detach-role-policy --role-name $role --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess 2>/dev/null
  aws iam detach-role-policy --role-name $role --policy-arn arn:aws:iam::aws:policy/PowerUserAccess 2>/dev/null
  aws iam detach-role-policy --role-name $role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null
  aws iam delete-role --role-name $role
done
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

## Detection rules & checklists

**CloudTrail query — detect chained assume-role from untrusted source ARN:**
```
SELECT *
FROM cloudtrail_111111111111
WHERE eventName = 'AssumeRole'
  AND userIdentity.type = 'AssumedRole'
  AND userIdentity.arn NOT LIKE '%:role/approved-%'
```

**Checklist:**
- [ ] Every cross-account trust policy includes `sts:ExternalId`.
- [ ] No trust policy allows `Principal: "*"` or `Principal: {"AWS": "*"}`.
- [ ] SCP denies `sts:AssumeRole` across accounts not in the organization.
- [ ] CloudTrail alerts fire on >5 denied `AssumeRole` calls within 5 minutes from same IP.

## References
- [AWS IAM: confused deputy prevention](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
- [AWS ExternalId design](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)
- [Azure Managed Identity delegation patterns](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations)
- [GCP Service Account impersonation](https://cloud.google.com/iam/docs/service-account-impersonation)
- [MITRE ATT&CK — Cloud Service Discovery (T1526)](https://attack.mitre.org/techniques/T1526/)
- [Cartography (Lyft)](https://github.com/lyft/cartography)
- [CloudMapper (Duo)](https://github.com/duo-labs/cloudmapper)
