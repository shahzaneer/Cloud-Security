# 06 — Permission Boundaries & Quarantine

> **Level:** Advanced
> **Prereqs:** [Identity Primitives per Cloud](identity-primitives-per-cloud.md) through [Federation SSO & External Providers](federation-sso-and-external-providers.md); [Blast Radius & Fail Secure](../Fundamentals/blast-radius-and-fail-secure.md) (Cloud Governance)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Privilege Escalation, Defense Evasion, Persistence
> **Authorization scope:** Identity attacks only in your own sandbox accounts / sanctioned targets.

## What & why

Permission boundaries are a *ceiling controlled by security* that even an administrator cannot exceed. Unlike IAM policies (which grant), boundaries *restrict* — they define the maximum set of permissions *any* principal can have, regardless of what identity policies say. Quarantine operationalizes this by isolating compromised identities into a zero-rights cage.

## The OnPrem reality

Active Directory AdminSDHolder: every 60 minutes, the SDProp process resets the ACL on protected accounts (Domain Admins, Enterprise Admins, Schema Admins) to match the AdminSDHolder container. No matter what permissions an attacker might grant themselves, they're reverted. Group Policy "Enforced" (No Override) links similarly create a floor that child OUs cannot undo. These are the on-prem ancestors of cloud permission boundaries.

## Cross-cloud comparison

| Provider | Boundary primitive | Who imposes it | Override path | Quarantine equivalent |
|---|---|---|---|---|
| AWS | IAM Permission Boundaries (managed policy) | IAM admin (security team) | Root user can remove (should be locked) | SCP Deny + boundary removal + revoke sessions |
| AWS | SCP (Service Control Policy) | Organization admin | Only management account root | SCP Deny all actions on quarantined OU |
| Azure | Deny Assignments (Azure Blueprints/Managed Apps) | Platform team / Azure Lighthouse | Global Admin can remove (audited) | Deny assignment blocking all actions |
| Azure | Management Group Policy | Organization admin | None below management group level | Azure Policy `deny` effect |
| GCP | Org Policy constraints | Organization admin | Org policy IAM admin can modify | `constraints/iam.allowedPolicyMemberDomains` |
| GCP | Denial policies (IAM Conditions with negative bindings) | IAM admin | Role `roles/iam.securityAdmin` can modify | Deny `*` condition on principal |
| OnPrem | AdminSDHolder / Group Policy Enforced | Domain Admins / AGPM | Domain Admin | Disable user + revoke Kerberos tickets |

## AWS

**Permission Boundaries — restrict an admin from escalating themselves:**

```bash
# 1. Create boundary policy (allows only read-only + specific bucket)
aws iam create-policy \
  --policy-name SecurityBoundary \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": "arn:aws:s3:::approved-bucket/*"
      },
      {
        "Effect": "Allow",
        "Action": ["iam:Get*", "iam:List*"],
        "Resource": "*"
      }
    ]
  }'

# 2. Attach boundary to an IAM User
aws iam put-user-permissions-boundary \
  --user-name dev-user \
  --permissions-boundary arn:aws:iam::111111111111:policy/SecurityBoundary

# 3. Even if dev-user attaches AdministratorAccess to themselves,
#    the boundary limits them to S3 GetObject/ListBucket + IAM read
aws iam attach-user-policy \
  --user-name dev-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# The effective permissions = AdministratorAccess INTERSECT SecurityBoundary
# = SecurityBoundary (the smaller set)
```

**SCP — Organization-level quarantine of an entire account:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "QuarantineAccount",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalArn": [
          "arn:aws:iam::111111111111:role/BreakGlassRole",
          "arn:aws:iam::111111111111:role/ForensicRole"
        ]
      }
    }
  }]
}
```

Attach to the OU containing the compromised account. Only Forensics and BreakGlass roles are exempt. All other principals — including the root user — are denied.

## Azure

**Deny Assignments — block public resources from being created:**

> (as of June 2026, Azure Deny Assignments are created via Azure Blueprints or the Azure portal for Managed Applications; the CLI supports read-only operations for Deny Assignments. Direct REST API creation is also available at `Microsoft.Authorization/denyAssignments`.)

```bash
# View existing deny assignments on a subscription
az role assignment list --all \
  --query "[?properties.principalType == 'DenyAssignment']" \
  -o table

# Azure Policy — deny effect (equivalent in practice)
az policy definition create \
  --name deny-public-blob \
  --rules '{
    "if": {
      "field": "type",
      "equals": "Microsoft.Storage/storageAccounts"
    },
    "then": {
      "effect": "deny"
    }
  }'

az policy assignment create \
  --name deny-public-blob-assignment \
  --policy deny-public-blob \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

**Management group-level policy — block resource types in an entire OU:**

```json
{
  "if": {
    "field": "type",
    "in": [
      "Microsoft.Network/publicIPAddresses",
      "Microsoft.Storage/storageAccounts"
    ]
  },
  "then": {
    "effect": "deny"
  }
}
```

Assigned at the management group level, this cannot be overridden by child subscriptions.

## GCP

**Org Policy — restrict identity domains to trusted sources:**

```bash
gcloud org-policies set-policy \
  --organization 000000000000 \
  --policy-file restrict-domains.yaml
```

```yaml
# restrict-domains.yaml
name: organizations/000000000000/policies/iam.allowedPolicyMemberDomains
spec:
  rules:
  - values:
      allowedValues:
      - "example.com"
      - "is:gserviceaccount.com"
  - condition:
      expression: "resource.type == 'cloudresourcemanager.googleapis.com/Organization'"
```

This blocks any IAM member not from `example.com` or a GCP service account — preventing cross-tenant guest additions.

**Org Policy — deny service account key creation:**

```bash
gcloud org-policies set-policy \
  --organization 000000000000 \
  --policy-file deny-sa-keys.yaml
```

```yaml
# deny-sa-keys.yaml
constraint: constraints/iam.disableServiceAccountKeyCreation
booleanPolicy:
  enforced: true
```

**Deny IAM policy binding (negative grant):**

IAM Conditions can express denial:

```bash
gcloud projects add-iam-policy-binding project-id-111111 \
  --member "user:quarantined@example.com" \
  --role roles/viewer \
  --condition-from-file condition.yaml
```

```yaml
# condition.yaml — effectively a denial
expression: "request.time < timestamp('2026-01-01T00:00:00Z')"
title: "expired_access"
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Ceiling primitive | AdminSDHolder / GPO Enforced | Permission Boundary / SCP | Deny Assignment / Azure Policy (deny) | Org Policy constraint |
| Applied by | SDProp / Group Policy engine | IAM / Organization | Azure Policy engine | Organization Policy Service |
| Can admin override? | Not without DA and AdminSDHolder change | Root user can remove boundaries | Global Admin can remove deny assignments | Org Policy Admin can modify |
| Quarantine playbook | Disable AD user + revoke TGTs via `klist purge` | SCP Deny * + revoke IAM sessions | Conditional Access block + revoke refresh tokens | Remove IAM bindings + revoke OAuth tokens |
| Audit evidence | `Security` log event 4662 (SDProp) | CloudTrail `PutUserPermissionsBoundary` | Azure Activity Log `MICROSOFT.AUTHORIZATION/DENYASSIGNMENTS` | Cloud Audit Log `SetOrgPolicy` |

## 🔴 Red Team view

**Bypass via boundary misconfiguration.** If the boundary is too narrow in the wrong direction, an admin retains dangerous permissions.

**Example — boundary that allows `iam:Attach*` without restricting `iam:Create*`:**

```json
// Vulnerable boundary — allows IAM administration despite attempting to restrict
{
  "Effect": "Allow",
  "Action": ["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy"],
  "Resource": "*"
}
```

An attacker with this boundary can create a new role with `AdministratorAccess`, attach it to themselves, and escalate — because the boundary didn't restrict `iam:CreateRole` or `iam:PutRolePolicy`.

**Conceptual quarantine-bypass attack (contained narrative):**

An attacker with a session token valid for 1 hour sees the `Deny *` SCP land on their account. The SCP applies to new API calls, but existing STS session tokens remain valid until expiry. The attacker uses the remaining 45 minutes of session to:

1. Assume a role in a *non-quarantined* account that trusts the quarantine account (trust policy predated the quarantine).
2. Using the assumed role's credentials, create a backdoor role in the non-quarantined account.
3. Persist across quarantine.

This underscores why quarantine must include **session revocation** — not just SCP application.

**Artifacts:**
- CloudTrail: `AssumeRole` from the quarantined account to a healthy account.
- The cross-account `AssumeRole` event has `sourceIPAddress` from the compromised host.
- The trust policy in the healthy account predates the quarantine — it was a pre-existing attack surface.

## 🔵 Blue Team view

**Quarantine playbook — revoke live sessions across all three clouds:**

```bash
# AWS — revoke all active sessions for a role
aws iam put-role-policy --role-name QuarantinedRole --policy-name RevokeSessions --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "DateLessThan": {"aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}
    }
  }]
}'

# Azure — revoke refresh tokens for a user (requires Graph API / Entra ID Admin)
az ad user revoke-sign-in-session --id quarantined@example-tenant.onmicrosoft.com
# ⚠️ Also revoke: az rest --method POST --uri "https://graph.microsoft.com/v1.0/users/{id}/revokeSignInSessions"

# GCP — remove a principal from all IAM policies
gcloud projects get-iam-policy project-id-111111 --format json > /tmp/iam.json
# Edit /tmp/iam.json to remove quarantined member from all bindings
gcloud projects set-iam-policy project-id-111111 /tmp/iam.json
```

**Preventive — add SCP for IAM role chaining restriction:**

```json
{
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalOrgID": "o-xxxxxxxxxx"
    }
  }
}
```

Blocks any role assumption from outside the AWS Organization.

**Preventive — deny IAM user creation:**

```json
{
  "Effect": "Deny",
  "Action": ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"],
  "Resource": "*"
}
```

**Detection queries:**

```
-- Detect permission boundary removal
SELECT eventTime, userIdentity.arn, requestParameters.permissionsBoundary
FROM cloudtrail_111111111111
WHERE eventName = 'DeleteUserPermissionsBoundary'

-- Azure: detect deny assignment removal
AzureActivity
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/DENYASSIGNMENTS/DELETE"
| project TimeGenerated, Caller, ResourceId
```

**Response steps — quarantine order:**
1. Attach SCP/Deny Assignment/Org Policy to prevent new actions.
2. Revoke active sessions (STS token deny, refresh token invalidate, GCP session delete).
3. Rotate all long-lived credentials (access keys, client secrets, SA keys).
4. Enable forensic logging (CloudTrail Lake query, Diagnostic Settings verbose).
5. Investigate trust policies that pointed *to* the compromised identity from other accounts.
6. Once containment confirmed, begin root-cause investigation.

## Hands-on lab

**Apply a permission boundary and verify it restricts admin actions:**

```bash
# 1. Create a boundary policy — ReadOnly + specific S3 bucket
aws iam create-policy --policy-name LabBoundary --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}'

# Wait, let's make it *restrictive* instead:
aws iam create-policy --policy-name LabBoundary --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ec2:Describe*", "s3:ListAllMyBuckets", "iam:Get*", "iam:List*"],
      "Resource": "*"
    }
  ]
}'

# 2. Create user and attach boundary + AdministratorAccess
aws iam create-user --user-name lab-boundary-user
aws iam put-user-permissions-boundary \
  --user-name lab-boundary-user \
  --permissions-boundary arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/LabBoundary
aws iam attach-user-policy \
  --user-name lab-boundary-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 3. Create access key for the user, test it
aws iam create-access-key --user-name lab-boundary-user | tee /tmp/boundary-key.json
export AWS_ACCESS_KEY_ID=$(jq -r .AccessKey.AccessKeyId /tmp/boundary-key.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .AccessKey.SecretAccessKey /tmp/boundary-key.json)

aws sts get-caller-identity  # works

# 4. Test boundary — try to create an S3 bucket (should fail)
aws s3 mb s3://lab-boundary-test-bucket-11111 2>&1
# Expected: AccessDenied — boundary allows only ListAllMyBuckets, not CreateBucket

# 5. Test boundary — try to describe EC2 (should work)
aws ec2 describe-instances  # works — matches boundary
```

**Expected output:** S3 bucket creation fails with `AccessDenied` despite the user having `AdministratorAccess` attached. The boundary's `ec2:Describe*` and `iam:Get*/List*` work normally.

**Teardown:**
```bash
aws iam delete-access-key --user-name lab-boundary-user \
  --access-key-id $(jq -r .AccessKey.AccessKeyId /tmp/boundary-key.json)
aws iam detach-user-policy --user-name lab-boundary-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user-permissions-boundary --user-name lab-boundary-user
aws iam delete-user --user-name lab-boundary-user
aws iam delete-policy --policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/LabBoundary
rm /tmp/boundary-key.json
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```

## Detection rules & checklists

**Cloud Custodian — detect users without permission boundaries:**
```yaml
policies:
  - name: users-without-boundary
    resource: iam-user
    filters:
      - type: value
        key: PermissionsBoundary
        value: absent
```

**Checklist:**
- [ ] All IAM Users (if any exist) have permission boundaries.
- [ ] SCPs deny `sts:AssumeRole` from outside the AWS Organization.
- [ ] Azure Deny Assignments block public blob container creation organization-wide.
- [ ] GCP Org Policy `iam.allowedPolicyMemberDomains` restricts to corporate domains.
- [ ] Quarantine runbook tested quarterly — revoke session + SCP in <5 minutes.

## References
- [AWS Permission Boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [AWS SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [Azure Deny Assignments](https://learn.microsoft.com/en-us/azure/role-based-access-control/deny-assignments)
- [GCP Org Policy Constraints](https://cloud.google.com/resource-manager/docs/organization-policy/overview)
- [MITRE ATT&CK — Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/)
