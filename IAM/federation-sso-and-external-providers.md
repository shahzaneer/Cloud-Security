# 05 — Federation, SSO & External Providers

> **Level:** Intermediate–Advanced
> **Prereqs:** [Identity Primitives per Cloud](identity-primitives-per-cloud.md) (Identity Primitives), [Authn Flows & Tokens](authn-flows-and-tokens.md) (AuthN Flows & Tokens)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Persistence, Credential Access
> **Authorization scope:** Identity attacks only in your own sandbox accounts / sanctioned targets.

## What & why

Most enterprises source identity outside the cloud — Active Directory, Okta, Entra ID, Google Workspace. The trust relationship between the identity provider (IdP) and the cloud is the *real* perimeter. When the IdP is compromised, every cloud account that trusts it is compromised.

## The OnPrem reality

ADFS (Active Directory Federation Services) bridged on-prem AD to cloud consoles. A SAML assertion — signed by the ADFS token-signing certificate — was the credential. RADIUS authenticated networking gear and VPNs. The shared weakness: the ADFS server was a domain-joined Windows host, reachable from the internet, and its token-signing certificate (if stolen) minted valid SAML assertions for any user — including domain admins.

## Cross-cloud federation comparison

| Provider | Federation technology | IdP source | Console role mapping | OIDC support |
|---|---|---|---|---|
| AWS | IAM Identity Center / SAML IdP trust / OIDC IdP | Okta, Azure AD, Google Workspace, Active Directory | IAM Identity Center Permission Sets → IAM Roles | Yes (OIDC IdP for AssumeRoleWithWebIdentity) |
| Azure | Entra ID (native) / B2B / SAML federation | On-prem AD (Entra Connect), Okta, Google | Entra ID Roles + RBAC assignment | Yes (Workload Identity Federation) |
| GCP | Workforce Identity Federation / Cloud Identity | Azure AD, Okta, Google Workspace, SAML IdP | IAM role bindings (groups/attributes mapped) | Yes (Workload Identity Federation + OIDC provider pool) |
| OnPrem | ADFS / Shibboleth / Keycloak | Active Directory, LDAP | Group claim → application role mapping | SAML only (legacy); modern: OIDC |

## AWS

AWS federates external identities through **IAM Identity Center** (preferred) or a direct **SAML/OIDC IdP** in IAM.

**Federate GitHub OIDC → AWS Role:**

```bash
# 1. Create OIDC provider in IAM
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list "6938fd4d98bab03faadb97b34396831e3780aea1"

# 2. Create role with trust for the OIDC provider
aws iam create-role --role-name GitHubActionsRole --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:example-org/my-repo:ref:refs/heads/main"
      }
    }
  }]
}'

# 3. In GitHub Actions:
# - uses: aws-actions/configure-aws-credentials@v4
#   with:
#     role-to-assume: arn:aws:iam::111111111111:role/GitHubActionsRole
#     aws-region: us-east-1
```

**IAM Identity Center — SAML federation to Okta:**

```bash
# Enable Identity Center in the organization management account
aws sso-admin create-instance --name MySSOInstance

# Create permission set (maps IdP group to IAM policies)
aws sso-admin create-permission-set \
  --instance-arn <instance-arn> \
  --name ReadOnly \
  --session-duration PT1H

aws sso-admin attach-managed-policy-to-permission-set \
  --instance-arn <instance-arn> \
  --permission-set-arn <ps-arn> \
  --managed-policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Map to AWS account
aws sso-admin create-account-assignment \
  --instance-arn <instance-arn> \
  --target-id 111111111111 \
  --target-type AWS_ACCOUNT \
  --permission-set-arn <ps-arn> \
  --principal-type GROUP \
  --principal-id <okta-group-object-id>
```

> (as of June 2026, IAM Identity Center supports automated provisioning via SCIM from external IdPs (Okta, Azure AD, etc.). "Just in Time" provisioning behavior and SCIM attribute mapping vary by region and SKU level; check the current AWS SSO/Identity Center documentation for your region.)

## Azure

Azure Entra ID *is* the IdP for Azure. Federation means Entra ID trusts an external IdP (e.g., on-prem AD via Entra Connect, or Okta via SAML federation).

**Entra ID as IdP — GitHub OIDC federation (Workload Identity Federation):**

```bash
# Create App Registration with federated credential
az ad app create --display-name github-actions-app

# Add federated credential (ties GitHub OIDC to this app)
az ad app federated-credential create \
  --id <app-object-id> \
  --name github-fc \
  --issuer https://token.actions.githubusercontent.com \
  --subject "repo:example-org/my-repo:ref:refs/heads/main" \
  --audiences api://AzureADTokenExchange

# Assign RBAC role to the service principal
az role assignment create \
  --assignee <sp-object-id> \
  --role Contributor \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

**B2B guest federation — cross-tenant identities:**

```bash
# Invite external user (tenant A invites tenant B user)
az ad user invite \
  --user-principal-name guest@example-tenant-b.onmicrosoft.com \
  --invited-user-email-address guest@example.com \
  --display-name "External Contractor"

# Check what roles the guest has
az role assignment list --assignee guest@example-tenant-a.onmicrosoft.com --all
```

> (as of June 2026, B2B guest default permissions are limited to directory read and basic profile access; cross-tenant consent settings can restrict guest enumeration. Recent Entra ID updates have tightened default guest access — check your tenant's External Identities settings for current defaults.)

## GCP

GCP federation comes in two flavors: **Workforce Identity Federation** (human users) and **Workload Identity Federation** (machine apps).

**Workforce Identity Federation — SAML from Okta:**

```bash
# Create workforce pool
gcloud iam workforce-pools create my-workforce-pool \
  --location global \
  --organization 000000000000

# Add SAML provider
gcloud iam workforce-pools providers create-saml okta-saml \
  --workforce-pool my-workforce-pool \
  --location global \
  --idp-metadata-path ./okta-metadata.xml \
  --attribute-mapping "google.subject=assertion.subject,google.groups=assertion.attributes.groups"

# Bind workforce identity to IAM
gcloud projects add-iam-policy-binding project-id-111111 \
  --member "principal://iam.googleapis.com/locations/global/workforcePools/my-workforce-pool/subject/admin@example.com" \
  --role roles/viewer
```

**Workload Identity Federation — GitHub OIDC:**

```bash
gcloud iam workload-identity-pools create github-pool --location global

gcloud iam workload-identity-pools providers create-oidc github-provider \
  --workload-identity-pool github-pool \
  --location global \
  --issuer-uri https://token.actions.githubusercontent.com \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
  --attribute-condition "attribute.repository == 'example-org/my-repo'"

gcloud iam service-accounts add-iam-policy-binding \
  sa-github@project-id-111111.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/github-pool/attribute.repository/example-org/my-repo"
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Federation protocol | SAML 2.0 (ADFS) | SAML 2.0 / OIDC | SAML 2.0 / OIDC / WIF | SAML 2.0 / OIDC (WIF pools) |
| Human IdP bridge | ADFS proxy | IAM Identity Center | Entra Connect (sync) / Entra ID B2B | Workforce Identity Federation |
| Machine IdP bridge | Kerberos gMSA | OIDC IdP → AssumeRoleWithWebIdentity | Workload Identity Federation | Workload Identity Federation (OIDC pool) |
| Group claim mapping | Group SID → SAML attribute | Permission Set → Group → IAM Role | Entra Group (SAML claim) → RBAC role | `google.groups` attribute → IAM binding |
| MFA enforcement | ADFS MFA extension | IdP-enforced (IAM Identity Center trusts IdP assertion) | Conditional Access (Entra ID P1/P2) | Cloud Identity / IdP-enforced |
| Session revocation | AD user disable (eventual consistency) | Revoke `aws:TokenIssueTime` / delete session | Conditional Access sign-in frequency / revoke refresh tokens | Revoke workforce pool session |

## 🔴 Red Team view

**IdP compromise → full cloud takeover.** If an attacker compromises the IdP (e.g., Okta super admin, Entra ID Global Admin), they mint valid SAML/OIDC assertions for any user. Every cloud account that trusts that IdP is accessible.

**Narrative scenario (contained, placeholder):**

An attacker gains access to `admin@example-tenant.onmicrosoft.com` (Entra ID Global Admin) via credential stuffing against a user without MFA. From the IdP, they:

1. Create a new app registration with `User.ReadWrite.All` and `RoleManagement.ReadWrite.Directory` delegated permissions.
2. Grant admin consent to their app (since they're Global Admin).
3. Use the app to assign themselves `Global Administrator` in the Entra ID role hierarchy.
4. With Global Admin, they can now access every Azure subscription that trusts `example-tenant.onmicrosoft.com` via the `Access management for Azure resources` toggle.

**Cross-tenant guest account attack (contained narrative):**

A malicious tenant (`example-attacker.onmicrosoft.com`) invites a target user as a guest. If the attacker has an Entra ID P2 license, they can use Conditional Access to force the guest to re-authenticate, potentially harvesting credentials through a lookalike sign-in page. Alternatively, the attacker with Global Admin in their own tenant can configure an app registration as multi-tenant, trick users in the target tenant into consenting, and then use the granted delegated permissions to read their data.

**Artifacts left:**
- Entra ID Audit Logs: `Add application`, `Grant admin consent`, `Add member to role`.
- AWS CloudTrail: `AssumeRoleWithSAML` with `sourceIdentity` from the IdP.
- GCP Cloud Audit Logs: `IdentityServiceWorkforcePoolSession` creation events.

## 🔵 Blue Team view

**Protect the IdP — this is the real perimeter.**

**Conditional Access (Entra ID):**
```json
{
  "displayName": "Require MFA for all admins",
  "state": "enabled",
  "conditions": {
    "userRiskLevels": ["high"],
    "clientAppTypes": ["all"],
    "applications": {
      "includeApplications": ["All"]
    },
    "users": {
      "includeRoles": [
        "62e90394-69f5-4237-9190-012177145e10"
      ]
    },
    "locations": {
      "includeLocations": ["AllTrusted"]
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  }
}
```

**AWS — IdP session revocation via `aws:TokenIssueTime`:**
```json
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "DateLessThan": {
      "aws:TokenIssueTime": "2026-06-22T00:00:00Z"
    }
  }
}
```
Attach this as an inline policy to the IAM role to revoke all sessions issued before the cutoff.

**IdP monitoring queries:**

```
-- Entra ID: detect risky sign-ins
SigninLogs
| where RiskLevelDuringSignIn in ("high", "medium")
| project UserPrincipalName, AppDisplayName, IpAddress, RiskDetail, ConditionalAccessStatus

-- AWS CloudTrail: SAML federation from unusual IP
SELECT eventTime, sourceIPAddress, responseElements.issuer 
FROM cloudtrail_111111111111
WHERE eventName = 'AssumeRoleWithSAML'
  AND sourceIPAddress NOT IN ('192.0.2.0/24')
```

**SCIM provisioning — automated user lifecycle:**
```bash
# AWS: Enable SCIM sync from Okta/Entra ID to IAM Identity Center
aws sso-admin put-inline-policy-to-permission-set \
  --instance-arn <instance-arn> \
  --permission-set-arn <ps-arn> \
  --inline-policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Null":{"aws:PrincipalTag/Department":"true"}}}]}'
```

**Checklist:**
- [ ] IdP admins protected by MFA and Conditional Access / risk-based authentication.
- [ ] All SAML/OIDC trust policies include audience restriction (`aud` claim check).
- [ ] SCIM/provisioning enabled to auto-deprovision when users leave the IdP.
- [ ] Cross-tenant guest access restricted to approved tenants only (Entra ID External Identities settings).
- [ ] IdP token-signing certificate monitored for expiration and unauthorized renewal.

## Hands-on lab

**Federate GitHub Actions OIDC to GCP (free-tier safe):**

> **Cost risk:** Free. GCP WIF is free; service accounts are free.

```bash
# 1. Create service account
gcloud iam service-accounts create lab-github-sa
gcloud projects add-iam-policy-binding project-id-111111 \
  --member "serviceAccount:lab-github-sa@project-id-111111.iam.gserviceaccount.com" \
  --role roles/viewer

# 2. Create workload identity pool
gcloud iam workload-identity-pools create lab-github-pool --location global

# 3. Create OIDC provider
gcloud iam workload-identity-pools providers create-oidc lab-github-provider \
  --workload-identity-pool lab-github-pool \
  --location global \
  --issuer-uri https://token.actions.githubusercontent.com \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition "attribute.repository == 'example-org/my-repo'"

# 4. Bind SA to pool
gcloud iam service-accounts add-iam-policy-binding \
  lab-github-sa@project-id-111111.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/lab-github-pool/attribute.repository/example-org/my-repo"

# 5. Verify the provider configuration
gcloud iam workload-identity-pools providers describe lab-github-provider \
  --workload-identity-pool lab-github-pool --location global
```

**Expected output:** The provider is configured. A GitHub Actions workflow in `example-org/my-repo` can now exchange its OIDC token for a GCP access token, all without storing a single service account key.

**Teardown:**
```bash
gcloud iam service-accounts remove-iam-policy-binding \
  lab-github-sa@project-id-111111.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/lab-github-pool/attribute.repository/example-org/my-repo"
gcloud iam workload-identity-pools providers delete lab-github-provider \
  --workload-identity-pool lab-github-pool --location global --quiet
gcloud iam workload-identity-pools delete lab-github-pool --location global --quiet
gcloud iam service-accounts delete lab-github-sa@project-id-111111.iam.gserviceaccount.com --quiet
```

## Detection rules & checklists

**Entra ID cross-tenant access monitor:**
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy" \
  --query "{default:default, partners:partners}" -o jsonc
```

**AWS — verify no SAML IdP without audience restriction:**
```bash
aws iam list-saml-providers --query "SAMLProviderList[].Arn" --output text | \
  xargs -I {} aws iam get-saml-provider --saml-provider-arn {}
```

## References
- [AWS IAM Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html)
- [Azure AD B2B collaboration](https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b)
- [GCP Workforce Identity Federation](https://cloud.google.com/iam/docs/workforce-identity-federation)
- [AADInternals toolkit (defensive research)](https://github.com/Gerenios/AADInternals)
- [MITRE ATT&CK — Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)
