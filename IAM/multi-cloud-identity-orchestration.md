# 12 — Multi-Cloud Identity Orchestration

> **Level:** Advanced
> **Prereqs:** [Federation, SSO & External Providers](federation-sso-and-external-providers.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Persistence, Privilege Escalation, Defense Evasion, Credential Access
> **Authorization scope:** Run only in your own sandbox accounts and test tenants. All cross-cloud federation examples use placeholder tenant IDs and role ARNs.

## What & why

Multi-cloud identity orchestration wires AWS, Azure, and GCP into a single identity fabric with one central IdP (Okta / Entra ID / Ping). When done right, a departing employee loses access across all clouds in seconds. When done wrong, shadow tenants, stale federated roles, and cross-cloud trust chains create persistence that can survive for months.

## The OnPrem reality

Multi-domain forests were managed with AD trust relationships — transitive, bi-directional, difficult to audit. Cloud federation replaces trust arrows with SAML/OIDC assertions and SCIM provisioning, but the same graph-traversal problems reappear: a trust from IdP → Cloud A combined with role chaining in Cloud A can reach Cloud B indirectly, creating unapproved paths.

## Core concepts

### Identity fabric architecture

```
                      ┌──────────────────┐
                      │  Central IdP      │
                      │  (Okta / Entra)   │
                      └───┬──────┬─────┬──┘
                          │      │     │
                    SAML/OIDC  │     │  SCIM (provisioning)
                          │    │     │
                 ┌────────▼┐   │  ┌──▼──────────┐
                 │   AWS   │   │  │    GCP       │
                 │ IAM IdC │   │  │ Workforce Id │
                 └─────────┘   │  └─────────────┘
                          ┌────▼──────┐
                          │   Azure   │
                          │  Entra ID │
                          └───────────┘
```

### SCIM provisioning flow

1. Central IdP is the system of record for users and groups.
2. SCIM pushes creates/updates/deletes to each cloud's user directory.
3. Each cloud maps SCIM groups to IAM roles / RBAC assignments / IAM bindings.
4. Deprovisioning in the IdP triggers SCIM DELETE cascading to all clouds within seconds (as of June 2026, typical propagation: AWS 30–60s, Azure instant, GCP 60–120s).

### Cross-cloud federation patterns

| Pattern | Description | Risk |
|---|---|---|
| Single IdP, multiple SPs | Okta → AWS + Azure + GCP | IdP = single point of compromise |
| Cloud as IdP to another cloud | Entra ID → AWS (via SAML) → GCP (via workload federation) | Trust chain complexity |
| Workload federation across clouds | GKE SA → federated to AWS IAM role | Cross-cloud lateral movement path |
| Org-wide identity hub | AWS Identity Center ↔ Entra ID ↔ GCP Workforce Identity | Most manageable at scale |

## AWS

### AWS as an SP to Okta / Entra ID

```bash
# Create SAML IdP in AWS
aws iam create-saml-provider \
  --saml-metadata-document file://okta-metadata.xml \
  --name OktaIdP

# Create role for IdP users
aws iam create-role \
  --role-name Okta-ReadOnly \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Federated": "arn:aws:iam::111111111111:saml-provider/OktaIdP"},
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}
      }
    }]
  }'

# SCIM provisioning via AWS IAM Identity Center
aws identitystore create-user \
  --identity-store-id d-9067f971ce \
  --user-name "jdoe" \
  --display-name "Jane Doe" \
  --emails '[{"Value":"jdoe@example.com","Type":"Work","Primary":true}]'
```

**Gotcha:** AWS IAM Identity Center (successor to AWS SSO) supports SCIM from Okta/Entra only when you use the Identity Center directory as the source of truth. If you use Active Directory as the identity source, SCIM is not available — deprovisioning requires AD sync lag.

### Cross-cloud workload federation

```bash
# GCP service account can assume an AWS role via OIDC
# In AWS: create OIDC IdP pointing to GCP
aws iam create-open-id-connect-provider \
  --url https://accounts.google.com \
  --client-id-list "111111111111-abcdef.apps.googleusercontent.com" \
  --thumbprint-list "abcdef123456"

# AWS role trusts the GCP OIDC principal
aws iam create-role \
  --role-name GcpWorkloadAssumeRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/accounts.google.com"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "accounts.google.com:sub": "sa-readonly@project-id.iam.gserviceaccount.com"
        }
      }
    }]
  }'
```

## Azure

### Azure as an IdP to AWS

```bash
# Create an enterprise application in Entra ID for AWS SSO
az ad app create --display-name "AWS-SSO-Integration"
# Get the service principal
az ad sp create --id <appId-from-above>

# Configure SAML: Entra ID → AWS
# This is done via Portal (Enterprise Apps → AWS Single-Account Access)
# Map Entra ID groups to AWS IAM roles via SAML attributes:
# https://aws.amazon.com/SAML/Attributes/Role
```

**Gotcha:** Entra ID can act as the central IdP for AWS and GCP simultaneously, creating a scenario where a single Entra ID compromise grants access to all three clouds. Protect Entra ID Global Admin accounts with phishing-resistant MFA and dedicated admin workstations (SAW/PAW).

### Cross-tenant trust (Azure B2B + AWS/GCP)

```bash
# Invite external user from a partner organization
az ad user create \
  --user-principal-name "partner@external.com#EXT#@mydirectory.onmicrosoft.com" \
  --display-name "Partner Admin" \
  --user-type Guest
# Assign the guest to a role in the subscription
az role assignment create \
  --assignee "partner@external.com#EXT#@mydirectory.onmicrosoft.com" \
  --role "Contributor" \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

**Risk:** Azure B2B guest accounts can be invited into any tenant by any member. A shadow IT team could invite external users without security review. Use Entra ID External Identities settings to restrict guest invitation to specific roles.

## GCP

### Workforce Identity Federation

```bash
# Set up workforce identity pool for Okta users
gcloud iam workforce-pools create okta-pool \
  --location global \
  --organization 111111111111

# Add Okta as a SAML IdP
gcloud iam workforce-pools providers create-saml okta-provider \
  --workforce-pool okta-pool \
  --location global \
  --idp-metadata-path okta-metadata.xml \
  --attribute-mapping "google.subject=assertion.subject"

# Grant access to GCP resources
gcloud projects add-iam-policy-binding project-id-111111 \
  --member "principal://iam.googleapis.com/locations/global/workforcePools/okta-pool/subject/jdoe@example.com" \
  --role roles/viewer
```

**Gotcha:** Workforce Identity Federation (as of June 2026) supports SAML and OIDC but SCIM provisioning to GCP groups is still maturing. Group membership often relies on SAML attribute assertions at login time rather than pre-provisioning, meaning a user removed from the IdP group may still have access until their token expires.

### SCIM for GCP

```bash
# GCP Cloud Identity supports SCIM from Entra ID / Okta
# Enable API access:
gcloud services enable cloudidentity.googleapis.com

# SCIM endpoint (configured in IdP):
# https://cloudidentity.googleapis.com/v1/scim/Users
# The provisioning connector syncs users and groups
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| User provisioning | AD account creation | SCIM via Identity Center | SCIM from Entra ID / Okta | SCIM via Cloud Identity |
| Group-to-role mapping | AD group → GPO → local admin | IdP group → SAML attribute → IAM role | Entra ID group → Azure RBAC role | Google Group → IAM binding |
| Deprovisioning | AD account disable (GPO lag) | SCIM DELETE (30–60s) | Instant (Entra ID native) | SCIM DELETE (60–120s) |
| Cross-cloud auth | AD trust → Kerberos | SAML/OIDC → STS → IAM role | SAML/OIDC → Entra ID → Azure RBAC | SAML/OIDC → Workforce Id → IAM |
| Shadow tenant detection | No equivalent | Org-wide CloudTrail | Entra ID audit logs | Org Policy + Cloud Audit Logs |
| Break-glass | AD Recovery Mode | Root account only | Break-glass Global Admin (permanent) | Super Admin (super admin role) |

## 🔴 Red Team view

### Technique 1 — Cross-cloud trust exploitation

An attacker compromises a GCP service account that the organization has federated to an AWS IAM role (via OIDC). The GCP SA can call `sts:AssumeRoleWithWebIdentity` against the AWS role, obtaining AWS credentials. The attacker now moves from GCP to AWS without touching the central IdP.

```bash
# From compromised GCP VM:
gcloud auth print-access-token
# Use the GCP token to assume the trusted AWS role:
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::222222222222:role/GcpWorkloadAssumeRole \
  --role-session-name gcp-pivot \
  --web-identity-token "$(gcloud auth print-identity-token)"
# Now operating in AWS with the role's permissions
```

**Detection:** CloudTrail records `AssumeRoleWithWebIdentity` with `sourceIdentity` from `accounts.google.com`. If that source is not a known GCP project, investigate.

### Technique 2 — Shadow tenant persistence

An attacker with Entra ID Global Admin creates a new Entra ID tenant (free tier), sets up cross-tenant federation to the victim's tenant, and uses it as a persistence mechanism. The victim's tenant trusts the attacker-controlled tenant.

```bash
# Attacker creates a new tenant:
az ad tenant create --display-name "ShadowCorp" --country-code US
# Sets up cross-tenant trust from victim to shadow tenant:
az ad app create --display-name "ShadowApp" --sign-in-audience AzureADMyOrg
# The shadow tenant can now mint tokens that the victim tenant trusts
```

### Technique 3 — SCIM deprovisioning gap

An attacker with IdP admin access disables SCIM provisioning before being terminated. Their cloud identities are never deprovisioned because the IdP can no longer push DELETE. The attacker retains access for months.

**Artifacts left:** SCIM provisioning logs in the IdP show when provisioning was paused. Cloud audit logs show continued access by a user whose IdP account is disabled — a strong detection signal.

## 🔵 Blue Team view

### Single source of truth design

1. **Central IdP as the system of record:**
   - All user lifecycle events (create, update, delete) originate in the IdP (Okta / Entra ID).
   - Cloud-native directories (AWS IAM, GCP Cloud Identity) are read-only replicas updated by SCIM.
   - No manual user creation in individual clouds — only break-glass accounts are cloud-native.

2. **Automated deprovisioning verification:**
```bash
# Daily job: compare IdP active users to cloud IAM users
# AWS
aws iam list-users --query "Users[?CreateDate<'2026-01-01'].UserName" --output text

# Azure
az ad user list --filter "accountEnabled eq true" --query "[?createdDateTime < '2026-01-01'].userPrincipalName"

# GCP
gcloud organizations list  # then per-org enumerate memberships
```

3. **Cross-cloud trust inventory:**
   - Document every OIDC provider, SAML IdP, and workload federation in a central inventory.
   - Reconcile monthly: does every trust have an owner and documented business need?
   - Disable trusts that are no longer approved.

### Detection signals

| Signal | Source | Query |
|---|---|---|
| Cross-cloud token exchange | CloudTrail + Cloud Audit Logs | `AssumeRoleWithWebIdentity` with `accounts.google.com` source AND source project ≠ approved |
| SCIM provisioning disabled | IdP audit logs | `event.type = "app.provisioning.disabled"` |
| New tenant created in Entra ID | Entra ID audit logs | `activityDisplayName = "Add unmanaged tenant"` |
| Stale federated user still active | Cloud IAM + IdP | User exists in AWS IAM but not in Okta (drift detector) |
| IdP admin changes to federation config | IdP logs | `event.type = "app.saml.update" OR "app.oidc.update"` |

### Response steps

1. If an IdP compromise is suspected:
   - Rotate the IdP signing certificate — this invalidates all existing SAML assertions.
   - Force all session revocation across all clouds.
   - Enable IdP sign-in risk policies (impossible travel, unfamiliar features).

2. For a cross-cloud lateral movement alert:
   - Suspend the source service account/role in the originating cloud.
   - Revoke the destination cloud session.
   - Audit all actions taken during the cross-cloud session.

3. For a SCIM deprovisioning gap:
   - Re-enable SCIM provisioning immediately.
   - Manually delete any users who should have been deprovisioned during the gap.
   - Create an alert: if SCIM fails for >1 hour, page the identity team.

## Hands-on lab

1. Set up a simple cross-cloud federation (Okta free trial → AWS):
   - Create an Okta developer account (free, developer.okta.com).
   - Add the AWS Single-Account Access application.
   - Configure SAML: download Okta metadata, upload to AWS IAM as a SAML provider.
   - Map an Okta group to an IAM role.
2. Test the SSO flow: log in via Okta dashboard, confirm you land in the AWS console with the correct role.
3. Simulate a deprovisioning event:
   - Remove the user from the Okta group.
   - Check if AWS session is revoked (typically it persists until token expiry — ~1 hour).
   - Note: without native session revocation, SCIM group removal alone does not kill active sessions.
4. Clean up: remove the IdP, role, and test user.

**Teardown:**
```bash
aws iam delete-saml-provider --saml-provider-arn arn:aws:iam::111111111111:saml-provider/OktaIdP
aws iam delete-role --role-name Okta-ReadOnly
```

## Detection rules & checklists

**Sigma rule — Cross-cloud token exchange from unapproved source:**
```yaml
title: Cross-Cloud AssumeRoleWithWebIdentity from Unapproved OIDC Source
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AssumeRoleWithWebIdentity
  filter:
    sourceIdentity|contains: "accounts.google.com"
  condition: selection and filter
  falsepositives:
    - Approved GCP→AWS workload federation
level: high
```

**Checklist:**
- [ ] Central IdP is the only source of truth for human identities.
- [ ] SCIM provisioning enabled and monitored for all three clouds.
- [ ] Cross-cloud trust inventory documented and reviewed monthly.
- [ ] Deprovisioning tested: disable a user in IdP → verify access gone in all 3 clouds within 5 minutes.
- [ ] No manual IAM user creation outside break-glass accounts.
- [ ] All SAML/OIDC IdP signing certificates have expiration alerts (30-day warning).
- [ ] IdP admin activity shipped to SIEM with high-severity alert rules.

## References
- [AWS IAM Identity Center — SCIM Provisioning](https://docs.aws.amazon.com/singlesignon/latest/userguide/provisioning-and-deprovisioning.html)
- [Azure — Cross-tenant access](https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview)
- [GCP Workforce Identity Federation](https://cloud.google.com/iam/docs/workforce-identity-federation)
- [MITRE ATT&CK — Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK — Trust Relationship (T1484.002)](https://attack.mitre.org/techniques/T1484/002/)
- [SCIM v2.0 Specification (RFC 7644)](https://datatracker.ietf.org/doc/html/rfc7644)
