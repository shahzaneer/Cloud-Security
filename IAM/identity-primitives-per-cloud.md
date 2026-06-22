# 01 — Identity Primitives Per Cloud

> **Level:** Fundamental
> **Prereqs:** [Authn Authz Accountability](../Fundamentals/authn-authz-accountability.md) (Cloud Architecture & Shared Responsibility)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Credential Access
> **Authorization scope:** Identity attacks only in your own sandbox accounts / sanctioned targets.

## What & why

Every action in the cloud resolves to an identity. Identity types — human, service/workload, machine, SAAS-fed — each carry different threat models, rotation behaviors, and attack surfaces. Choosing the wrong type (e.g., a long-lived IAM user for a CI/CD runner) is a free foothold.

## The OnPrem reality

On-prem identity was layered: local OS users (`/etc/passwd`, `SAM`), LDAP directory identities (AD user objects), and service accounts with passwords stashed in config files or cron tabs. None were designed for an always-internet control plane. Cloud identity makes these problems worse because credentials appear in env vars, CI logs, and Terraform state — no physical network boundary helps you.

## Core concepts — identity primitive matrix

| Primitive | Description | Rotation | Threat surface |
|---|---|---|---|
| Human user | Person with console/CLI access | Manual / SSO-enforced | Phishing, credential stuffing, long-lived keys |
| Admin group | Collection of humans with elevated rights | Inherits group membership | Group membership persistence |
| Machine role | Non-human identity for a service/resource | Automated, short-lived (STS) | Trust-policy misconfiguration |
| Instance identity | Identity baked into VM/container metadata | Auto-rotated by provider | SSRF to metadata endpoint |
| Workload identity | Pod/function identity via OIDC/federation | Ephemeral, no stored secret | OIDC audience misconfiguration |
| Tenant / directory | Organization container for all identities | N/A | Guest federation, cross-tenant trust |
| Service principal | Enterprise app identity in Entra ID | Certificate/secret rotation | Secret lifetime, app consent grants |
| External federation | IdP-sourced identity (SAML/OIDC) | IdP-controlled | IdP compromise = cloud compromise |

## AWS

AWS identity primitives live under the IAM service. The root user (account-creation email) is the ultimate owner and should be locked down immediately.

| Primitive | AWS name | Key attribute |
|---|---|---|
| Human user | IAM User | `aws_secret_access_key` (static) or SSO via Identity Center |
| Admin group | IAM Group with `AdministratorAccess` | Group-level policy attachment |
| Machine role | IAM Role with trust policy | `sts:AssumeRole` by service/user |
| Instance identity | EC2 instance profile → IAM Role | Credential exposed at `169.254.169.254` |
| Workload identity | IRSA (EKS) via OIDC | `sts.amazonaws.com` OIDC provider |
| Federation | IAM Identity Center / SAML IdP | Assertion → role mapping |

**Canonical create — CLI:**

```bash
# IAM User with long-lived key (avoid in production)
aws iam create-user --user-name dev-readonly
aws iam create-access-key --user-name dev-readonly

# IAM Role for EC2 (instance identity)
aws iam create-role \
  --role-name Ec2ReadOnly \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'
aws iam attach-role-policy \
  --role-name Ec2ReadOnly \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

**Gotcha:** IAM Users support access keys that never expire by default. IAM Roles always return temporary credentials via STS (max 12h chained, 1h default).

## Azure

Azure's identity plane is Entra ID (formerly Azure AD). Every identity is an Entra ID object — no separate "IAM" service.

| Primitive | Azure name | Key attribute |
|---|---|---|
| Human user | Entra ID User | `UserPrincipalName@tenant.onmicrosoft.com` |
| Admin group | Entra ID Group + Role assignment | PIM-eligible for higher privilege |
| Machine role | Managed Identity (system/user-assigned) | No credential to manage |
| Instance identity | System-assigned Managed Identity on VM | `http://169.254.169.254/metadata/identity/oauth2/token` |
| Workload identity | AKS Workload Identity via OIDC | Federated credential on Service Principal |
| Service principal | App Registration + Service Principal | Client secret / certificate auth |
| Federation | Entra Connect / B2B / SAML | Federation trust to on-prem AD |

**Canonical create — CLI:**

```bash
# Entra ID User
az ad user create \
  --display-name "Dev ReadOnly" \
  --user-principal-name dev@example-tenant.onmicrosoft.com \
  --password "PLACEHOLDER_PASSWORD_123!"

# Managed Identity (System-assigned on VM)
az vm identity assign \
  --name vm-prod-01 \
  --resource-group rg-prod \
  --role Reader \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

**Gotcha:** User-assigned Managed Identities can be attached to multiple resources, creating lateral movement paths. System-assigned MIs die with the resource.

## GCP

GCP identity centers on the Google identity object (Google Account, Google Workspace, Cloud Identity). Service accounts are first-class citizens.

| Primitive | GCP name | Key attribute |
|---|---|---|
| Human user | Cloud Identity / Google Account | `user@example.com` |
| Admin group | Google Group + IAM binding | Group-as-principal in policy |
| Machine role | Service Account (SA) | `sa-name@project-id.iam.gserviceaccount.com` |
| Instance identity | Compute Engine default SA | `http://metadata.google.internal/` |
| Workload identity | GKE Workload Identity | SA annotation on Kubernetes SA |
| Service principal | Service Account | SA keys (static) or OAuth2 (short-lived) |
| Federation | Workforce / Workload Identity Federation | OIDC/SAML → IAM principal |

**Canonical create — CLI:**

```bash
# Service Account
gcloud iam service-accounts create sa-readonly \
  --display-name "ReadOnly Service Account"

# Human user binding
gcloud projects add-iam-policy-binding project-id-111111 \
  --member user:dev@example.com \
  --role roles/viewer

# GKE Workload Identity
gcloud iam service-accounts add-iam-policy-binding \
  sa-readonly@project-id-111111.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:project-id-111111.svc.id.goog[default/my-app]"
```

**Gotcha:** The Compute Engine default service account exists in every project with `roles/editor` unless explicitly disabled — a built-in privilege escalation path if instances are compromised.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Human user | AD User / local OS user | IAM User / Identity Center User | Entra ID User | Cloud Identity User |
| Admin group | AD Security Group + GPO | IAM Group + Policy | Entra ID Group + Role | Google Group + IAM binding |
| Service identity | gMSA / svc account | IAM Role | Managed Identity / Service Principal | Service Account |
| Metadata endpoint | N/A (no cloud metadata) | `169.254.169.254/latest/meta-data/iam/` | `169.254.169.254/metadata/identity/` | `metadata.google.internal/` |
| Credential lifetime | Until password expires / gMSA auto-rotates | STS: 15min–12h | OAuth2: default 1h | OAuth2: default 1h |
| Trust boundary | Domain/forest trust | Trust policy + ExternalId | Cross-tenant consent | IAM allow policy + org constraints |

## 🔴 Red Team view

Long-lived IAM User access keys are the most abused cloud credential type. Unlike ephemeral roles, a static `AKIA*` key works anywhere, anytime, until revoked. Attackers scrape them from public repos, CI logs, and compromised dev laptops.

**Conceptual attack flow:**

```bash
# Attacker finds a committed key in a public repo
git grep -i "AKIA" $(git rev-list --all)

# The key is valid — attacker uses it
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws sts get-caller-identity

# Enumerate what the compromised IAM User can do
aws iam list-attached-user-policies --user-name victim-user
```

**Artifacts left:** The `git log` commit hash ties the leaked key to a developer and timestamp. CloudTrail records the `GetCallerIdentity` and subsequent calls from an unusual source IP/source ARN. GitHub secret scanning (`AKIA*` regex) may alert the repo owner.

**Defensive pairing:** See 🔵 section below for key inventory and rotation. The compile-time fix is to never create IAM Users for machine workloads.

## 🔵 Blue Team view

**Preventive controls:**

1. **Eliminate IAM Users for workloads.** Migrate to IAM Roles with STS, Managed Identities, or Workload Identity Federation.
2. **Enforce credential rotation.** AWS IAM credential report, Azure App Registration credential expiry policy, GCP service account key rotation.
3. **Guard the metadata endpoint.** IMDSv2 (AWS), enforced for all EC2 instances. Azure blocks metadata from containers by default. GCP enforces metadata concealment on GKE `workload_metadata_config: GKE_METADATA`.

**Inventory one-liners:**

```bash
# AWS: list users with active access keys
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d | grep -v "N/A" | awk -F',' '$4 != "" {print $1 " has active key"}'

# Azure: list app registrations with expiring client secrets
az ad app list --all --query "[?passwordCredentials[].endDate < '@{0}'].{App:displayName,AppId:appId}" \
  -o table

# GCP: list service accounts with user-managed keys
gcloud iam service-accounts list --format json | \
  jq -r '.[] | select(.email | contains("gserviceaccount")) | "\(.email)"'
# Then per account: gcloud iam service-accounts keys list --iam-account=...
```

**Detection signals:**
- CloudTrail `GetCallerIdentity` from never-before-seen IP or User-Agent.
- `CreateAccessKey` events outside change windows.
- Key usage from regions where the organization has no workloads.

**Response steps:**
1. Immediately deactivate the compromised key: `aws iam update-access-key --status Inactive`.
2. Rotate — create new key, update all valid consumers, delete old.
3. Quarantine the IAM User by attaching a deny-all inline policy.
4. Investigate all actions performed during the compromise window via CloudTrail Lake.

## Hands-on lab

**Pre-lab:** You need an AWS sandbox account (free tier) and the AWS CLI configured.

1. Create an IAM User with programmatic access key:
```bash
aws iam create-user --user-name lab-leaked-user
aws iam create-access-key --user-name lab-leaked-user

# Save the output to a temporary file
echo "AKIAIOSFODNN7EXAMPLE:secretkey" > /tmp/creds.txt
```

2. Simulate a leak — check that the key works:
```bash
export AWS_ACCESS_KEY_ID=<from-output>
export AWS_SECRET_ACCESS_KEY=<from-output>
aws sts get-caller-identity
```

3. View the credential report:
```bash
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --query Content --output text | base64 -d
```

4. Rotate (deactivate → delete old key → create new):
```bash
aws iam update-access-key --user-name lab-leaked-user \
  --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive
aws iam delete-access-key --user-name lab-leaked-user \
  --access-key-id AKIAIOSFODNN7EXAMPLE
aws iam create-access-key --user-name lab-leaked-user
```

**Teardown:**
```bash
aws iam delete-access-key --user-name lab-leaked-user --access-key-id <new-key-id>
aws iam delete-user --user-name lab-leaked-user
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
rm /tmp/creds.txt
```

## Detection rules & checklists

**Audit check — no root account usage:**
```bash
aws iam generate-credential-report && \
aws iam get-credential-report --query Content --output text | base64 -d | \
  awk -F',' 'NR>1 && $1 == "<root_account>" && $4 != "not_supported" {print "ROOT HAS ACTIVE KEY!"}'
```

**AWS Config rule — no IAM Users with active keys older than 90 days:**
```json
{
  "ConfigRuleName": "iam-user-keys-rotated",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "IAM_USER_ACCESS_KEYS_ROTATED"
  }
}
```

**CSPM check (Cloud Custodian):**
```yaml
policies:
  - name: iam-users-with-keys
    resource: iam-user
    filters:
      - type: credential
        key: access_keys.active
        value: true
```

## References
- [AWS IAM Identities](https://docs.aws.amazon.com/IAM/latest/UserGuide/id.html)
- [Azure Managed Identities](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
- [GCP Service Accounts](https://cloud.google.com/iam/docs/service-account-overview)
- [MITRE ATT&CK — Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)
- [GitHub Secret Scanning — AWS keys](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-patterns)
