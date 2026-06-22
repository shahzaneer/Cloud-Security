# 05 — Blast Radius & Fail-Secure Design

> **Level:** Fundamental
> **Prereqs:** 02-cia-triad-in-cloud, 04-authn-authz-accountability
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Lateral Movement, Privilege Escalation, Impact
> **Authorization scope:** Run only in your own sandbox organization. For cross-account labs, use only accounts you fully own.

## What & why
Blast radius is the maximum damage one compromised identity or resource can cause. Fail-secure means when a control breaks, it defaults to deny instead of allow. Together they drive roughly 80% of cloud defense architecture — separate accounts, least privilege, and default-deny guardrails.

## The OnPrem reality
- **Blast radius:** A domain admin credential compromises the entire forest. No isolation between HR file server and production database — one domain, one fate.
- **Fail-secure:** A firewall's default rule is "deny all." When the firewall crashes, traffic stops — fail-secure. A poorly configured failover to "allow all" is fail-open (dangerous).

## Core concepts

### Blast-radius containers
The cloud provides account/project/tenant boundaries as blast-radius containers. A compromise in account A should not leak to account B by default.

| Blast-radius primitive | AWS | Azure | GCP |
|------------------------|-----|-------|-----|
| Top-level isolation unit | AWS Account | Subscription | Project |
| Grouping / hierarchy | AWS Organization → OU → Account | Management Group → Subscription | Organization → Folder → Project |
| Cross-account guardrails | SCP (Service Control Policy) | Azure Policy (Deny effect) | Org Policy |
| Access boundary | IAM trust policy, Resource Access Manager (RAM) | Managed Identity cross-tenant, Lighthouse | IAM Conditions, VPC Service Controls perimeters |
| Quarantine account | Dedicated "security" account for logging/audit (no workloads) | Dedicated management subscription | Dedicated "audit" or "logging" project |

### Fail-secure primitives
A fail-secure system denies by default when a control fails:

| Fail-secure example | How it works |
|---------------------|-------------|
| SCP with `Deny` + `*:*` | If the SCP syntax is broken, the policy fails to apply — but existing explicit allows remain. Write SCPs as deny-lists so a syntax error doesn't open access. |
| IMDSv2 (token required) | If the token endpoint is unreachable, metadata is not served — fail-secure. IMDSv1 serves metadata without a token — fail-open. |
| AWS IAM policy evaluation: explicit deny | An explicit Deny always wins over an Allow. If an admin accidentally attaches an over-broad Allow, a Deny SCP still blocks it — fail-secure. |
| Org Policy with `constraints/iam.disableServiceAccountKeyCreation` | If the policy evaluation fails, no new keys can be created — fails to deny. |
| VPC endpoint policies | If you use an endpoint policy that allows only `s3:GetObject` from `arn:aws:s3:::prod-bucket`, any S3 call that fails to match is denied — default-deny. |

## Cross-cloud combat table

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Blast-radius boundary | Forest/domain boundary (weak) | AWS Account (strong — everything isolated by default) | Subscription (strong — separate IAM plane) | Project (strong — separate IAM bindings) |
| Enforcing boundaries across units | Firewall, GPO | SCP (at org/OU level) + Guardrails (Control Tower) | Azure Policy at management-group scope | Org Policy at org/folder/project level |
| Separation of duties | Separate admin accounts | Multiple accounts + cross-account roles (no shared creds) | Multiple subscriptions + Azure Lighthouse (delegated access) | Multiple projects + IAM Conditions (limited scope) |
| Quarantine/emergency access | Physical console / out-of-band network | Org-level break-glass role in dedicated account, MFA, IAM | Emergency access ("break glass") accounts in Entra ID, monitored | SA in dedicated project, alert on usage |
| Default network isolation | VLANs | VPCs are isolated. Peering/Transit Gateway required for cross-VPC traffic. | VNets are isolated. Peering required. | VPCs are isolated. Peering / Shared VPC required. |
| Public-by-default risk | Internal network is private; internet-facing services deliberately exposed | S3 buckets can be public; RDS can be public. Opt-in public. | Storage accounts can be public; VMs can have public IPs. Opt-in public. | Cloud Storage buckets can be public; VMs can have public IPs. Opt-in public. |

## 🔴 Red Team view

### Exploiting large blast radius — cross-account role chaining (contained)

**Scenario:** An organization has dev, staging, and prod in a single AWS account. One IAM role in dev has `sts:AssumeRole` trust from a third-party CI tool. The CI tool is compromised. Because everything is in one account, the attacker can enumerate and potentially access prod resources.

```bash
# Attacker has compromised the CI role in the single account:
aws sts get-caller-identity
# { "Arn": "arn:aws:iam::111111111111:role/ci-deployer" }

# Discovery — what's in this account?
aws ec2 describe-instances
aws rds describe-db-instances
aws s3 ls

# Production database found — accessible because the CI role has over-privileged policies:
aws rds describe-db-instances --db-instance-identifier prod-primary
# Connection details exposed — attacker now has prod DB endpoint.

# No cross-account AssumeRole needed — everything was in one account.
# Blast radius = entire organization's infrastructure.
```

**Properly isolated (Blue counter-example):**
```bash
# Same scenario, but dev/staging/prod are separate accounts.
# CI role is in account 222222222222 (dev).
aws sts assume-role --role-arn arn:aws:iam::333333333333:role/read-staging \
  --role-session-name test
# Fails: SCP on dev account denies sts:AssumeRole to accounts outside the org, or
# the staging account's trust policy doesn't include the dev CI role.
# Blast radius contained to dev account.
```

**Artifacts from the attack:**
- CloudTrail in prod account: no events (attacker never reached it — contained).
- CloudTrail in dev account: `DescribeInstances`, `DescribeDBInstances`, `ListBuckets` from CI role.
- GuardDuty: unusual resource enumeration from a CI role.

**Azure equivalent (contained):**
```bash
# If all resources are in one subscription, a compromised Managed Identity
# with Contributor can read prod DB connection strings from Key Vault.
az keyvault secret show --vault-name prod-vault --name db-connection-string
# Detection: Azure Activity Log — Key Vault read from unexpected MI.
```

**GCP equivalent (contained):**
```bash
# If all resources are in one project, a compromised SA with overly broad IAM
# can access production Cloud SQL.
gcloud sql instances describe prod-primary
# Detection: Cloud Audit Logs — Cloud SQL Admin API calls from unexpected SA.
```

## 🔵 Blue Team view

### Hardening blast-radius boundaries

**Account-level isolation (recommended landing zone):**

```
AWS Organization
├── OU: Security (111111111111) — logging, GuardDuty master, break-glass role
├── OU: Production (222222222222)
│   ├── prod-workloads (333333333333)
│   └── prod-data (444444444444)
├── OU: Staging (555555555555)
├── OU: Dev (666666666666)
└── OU: Sandbox (777777777777)
```

**SCP examples that shrink blast radius:**

```json
// Deny leaving the org — no resource sharing outside the org
// Applied to root OU, inherited by all accounts
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeavingOrg",
      "Effect": "Deny",
      "Action": [
        "sts:AssumeRole",
        "ram:CreateResourceShare",
        "ec2:ModifySnapshotAttribute",
        "s3:PutBucketAcl"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
```

**Azure Policy equivalent:**
```json
{
  "properties": {
    "policyRule": {
      "if": {
        "anyOf": [
          { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
          { "field": "type", "equals": "Microsoft.Sql/servers" }
        ]
      },
      "then": { "effect": "deny" }
    }
  }
}
```

**GCP Org Policy equivalent:**
```yaml
# Deny service account key creation org-wide
constraint: constraints/iam.disableServiceAccountKeyCreation
enforce: true
# Deny public bucket access org-wide
constraint: constraints/storage.publicAccessPrevention
enforce: true
```

### Break-glass accounts

| Cloud | How to implement |
|-------|-----------------|
| AWS | Dedicated account (OU=Security). One IAM user with MFA, no access key, login-only, SCP-exempted, CloudTrail alert on any login. |
| Azure | Entra ID emergency access accounts (no Conditional Access applied, no MFA if fed auth is the break — but alert on any sign-in). Use Azure Monitor alert. |
| GCP | Dedicated "audit" project. SA with `roles/iam.securityReviewer` at org level. Cloud Monitoring alert on SA activity. |

### Fail-secure checklist per service

| Service | Fail-open behavior | Fail-secure fix |
|---------|-------------------|-----------------|
| S3 bucket | Public by ACL if you set it | SCP `s3:PutPublicAccessBlock` at org root. Account-level block. |
| EC2 IMDS | IMDSv1 serves without token | Enforce IMDSv2 via metadata options |
| IAM role trust | Any principal in the same account can AssumeRole if trust policy allows `root` | Always specify explicit `AWS: arn:aws:iam::<account-id>:role/<specific-role>` in trust policy |
| Security group | Egress all-allowed by default (0.0.0.0/0) | Remove default egress SG rule; use explicit allow-listed egress |
| Azure Storage | "Allow Blob Public Access" = true by default | Set to false at creation; Azure Policy deny effect |
| GCP Cloud Storage | Fine-grained ACLs can make individual objects public | Enforce uniform bucket-level access + `publicAccessPrevention=Enforced` |

## Hands-on lab

**Prereq:** Two AWS accounts in the same Organization (or simulate with LocalStack / `terraform plan` only).

1. **Set up:** Account A has an IAM role `test-role` with EC2 read permissions. Account B has an IAM user `test-user`.
2. **Without SCP:** `test-user` in Account B tries `sts:AssumeRole` to Account A's `test-role`. It works (if trust policy allows Account B). Demonstrates cross-account access — potential blast radius.
3. **With SCP:** Apply an SCP to Account B's root that denies `sts:AssumeRole` to roles outside Account B.
   ```json
   {
     "Sid": "DenyCrossAccountAssume",
     "Effect": "Deny",
     "Action": "sts:AssumeRole",
     "Resource": "*",
     "Condition": {
       "StringNotEquals": {
         "aws:RequestedAccount": "111111111111"
       }
     }
   }
   ```
4. **Re-test:** `test-user` tries AssumeRole again — this time **AccessDenied**.
5. **Verify:** Check CloudTrail in Account B. You see the denied `AssumeRole` event with `errorCode: "AccessDenied"`. Blast radius contained.
6. **Teardown:** Detach the SCP, delete test role and user.

**Azure equivalent (simulated):**
```bash
# Cross-subscription role assignment attempt:
az role assignment create --assignee "user@example.com" \
  --role "Reader" --scope "/subscriptions/00000000-0000-0000-0000-000000000000"
# Azure Policy at management-group scope can deny role assignments across subscriptions.
```

**GCP equivalent (simulated):**
```bash
# Cross-project IAM binding attempt:
gcloud projects add-iam-policy-binding other-project-id \
  --member="serviceAccount:sa-example@my-project.iam.gserviceaccount.com" \
  --role="roles/viewer"
# Org Policy + VPC Service Controls can restrict cross-project access.
```

## Detection rules & checklists

- [ ] Every production workload runs in its own AWS account / Azure subscription / GCP project.
- [ ] SCPs / Azure Policies / Org Policies enforce: no public S3/bucket/storage, no leaving the org, no long-lived access keys.
- [ ] Break-glass accounts exist, have MFA (where applicable), and trigger alerts on any use.
- [ ] Default egress SG rules removed — explicit egress only.
- [ ] IMDSv2 enforced on all EC2 instances.
- [ ] Cross-account trust policies specify exact principal ARNs — never `"Principal": {"AWS": "*"}` or `"Principal": {"AWS": "arn:aws:iam::111111111111:root"}` (the latter allows ANY principal in account 111111111111).
- [ ] Denied AssumeRole events reviewed weekly for attempted lateral movement.
- [ ] Resource deletion protection enabled on all tier-1 infrastructure (RDS, DynamoDB, Cloud SQL, etc.).

## References
- AWS Organizations & SCPs: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scp.html
- AWS Control Tower / Landing Zone: https://docs.aws.amazon.com/controltower/latest/userguide/what-is-control-tower.html
- Azure Landing Zones (Cloud Adoption Framework): https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/
- GCP Resource Hierarchy: https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy
