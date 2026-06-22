# 03 — Blast-Radius Reduction Patterns

> **Level:** Intermediate–Advanced
> **Prereqs:** [Blast Radius & Fail Secure](../Fundamentals/blast-radius-and-fail-secure.md), [Landing Zone As Defense](landing-zone-as-defense.md), [Blast Radius Reduction Patterns](blast-radius-reduction-patterns.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Lateral Movement, Privilege Escalation, Collection
> **Authorization scope:** Design blast-radius architectures in your own sandbox orgs/subscriptions/projects.

## What & why

Blast-radius reduction is the practice of partitioning your cloud estate so that one compromised account, role, or resource cannot cascade into the entire organization. An attacker who owns an entire dev account should still be zero steps from owning production.

## The OnPrem reality

On-prem blast radius was enforced physically: separate hardware, separate VLANs, zone-based firewalls with strict ACLs, and tiered AD forests. Crossing tiers required a controlled jump host with multi-factor auth. Most organizations had one flat AD forest, and lateral movement between tiers was limited only by firewall rules — not a hard token boundary.

## Core concepts — isolation layers ranked (strongest to weakest)

| Layer | Primitive | What it prevents |
|---|---|---|
| 1 | Separate Org / Tenant / Org node | Cross-org enumeration, SCP bypass, billing separation |
| 2 | OU / Management Group / Folder | SCP/Policy inheritance, guardrail bypass |
| 3 | Account / Subscription / Project | IAM escalation, cross-account trust abuse, billing blast |
| 4 | VPC / VNet / Network (no peering) | East-west lateral movement, metadata endpoint abuse |
| 5 | IAM Role / Managed Identity / SA | Trust policy chain exploitation |
| 6 | Security Group / NSG / Firewall Rule | Port/protocol lateral movement |
| 7 | Resource tags + IAM conditions | Access to specific tagged resources within an account |

## AWS — account-per-team isolation patterns

```
Management Account (111111111111)
├── Prod OU
│   ├── Prod-App-A account (222222222222)
│   │   ├── VPC-A (10.1.0.0/16)
│   │   ├── IAM Role: AppA-Runtime (only S3 + DynamoDB in 222222222222)
│   │   └── Tags: env=prod, team=app-a
│   ├── Prod-App-B account (333333333333)
│   │   ├── VPC-B (10.2.0.0/16)
│   │   └── IAM Role: AppB-Runtime (zero cross-account trust to 222222222222)
├── Dev OU
│   └── Dev-sandbox account (444444444444)
│       ├── SCP: deny sts:AssumeRole outside org
│       └── SCP: deny cloudtrail:StopLogging
├── Security OU
│   └── LogArchive account (555555555555)
│       ├── Org CloudTrail destination
│       └── SCP: deny all write except s3:PutObject (immutable log)
```

**Create a prod account programmatically:**

```bash
aws organizations create-account \
  --account-name "Prod-App-A" \
  --email "aws-prod-app-a@example.com" \
  --role-name OrganizationAccountAccessRole

aws organizations move-account \
  --account-id 222222222222 \
  --source-parent-id r-xxxx \
  --destination-parent-id ou-xxxx-prod

aws organizations attach-policy \
  --policy-id p-denyoutsideorg \
  --target-id 222222222222
```

**Cross-account trust — restricted with ExternalId:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::444444444444:root"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {"sts:ExternalId": "prod-app-a-unique-external-id-xxx"}
    }
  }]
}
```

**Region pinning SCP — limit blast radius geographically:**

```json
{
  "Sid": "DenyOutsideAllowedRegions",
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "eu-west-1"]},
    "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassRole"}
  }
}
```

**Network segmentation — no VPC peering by default:**

```bash
aws ec2 describe-vpc-peering-connections \
  --query 'VpcPeeringConnections[?Status.Code==`active`].{Acceptor:AccepterVpcInfo.VpcId,Requester:RequesterVpcInfo.VpcId}'

aws ec2 delete-vpc-peering-connection --vpc-peering-connection-id pcx-xxxxxxxxxx
```

## Azure — per-tenant SaaS isolation

**Subscription-per-tenant pattern:**

```bash
az account create \
  --name "saas-tenant-001" \
  --offer-type MS-AZR-0017P \
  --email admin@example-tenant.onmicrosoft.com

az account management-group add \
  --name "SaaS-Tenants" \
  --subscription 00000000-0000-0000-0000-000000000000

az policy assignment create \
  --name deny-public-resources \
  --policy deny-public-resources \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

**Network micro-segmentation — deny cross-VNet traffic by default:**

```json
{
  "if": {
    "allOf": [
      {"field": "type", "equals": "Microsoft.Network/virtualNetworks"},
      {"field": "Microsoft.Network/virtualNetworks/enableVmProtection", "equals": false}
    ]
  },
  "then": {"effect": "deny"}
}
```

**Resource group partitioning with Azure Policy — restrict actions by tag:**

```json
{
  "if": {
    "allOf": [
      {"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
      {"not": {"field": "tags[team]", "equals": "[parameters('teamName')]"}}
    ]
  },
  "then": {"effect": "deny"}
}
```

## GCP — per-tenant project isolation

**Create a project per tenant:**

```bash
gcloud projects create saas-tenant-001 \
  --folder=111111111111 \
  --billing-account=000000-000000-000000

gcloud projects add-iam-policy-binding saas-tenant-001 \
  --member "group:tenant-001-admins@example.com" \
  --role roles/owner

gcloud org-policies set-policy \
  --project=saas-tenant-001 \
  --policy '{
    "constraint": "constraints/compute.restrictSharedVpcSubnetworks",
    "listPolicy": {"deniedValues": ["under:folders/111111111111"]}
  }'
```

**Shared VPC with service project attachment — network-level isolation:**

```bash
gcloud compute shared-vpc enable prd-networking

gcloud compute shared-vpc associated-projects add saas-tenant-001 \
  --host-project prd-networking

gcloud compute networks subnets get-iam-policy subnet-tenant-001 \
  --region us-east1 \
  --project prd-networking
```

**IAM deny policies for extra-layer restrict:**

```yaml
# deny cross-project.yaml
name: organizations/000000000000/policies/deny-cross-project-access
spec:
  rules:
  - denyRule:
      deniedPermissions:
      - iam.googleapis.com/serviceAccounts.getAccessToken
      deniedPrincipals:
      - principalSet://goog/group/tenant-001-admins@example.com
    exceptionPrincipals:
    - principalSet://goog/group/break-glass@example.com
```

**Instance isolation — no public IPs on VMs policy:**

```bash
gcloud org-policies set-policy --organization 000000000000 \
  --policy '{
    "constraint": "constraints/compute.vmExternalIpAccess",
    "listPolicy": {"deniedValues": ["projects/prod-gateway"]}
  }'
```

## OnPrem mapping (recap table)

| Isolation layer | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Hard org boundary | Separate AD forest | Separate AWS Organization | Separate Entra ID tenant | Separate Google Org |
| Policy boundary | Domain + GPO Enforced | OU + SCP | Management Group + Azure Policy | Folder + Org Policy |
| Account boundary | Separate domain member server | Account + IAM trust policy | Subscription + RBAC scope | Project + IAM allow policy |
| Network boundary | VLAN + firewall zone | VPC (no peering) | VNet (no peering) | VPC (no peering) |
| Identity boundary | Separate AD groups / gMSA | IAM Role + trust policy conditions | Managed Identity + RBAC | Service Account + IAM conditions |
| Resource boundary | OU + GPO software restriction | Tags + IAM condition `aws:ResourceTag` | Tags + Azure Policy conditions | Labels + IAM conditions |

## 🔴 Red Team view

**When isolation lives only at IAM — no account/OU boundary.**

**Narrative (contained):**

A SaaS company uses a single AWS account for all tenants. Isolation is enforced entirely through IAM: each tenant's services assume a role with `ResourceTag/tenant-id=xxx` conditions. An attacker compromises `Tenant-A-Role` and discovers it has `iam:PassRole` to the Lambda execution role. The Lambda execution role has no tag conditions. The attacker passes the Lambda role to a new Lambda function, writes code that queries DynamoDB for all tenant data (since the table has no tag-based access control), and exfiltrates.

```
Compromised: Tenant-A-Role (resource-level IAM condition)
  -> iam:PassRole to LambdaExecRole (no tag condition)
    -> Lambda creates function with LambdaExecRole
      -> DynamoDB scan across ALL tenants (table-level IAM allows *)
```

**Why account-per-tenant would have prevented this:**
- Each tenant's DynamoDB table lives in a separate account.
- `iam:PassRole` within account A cannot cross into account B's roles.
- Even if all of Account A is owned, the attacker has zero access to Account B's data plane.

**Artifacts:**
- CloudTrail: `PassRole` from `Tenant-A-Role` to `LambdaExecRole`.
- CloudTrail: `CreateFunction` with `LambdaExecRole` by the compromised principal.
- CloudTrail: `DynamoDB.Scan` on table with `env=all` returning rows across tenants.

## 🔵 Blue Team view

**Multi-layer blast-radius risk register:**

| Scenario | Layer-1 (Org SCP) | Layer-2 (Account Boundary) | Layer-3 (IAM) | Residual blast | Mitigation |
|---|---|---|---|---|---|
| Dev sandbox key leaked | Denies `sts:AssumeRole` outside org | Blocks cross-account role assumption | Role only has `s3:GetObject` on dev bucket | One dev bucket read within that account | Acceptable |
| Prod CI/CD role compromised | Denies `iam:CreateUser`, `cloudtrail:StopLogging` | Account boundary blocks cross-env access | Role scoped to prod-app-A resources only | Prod-app-A resources only | Acceptable; rotate role |
| Security tooling admin token stolen | SCP ignores break-glass role | Cross-account trust to logging account exists | Admin role in security-tooling account | Could stop/delete logging, tamper with GuardDuty | Unacceptable — segment security into sub-accounts: logging separate from tooling |
| Management account root compromised | No SCP applies to management account | Root can detach all SCPs | Root has * in all member accounts | Total organization loss | Unacceptable — root locked with MFA, no API keys, monitored |

**Reduce blast-radius checklist:**

| # | Action | AWS | Azure | GCP |
|---|---|---|---|---|
| 1 | Account-per-tenant/environment | Organizations account per tenant | Subscription per tenant | Project per tenant |
| 2 | Disable default VPC/VNet | SCP: deny `ec2:CreateDefaultVpc` | Policy: deny classic VNet | Org policy: `skipDefaultNetworkCreation` |
| 3 | Deny cross-region unless approved | SCP: region restriction | Policy: `allowedLocations` | Org policy: `resourceLocations` |
| 4 | Limit max session duration | SCP: `aws:TokenIssueTime` condition | PIM: activation duration max 1h | IAM condition: `request.time` |
| 5 | No VPC peering to security accounts | SCP: deny `ec2:CreateVpcPeeringConnection` | Policy: deny VNet peering | Org policy: restrict shared VPC |
| 6 | Instance metadata v2 only | SCP: `ec2:MetadataHttpTokens=required` | N/A (Azure blocks by default) | GKE: `workload_metadata_config: GKE_METADATA` |

**Detect cross-boundary access attempts:**

```
-- Detect cross-account AssumeRole from dev to prod
SELECT eventTime, userIdentity.arn, requestParameters.roleArn,
       sourceIPAddress, userAgent
FROM cloudtrail_111111111111
WHERE eventName = 'AssumeRole'
  AND requestParameters.roleArn LIKE '%:role/prod-%'
  AND userIdentity.accountId IN ('444444444444')
  AND sourceIPAddress NOT IN ('10.0.0.0/8', 'approved-proxy-ip')
```

**Containment architecture — honey account trap:**

When detecting lateral movement attempts from a compromised account, redirect the attacker into a "zero-perm" honey account (see [10-04 Deception](deception-honeytokens.md)) where every API call is logged and no resources exist.

Cross-link: [00-05 Blast Radius](../Fundamentals/blast-radius-and-fail-secure.md), [10-01 Landing Zone](landing-zone-as-defense.md), [09-06 Lateral Movement](../Red-Team-Offense/lateral-movement-and-pivoting.md), [02-03 Assume-Role Chains](../IAM/assume-role-chains-and-trust-graphs.md).

## Hands-on lab

See [labs/landing-zone-mini-lab.md](labs/landing-zone-mini-lab.md) for account isolation and SCP testing.

## Detection rules & checklists

**OPA rule — deny cross-account assume-role without ExternalId:**

```rego
package terraform

deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_iam_role"
  doc := r.change.after.assume_role_policy
  stmt := doc.Statement[_]
  stmt.Effect == "Allow"
  stmt.Principal.AWS != null
  not stmt.Condition.StringEquals["sts:ExternalId"]
  msg = sprintf("%s: cross-account assume-role without ExternalId", [r.name])
}
```

**Checklist:**
- [ ] Each tenant has its own account/subscription/project.
- [ ] Dev accounts have SCP denying `sts:AssumeRole` to prod account roles.
- [ ] All cross-account trusts require `ExternalId`.
- [ ] Shared VPC/VNet projects restrict which service projects can attach.
- [ ] Default VPC/VNet is disabled in all accounts/projects.
- [ ] Security account is isolated — no workload account can assume roles into it.

## References
- [AWS Account Isolation best practices](https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/organizing-your-aws-environment.html)
- [Azure Enterprise-Scale architecture](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/enterprise-scale/)
- [GCP Resource Hierarchy](https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy)
- [MITRE ATT&CK — Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/)
