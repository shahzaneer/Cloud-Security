# 01 — Landing Zone as Defense

> **Level:** Intermediate
> **Prereqs:** [Blast Radius & Fail Secure](../Fundamentals/blast-radius-and-fail-secure.md), [Permission Boundaries & Quarantine](../IAM/permission-boundaries-and-quarantine.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Persistence, Privilege Escalation
> **Authorization scope:** Run only in your own sandbox accounts with Organizations/Folder/Management Group permissions.

## What & why

A landing zone is the security architecture of your cloud organization — the OU structure, guardrails, logging infrastructure, and account provisioning patterns that define your blast-radius blueprint. Building it correctly first is ~10× cheaper than retrofitting guardrails onto a flat, uncontrolled multi-account sprawl.

## The OnPrem reality

On-prem, the landing-zone analogue was Active Directory forest design: root domain, child domains per business unit, GPO inheritance blocked at the OU level, separate management forests for Tier-0 (domain controllers), Tier-1 (servers), Tier-2 (workstations), and a delegated administration model via AdminSDHolder. A "flat" AD — one domain, one OU, everyone in Domain Admins — was the pre-cloud equivalent of a single-account, no-OU cloud deployment.

## Core concepts

```
Organization Root (management account / root management group / org node)
├── Security OU (logging, security tooling, audit — no workloads)
│   ├── Log Archive Account (CloudTrail org trail, immutable bucket)
│   └── Security Tooling Account (GuardDuty admin, Security Hub, Sentinel, SCC)
├── Infrastructure OU (shared services: networking, CI/CD, identity)
│   ├── Network Account (Transit Gateway, Azure Virtual WAN, Shared VPC)
│   └── Identity Account (IAM Identity Center, Entra ID, Cloud Identity)
├── Workloads OU (one per environment — dev, staging, prod)
│   ├── Workload Account A (app team; restrictive SCPs)
│   └── Workload Account B
├── Sandbox OU (developer sandboxes; tight spend limits, no prod access)
└── Suspended OU (quarantine destination for compromised accounts)
```

| Landing-zone property | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Root container | Organization | Root Management Group | Organization node | Forest root |
| Sub-containers | OUs | Management Groups | Folders | OUs / Domains |
| Guardrail primitive | SCP | Azure Policy | Org Policy constraints | GPO |
| Account factory | Control Tower Account Factory | Azure landing-zone subscription vending | Project Factory (Cloud Foundation Toolkit) | SCCM OS deployment |
| Baseline product | AWS Control Tower | Azure CAF landing zone (Bicep/Terraform) | GCP Landing Zone (Terraform/CFT) | AD tiered model |
| Log archive | Organization CloudTrail → central S3 | Log Analytics workspace per subscription → central | Aggregated sink → central logging project | SIEM collector |
| Network hub | AWS Transit Gateway + Network Firewall | Azure Virtual WAN + Firewall | Shared VPC + Cloud NGFW | Core switch/distribution layer |

## AWS

AWS Control Tower automates landing-zone creation: it provisions a management account, creates the foundational OUs (`Security`, `Sandbox`, plus customizable `Workloads`), enables mandatory guardrails (preventive + detective), and sets up central logging.

**Terraform minimal landing zone (no Control Tower):**

```hcl
resource "aws_organizations_organization" "main" {
  feature_set = "ALL"
}

resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_account" "log_archive" {
  name      = "LogArchive"
  email     = "aws-logarchive@example.com"
  parent_id = aws_organizations_organizational_unit.security.id
}

resource "aws_organizations_organizational_unit" "suspended" {
  name      = "Suspended"
  parent_id = aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_policy" "deny_leave_org" {
  name    = "DenyLeaveOrganization"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyLeaveOrg"
      Effect = "Deny"
      Action = ["organizations:LeaveOrganization"]
      Resource = ["*"]
    }]
  })
}

resource "aws_organizations_policy_attachment" "security_attach" {
  policy_id = aws_organizations_policy.deny_leave_org.id
  target_id = aws_organizations_organizational_unit.security.id
}
```

**Mandatory Control Tower guardrails (partial list):**

| Guardrail | Type | Effect |
|---|---|---|
| Disallow actions as root user | Preventive SCP | Blocks root user API calls in member accounts |
| Enable CloudTrail in all accounts | Detective | AWS Config rule checks CloudTrail is enabled |
| Detect public S3 buckets | Detective | Config rule `s3-bucket-public-read-prohibited` |
| Disallow deletion of VPC flow logs | Preventive SCP | Blocks `ec2:DeleteFlowLogs` |
| Require MFA for the root user | Detective | Config rule checks `root-has-mfa-enabled` |

> (as of June 2026, the Control Tower mandatory guardrail list is updated per AWS release; check the current [Control Tower guardrails reference](https://docs.aws.amazon.com/controltower/latest/userguide/guardrails-reference.html) for the complete list.)

## Azure

Azure landing zones follow the Cloud Adoption Framework (CAF). The reference architecture places management groups under the root:

```
Root Management Group (Tenant Root Group)
├── Platform (Connectivity, Identity, Management)
│   ├── Connectivity (hub vnet, firewall)
│   ├── Identity (Entra ID DS)
│   └── Management (Log Analytics, Sentinel, Automation)
├── Landing Zones (corp, online, SAP)
│   ├── Corp (internal apps)
│   └── Online (internet-facing apps)
├── Sandbox
└── Decommissioned
```

**Azure Policy assignment at management group level:**

```bash
az policy definition create \
  --name deny-public-ip \
  --mode All \
  --rules '{
    "if": {"field": "type", "equals": "Microsoft.Network/publicIPAddresses"},
    "then": {"effect": "deny"}
  }'

az policy assignment create \
  --name deny-public-ip-corp \
  --policy deny-public-ip \
  --scope /providers/Microsoft.Management/managementGroups/Corp
```

**Bicep landing zone subscription vending:**

```bicep
targetScope = 'managementGroup'

resource sub 'Microsoft.Subscription/aliases@2021-10-01' = {
  name: 'sub-landingzone-001'
  properties: {
    displayName: 'LZ-Corp-Prod-001'
    billingScope: '/providers/Microsoft.Billing/billingAccounts/00000000/enrollmentAccounts/00000000'
    managementGroupId: 'Corp'
    workload: 'Production'
  }
}
```

**Gotcha:** Subscription vending requires billing permissions at the EA/MCA scope, not just RBAC. Plan the vending identity carefully.

## GCP

GCP Landing Zone uses the Cloud Foundation Toolkit (CFT) or Terraform modules. The hierarchy is:

```
Organization
├── Folder: production
│   ├── Project: prd-networking (Shared VPC host)
│   ├── Project: prd-logging (log sink destination)
│   ├── Project: prd-security (SCC, audit resources)
│   └── Project: prd-app-01 (workload)
├── Folder: non-production
│   ├── Project: dev-app-01
│   └── Project: stg-app-01
└── Folder: sandbox
```

**Terraform GCP landing zone foundation:**

```hcl
resource "google_folder" "production" {
  display_name = "Production"
  parent       = "organizations/000000000000"
}

resource "google_folder" "security" {
  display_name = "Security"
  parent       = "organizations/000000000000"
}

resource "google_project" "log_archive" {
  name       = "prd-logging"
  project_id = "prd-logging-abc123"
  folder_id  = google_folder.security.id
  billing_account = "000000-000000-000000"
}

resource "google_organization_policy" "deny_sa_key_creation" {
  org_id     = "000000000000"
  constraint = "constraints/iam.disableServiceAccountKeyCreation"

  boolean_policy {
    enforced = true
  }
}
```

**Org-level logging sink:**

```bash
gcloud logging sinks create org-logs \
  storage.googleapis.com/prd-logging-logs \
  --organization=000000000000 \
  --include-children \
  --log-filter='logName:activity OR logName:data_access'
```

**Gotcha:** Org-level sinks require `roles/logging.configWriter` at the org level, and the destination bucket must grant write access to the sink's writer identity.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Hierarchy root | Forest | Organization | Root Management Group | Organization node |
| Policy enforcement boundary | Domain/OU + GPO Enforced | OU + SCP | Management Group + Azure Policy | Folder + Org Policy |
| Account/project factory | SCCM/PXE boot | Control Tower Account Factory | Subscription vending | Project Factory / CFT |
| Log centralization | SIEM forwarders | Org CloudTrail → central S3 | Log Analytics → central workspace | Aggregated sink → central project |
| Immutable logging | WORM storage + SIEM | S3 Object Lock + CloudTrail | Immutable blob storage | Bucket retention policy + audit logs |
| Security baseline scanner | Nessus/Qualys on-prem | Security Hub + AWS Config | Defender for Cloud + Azure Policy | SCC + Security Health Analytics |
| Quarantine destination | Disabled OU + GPO block | Suspended OU + Deny * SCP | Decommissioned MG + Deny policy | Suspended folder + Deny * constraint |

## 🔴 Red Team view

Landing zone weaknesses attackers exploit — a flat account structure without security boundaries.

**Narrative (contained):**

A company provisions accounts via a self-service portal. The portal creates all accounts in a single `Workloads` OU with no SCPs. Every account shares the same CloudTrail trail configured in the management account. An attacker compromises a developer's IAM User in the `sandbox-prod` account. Because of the flat structure:

1. The sandbox account has no SCP restricting cross-account `sts:AssumeRole`. The attacker enumerates all accounts in the organization via `organizations:ListAccounts`.
2. The attacker discovers a trust policy in the `security-tooling` account that allows role assumption from `sandbox-prod` — the trust was designed for a legitimate CI/CD pipeline but was left over-broad.
3. The attacker assumes the role and discovers it has `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail` permissions.
4. The attacker stops the organization trail, obscuring all subsequent activity.

**Why landing-zone design would have prevented this:**
- The `Security` OU would have an SCP denying `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail`.
- The `Sandbox` OU would have an SCP denying `sts:AssumeRole` except to explicit allow-listed targets.
- Separation of the logging account from the security-tooling account would mean no single compromise could disable both detection and logging.

**Artifacts:**
- CloudTrail: `ListAccounts`, `AssumeRole`, `StopLogging` events before trail silence.
- The `AssumeRole` source is the compromised sandbox account; the target is the security-tooling account.

## 🔵 Blue Team view

**Landing-zone hardening checklist (cross-cloud):**

| # | Control | AWS | Azure | GCP |
|---|---|---|---|---|
| 1 | Separate logging account/project | Dedicated LogArchive account in Security OU | Separate Log Analytics workspace per landing zone | Dedicated logging project under Security folder |
| 2 | Deny CloudTrail/audit log disable | SCP: Deny `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail` | Azure Policy: deny `Microsoft.Insights/diagnosticSettings/delete` | Org policy: deny `logging.sinks.delete` |
| 3 | Deny leaving the organization | SCP: Deny `organizations:LeaveOrganization` | Azure Policy: deny subscription moving | Org policy: deny project deletion/move |
| 4 | Restrict region | SCP: Deny `*` if `aws:RequestedRegion` not in allow-list | Azure Policy: `allowedLocations` | Org policy: `constraints/gcp.resourceLocations` |
| 5 | Enforce SCP/Policy on all OUs/mgmt groups | Attach to every OU (no unattached OUs) | Assign to every management group | Enforce at org or folder level |
| 6 | Account creation hook → baseline auto-apply | EventBridge on `CreateAccount` → Lambda attach SCPs | Azure Policy auto-assign at management group | GCP project creation → Cloud Function attach org policies |
| 7 | Root user / Global Admin MFA enforced | SCP + Config rule | PIM + Conditional Access policy | Cloud Identity 2FA enforced |

**Account-birth automation (AWS EventBridge → Terraform baseline):**

```bash
aws events put-rule --name NewAccountCreated \
  --event-pattern '{
    "source": ["aws.organizations"],
    "detail-type": ["AWS Service Event via CloudTrail"],
    "detail": {"eventName": ["CreateManagedAccount"]}
  }'

aws events put-targets --rule NewAccountCreated \
  --targets "Id=1,Arn=arn:aws:lambda:us-east-1:111111111111:function:ApplyBaselinePolicy"
```

**Audit one-liner — verify no unattached OUs:**

```bash
aws organizations list-organizational-units-for-parent \
  --parent-id $(aws organizations list-roots --query 'Roots[0].Id' --output text) \
  --query 'OrganizationalUnits[*].Id' --output text | \
  xargs -I {} aws organizations list-policies-for-target \
  --target-id {} --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[].Name' --output text
```

**Detection queries:**

```
-- Detect OU creation outside change window
SELECT eventTime, userIdentity.arn, requestParameters.name
FROM cloudtrail_111111111111
WHERE eventName = 'CreateOrganizationalUnit'
  AND eventTime NOT BETWEEN '2026-06-22T02:00:00Z' AND '2026-06-22T06:00:00Z'

-- Azure: detect management group creation
AzureActivity
| where OperationNameValue == "MICROSOFT.MANAGEMENT/MANAGEMENTGROUPS/WRITE"
| where TimeGenerated !between (datetime(2026-06-22 02:00:00) .. datetime(2026-06-22 06:00:00))
```

Cross-link: [02-06 Permission Boundaries & Quarantine](../IAM/permission-boundaries-and-quarantine.md), [00-05 Blast Radius](../Fundamentals/blast-radius-and-fail-secure.md), [06-02 CloudTrail](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md).

## Hands-on lab

See [`labs/landing-zone-mini-lab.md`](labs/landing-zone-mini-lab.md).

## Detection rules & checklists

**Cloud Custodian — detect accounts not in an OU with SCPs:**

```yaml
policies:
  - name: accounts-missing-scp
    resource: account
    filters:
      - type: value
        key: Policies
        value: empty
```

**Checklist:**
- [ ] Every OU/Management Group/Folder has at least one preventive policy attached.
- [ ] Logging account/project is in a separate OU/Folder from workloads.
- [ ] `cloudtrail:StopLogging` / `logging.sinks.delete` is denied organization-wide.
- [ ] `organizations:LeaveOrganization` / subscription move is blocked.
- [ ] Root user / Global Admin MFA is enforced and monitored.
- [ ] Suspended/Decommissioned container exists and is tested quarterly.

## References
- [AWS Control Tower](https://docs.aws.amazon.com/controltower/latest/userguide/what-is-control-tower.html)
- [Azure CAF Landing Zones](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/)
- [GCP Landing Zone (CFT)](https://cloud.google.com/architecture/landing-zones)
- [MITRE ATT&CK — Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)
