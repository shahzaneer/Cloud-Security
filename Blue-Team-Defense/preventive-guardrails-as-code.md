# 02 — Preventive Guardrails as Code

> **Level:** Intermediate–Advanced
> **Prereqs:** [Permission Boundaries & Quarantine](../IAM/permission-boundaries-and-quarantine.md), [Policy As Code Rego Sentinel](../IaC-Security/policy-as-code-rego-sentinel.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Privilege Escalation, Defense Evasion, Persistence
> **Authorization scope:** Deploy guardrail policies only in your own sandbox organizations/directories.

## What & why

Preventive guardrails are policy artifacts that *deny* dangerous actions before they reach the API — not audit, not alert. They are the strongest control available: a denied API call never executes, regardless of IAM permissions. Without them, your infrastructure is protected only by hope and IAM accidental correctness.

## The OnPrem reality

On-prem preventive enforcement came from Group Policy (GPO) — domain-wide password policy, restricted group membership, firewall rules, software restriction policies. A misconfigured GPO with "Enforced" set would propagate and override child-OUs. The limitation: GPOs were OS-level and didn't protect cloud APIs. The migration to cloud lifted-and-shifted the need: infrastructure objects (S3 buckets, VMs, service accounts) needed the same "can't do it" enforcement as AD had for workstation policies.

## Cross-cloud comparison — the preventive primitive

| Provider | Preventive primitive | How it works | Can users override? | Static-analysis tool |
|---|---|---|---|---|
| AWS | SCP (Service Control Policy) | Attached to OU/Account; evaluates all IAM principals in that scope | Root in management account can detach | `aws iam simulate-principal-policy` |
| Azure | Azure Policy (deny effect) | Assigned at management group/subscription/resource group level | Global Admin can modify assignments | `az policy compliance` / `OPA` on ARM |
| Azure | Deny Assignments (Blueprints) | RBAC deny; blocks even Admin | Only platform owner (Blueprint) | Azure CLI `list`-only |
| GCP | Org Policy constraints | Boolean/list constraint enforced at org/folder/project | Org Policy Admin can modify | `gcloud beta org-policies` simulate |
| GCP | IAM Deny policies (conditions) | IAM condition that evaluates to deny | IAM Admin can remove condition | `gcloud iam policies lint` |
| OnPrem | OPA/Gatekeeper (K8s) / GPO | Admission control + registry key enforcement | Cluster admin / Domain Admin | `conftest test` / `gplink` audit |

## AWS — SCP catalog (6 canonical deny policies)

### 1. Deny public S3

```json
{
  "Sid": "DenyPublicS3",
  "Effect": "Deny",
  "Action": ["s3:PutBucketAcl", "s3:PutBucketPolicy", "s3:PutBucketPublicAccessBlock"],
  "Resource": "*",
  "Condition": {
    "StringEqualsIfExists": {
      "s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]
    }
  }
}
```

### 2. Deny unencrypted EBS

```json
{
  "Sid": "DenyUnencryptedEBS",
  "Effect": "Deny",
  "Action": ["ec2:RunInstances", "ec2:CreateVolume"],
  "Resource": "*",
  "Condition": {
    "BoolIfExists": {"ec2:Encrypted": "false"}
  }
}
```

### 3. Deny regions outside allow-list

```json
{
  "Sid": "DenyDisallowedRegions",
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:RequestedRegion": ["us-east-1", "us-east-2", "eu-west-1"]
    },
    "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassRole"}
  }
}
```

### 4. Deny IAM user creation (enforce SSO)

```json
{
  "Sid": "DenyIAMUserCreation",
  "Effect": "Deny",
  "Action": ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"],
  "Resource": "*"
}
```

### 5. Enforce IMDSv2

```json
{
  "Sid": "DenyIMDSv1",
  "Effect": "Deny",
  "Action": ["ec2:RunInstances"],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "ec2:MetadataHttpTokens": "required"
    }
  }
}
```

### 6. Deny CloudTrail disable

```json
{
  "Sid": "DenyStopLogging",
  "Effect": "Deny",
  "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"],
  "Resource": "*"
}
```

**Attach SCP to OU:**

```bash
aws organizations attach-policy \
  --policy-id p-xxxxxxxxxx \
  --target-id ou-xxxxxxxxxx
```

## Azure — Azure Policy catalog (6 deny definitions)

### 1. Deny public blob storage

```json
{
  "if": {
    "allOf": [
      {"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
      {"field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", "equals": true}
    ]
  },
  "then": {"effect": "deny"}
}
```

### 2. Deny unencrypted managed disks

```json
{
  "if": {
    "allOf": [
      {"field": "type", "equals": "Microsoft.Compute/disks"},
      {"field": "Microsoft.Compute/disks/encryption.type", "equals": "NotEncrypted"}
    ]
  },
  "then": {"effect": "deny"}
}
```

### 3. Restrict allowed locations

```json
{
  "if": {
    "field": "location",
    "notIn": ["eastus", "eastus2", "westeurope"]
  },
  "then": {"effect": "deny"}
}
```

### 4. Deny classic resources (ARM only)

```json
{
  "if": {
    "field": "type",
    "in": [
      "Microsoft.ClassicCompute/virtualMachines",
      "Microsoft.ClassicStorage/storageAccounts",
      "Microsoft.ClassicNetwork/virtualNetworks"
    ]
  },
  "then": {"effect": "deny"}
}
```

### 5. Deny VMs without Azure Monitor agent

```json
{
  "if": {
    "allOf": [
      {"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
      {
        "anyOf": [
          {"field": "Microsoft.Compute/virtualMachines/extensions.type", "notEquals": "AzureMonitorWindowsAgent"},
          {"field": "Microsoft.Compute/virtualMachines/extensions.provisioningState", "notEquals": "Succeeded"}
        ]
      }
    ]
  },
  "then": {"effect": "deny"}
}
```

### 6. Deny activity log diagnostic settings deletion

```json
{
  "if": {
    "field": "type",
    "equals": "Microsoft.Insights/diagnosticSettings"
  },
  "then": {"effect": "deny"}
}
```

**Assign at management group:**

```bash
az policy assignment create \
  --name deny-public-blob \
  --policy deny-public-blob \
  --scope /providers/Microsoft.Management/managementGroups/Corp
```

## GCP — Org Policy catalog (6 constraints)

### 1. Deny public bucket IAM

```bash
gcloud org-policies set-policy --organization 000000000000 \
  --policy '{
    "constraint": "constraints/storage.publicAccessPrevention",
    "booleanPolicy": {"enforced": true}
  }'
```

### 2. Require CMEK on resources

```bash
gcloud org-policies set-policy --organization 000000000000 \
  --policy '{
    "constraint": "constraints/gcp.restrictNonCmekServices",
    "listPolicy": {"deniedValues": ["all"]}
  }'
```

### 3. Restrict resource locations

```bash
gcloud org-policies set-policy --organization 000000000000 \
  --policy '{
    "constraint": "constraints/gcp.resourceLocations",
    "listPolicy": {"allowedValues": ["in:us-locations", "in:eu-locations"]}
  }'
```

### 4. Disable service account key creation

```bash
gcloud org-policies set-policy --organization 000000000000 \
  --policy '{
    "constraint": "constraints/iam.disableServiceAccountKeyCreation",
    "booleanPolicy": {"enforced": true}
  }'
```

### 5. Disable default VPC creation

```bash
gcloud org-policies set-policy --organization 000000000000 \
  --policy '{
    "constraint": "constraints/compute.skipDefaultNetworkCreation",
    "booleanPolicy": {"enforced": true}
  }'
```

### 6. Restrict allowed IAM member domains

```bash
gcloud org-policies set-policy --organization 000000000000 \
  --policy '{
    "constraint": "constraints/iam.allowedPolicyMemberDomains",
    "listPolicy": {
      "allowedValues": ["example.com", "is:gserviceaccount.com"]
    }
  }'
```

## OnPrem — OPA/Gatekeeper examples

### 1. OPA deny public S3 (Terraform plan check)

```rego
package terraform

deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_s3_bucket"
  r.change.after.acl == "public-read"
  msg = sprintf("bucket %s must not be public-read", [r.name])
}
```

### 2. Gatekeeper deny hostPath volumes

```rego
package k8srequiredlabels

violation[msg] {
  input.review.object.spec.volumes[_].hostPath
  msg = "hostPath volumes are denied"
}
```

## OnPrem mapping (recap table)

| Guardrail category | OnPrem GPO/OPA | AWS SCP | Azure Policy | GCP Org Policy |
|---|---|---|---|---|
| Public data exposure | OPA on state file | `s3:PutBucketAcl` deny | `allowBlobPublicAccess` deny | `storage.publicAccessPrevention` |
| Encryption mandate | GPO BitLocker enforcement | `ec2:Encrypted` condition | `encryption.type` field check | `restrictNonCmekServices` |
| Region restriction | N/A (on-prem has no regions) | `aws:RequestedRegion` | `location` field check | `gcp.resourceLocations` |
| IAM key creation block | GPO: disable local admin creation | `iam:CreateAccessKey` deny | Condition on App Registration secret | `iam.disableServiceAccountKeyCreation` |
| Logging protection | GPO: restrict service stop | `cloudtrail:StopLogging` deny | `diagnosticSettings` deny | `logging.sinks.delete` forbid |
| SSO-only (no local users) | GPO: restrict local accounts | `iam:CreateUser` deny | Entra ID-only (no Azure AD B2C) | `constraints/iam.allowedPolicyMemberDomains` |

## 🔴 Red Team view

**Bypass technique: audit-not-deny guardrails.** When a guardrail is set to `audit` effect (Azure) or is a Config rule (AWS, detective-only), an attacker can trigger the violation and the alert fires — but the action succeeds.

**Narrative (contained):**

An organization has an Azure Policy with `"effect": "audit"` for public storage accounts. The SOC receives alerts for non-compliant resources but has a 72-hour remediation SLA. An attacker compromises a contributor role and creates a public blob container. The audit alert fires but the container is publicly accessible. The attacker exfiltrates data before the SOC investigates.

**SCP composability bypass (contained):**

An attacker identifies that SCP "A" denies `s3:PutBucketAcl` only for `public-read` and `public-read-write`, but not `authenticated-read`. The attacker creates a bucket, applies `authenticated-read`, then writes a bucket policy granting `Principal: *` access. The SCP-gap: SCP blocks ACL-based public access but not policy-based public access.

```json
// Gap: this SCP does not block s3:PutBucketPolicy
{
  "Sid": "DenyPublicACL",
  "Effect": "Deny",
  "Action": ["s3:PutBucketAcl"],
  "Resource": "*"
}
```

The attacker bypasses it:

```bash
aws s3api put-bucket-policy --bucket exfil-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::exfil-bucket/*"
  }]
}'
```

**Artifacts:**
- CloudTrail: `PutBucketPolicy` succeeds; `PutBucketAcl` is never called.
- The bucket has public access via policy, not ACL — CSPM tools that only check ACLs miss it.
- Remediation playbook applied `PutPublicAccessBlock` and rolled it back.

## 🔵 Blue Team view

**Strong-stack: all guardrails must be `deny` and tested monthly in CI.**

```bash
# AWS: test that a test user cannot make a bucket public
aws sts assume-role --role-arn arn:aws:iam::111111111111:role/GuardrailTestRole \
  --role-session-name "guardrail-test"
export AWS_ACCESS_KEY_ID=...
aws s3api create-bucket --bucket guardrail-test-bucket-11111 --region us-east-1
aws s3api put-bucket-acl --bucket guardrail-test-bucket-11111 --acl public-read
# Expected: AccessDenied — SCP blocked it

# Azure: test policy enforcement
az storage account create --name guardrailtest001 --resource-group rg-test \
  --allow-blob-public-access true
# Expected: RequestDisallowedByPolicy

# GCP: test org policy
gcloud org-policies describe constraints/storage.publicAccessPrevention \
  --organization=000000000000
gcloud storage buckets create gs://guardrail-test-bucket --project=prd-test-111
gcloud storage buckets add-iam-policy-binding gs://guardrail-test-bucket \
  --member=allUsers --role=roles/storage.objectViewer
# Expected: FAILED_PRECONDITION
```

**Policy-as-code library (Terraform module):**

```hcl
module "guardrails" {
  source = "github.com/example/terraform-cloud-guardrails"

  enable_deny_public_s3     = true
  enable_deny_unencrypted    = true
  enable_deny_regions        = true
  allowed_regions            = ["us-east-1", "eu-west-1"]
  enable_deny_iam_user_create = true

  targets = [
    aws_organizations_organizational_unit.workloads.id,
    aws_organizations_organizational_unit.sandbox.id
  ]
}
```

**Monthly CI guardrail test:**

```yaml
# .github/workflows/guardrail-test.yml
name: Monthly Guardrail Validation
on:
  schedule: [{cron: "0 0 1 * *"}]

jobs:
  test-guardrails:
    strategy:
      matrix:
        cloud: [aws, azure, gcp]
        policy:
          - deny-public-s3
          - deny-unencrypted-ebs
          - deny-regions
    steps:
      - name: Assume test role
        run: |
          # For each cloud/policy, attempt the prohibited action
          # Assert: AccessDenied / RequestDisallowed / FAILED_PRECONDITION
      - name: Alert on pass-through
        if: success()
        run: |
          curl -X POST "$SLACK_WEBHOOK" -d '{"text":"CRITICAL: Guardrail ${matrix.policy} on ${matrix.cloud} allowed a prohibited action!"}'
```

**Audit — detect policy assignments being removed:**

```
-- AWS: SCP detachment
SELECT eventTime, userIdentity.arn, requestParameters.policyId, requestParameters.targetId
FROM cloudtrail_111111111111
WHERE eventName = 'DetachPolicy'

-- Azure: policy assignment deletion
AzureActivity
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS/DELETE"
| project TimeGenerated, Caller, ResourceId

-- GCP: org policy removed
SELECT timestamp, protoPayload.authenticationInfo.principalEmail
FROM cloudaudit_000000000000
WHERE protoPayload.methodName = "SetOrgPolicy"
  AND protoPayload.request.spec.etag = ""
```

**Checklist:**
- [ ] Every guardrail uses `deny` effect, not `audit`/`deployIfNotExists`.
- [ ] SCPs cover ACLs, bucket policies, and public access to all storage services.
- [ ] Monthly CI job verifies all guardrails still block prohibited actions.
- [ ] Policy detachment events page on-call immediately.
- [ ] Guardrail policies stored as code in version control, applied via CI/CD.

Cross-link: [02-06 Permission Boundaries & Quarantine](../IAM/permission-boundaries-and-quarantine.md), [08-04 Policy-as-Code with OPA/Sentinel](../IaC-Security/policy-as-code-rego-sentinel.md), [06-07 Detection-as-Code](../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md).

## Hands-on lab

Apply an SCP denying public S3 buckets and test it. See [10-01 lab](labs/landing-zone-mini-lab.md) which includes SCP testing.

## Detection rules & checklists

**Cloud Custodian — detect buckets that bypassed the guardrail:**

```yaml
policies:
  - name: public-buckets-guardrail-bypass
    resource: s3
    filters:
      - type: bucket-policy
        key: "Statement[].Principal"
        op: contains
        value: "*"
      - type: event
        key: eventName
        value: "PutBucketPolicy"
```

## References
- [AWS SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [Azure Policy effects](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects)
- [GCP Org Policy constraints](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints)
- [OPA — Rego policy language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [MITRE ATT&CK — Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/)
