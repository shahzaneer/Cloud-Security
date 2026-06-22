# 08 — Policy-as-Code Checkers

> **Level:** Intermediate
> **Prereqs:** [Identity Primitives per Cloud](identity-primitives-per-cloud.md) through [Just In Time & Break Glass](just-in-time-and-break-glass.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Privilege Escalation
> **Authorization scope:** Identity attacks only in your own sandbox accounts / sanctioned targets.

## What & why

Manual policy reviews do not scale. Policy-as-code — running security checks in CI at PR time — is the engineering discipline that catches overly permissive IAM policies, open security groups, and misconfigured resources before deployment.

## The OnPrem reality

Before infrastructure-as-code, on-prem security validation was a checklist: review group policy objects with `gpresult`, audit firewall rules with `netsh`, scan config files with custom lint scripts. Tools like `PuppetLint`, `cookstyle`, and `grouper` (policy lint) filled the gap between manual review and automated enforcement. The lesson: if a human must remember to check it, it will be missed.

## Cross-cloud tool coverage

| Tool | AWS | Azure | GCP | Terraform | Kubernetes | OnPrem |
|---|---|---|---|---|---|---|
| Cloud Custodian (c7n) | Primary | Moderate | Emerging | No | No | No |
| Checkov (Bridgecrew) | Yes | Yes | Yes | Yes | Yes | Dockerfile, Helm |
| tfsec / Trivy | Via TF | Via TF | Via TF | Yes | No | No |
| OPA / Gatekeeper | Via rego | Via rego | Via rego | Yes | Yes | Via rego |
| KICS (Checkmarx) | Yes | Yes | Yes | Yes | Yes | Docker / Ansible |
| Azure Policy (native) | No | Native | No | Yes (export) | No | No |
| GCP Org Policy (native) | No | No | Native | No | No | No |
| AWS Config Rules (native) | Native | No | No | No | No | No |

### Policy-as-code architecture

```
Developer PR ──▶ GitHub Actions ──▶ Checkov scan ──▶ Pass? ──▶ Terraform Plan (dry-run)
                      │                     │
                      │                     ▼ Fail
                      │               Block PR with violation report
                      │
                      ▼ (post-deployment)
              Cloud Custodian (c7n) ──▶ Continuous monitoring ──▶ SIEM/Slack alert
```

## AWS

**Cloud Custodian — forbid public S3 buckets:**

```yaml
policies:
  - name: s3-bucket-public-read-prohibited
    resource: aws.s3
    filters:
      - type: bucket-ssl
    actions:
      - type: set-statements
        statements:
          - Sid: "DenyPublicRead"
            Effect: "Deny"
            Principal: "*"
            Action: "s3:GetObject"
            Resource: "arn:aws:s3:::{bucket_name}/*"
```

```bash
pip install c7n
custodian run -s output policy.yaml
```

**AWS Config — managed rule for S3 public read:**

```bash
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-public-read-prohibited",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}'
```

**Checkov — Terraform plan scan:**

```bash
# Scan Terraform plan for IAM misconfigurations
checkov -f main.tf --framework terraform

# Example finding: CKV_AWS_40 — IAM policy allows "*" on "*"
# checkov -d . --check CKV_AWS_40
```

## Azure

**Azure Policy — forbid public SSH (NSG with source 0.0.0.0/0 port 22):**

```json
{
  "properties": {
    "displayName": "Deny inbound SSH from internet",
    "policyRule": {
      "if": {
        "allOf": [
          { "field": "type", "equals": "Microsoft.Network/networkSecurityGroups/securityRules" },
          {
            "anyOf": [
              { "field": "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix", "equals": "*" },
              { "field": "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix", "equals": "0.0.0.0/0" },
              { "field": "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix", "equals": "Internet" }
            ]
          },
          { "field": "Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRange", "equals": "22" },
          { "field": "Microsoft.Network/networkSecurityGroups/securityRules/access", "equals": "Allow" },
          { "field": "Microsoft.Network/networkSecurityGroups/securityRules/direction", "equals": "Inbound" }
        ]
      },
      "then": { "effect": "deny" }
    }
  }
}
```

```bash
az policy definition create --name deny-internet-ssh --rules @policy.json
az policy assignment create --name deny-ssh --policy deny-internet-ssh --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

**OPA rego — forbid wildcard IAM (cross-cloud, applied to Terraform plan):**

```rego
package terraform.aws.iam

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    policy := resource.change.after.policy
    statements := json.unmarshal(policy).Statement[_]
    statements.Action[_] == "*"
    statements.Resource[_] == "*"
    msg := sprintf("Wildcard IAM policy denied: %s", [resource.address])
}
```

## GCP

**Org Policy — restrict IAM policy to corporate domain:**

```bash
gcloud org-policies set-policy \
  --organization 000000000000 \
  --policy-file restrict-iam-domain.yaml
```

```yaml
# restrict-iam-domain.yaml
constraint: constraints/iam.allowedPolicyMemberDomains
listPolicy:
  allowedValues:
    - "example.com"
    - "is:gserviceaccount.com"
```

**Checkov GCP example — detect public GCS buckets:**

```bash
checkov -d . --framework terraform
# CKV_GCP_29: Ensure GCP storage buckets are not publicly accessible
```

**KICS — scanning Terraform for multi-cloud misconfigurations:**

```bash
kics scan -p . -o results
# Checks across AWS, Azure, GCP, Kubernetes, Docker
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Policy lint tool | `grouper`, custom bash checks | c7n, AWS Config Rules | Azure Policy, Checkov | Org Policy Constraints, Checkov |
| CI integration | Jenkins + shellcheck + puppetlint | GitHub Actions + c7n dry-run | Azure DevOps + Checkov task | Cloud Build + Checkov/tfsec |
| Preventative (pre-deploy) | Puppet noop / GPO modeling | Terraform plan + Checkov | `az deployment what-if` + policy test | `terraform plan` + constraint dry-run |
| Detective (post-deploy) | SCCM compliance baseline | AWS Config | Azure Policy (audit effect) | Security Command Center |
| Rego/OPA support | Custom rego rules | OPA Gatekeeper + Config | OPA + Azure Policy export | OPA + Config Validator |

## 🔴 Red Team view

**Auditing tool pollution — PR-friendly policies miss specific resources.** Policy-as-code tools evaluate the Terraform/CloudFormation template as written — but not what an attacker can bypass.

**Example — `import_resource` that bypasses policy evaluation:**

```hcl
# main.tf — passes Checkov because it references a known-good security group
resource "aws_security_group" "approved_sg" {
  name        = "approved-sg"
  description = "Pre-approved SG with restricted access"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["192.0.2.0/24"]
  }
}
```

The above passes policy checks. But the attacker (or a careless dev) adds:

```hcl
# Not in main.tf — applied via a separate Terraform state or manual console action
resource "aws_security_group_rule" "open_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.approved_sg.id
}
```

The `security_group_rule` resource is evaluated independently by some scanners. If Checkov only checks `aws_security_group` resources and not `aws_security_group_rule`, the open rule passes unnoticed.

**Legacy resources imported after-the-fact:**

```bash
# Attacker imports an existing public S3 bucket into the state
# so Terraform manages it — but Checkov only scans changes in the PR diff.
terraform import aws_s3_bucket.legacy_bucket existing-bucket-name
```

If the CI pipeline only scans `terraform plan` output (changes only), not the full state, the imported public bucket survives undetected.

**Artifacts:** The Terraform state file now contains the imported public resource. CloudTrail records the `import` API calls. A full-state scan (e.g., `checkov --directory . --soft-fail-on ...`) would catch it, but PR-diff-only scans won't.

**Defensive pairing:** Run `checkov` against the full plan, not just the diff. Use `terraform plan -refresh-only` to detect drift between state and reality as part of CI.

## 🔵 Blue Team view

**Pre-deployment hook that catches the bypass above:**

```yaml
# .github/workflows/terraform-plan.yml
name: Terraform Security Scan
on:
  pull_request:
    paths:
      - 'terraform/**'

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Checkov on full plan
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          framework: terraform
          output_format: json
          soft_fail: false  # Hard fail on violations

      - name: Terraform Plan (dry-run only)
        run: |
          cd terraform
          terraform init -backend=false
          terraform plan -input=false -out=plan.tfplan

      - name: Scan the plan file (catches imported resources)
        run: |
          cd terraform
          terraform show -json plan.tfplan | checkov -f - --framework terraform_plan
```

**OPA Gatekeeper — prevent wildcard IAM in Kubernetes (K8s specific):**

```rego
package k8s.rbac

deny[msg] {
    input.kind == "RoleBinding"
    subject := input.subjects[_]
    subject.kind == "ServiceAccount"
    role := input.roleRef.name
    # Deny if SA gets cluster-admin
    role == "cluster-admin"
    msg := sprintf("ServiceAccount %s cannot be bound to cluster-admin", [subject.name])
}
```

**Post-deployment continuous monitoring with c7n:**

```yaml
# c7n-custodian.yml — hourly scan for public resources
policies:
  - name: detect-public-s3
    resource: aws.s3
    mode:
      type: periodic
      schedule: "rate(1 hour)"
      role: arn:aws:iam::111111111111:role/CustodianExecutionRole
    filters:
      - type: bucket-ssl
    actions:
      - type: notify
        template: default
        priority_header: 1
        subject: "Public S3 bucket detected - [account_id] [region]"
        to:
          - security@example.com
          - slack://#security-alerts
```

**CI integration — sample GitHub Actions step:**

```yaml
- name: Checkov IAM scan
  run: |
    checkov -d terraform/ --check CKV_AWS_40,CKV_AWS_41,CKV_AWS_62 --soft-fail
    # CKV_AWS_40: IAM policy allows "*" actions
    # CKV_AWS_41: IAM policy attached to user instead of group/role
    # CKV_AWS_62: IAM role missing permission boundary
```

**Checklist:**
- [ ] Policy-as-code runs on every PR before merge (Checkov, tfsec, or KICS).
- [ ] Scanner evaluates full Terraform plan, not just changed resources.
- [ ] Cloud Custodian (or equivalent) runs continuously to detect drift.
- [ ] All four clouds covered in the scanning toolchain.
- [ ] Policy violations in CI block the PR (hard fail) — no `soft-fail` in production repos.

## Hands-on lab

**Run Checkov against a deliberately vulnerable Terraform template:**

```bash
mkdir /tmp/checkov-lab && cd /tmp/checkov-lab

cat > main.tf << 'EOF'
provider "aws" {
  region = "us-east-1"
}

# Vulnerable: wildcard IAM policy
resource "aws_iam_policy" "bad_policy" {
  name = "bad-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# Vulnerable: public S3 bucket
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket-111111111111"
}

resource "aws_s3_bucket_public_access_block" "public_bucket_block" {
  bucket = aws_s3_bucket.public_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
EOF

# Run Checkov
pip install checkov
checkov -f main.tf --framework terraform

# Expected: multiple failures (CKV_AWS_40 for wildcard IAM, CKV_AWS_55 for public S3, etc.)
```

**Fix the violations and re-scan:**

```hcl
resource "aws_iam_policy" "good_policy" {
  name = "good-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::specific-bucket/*"]
    }]
  })
}
```

**Teardown:**
```bash
rm -rf /tmp/checkov-lab
```

## Detection rules & checklists

**c7n — enforce IAM user key rotation:**

```yaml
policies:
  - name: iam-keys-not-rotated
    resource: iam-user
    filters:
      - type: credential
        key: access_keys.active
        value: true
      - type: credential
        key: access_keys.last_rotated
        value_type: age
        op: gt
        value: 90
    actions:
      - type: notify
        to:
          - security@example.com
```

**tfsec — enable via pre-commit hook:**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/aquasecurity/tfsec
    rev: v1.28.0
    hooks:
      - id: tfsec
```

## References
- [Cloud Custodian](https://cloudcustodian.io/docs/)
- [Checkov](https://www.checkov.io/)
- [OPA / Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)
- [tfsec](https://github.com/aquasecurity/tfsec)
- [KICS](https://docs.kics.io/)
- [AWS Config Rules](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html)
- [Azure Policy](https://learn.microsoft.com/en-us/azure/governance/policy/overview)
