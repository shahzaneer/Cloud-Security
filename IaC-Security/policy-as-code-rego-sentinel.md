# 04 — Policy-as-Code: Rego & Sentinel

> **Level:** Advanced
> **Prereqs:** [02-08 — Policy-as-Code Checkers](../IAM/policy-as-code-checkers.md), [08-05 — Static Analysis Checkov/tfsec](./static-analysis-checkov-tfsec.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Execution, Privilege Escalation
> **Authorization scope:** Run policies against your own Terraform plans and sandbox infrastructure only.

## What & why

Policy-as-code lets you define rules that block non-compliant infrastructure before it's deployed — or detect it after. Three dominant engines exist: **OPA/Rego** (open-source, plan-time and runtime), **Sentinel** (Terraform Cloud/Enterprise, plan-time only), and **native cloud policy** (Azure Policy, GCP Org Policy, AWS SCPs). Each targets a different phase: PR preview (shift-left), apply gating, or continuous runtime detection.

## The OnPrem reality

CFEngine promise theory was the original policy-as-code: every node declared its desired state in a DSL, and the agent continuously reconciled. If a resource drifted — a file changed, a process stopped — CFEngine corrected it. Cloud policy-as-code inherits this philosophy but adds admission control (block before deploy) and multi-cloud portability.

```bash
# CFEngine promise — original policy-as-code (circa 1993)
bundle agent sshd_config {
  files:
    "/etc/ssh/sshd_config"
      perms => mog("600", "root", "root"),
      handle => "sshd_config_perms",
      comment => "SSH config must not be world-readable";
}
```

## Core engine comparison

| Dimension | OPA / Rego (Conftest) | Sentinel (TFC/TFE) | Azure Policy | GCP Org Policy | Cloud Custodian |
|---|---|---|---|---|---|
| Scope | Plan files + live API | Terraform plan only | Live ARM resources (Azure) | Live GCP resources | Live resources (multi-cloud) |
| Language | Rego (Prolog-like Datalog) | Sentinel (policy DSL, imperative-ish) | JSON (policy definition) | YAML constraint | YAML DSL |
| Evaluation point | PR plan, pre-apply, runtime | PR plan, Sentinel-in-TFC | Resource create/update, drift | Resource create, drift | Scheduled or event-driven |
| Drift detection | No native — pair with live eval | No | Yes (policy compliance state) | Yes (constraint violations) | Yes (periodic + event-driven) |
| Open source | Yes (CNCF graduated) | No (proprietary to HashiCorp) | Policy engine free; ARC for custom | Yes | Yes |
| Learning curve | High (rego logic is unconventional) | Medium (familiar imperative style) | Medium (JSON structure) | Low (simple YAML) | Medium (YAML + JMESPath) |

## Rule: "Deny if EC2 / VM has a public IP"

### Rego (OPA / Conftest)

```rego
# policy/deny-public-ip.rego
package terraform.aws

deny_public_ip[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"
  resource.change.after.associate_public_ip_address == true
  msg := sprintf("Instance %s has public IP enabled", [resource.address])
}

deny_public_ip[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_launch_configuration"
  resource.change.after.associate_public_ip_address == true
  msg := sprintf("Launch config %s has public IP enabled", [resource.address])
}
```

```bash
# Evaluate against a plan
terraform plan -out=tfplan
terraform show -json tfplan | conftest test --policy policies/ -
```

### Sentinel (Terraform Cloud/Enterprise)

```sentinel
# deny-public-ip.sentinel
import "tfplan/v2" as tfplan

public_ip_resources = filter tfplan.resource_changes as _, rc {
    rc.type is "aws_instance" and
    rc.change.after.associate_public_ip_address is true
}

main = rule {
    length(public_ip_resources) == 0 else
    "Resources with public IP found: " + 
    join(", ", public_ip_resources[*].address)
}
```

```bash
# Sentinel is evaluated automatically in TFC/TFE — no CLI command needed
# For local testing: use the Sentinel CLI (HashiCorp)
sentinel apply -trace deny-public-ip.sentinel
```

### Azure Policy (JSON)

```json
{
  "properties": {
    "displayName": "Deny public IP for VMs",
    "policyType": "Custom",
    "mode": "Indexed",
    "policyRule": {
      "if": {
        "allOf": [
          { "field": "type", "equals": "Microsoft.Network/publicIPAddresses" },
          { "field": "Microsoft.Network/publicIPAddresses/publicIPAllocationMethod",
            "equals": "Static" }
        ]
      },
      "then": { "effect": "deny" }
    }
  }
}
```

```bash
# Assign to subscription
az policy definition create --name deny-public-ip --rules deny-public-ip.json
az policy assignment create --policy deny-public-ip --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

### GCP Org Policy constraint

```yaml
# deny-public-ip.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sComputeDisableExternalIP
metadata:
  name: disable-external-ip
spec:
  match:
    namespaces: ["default"]
```

```bash
# Apply via gcloud
gcloud org-policies set-policy deny-public-ip.yaml \
  --organization=000000000000

# Native GCP org policy for external IPs
gcloud org-policies enable constraints/compute.disableExternalIPs \
  --organization=000000000000
```

### Cloud Custodian (multi-cloud runtime)

```yaml
# deny-public-ip-custodian.yml
policies:
  - name: ec2-no-public-ip
    resource: aws.ec2
    filters:
      - type: value
        key: "PublicIpAddress"
        value: present
    actions:
      - terminate
      - type: notify
        to: ["secops@example.com"]
```

```bash
custodian run --output-dir=./reports deny-public-ip-custodian.yml
```

## Per-cloud policy implementation

| Policy | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Block public S3 buckets | SCP + S3 Block Public Access | Azure Policy `deny public blob access` | Org Policy `storage.publicAccessPrevention` | OPA against MinIO API |
| Block 0.0.0.0/0 SGs | `aws_vpc_security_group_rule` Sentinel check | Azure Policy `deny NSG inbound any-to-any` | Org Policy `compute.restrictProtocolForwarding` | OPA against firewall config |
| Require encryption | KMS key policy + SCP | Azure Policy `deny storage without encryption` | Org Policy `requireCMEK` | OPA against Vault audit |
| Block IAM wildcards | SCP denies `*` in `Action` | Azure Policy checks `NotActions: *` | Org Policy deny `*` principal | OPA against LDAP/AD group |

## Evaluation pipeline — three phases

```
PR OPEN ──► terraform plan ──► conftest test (Rego) ──► FAIL? ──► BLOCK MERGE
                │
MERGE ──► terraform apply ──► Sentinel gating (TFC) ──► FAIL? ──► REJECT APPLY
                │
POST-APPLY ──► Cloud Custodian / Azure Policy / Org Policy ──► DRIFT? ──► ALERT + REMEDIATE
```

## 🔴 Red Team view

Policy-as-code creates a false confidence if it only runs at plan time. Long-running resources created manually — or resources imported after-the-fact — bypass all plan-time checks.

**Narrative: Policy bypass via manual resource creation + `terraform import`**

1. Attacker gets temporary console access (phishing, leaked access key).
2. Creates `aws_security_group` with `0.0.0.0/0` inbound SSH directly via console/CLI — no Terraform, no policy check.
3. Later runs `terraform import aws_security_group.shady sg-0a1b2c3d` to bring it under management.
4. The import creates no `resource_changes` (it's an import, not a create/update), so plan-time Rego/Sentinel sees nothing.
5. The security group lives in state, inherits the "IaC-managed" trust, and no alert fires.

**Artifacts:**
- CloudTrail `AuthorizeSecurityGroupIngress` from attacker IP
- CloudTrail `ec2:CreateSecurityGroup` without `userAgent` containing `HashiCorp-Terraform`
- State file mutation visible in `terraform state pull` diff — new resource appears without corresponding `resource_changes.create`

## 🔵 Blue Team view

**Mitigation: Periodic policy evaluation against live state, not just plan.**

```bash
# Schedule this in CI (nightly): evaluate all policies against current state
terraform state pull > live-state.json

# Convert state to HCL-ish JSON for conftest
jq '{resource_changes: [.resources[] | {
  address: .name,
  type: .type,
  change: {after: .instances[0].attributes}
}]}' live-state.json | conftest test --policy policies/ -
```

**Azure Policy — compliance scan (drift-aware):**

```bash
# Trigger on-demand compliance scan for a subscription
az policy state trigger-scan --subscription 00000000-0000-0000-0000-000000000000

# List non-compliant resources
az policy state list --filter "complianceState eq 'NonCompliant'"
```

**GCP Org Policy — constraint violation view:**

```bash
gcloud org-policies list-violations --organization=000000000000
```

**Defense-in-depth policy stack:**

| Layer | Tool | Frequency | Catches |
|---|---|---|---|
| PR preview | `conftest` + Rego | Every PR push | Known-bad config before merge |
| Apply gate | Sentinel (TFC) | Every `apply` | Compliance of final plan |
| Runtime drift | Azure Policy / Org Policy / Custodian | Continuous (15–60 min lag) | Console/CLI-created violations |
| Nightly audit | `terraform state pull` + Rego | Daily | Drift + imports + legacy resources |
| Incident response | Cloud Custodian `remediate` action | On alert | Auto-remediate high-sev violations |

**Detection checklist:**
- [ ] Every Terraform module shipped with a `policies/` directory containing Rego rules
- [ ] PR CI runs `conftest test` against every `terraform plan` output
- [ ] Sentinel policies defined in TFC for modules that use TFE workspaces
- [ ] Azure Policy assignments cover all subscriptions containing Terraform-managed resources
- [ ] GCP Org Policy constraints enabled at org/folder level
- [ ] Nightly pipeline evaluates all three engines against live state
- [ ] CloudTrail alert for resources created without `HashiCorp-Terraform` user-agent (see [07-drift-detection](./drift-detection-and-reconciliation.md))

## Hands-on lab

1. Install conftest and write a rule:
   ```bash
   brew install conftest  # or: curl -L https://github.com/open-policy-agent/conftest/releases/latest/download/conftest_linux_amd64.tar.gz | tar xz

   mkdir lab-policy && cd lab-policy
   mkdir policies
   ```

2. Create a Rego rule (block S3 public ACL):
   ```rego
   # policies/deny-public-acl.rego
   package terraform.aws

   deny[msg] {
     resource := input.resource_changes[_]
     resource.type == "aws_s3_bucket_acl"
     resource.change.after.acl == "public-read"
     msg := sprintf("Public ACL on %s", [resource.address])
   }
   ```

3. Generate a compliant and non-compliant plan:
   ```bash
   # Compliant plan
   cat > good.tf <<'EOF'
   resource "aws_s3_bucket" "good" { bucket = "good-bucket-111111111111" }
   resource "aws_s3_bucket_acl" "good" {
     bucket = aws_s3_bucket.good.id
     acl    = "private"
   }
   EOF
   terraform init && terraform plan -out=tfplan-good
   terraform show -json tfplan-good | conftest test --policy policies/
   # Expected: PASS

   # Non-compliant
   sed -i 's/"private"/"public-read"/' good.tf
   terraform plan -out=tfplan-bad
   terraform show -json tfplan-bad | conftest test --policy policies/
   # Expected: FAIL — "Public ACL on aws_s3_bucket_acl.good"
   ```

4. **Teardown:** `rm -rf lab-policy`

## References

- [OPA Rego Cheatsheet](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Conftest Documentation](https://www.conftest.dev/)
- [Sentinel Language Docs](https://developer.hashicorp.com/sentinel)
- [Azure Policy Definition Structure](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure)
- [GCP Organization Policy Constraints](https://cloud.google.com/resource-manager/docs/organization-policy/understanding-constraints)
- [Cloud Custodian](https://cloudcustodian.io/)
- [02-08 — Policy-as-Code Checkers](../IAM/policy-as-code-checkers.md)
- [08-07 — Drift Detection & Reconciliation](./drift-detection-and-reconciliation.md)
