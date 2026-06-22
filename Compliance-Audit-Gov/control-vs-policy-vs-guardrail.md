# 02 — Control vs. Policy vs. Guardrail vs. Evidence

> **Level:** Fundamental
> **Prereqs:** [Frameworks Overview CIS NIST ISO PCI](frameworks-overview-cis-nist-iso-pci.md), [Permission Boundaries & Quarantine](../IAM/permission-boundaries-and-quarantine.md), [Blast Radius Reduction Patterns](../Blue-Team-Defense/blast-radius-reduction-patterns.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Persistence
> **Authorization scope:** All guardrail examples must be deployed only in your own sandbox OUs/subscriptions/projects.

## What & why

These four terms are confused constantly, and the confusion is exploitable. A precise taxonomy:

- **Policy** = stated intent ("data must be encrypted at rest").
- **Guardrail** = preventive enforcement machinery that *denies* the API call before execution.
- **Control** = a measurable, auditable safeguard that *verifies* the policy is being followed — it may be *detective* (config rule) or *preventive* (guardrail), but the term "control" in audit context means "a testable thing you do."
- **Evidence** = the artifact that proves the control operated during the audit period.

If your guardrail is in `Audit` mode, you have a control but **no enforcement**. If your policy exists in a Confluence page but has no control, you have nothing. Auditors often accept "control exists + evidence shows green" without testing whether the guardrail actually denies the bad action.

## The OnPrem reality

| Term | OnPrem |
|---|---|
| Policy | Signed acceptable-use policy, password complexity standard |
| Guardrail | Firewall ACL, GPO "Deny logon locally", file system DACL deny |
| Control | Weekly Nessus credentialed scan, quarterly AD access review |
| Evidence | PDF scan report emailed to auditor, screenshot of GPO `rsop.msc` |

The on-prem gap: firewall rules were preventive but coarse (IP/port, not API-level). GPOs were preventive but OS-scoped. Cloud guardrails operate at the **API authorization plane** — you can deny `s3:PutBucketAcl` with public grants regardless of IAM permissions.

## Cross-cloud guardrail layering — "no public S3 / blob / bucket" example

### AWS — full stack for one policy

```hcl
# 1. POLICY (stated intent — in your security docs)
# "No S3 bucket shall be publicly accessible."

# 2. GUARDRAIL (preventive — SCP on the OU)
data "aws_iam_policy_document" "deny_public_s3" {
  statement {
    effect    = "Deny"
    actions   = [
      "s3:PutBucketAcl",
      "s3:PutBucketPolicy",
      "s3:PutBucketPublicAccessBlock"
    ]
    resources = ["*"]
    condition {
      test     = "StringEqualsIfExists"
      variable = "s3:x-amz-acl"
      values   = ["public-read", "public-read-write", "authenticated-read"]
    }
  }
}

resource "aws_organizations_policy" "deny_public_s3_scp" {
  name    = "DenyPublicS3"
  content = data.aws_iam_policy_document.deny_public_s3.json
}

# 3. CONTROL (detective verification — Config rule)
resource "aws_config_config_rule" "s3_public_read" {
  name = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}

# 4. EVIDENCE (artifacts for auditor)
# - Audit Manager assessment report S3 path
# - Config rule compliance snapshot
# - SCP attachment verification: aws organizations list-policies-for-target
```

```bash
# Evidence query: show all public S3 access blocks in last 90 days
aws configservice select-aggregate-resource-config \
  --expression "SELECT resourceId, configuration.publicAccessBlockConfiguration \
                WHERE resourceType='AWS::S3::Bucket' \
                AND configuration.publicAccessBlockConfiguration.blockPublicAcls = false"
```

### Azure — same policy, same layering

```hcl
# 1. POLICY (stated intent)

# 2. GUARDRAIL — Azure Policy (deny effect) on management group
resource "azurerm_policy_definition" "deny_public_blob" {
  name         = "deny-public-blob-container"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny public blob containers"
  policy_rule  = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        { field = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", equals = "true" }
      ]
    }
    then = { effect = "deny" }
  })
}

resource "azurerm_management_group_policy_assignment" "deny_public_blob" {
  name                 = "deny-public-blob-mgmt"
  policy_definition_id = azurerm_policy_definition.deny_public_blob.id
  management_group_id  = data.azurerm_management_group.root.id
}

# 3. CONTROL — Defender for Cloud regulatory compliance
# Azure Policy "Storage account public access should be disallowed" in Audit mode

# 4. EVIDENCE — Azure Policy compliance API
# az policy state list --filter "policyAssignmentName eq 'deny-public-blob-mgmt'"
```

```bash
# Evidence query: list any storage account with public blob access
az graph query -q "
  resources
  | where type =~ 'Microsoft.Storage/storageAccounts'
  | where properties.allowBlobPublicAccess == true
  | project name, resourceGroup, location
"
```

### GCP — same policy, same layering

```hcl
# 1. POLICY (stated intent)

# 2. GUARDRAIL — Org Policy constraint (preventive)
resource "google_org_policy_policy" "deny_public_gcs" {
  parent = "organizations/000000000000"
  name   = "organizations/000000000000/policies/storage.publicAccessPrevention"
  spec {
    rules {
      enforce = true
    }
  }
}

# 3. CONTROL — SCC Security Health Analytics
# Finding: "PUBLIC_BUCKET_ACL" (built-in detector)

# 4. EVIDENCE — SCC findings export to BigQuery
# Plus: gcloud asset search-all-resources
```

```bash
# Evidence query: search for publicly accessible buckets
gcloud asset search-all-resources \
  --scope="organizations/000000000000" \
  --asset-types="storage.googleapis.com/Bucket" \
  --query="labels:public"
```

### OnPrem — equivalent stack

```hcl
# 1. POLICY: corporate standard doc

# 2. GUARDRAIL: OPA/Rego constraint on Kubernetes storage
# Gatekeeper ConstraintTemplate denying public-facing storage class
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDenyPublicStorage
metadata:
  name: deny-public-storage
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["PersistentVolumeClaim"]
  parameters:
    allowedStorageClasses: ["encrypted-rbd", "encrypted-nfs"]

# 3. CONTROL: Nessus/OpenSCAP network scan checking SMB/CIFS exposure

# 4. EVIDENCE: scan report JSON exported to audit share
```

## The audit failure pattern

```text
POLICY:         ✅ "Encryption at rest is required"          ← Auditor: "Show me the policy."
GUARDRAIL:      ⬜ SCP planned but not attached               ← Auditor: "Show me enforcement."
CONTROL:        ✅ Config rule s3-bucket-encryption-enabled   ← Auditor: "This shows green for all 342 buckets."
EVIDENCE:       ✅ Audit Manager compliance snapshot          ← Auditor: "Accepted — passed."

REALITY:        ❌ Guardrail missing. 12 buckets created without encryption in last quarter.
                Config rule checked *bucket default encryption* only, not per-object SSE.
                Attacker wrote unencrypted objects via legacy ACL grants.
```

## 🔴 Red Team view — exploiting the guardrail gap

**Attack narrative:** Organization passed a SOC 2 audit with "data encrypted at rest" as a Trust Services Category control. The Azure Policy initiative for encryption is assigned in `Audit` mode at the subscription level. The AWS Config rule `s3-bucket-server-side-encryption-enabled` evaluates `NON_COMPLIANT` for 14 buckets, but nobody configured auto-remediation or an alert — the SOC 2 evidence pack cherry-picked a dashboard showing the 328 compliant buckets only.

**Exploitation steps (contained, educational, sandbox-only):**

```bash
# Step 1: Recon — attacker discovers no SCP prevents PutObject without encryption
aws s3api put-object \
  --bucket test-bucket-111111111111-us-east-1 \
  --key sensitive-data.csv \
  --body exfil_data.csv \
  --acl bucket-owner-full-control
# Succeeds — no encryption header, no denial

# Step 2: Attacker checks if Azure blob can be written without encryption
az storage blob upload \
  --account-name storagellllllll \
  --container-name internal-data \
  --name sensitive-data.csv \
  --file exfil_data.csv
# Succeeds — Azure Policy is audit-only, not deny

# Step 3: Persistence — attacker creates a new bucket unencrypted, writes data there
# Config rule will detect noncompliance at next evaluation (default: 24h)
# But no alert fires — the monitoring team only reviews audit dashboards quarterly
```

**Artifacts left:**
- CloudTrail `PutObject` events without `x-amz-server-side-encryption` header
- Azure Activity Log `Microsoft.Storage/storageAccounts/blobServices/containers/read` with no encryption property
- SCC finding `BUCKET_POLICY_ONLY_DISABLED` if GCP; fires as MEDIUM severity, suppressed

## 🔵 Blue Team view — engineering a "quality BAR" per control

Every control must pass this BAR (Baseline Assurance Requirement) checklist:

```yaml
control:
  id: "PUBLIC-BLOCK-001"
  policy: "No cloud storage resource shall be publicly accessible"
  guardrail:
    status: "DEPLOYED"
    type: "DENY"
    tested: "2026-06-22"  # date of last purple-team test
    test_result: "API call denied successfully, CloudTrail logged denied attempt"
  verification:
    config_rule: "s3-bucket-public-read-prohibited"
    evaluation_frequency: "24h"
    last_evaluation: "COMPLIANT"
  detection:
    alert_rule: "PublicBucketAttempt"
    query: "filter eventName = 'PutBucketAcl' AND requestParameters.AccessControlPolicy like /AllUsers/"
    test_fired: true  # purple-team trigger confirmed alert delivery to PagerDuty
  exception_registry:
    path: "s3://compliance-evidence/exceptions/public-block-001.json"
    active_exceptions: 0
    expired_exceptions: 1
  evidence:
    exports: ["audit-manager-assessment-report", "config-compliance-snapshot", "guardrail-test-log"]
    last_export: "2026-06-22"
    published_hash: "sha256:abc123def456..."
```

**Quarterly purple-team test protocol:**

```bash
# Automated test: attempt the forbidden action, confirm denial
aws s3api put-bucket-acl \
  --bucket test-bucket \
  --acl public-read \
  --profile purple-team-role 2>&1 | grep "AccessDenied"
# Expected: AccessDenied

# Confirm that the denial was logged
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketAcl \
  --query "Events[?Username=='purple-team-role'].{Time:EventTime,Error:ErrorMessage}" \
  --start-time $(date -v-1H -u +%s) \
  --end-time $(date -u +%s)
```

## Hands-on lab — test guardrail vs. control

**Duration:** 20 min. **Prereqs:** Sandbox AWS account with Organizations or equivalent.

```bash
# 1. Deploy a detective Config rule only (no SCP)
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "test-s3-public",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}'

# 2. Create a public bucket — observe it succeeds
aws s3api create-bucket --bucket test-public-111111111111-us-east-1
aws s3api put-bucket-acl --bucket test-public-111111111111-us-east-1 --acl public-read
# Succeeds — no guardrail

# 3. Wait for Config rule evaluation (~10 min or trigger manually)
aws configservice start-config-rules-evaluation \
  --config-rule-names test-s3-public

# 4. Check — shows NON_COMPLIANT, but bucket already public
# This is the gap: detection without prevention

# 5. Now deploy the SCP guardrail (requires Organizations)
# Attach the SCP from the AWS example above to your sandbox OU

# 6. Delete the test bucket, clean up rule
aws s3 rm s3://test-public-111111111111-us-east-1 --recursive
aws s3api delete-bucket --bucket test-public-111111111111-us-east-1
aws configservice delete-config-rule --config-rule-name test-s3-public
```

## Detection rules & checklists

**Guardrail audit checklist (monthly):**

```bash
# AWS: verify SCPs are attached to all OUs
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations list-targets-for-policy --policy-id p-xxxxxxxxxx

# Azure: verify policy assignments are in Deny mode, not Audit
az policy assignment list --query "[].{name:name, enforcementMode:properties.enforcementMode}"

# GCP: verify org policy constraints are enforced
gcloud org-policies list --organization=000000000000 --format="table(constraint, spec.rules.enforce)"
```

**Sigma rule stub — guardrail attempted bypass:**

```yaml
title: API Call Blocked by Preventive Guardrail
id: g6a7b8c9-1000-4000-8000-d1e2f3a4b5c6
status: experimental
description: Detects denied API calls matching preventive guardrail patterns
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    errorCode: AccessDenied
    eventName:
      - PutBucketAcl
      - PutBucketPolicy
      - PutObject
  condition: selection
level: low  # expected if guardrail is working — becomes high if volume spikes
```

## References

- [AWS SCP Best Practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [Azure Policy effects: deny](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects#deny)
- [GCP Org Policy constraints](https://cloud.google.com/resource-manager/docs/organization-policy/overview)
- [OPA/Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)
- MITRE ATT&CK: T1562 Impair Defenses (disabling/modifying security tools)
- Cross-links: [../IAM/cross-account-access-analysis.md](../IAM/cross-account-access-analysis.md), [../Blue-Team-Defense/preventive-guardrails-as-code.md](../Blue-Team-Defense/preventive-guardrails-as-code.md)
