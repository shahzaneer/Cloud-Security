# 01 — Frameworks Overview: CIS, NIST CSF, ISO 27001, PCI DSS, SOC 2, HIPAA

> **Level:** Fundamental
> **Prereqs:** [Shared Responsibility](../Fundamentals/shared-responsibility.md), [The Security Log Mosaic per Cloud](../Monitoring-Detection-SIEM/the-security-log-mosaic-per-cloud.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** N/A — governance & compliance mapping
> **Authorization scope:** All examples reference your own sandbox accounts and compliance dashboards. No real audit data is used.

## What & why

Compliance frameworks are the shared vocabulary between security engineers, auditors, executives, and customers. Each framework answers a different question: CIS Benchmarks say "configure these 150 things correctly"; NIST CSF says "identify, protect, detect, respond, recover"; ISO 27001 says "build a management system around these 93 Annex A controls"; PCI DSS says "anything touching cardholder data must meet these 300+ requirements"; SOC 2 says "your service is secure, available, and confidential per a trusted third-party opinion"; HIPAA says "protect PHI or face OCR fines." Which one you satisfy depends on your customers and data — but every cloud provider maps them to their native tooling.

## The OnPrem reality

Pre-cloud, compliance meant printed binders of control narratives, manually signed attestations, and quarterly scans dumped into SharePoint. A Qualys/Nessus scan was your "control verification." The auditor asked for evidence; you spent six weeks emailing sysadmins for screenshots. Cloud didn't eliminate compliance — it made it programmable.

## Core frameworks at a glance

| Framework | Focus | Structure | Who demands it | Cloud mapping available? |
|---|---|---|---|---|
| **CIS Benchmarks** | Prescriptive config hardening | ~150 controls per OS/cloud service | Security-first orgs, insurers | AWS/Azure/GCP CIS conformance packs |
| **NIST CSF** | Risk management functions | 5 functions → 23 categories → 108 subcategories | US federal, critical infrastructure | AWS Audit Manager NIST CSF framework |
| **NIST SP 800-53** | Control catalogue for federal systems | 20 families, 1,000+ controls | FedRAMP, DoD, US GOV | Azure Blueprints, GCP Assured Workloads |
| **ISO 27001** | Information Security Management System (ISMS) | 93 Annex A controls (ISO 27001:2022 reduced) | International, enterprises | AWS Artifact, Azure ISO compliance, GCP compliance reports |
| **PCI DSS v4.0** | Cardholder data protection | 12 requirements, ~300 sub-requirements | Payment processors, merchants | AWS PCI DSS Quick Start, Azure PCI compliance |
| **SOC 2** | Trust Services Criteria (TSC) | Security + Availability + Confidentiality + Processing Integrity + Privacy | SaaS vendors, B2B | AWS SOC reports in Artifact, Azure SOC attestations |
| **HIPAA** | Protected Health Information (PHI) safeguards | Privacy Rule + Security Rule + Breach Notification | Healthcare, health-tech | AWS BAA, Azure HIPAA compliance, GCP BAA |

## Framework-to-cloud control mapping

### CIS Benchmarks → cloud native

CIS publishes benchmarks per cloud service. Each recommendation has a CIS control ID (e.g. `CIS 1.4` = "Ensure no root account access key exists"). Cloud providers ship conformance packs that evaluate these directly.

| CIS Rec | Topic | AWS Config Rule | Azure Policy | GCP SCC |
|---|---|---|---|---|
| 1.1 | Access keys rotated ≤ 90d | `iam-user-unused-credentials-check` | Not directly — Entra access review | IAM recommender |
| 1.4 | Root MFA enabled | `root-account-mfa-enabled` | `accounts with write on subscription should have MFA` | `constraints/iam.mfaRequiredForRoot` |
| 3.1 | Block public S3 buckets | `s3-bucket-public-read-prohibited` | storage account public access deny | `constraints/storage.publicAccessPrevention` |
| 4.1 | CloudTrail enabled | `cloud-trail-enabled` | `subscription log profile for activity log` | `constraints/gcp.enableAuditLogging` |
| 5.2 | Security groups restrict 0.0.0.0/0 | `vpc-sg-open-only-to-authorized-ports` | NSG flow logs review | VPC firewall rules audit |

### NIST CSF → cloud posture

The NIST CSF functions map cleanly to cloud security services:

| Function | AWS | Azure | GCP |
|---|---|---|---|
| **Identify** | Security Hub + Config inventory | Defender for Cloud + Resource Graph | SCC asset inventory |
| **Protect** | SCPs + KMS + WAF | Azure Policy + Key Vault + Front Door WAF | Org Policy + CMEK + Cloud Armor |
| **Detect** | GuardDuty + CloudTrail | Defender for Cloud alerts + Sentinel | SCC Threat Detection + Audit Logs |
| **Respond** | Lambda auto-remediation | Logic Apps + Sentinel playbooks | Cloud Functions + SCC response |
| **Recover** | Backup + Cross-region DR | Site Recovery + Backup | Cloud Storage replication + DR |

## AWS

### AWS Audit Manager — conformance packs

AWS Audit Manager provides prebuilt framework assessments. Each maps an external standard to a set of AWS Config rules and manual evidence collection steps.

```bash
aws auditmanager list-assessment-frameworks
aws auditmanager create-assessment \
  --name "PCI DSS Q1 2026" \
  --framework-id "CIS Benchmark v1.4.0" \
  --assessment-reports-destination "S3" \
  --s3-destination bucket="compliance-evidence-111111111111-us-east-1"
```

**Canonical AWS Config conformance pack ARN examples (verify via console):**

```bash
aws configservice list-conformance-packs
# Sample output packs:
# aws-foundational-security-best-practices/v1.0.0
# Operational-Best-Practices-for-CIS-AWS-Foundations-Benchmark-v1.4-Level1
# Operational-Best-Practices-for-PCI-DSS-v3.2.1
# Operational-Best-Practices-for-HIPAA-Security
```

**SOC 2 reports** live in AWS Artifact — SOC 2 Type II reports are downloadable PDFs you share with customers under NDA.

### IaC — onboarding AWS Config conformance packs

```hcl
resource "aws_config_conformance_pack" "cis_level1" {
  name = "cis-aws-foundations-benchmark-v1.4-level1"

  template_body = file("${path.module}/conformance_packs/cis-conformance.yaml")

  input_parameter {
    parameter_name  = "AccessKeysRotatedMaxAge"
    parameter_value = "90"
  }
}

resource "aws_config_config_rule" "root_mfa" {
  name = "root-account-mfa-enabled"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }
}
```

## Azure

### Azure Regulatory Compliance dashboard

Azure Defender for Cloud ships a regulatory compliance dashboard with built-in assessments mapped to PCI DSS, ISO 27001, NIST SP 800-53, HIPAA, FedRAMP Moderate, and more. Each control shows pass/fail counts across all subscriptions in the management group.

```bash
az security regulatory-compliance-standards list
az security regulatory-compliance-assessments list \
  --standard-name "PCI-DSS-v3.2.1"
```

**Azure Policy Initiative examples:**

```bash
az policy set-definition list \
  --query "[?contains(displayName,'PCI') || contains(displayName,'ISO 27001') || contains(displayName,'HIPAA')]" \
  --output table
```

> (as of June 2026, initiative names may change across Azure API versions; search via `az policy set-definition list --query "[?contains(displayName,'NIST SP 800-53')]"`. Check the [Azure built-in policy initiatives list](https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-initiatives) for current names.)

### Built-in regulatory initiatives

| Initiative name | Framework | Number of policies | Scope |
|---|---|---|---|
| PCI DSS v4.0 | PCI | ~200 | Subscription |
| ISO 27001:2013 | ISO 27001 | ~90 | Subscription |
| NIST SP 800-53 Rev. 5 | US Federal | ~400 | Management group |
| HIPAA HITRUST | HIPAA | ~130 | Subscription |
| Azure CIS 2.0.0 | CIS | ~180 | Subscription |
| FedRAMP High | US Federal | ~400 | Management group |

```hcl
resource "azurerm_subscription_policy_assignment" "pci_dss" {
  name                 = "pci-dss-v4"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/496eeda2-1e0a-4b33-9a54-5e9f4f8c4c0b"
}
```

## GCP

### Security Command Center Premium

SCC Premium maps findings against CIS benchmarks, NIST SP 800-53, PCI DSS, ISO 27001, SOC 2, and HIPAA. The compliance report is generated per project/folder/organization.

```bash
gcloud scc findings list --organization=000000000000 \
  --source=organizations/000000000000/sources/8888888888888888888

gcloud scc assets list --organization=000000000000 \
  --filter="security_center_properties.resource_type=\"google.cloud.storage.Bucket\""
```

### Org Policy constraints — CIS mapping

```bash
gcloud org-policies list --organization=000000000000
gcloud org-policies describe constraints/iam.disableServiceAccountKeyCreation \
  --organization=000000000000
```

| CIS GCP Control | Org Policy Constraint |
|---|---|
| 1.4 | `constraints/iam.automaticIamGrantsForDefaultServiceAccounts` |
| 2.3 | `constraints/compute.disableSerialPortAccess` |
| 4.2 | `constraints/storage.publicAccessPrevention` |
| 5.1 | `constraints/sql.restrictPublicIp` |

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| CIS benchmarks | CIS-CAT Pro assessor | Config conformance packs | Azure Policy CIS initiative | Security Health Analytics |
| NIST CSF | NIST CSF Excel workbook | Audit Manager + Security Hub | Defender for Cloud NIST | SCC compliance report |
| ISO 27001 | Manual ISMS + Nessus | AWS Artifact + Config | ISO 27001 initiative | GCP compliance reports |
| PCI DSS | ASV external scan + SAQ | PCI DSS Quick Start + Config | PCI DSS initiative | PCI assessments in SCC |
| SOC 2 | External audit by CPA firm | AWS Artifact SOC reports | Azure SOC attestations | GCP SOC reports |
| HIPAA | BAA + on-prem encryption | AWS BAA + HIPAA eligible services | Azure HIPAA eligible services | GCP BAA + HIPAA scope |

## 🔴 Red Team view — Compliance theater

**Attack vector:** An organization passes a PCI audit because the Azure Policy initiative is assigned in `Audit` mode (non-enforcing) and AWS Config rules "evaluate" but nobody reads the noncompliant results. The SOC 2 Type II report says "encryption at rest is enforced" — but the actual guardrail (SCP / Azure Policy `Deny`) was never deployed.

**Contained example — gap exploitation:**

1. Recon: Attacker reviews the organization's published SOC 2 trust services criteria and notes "data encrypted at rest" is a claimed control.
2. Probe: Attacker with a low-privilege IAM role attempts `s3:PutObject` with `--no-server-side-encryption`. The call succeeds because the SCP was only planned but never attached.
3. Result: Attacker exfiltrates a bucket's content written by a previous attacker, stored unencrypted — the auditor's evidence was a screenshot from the `s3-bucket-server-side-encryption-enabled` Config rule dashboard that showed "green" because the rule only checked *bucket-level* default encryption, not per-object overrides.

**Artifacts left:** S3 data events (`PutObject` without `x-amz-server-side-encryption` header). CloudTrail shows the Config rule still evaluating. No alerts fire because the guardrail evaluation never ran.

## 🔵 Blue Team view — Audit-as-Code

Every control must be a self-contained artifact that ties together:

```yaml
control:
  id: "ENCR-AT-REST-001"
  framework_refs:
    - "CIS AWS 3.6"
    - "NIST CSF PR.DS-1"
    - "PCI DSS 3.4"
    - "SOC 2 CC6.1"
  requirement: "All S3 objects must be encrypted at rest using KMS or SSE-S3"
  implementation:
    aws:
      guardrail: "SCP denying PutObject without s3:x-amz-server-side-encryption"
      verification: "AWS Config rule s3-bucket-server-side-encryption-enabled"
      evidence_query: "config:advancedquery SELECT * WHERE configuration.targetResourceType='AWS::S3::Bucket'"
  detection:
    rule: "CloudTrail data event: PutObject without encryption header → alert"
  exception_registry: "s3://compliance-evidence/exceptions/encr-at-rest-001.json"
  last_evaluated: "2026-06-22T00:00:00Z"
  status: "COMPLIANT"
```

**Engineering checklist:**
1. Each control has a preventive guardrail (not just audit).
2. Each control has a detection rule (not just config evaluation).
3. Each control has an evidence query (not manual screenshots).
4. Exceptions are registered, timestamped, approved, and expired.
5. Quarterly purple-team test: attempt the forbidden action against the guardrail; confirm denial + alert.

## Hands-on lab — Framework assessment mini-pack

**Duration:** 15 min. **Cost:** Free-tier audit manager usage.

```bash
# AWS: Enable a conformance pack on your sandbox account
aws configservice put-organization-conformance-pack \
  --organization-conformance-pack-name "cis-benchmark-v1.4-level1"

# After ~10 minutes, query noncompliant rules
aws configservice describe-compliance-by-config-rule \
  --compliance-types NON_COMPLIANT \
  --query "ComplianceByConfigRules[*].ConfigRuleName"

# Azure: List regulatory compliance state
az security regulatory-compliance-assessments list \
  --standard-name "PCI-DSS-v3.2.1" \
  --query "[?status=='Unhealthy']"

# GCP: List active findings
gcloud scc findings list --organization=000000000000 \
  --filter="state=\"ACTIVE\" AND severity=\"HIGH\"" \
  --format="table(finding.name, securityMarks)"
```

**Teardown:** Delete the conformance pack (`aws configservice delete-organization-conformance-pack`), no further cleanup needed.

## Detection rules & checklists

```yaml
# Sigma rule stub — framework control reported noncompliant for >7 days
title: Compliance Control Failing Extended Period
id: a1b2c3d4-5500-4400-9000-e5f6a7b8c9d0
status: experimental
description: Detects when a compliance control remains noncompliant for more than 7 days
logsource:
  product: aws
  service: config
detection:
  selection:
    eventName: complianceChange
    complianceType: NON_COMPLIANT
  timeframe: 7d
  condition: selection
level: medium
```

**CLI audit one-liners:**

```bash
# AWS: list all noncompliant config rules
aws configservice describe-compliance-by-config-rule \
  --query "ComplianceByConfigRules[?Compliance.ComplianceType=='NON_COMPLIANT'].ConfigRuleName"

# Azure: count unhealthy assessments per standard
az security regulatory-compliance-assessments list \
  --standard-name "ISO27001" \
  --query "[?status=='Unhealthy'].{id:id, displayName:displayName}" -o table

# GCP: list projects missing SCC coverage
gcloud scc assets list --organization=000000000000 \
  --filter="security_center_properties.resource_type=\"google.cloud.resourcemanager.Project\""

# OnPrem: CIS-CAT command-line assessment
# cis-cat.sh -p "Windows 10" -b "CIS_Workstation" -t /tmp/results
```

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library)
- [AICPA SOC 2](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/soc-for-service-organizations.html)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [AWS Audit Manager](https://docs.aws.amazon.com/audit-manager/latest/userguide/what-is.html)
- [Azure Regulatory Compliance](https://learn.microsoft.com/en-us/azure/defender-for-cloud/regulatory-compliance-dashboard)
- [GCP SCC Premium](https://cloud.google.com/security-command-center/docs/concepts-security-command-center-overview)
- MITRE ATT&CK: T1562 Impair Defenses (relevant to compliance audit evasion)
- Cross-links: [../IAM/cross-account-access-analysis.md](../IAM/cross-account-access-analysis.md), [../Monitoring-Detection-SIEM/the-security-log-mosaic-per-cloud.md](../Monitoring-Detection-SIEM/the-security-log-mosaic-per-cloud.md)
