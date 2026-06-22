# 05 — Data Residency & Sovereignty

> **Level:** Intermediate
> **Prereqs:** [Snapshots & Backup Tampering](../Storage-Data-Security/snapshots-and-backup-tampering.md), [Frameworks Overview CIS NIST ISO PCI](frameworks-overview-cis-nist-iso-pci.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Exfiltration, Collection
> **Authorization scope:** Residency guardrails must be tested only in your own sandbox organizations/subscriptions. Placeholder region lists and key ARNs throughout.

## What & why

Data residency is the geographical constraint on where data at rest can live. Sovereignty adds the legal layer: data must not only reside in a specific jurisdiction but also be inaccessible by foreign law enforcement or personnel. Industries that demand this: government (ITAR, FedRAMP, Protected B), healthcare (GDPR-bound PHI), financial services (EU MiFID II, Australian APRA). Implementation is a stack of region-restriction policies, encryption key locality, and access controls — all enforced by cloud guardrails.

## The OnPrem reality

Pre-cloud, residency was physical: data lived on a SAN in a cage in a Frankfurt data center. Sovereignty was layered: the rack was in Germany, the sysadmin's desk was in Frankfurt, the encryption key stayed in an HSM in the same building. Cloud residency replaces the cage with a region-locked service and the HSM with a region-bound KMS. The attacker's question: "If I get the decryption key, does residency still matter?"

## Cross-cloud residency enforcement

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| **Region restriction** | Physical rack location | SCP `aws:RequestedRegion`, Config rule `ec2-instance-in-allowed-region` | Azure Policy `allowedLocations` + `dataResidency` (`Microsoft.Resources/locations`) | Org Policy `constraints/gcp.resourceLocations` |
| **Key locality** | HSM in locked cage | KMS single-region key (non-MRK), CMEK with `kms:ResourceAliases` condition | Key Vault `location`, Managed HSM region, CSEK | CMEK+Cloud KMS `locations` constraint, key ring per region |
| **Access boundary** | Domain-joined workstations only | SCP + `aws:PrincipalTag` + IAM condition for `aws:SourceIp` in allowed egress range | Conditional Access + named locations (IP ranges) | VPC Service Controls perimeter defining allowed access |
| **Audit proof** | Visitor log + access badge + CCTV | CloudTrail + Config advanced query `WHERE awsRegion IN ('eu-central-1', ...)` | Activity Log filtered by resource location + Resource Graph | Cloud Audit Logs + Org Policy audit |
| **Data lifecycle** | Tape rotation + offsite in same country | S3 lifecycle to same-region Glacier, S3 Object Lock | Blob lifecycle to same-region Cool/Archive | GCS lifecycle to same-region Nearline/Coldline |

## AWS — residency enforcement

### SCP region restriction

```json
{
  "Sid": "DenyDisallowedRegions",
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:RequestedRegion": ["eu-central-1", "eu-west-1", "eu-west-2"]
    },
    "ArnNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/BreakGlassRole",
        "arn:aws:iam::*:role/audit-reader"
      ]
    }
  }
}
```

### KMS key locality guardrail

```hcl
resource "aws_kms_key" "eu_only_key" {
  description             = "Sovereignty-bound KMS key — EU regions only"
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation     = true
  multi_region            = false  # NO multi-region replica — no key material leaves EU
}

data "aws_iam_policy_document" "kms_region_restriction" {
  statement {
    effect = "Deny"
    actions = ["kms:Decrypt", "kms:Encrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*"]
    resources = [aws_kms_key.eu_only_key.arn]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = ["eu-central-1", "eu-west-1", "eu-west-2"]
    }
  }
}
```

### Verify key locality

```bash
aws kms list-aliases --region eu-central-1 \
  --query "Aliases[?starts_with(AliasName,'alias/sovereignty')].{name:AliasName, keyId:TargetKeyId}"

aws kms describe-key --key-id arn:aws:kms:eu-central-1:111111111111:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
  --query "KeyMetadata.{MultiRegion:MultiRegion, KeyState:KeyState}"
```

### Config advanced query — resources outside allowed regions

```sql
SELECT
  resourceId,
  resourceType,
  awsRegion
WHERE resourceType IN (
  'AWS::S3::Bucket',
  'AWS::EC2::Instance',
  'AWS::RDS::DBInstance'
)
AND awsRegion NOT IN ('eu-central-1', 'eu-west-1', 'eu-west-2')
```

## Azure — residency enforcement

### Azure Policy — allowed locations

```hcl
resource "azurerm_policy_definition" "allowed_locations" {
  name        = "allowed-locations-eu"
  policy_type = "Custom"
  mode        = "Indexed"
  display_name = "Allow only EU data center locations"
  policy_rule = jsonencode({
    if = {
      field = "location"
      notIn = ["westeurope", "northeurope", "francecentral", "germanywestcentral"]
    }
    then = { effect = "deny" }
  })
}

resource "azurerm_subscription_policy_assignment" "eu_locations" {
  name                 = "eu-locations-only"
  policy_definition_id = azurerm_policy_definition.allowed_locations.id
  subscription_id      = data.azurerm_subscription.current.id
  location             = "westeurope"
}
```

### Data residency policy for storage

Azure has a specific `dataResidency` effect within policy. The built-in policy "Azure Data Box jobs should have data residency" can be extended:

```bash
az policy definition list --query "[?contains(displayName,'data residency')]"
```

### Key Vault locality

```hcl
resource "azurerm_key_vault" "eu_kv" {
  name                = "kv-eu-sovereignty-00001"
  location            = "westeurope"
  resource_group_name = "rg-eu-sovereignty"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "premium"

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    virtual_network_subnet_ids = [azurerm_subnet.trusted.id]
  }
}
```

### Resource Graph — resources outside allowed regions

```bash
az graph query -q "
  resources
  | where location !in ('westeurope', 'northeurope', 'francecentral', 'germanywestcentral')
  | project name, type, location, resourceGroup
" --output table
```

## GCP — residency enforcement

### Org Policy — resource locations constraint

```hcl
resource "google_org_policy_policy" "eu_locations" {
  parent = "organizations/000000000000"
  name   = "organizations/000000000000/policies/gcp.resourceLocations"
  spec {
    rules {
      values {
        allowed_values = [
          "in:europe-west1-locations",
          "in:europe-west2-locations",
          "in:europe-west3-locations"
        ]
      }
    }
  }
}
```

### CMEK key region restriction

```hcl
resource "google_kms_key_ring" "eu_keyring" {
  name     = "sovereignty-eu-keyring"
  location = "europe-west1"  # Key material never leaves this region
}

resource "google_kms_crypto_key" "eu_key" {
  name            = "sovereignty-cmek"
  key_ring        = google_kms_key_ring.eu_keyring.id
  rotation_period = "7776000s"  # 90 days
}

resource "google_org_policy_policy" "cmek_region" {
  parent = "organizations/000000000000"
  name   = "organizations/000000000000/policies/constraints/gcp.restrictCmekCryptoKeyProjects"
  spec {
    rules {
      values {
        allowed_values = ["projects/sovereignty-project"]
      }
      condition {
        expression = "resource.matchTagId('123456789012/env', 'sovereignty-eu')"
      }
    }
  }
}
```

### Verify project locations

```bash
gcloud asset search-all-resources \
  --scope="organizations/000000000000" \
  --query="NOT location:europe-*" \
  --format="table(name, assetType, location)"
```

## OnPrem — residency

On-prem residency is physical boundary enforcement. A GCC-High or air-gapped environment has:
- All infrastructure in a cryptographically defined physical boundary
- Hardware security modules on-premises
- No outbound internet — proxy through an on-prem SIEM
- Tape backup stored in same-country vault

## 🔴 Red Team view — residency bypass

**Attack narrative:** Residency guardrails prevent data from being created in non-approved regions. But if the attacker obtains access to the decryption key (e.g., KMS key accessible via cross-account assumption), the actual data content is unprotected — the attacker can decrypt in any region and exfiltrate. Residency protects *at rest*; it does NOT protect data in use or transit if keys are compromised.

**Threat model — symmetric mutual target:**

```text
"If attacker has KMS:Decrypt, residency controls don't protect the data."

  ┌──────────────────────┐         ┌──────────────────────┐
  │  eu-central-1        │         │  us-east-1            │
  │  S3 bucket (data)    │         │  Attacker EC2         │
  │  + Resident KMS key  │◄────────┤  AssumeRole → KMS    │
  │  SCP blocks outbound          │  kms:Decrypt → data   │
  │  region write         │        │  exfil via DNS tunnel │
  └──────────────────────┘         └──────────────────────┘
               ▲
               │  Exfil possible because data is accessible
               │  wherever the key is accessible
```

**Contained exploitation:**

```bash
# Attacker has assumed a cross-account role that can call KMS
aws kms decrypt \
  --ciphertext-blob fileb://encrypted-data.bin \
  --key-id arn:aws:kms:eu-central-1:111111111111:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
  --region eu-central-1 \
  --output text --query Plaintext | base64 -d > plaintext.bin

# The plaintext is now on the attacker's machine in us-east-1 (or anywhere)
# Residency was bypassed — the key was accessible from outside the EU region
```

**Artifacts left:**
- CloudTrail `kms:Decrypt` event with `sourceIPAddress` from outside the allowed region
- SCP denies any write to non-EU regions, but `kms:Decrypt` doesn't write data — it reads keys
- GuardDuty finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` if EC2 creds used
- VPC Flow Logs showing DNS tunnel to exfiltration domain

## 🔵 Blue Team view — multi-layer residency defense

### Layer 1: Region restriction SCP (preventive)

Already shown above — deny all API calls outside approved regions.

### Layer 2: KMS key policy that restricts access by source VPC / IP

```json
{
  "Sid": "KMSDecryptFromEUOnly",
  "Effect": "Deny",
  "Principal": "*",
  "Action": ["kms:Decrypt", "kms:ReEncrypt*"],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "kms:CallerAccount": "111111111111",
      "aws:SourceVpc": "vpc-0a1b2c3d4e5f67890"
    }
  }
}
```

### Layer 3: Daily region drift alert

```bash
# AWS Config advanced query — resources outside approved regions
aws configservice select-aggregate-resource-config \
  --expression "
    SELECT resourceId, resourceType, awsRegion
    WHERE resourceType IN ('AWS::S3::Bucket', 'AWS::EC2::Instance', 'AWS::RDS::DBInstance', 'AWS::DynamoDB::Table')
    AND awsRegion NOT IN ('eu-central-1', 'eu-west-1', 'eu-west-2')
  " > region-drift-$(date +%Y%m%d).json

# Alert if not empty
if [ -s region-drift-$(date +%Y%m%d).json ]; then
  aws sns publish \
    --topic-arn arn:aws:sns:eu-central-1:111111111111:region-drift-alerts \
    --message "$(cat region-drift-$(date +%Y%m%d).json)"
fi
```

### Layer 4: Azure Resource Graph daily residency query

```kql
// Query resources outside approved EU regions
resources
| where location !in ('westeurope', 'northeurope', 'francecentral', 'germanywestcentral')
| project name, type, location, resourceGroup, subscriptionId
| order by type asc, name asc
```

### Layer 5: KMS key access monitoring

```sql
-- CloudWatch Logs Insights — KMS decrypt from non-EU source IP
fields @timestamp, userIdentity.arn, sourceIPAddress, requestParameters.keyId
| filter eventSource = "kms.amazonaws.com"
| filter eventName = "Decrypt"
| filter sourceIPAddress not like /^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168\.)/
| stats count(*) by sourceIPAddress, userIdentity.arn
```

```kql
// Azure — Key Vault decrypt from unexpected location
AzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName == "SecretGet"
| extend callerIP = coalesce(CallerIPAddress, tostring(identity_claim_ipaddr_s))
| where callerIP !startswith "10."
| project TimeGenerated, callerIP, identity_claim_unique_name_s, ResultType
```

## Hands-on lab — residency enforcement test

**Duration:** 15 min. **Cost:** Free-tier policy eval only.

```bash
# AWS: test SCP by simulating a principal action in denied region
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111111111111:user/testuser \
  --action-names s3:CreateBucket \
  --context-entries "ContextKeyName=aws:RequestedRegion,ContextKeyValues=ap-southeast-1,ContextKeyType=string"

# Azure: test policy by evaluating What-If
az policy state trigger-scan --subscription 00000000-0000-0000-0000-000000000000

# GCP: simulate org policy
gcloud org-policies describe constraints/gcp.resourceLocations \
  --organization=000000000000
```

**Expected output:** SCP simulation returns `ImplicitDeny` for non-EU region; Azure Resource Graph returns 0 resources outside approved locations.

## Detection rules & checklists

```yaml
title: Resource Created Outside Approved Regions
id: a1b2c3d4-9000-4000-8000-e5f6a7b8c9d0
status: experimental
description: Detect resource creation in a region not approved for residency
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource:
      - s3.amazonaws.com
      - ec2.amazonaws.com
      - rds.amazonaws.com
      - dynamodb.amazonaws.com
    eventName:
      - CreateBucket
      - RunInstances
      - CreateDBInstance
      - CreateTable
    awsRegion:
      - us-east-1
      - ap-southeast-1
      - ap-northeast-1
  condition: selection
level: high
```

**Residency and sovereignty checklist:**

- [ ] SCP / Azure Policy / Org Policy denies resource creation outside approved regions.
- [ ] KMS/Key Vault/Cloud KMS keys are single-region (no multi-region replicas) for sovereignty-sensitive data.
- [ ] KMS key policy restricts `Decrypt` to specific VPCs or IP ranges.
- [ ] Daily automated query checks for resources outside approved regions.
- [ ] CMEK keys for data at rest are resident in the same region as the data.
- [ ] VPC Service Controls / Conditional Access restrict access from outside approved geographies.
- [ ] Data lifecycle policies keep backups, snapshots, and replicas in-region.

## References

- [AWS SCPs — Region Restriction](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_general.html#example-scp-deny-region)
- [Azure Policy — Allowed Locations](https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies#general)
- [GCP Resource Locations Constraint](https://cloud.google.com/resource-manager/docs/organization-policy/defining-locations)
- [AWS KMS — Multi-Region Keys](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html)
- MITRE ATT&CK: T1537 Transfer Data to Cloud Account, T1041 Exfiltration Over C2 Channel
- Cross-links: [../Storage-Data-Security/data-encryption-at-rest.md](../Storage-Data-Security/data-encryption-at-rest.md), [../Secrets-KMS/kms-key-management-basics.md](../Secrets-KMS/kms-key-management-basics.md)
