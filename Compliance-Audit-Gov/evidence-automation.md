# 03 — Evidence Automation

> **Level:** Intermediate
> **Prereqs:** [Frameworks Overview CIS NIST ISO PCI](frameworks-overview-cis-nist-iso-pci.md), [Access Reviews & Certification](access-reviews-and-certification.md), [IaC Security](../IaC-Security)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Collection
> **Authorization scope:** Evidence generation scripts must be pointed at your own sandbox accounts and only use placeholder bucket/resource names.

## What & why

The auditor's question is always the same: "Show me evidence that control X operated for the entire audit period." If your answer is "I'll get back to you in a week," you lose engineering trust and auditor confidence. Automate evidence capture, storage, and retrieval — indexed by control ID, timestamped, immutable, and queryable. The goal: any auditor question answered in < 5 minutes by running a query on a pre-built evidence bucket.

## The OnPrem reality

Pre-cloud: Nessus/Qualys scheduled scans dumped PDF/CSV into a SharePoint folder named `Audit_Evidence_Q3_2025_FINAL_v3_REVISED.pptx`. The sysadmin who ran the scan left the company; the credentials embedded in the scan config expired; the auditor flagged the gap as "control not operating for 47 days." Cloud-native evidence automation eliminates this fragility.

## Evidence architecture — four columns

| Layer | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| **Collect** | Audit Manager assessment, Config advanced query | Azure Policy compliance API, Resource Graph | SCC findings export, Asset Inventory | OpenSCAP JSON, Nessus API export |
| **Normalize** | Lambda formatting function | Logic App or Azure Function | Cloud Function dataflow | Python script on cron |
| **Store** | S3 + Object Lock (Compliance mode) | Blob immutable storage (time-based retention) | GCS + bucket lock (retention policy) | MinIO with WORM + `chattr +a` |
| **Index** | JSON per control ID + DynamoDB metadata index | Azure Table Storage or CosmosDB metadata | BigQuery external table over GCS | SQLite or PostgreSQL evidence table |
| **Retrieve** | `config:advancedquery` + S3 Select | Resource Graph Explorer + `az graph query` | `gcloud asset search-all-resources` | `jq` + Python evidence CLI |
| **Publish** | SHA-256 manifest in README | SHA-256 in blob metadata | SHA-256 in object metadata | `sha256sum *.json > manifest.txt` |

## Evidence pack structure

```
s3://compliance-evidence/
├── 2026-Q1/
│   ├── manifest.txt                       # SHA-256 of every file below
│   ├── CIS-1.1-access-keys-rotated.json
│   ├── CIS-1.4-root-mfa.json
│   ├── CIS-3.1-public-s3-block.json
│   ├── PCI-3.4-encryption-at-rest.json
│   ├── SOC2-CC6.1-logical-access.json
│   └── exceptions/
│       ├── CIS-1.1-exceptions.json
│       └── CIS-3.1-exceptions.json
```

Each evidence file format:

```json
{
  "control_id": "CIS-3.1",
  "framework": "CIS AWS Foundations Benchmark v1.4.0",
  "period": "2026-Q1",
  "generated_at": "2026-04-01T00:05:00Z",
  "generated_by": "evidence-automation-lambda-111111111111-us-east-1",
  "status": "COMPLIANT_WITH_EXCEPTIONS",
  "total_resources": 342,
  "compliant": 338,
  "noncompliant": 2,
  "excepted": 2,
  "evidence": [
    {
      "resource_id": "arn:aws:s3:::data-lake-111111111111-us-east-1",
      "resource_type": "AWS::S3::Bucket",
      "compliant": true,
      "evaluation_time": "2026-03-31T23:59:59Z",
      "config_rule": "s3-bucket-public-read-prohibited",
      "details": {"blockPublicAcls": true, "blockPublicPolicy": true}
    }
  ],
  "audit_queries": [
    "SELECT * FROM compliance WHERE control_id='CIS-3.1' AND period='2026-Q1'"
  ]
}
```

## AWS — evidence automation pipeline

### Step 1: Collect via Audit Manager

```bash
# Create an assessment for CIS benchmarks
aws auditmanager create-assessment \
  --name "CIS-Level1-2026-Q2" \
  --assessment-reports-destination "S3" \
  --s3-destination bucket="compliance-evidence-111111111111-us-east-1" \
  --framework-id "arn:aws:auditmanager:us-east-1:111111111111:framework/CIS-AWS-Foundations-Benchmark"

# Export the assessment report
aws auditmanager get-assessment \
  --assessment-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

### Step 2: Collect via Config advanced query

```bash
aws configservice select-aggregate-resource-config \
  --expression "
    SELECT
      resourceId,
      resourceType,
      configuration.publicAccessBlockConfiguration.blockPublicAcls,
      configuration.publicAccessBlockConfiguration.blockPublicPolicy,
      configuration.publicAccessBlockConfiguration.restrictPublicBuckets,
      configuration.publicAccessBlockConfiguration.ignorePublicAcls
    WHERE resourceType = 'AWS::S3::Bucket'
    ORDER BY resourceId
  " \
  --limit 200 \
  | jq '.Results[]' -r \
  > s3-public-access-block-2026-Q1.json
```

### Step 3: Store with Object Lock

```hcl
resource "aws_s3_bucket" "compliance_evidence" {
  bucket = "compliance-evidence-111111111111-us-east-1"
}

resource "aws_s3_bucket_versioning" "evidence_versioning" {
  bucket = aws_s3_bucket.compliance_evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_lock" {
  bucket = aws_s3_bucket.compliance_evidence.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      years = 7
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_encryption" {
  bucket = aws_s3_bucket.compliance_evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence_key.arn
    }
  }
}
```

### Step 4: Generate manifest

```python
import boto3
import hashlib
import json
from datetime import datetime

s3 = boto3.client("s3")
bucket = "compliance-evidence-111111111111-us-east-1"
prefix = "2026-Q1/"
manifest = {"generated_at": datetime.utcnow().isoformat() + "Z", "files": {}}

paginator = s3.get_paginator("list_objects_v2")
for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
    for obj in page.get("Contents", []):
        if obj["Key"].endswith("manifest.txt"):
            continue
        resp = s3.get_object(Bucket=bucket, Key=obj["Key"])
        sha = hashlib.sha256(resp["Body"].read()).hexdigest()
        manifest["files"][obj["Key"]] = {
            "sha256": sha,
            "size": obj["Size"],
            "last_modified": obj["LastModified"].isoformat()
        }

s3.put_object(
    Bucket=bucket,
    Key=f"{prefix}manifest.txt",
    Body=json.dumps(manifest, indent=2),
    ContentType="text/plain"
)
print(f"Manifest published: {bucket}/{prefix}manifest.txt")
```

## Azure — evidence automation pipeline

### Step 1: Collect via Azure Policy compliance API

```bash
az policy state list \
  --filter "complianceState eq 'NonCompliant'" \
  --query "[].{policy:policyDefinitionName, resource:resourceId}"

# Full compliance snapshot per assignment
az policy state summarize \
  --filter "policyAssignmentName eq 'pci-dss-v4'"
```

### Step 2: Collect via Resource Graph

```bash
az graph query -q "
  resources
  | where type =~ 'Microsoft.Storage/storageAccounts'
  | extend allowBlob = properties.allowBlobPublicAccess
  | extend minTLS = properties.minimumTlsVersion
  | project name, resourceGroup, allowBlob, minTLS
" --output json > azure-storage-compliance-2026-Q1.json
```

### Step 3: Store with immutable blob

```bash
az storage container create \
  --name evidence-2026-q1 \
  --account-name complianceevidencellllllll \
  --account-key "PLACEHOLDER"

# Enable immutability policy (time-based retention)
az storage container immutability-policy create \
  --container-name evidence-2026-q1 \
  --account-name complianceevidencellllllll \
  --period 2555  # days (~7 years)
```

### Step 4: Upload and generate manifest

```bash
az storage blob upload-batch \
  --destination evidence-2026-q1 \
  --source ./evidence-output/ \
  --account-name complianceevidencellllllll

# Generate manifest
for f in evidence-output/*.json; do
  sha256sum "$f" | tee -a manifest.txt
done
az storage blob upload \
  --container-name evidence-2026-q1 \
  --file manifest.txt \
  --name manifest.txt \
  --account-name complianceevidencellllllll
```

## GCP — evidence automation pipeline

### Step 1: Collect via SCC findings export

```bash
gcloud scc findings list --organization=000000000000 \
  --filter="state=\"ACTIVE\" AND sourceProperties.Category:\"PUBLIC_BUCKET_ACL\"" \
  --format="json" > scc-public-bucket-findings-2026-Q1.json

gcloud asset search-all-resources \
  --scope="organizations/000000000000" \
  --asset-types="storage.googleapis.com/Bucket" \
  --format="json" > gcs-inventory-2026-Q1.json
```

### Step 2: Store with bucket lock

```hcl
resource "google_storage_bucket" "compliance_evidence" {
  name     = "compliance-evidence-000000000000"
  location = "US"
  uniform_bucket_level_access = true

  retention_policy {
    retention_period = 2555 * 86400  # 7 years in seconds
    is_locked        = true
  }
}
```

### Step 3: Manifest via Cloud Function

```python
def generate_manifest(event, context):
    from google.cloud import storage
    import hashlib, json
    client = storage.Client()
    bucket = client.bucket("compliance-evidence-000000000000")
    manifest = {"files": {}}
    for blob in bucket.list_blobs(prefix="2026-Q1/"):
        if "manifest" in blob.name: continue
        sha = hashlib.sha256(blob.download_as_bytes()).hexdigest()
        manifest["files"][blob.name] = {"sha256": sha}
    bucket.blob("2026-Q1/manifest.txt").upload_from_string(
        json.dumps(manifest, indent=2))
```

## OnPrem — evidence automation

```bash
#!/bin/bash
# Run OpenSCAP scan, output JSON, sign manifest
oscap xccdf eval --profile cis_workstation_l1 \
  --results /tmp/oscap-results.xml \
  /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml

oscap xccdf generate report /tmp/oscap-results.xml > /tmp/oscap-report.html

# Convert to normalized JSON
python3 oscap-to-evidence.py /tmp/oscap-results.xml > workstation-cis-2026-Q1.json

# Store in WORM directory
chattr +a /evidence/2026-Q1/

# Generate manifest
sha256sum /evidence/2026-Q1/*.json > /evidence/2026-Q1/manifest.txt
```

## 🔴 Red Team view — evidence tampering

**Attack narrative:** An attacker with `s3:PutObject` permission on the evidence bucket overwrites the noncompliant findings JSON with a forged "all green" version. The auditor relies on the evidence pack without independently verifying against live Config rule results. The manifest file is also overwritten since it's in the same bucket with the same permissions.

**Contained exploitation steps:**

```bash
# Attacker discovers evidence bucket via reconnaissance
aws s3 ls s3://compliance-evidence-111111111111-us-east-1/2026-Q1/

# Downloads the real evidence file showing noncompliant buckets
aws s3 cp \
  s3://compliance-evidence-111111111111-us-east-1/2026-Q1/CIS-3.1-public-s3-block.json \
  original.json

# Modifies the JSON: sets all "compliant": true and "status": "COMPLIANT"
cat original.json | jq '.status="COMPLIANT" | .noncompliant=0 | .compliant=342' > forged.json

# Overwrites evidence
aws s3 cp forged.json \
  s3://compliance-evidence-111111111111-us-east-1/2026-Q1/CIS-3.1-public-s3-block.json

# Generates new manifest to match forged evidence
python3 generate-manifest.py --bucket compliance-evidence-111111111111-us-east-1 --prefix 2026-Q1/
aws s3 cp new-manifest.txt \
  s3://compliance-evidence-111111111111-us-east-1/2026-Q1/manifest.txt
```

**Artifacts left:**
- S3 data event `PutObject` on evidence bucket (logged to separate CloudTrail trail)
- Versioning history shows old version with real noncompliant data, new version with forged data
- `PutObject` event timestamp does not match quarterly evidence generation window
- IAM user/role ARN performing the `PutObject` does not match the evidence automation service role

## 🔵 Blue Team view — tamper-proof evidence architecture

### Immutable, copy-on-write evidence bucket

```hcl
# S3 Object Lock in COMPLIANCE mode — NO ONE can delete/overwrite, not even root
resource "aws_s3_bucket_object_lock_configuration" "lock" {
  bucket = aws_s3_bucket.compliance_evidence.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      years = 7
    }
  }
}
```

### Cross-account evidence ingestion (write-only publisher)

```hcl
# Evidence bucket policy — only the automation role can write;
# security readers can list/read but NOT write or delete
data "aws_iam_policy_document" "evidence_bucket_policy" {
  statement {
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = ["arn:aws:iam::111111111111:role/evidence-automation-publisher"]
    }
    actions   = ["s3:PutObject", "s3:PutObjectAcl"]
    resources = ["${aws_s3_bucket.compliance_evidence.arn}/*"]
  }
  statement {
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = ["arn:aws:iam::222222222222:role/evidence-reader-security"]
    }
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      aws_s3_bucket.compliance_evidence.arn,
      "${aws_s3_bucket.compliance_evidence.arn}/*"
    ]
  }
  statement {
    effect = "Deny"
    principals { type = "*" }
    actions   = ["s3:DeleteObject", "s3:DeleteBucket", "s3:PutObject"]
    resources = [
      aws_s3_bucket.compliance_evidence.arn,
      "${aws_s3_bucket.compliance_evidence.arn}/*"
    ]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::111111111111:role/evidence-automation-publisher"]
    }
  }
}
```

### Detection: evidence bucket modifications outside assessment window

```sql
-- CloudWatch Logs Insights — evidence bucket writes outside scheduled window
fields @timestamp, eventName, userIdentity.arn, requestParameters.bucketName
| filter eventSource = "s3.amazonaws.com"
| filter eventName = "PutObject"
| filter requestParameters.bucketName = "compliance-evidence-111111111111-us-east-1"
| filter @timestamp not like /2026-0[147]-0[13]/  -- Q1 windows: Jan 1-3, Apr 1-3, Jul 1-3, Oct 1-3
| stats count(*) by bin(1h)
```

**Azure equivalent — evidence container writes:**

```kql
StorageBlobLogs
| where AccountName == "complianceevidence"
| where OperationName == "PutBlob"
| where TimeGenerated !between (datetime(2026-04-01) .. datetime(2026-04-04))
| project TimeGenerated, CallerIpAddress, ObjectKey
```

### Manifest integrity verification (manual or automated)

```bash
# Verify every file matches published manifest
python3 -c "
import json, hashlib, boto3
s3 = boto3.client('s3')
bucket = 'compliance-evidence-111111111111-us-east-1'
manifest = json.loads(s3.get_object(Bucket=bucket, Key='2026-Q1/manifest.txt')['Body'].read())
for fname, meta in manifest['files'].items():
    obj = s3.get_object(Bucket=bucket, Key=fname)
    actual = hashlib.sha256(obj['Body'].read()).hexdigest()
    status = '✅' if actual == meta['sha256'] else '❌ TAMPERED'
    print(f'{status}  {fname}  expected={meta[\"sha256\"][:12]}  actual={actual[:12]}')
"
```

## Hands-on lab — evidence pack generator

See [../labs/audit-evidence-mini-pack.md](../labs/audit-evidence-mini-pack.md) for the end-to-end exercise.

## Detection rules & checklists

```yaml
title: Compliance Evidence Bucket Modified Outside Assessment Window
id: c1d2e3f4-6000-4000-8000-a5b6c7d8e9f0
status: experimental
description: Evidence files written outside quarterly assessment generation windows
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: PutObject
    requestParameters.bucketName: compliance-evidence-
  timeframe: outside (Jan 1-3, Apr 1-3, Jul 1-3, Oct 1-3)  -- adjust per org
  condition: selection
level: high
```

**Evidence automation checklist:**

- [ ] Evidence bucket has Object Lock in COMPLIANCE mode (or equivalent per cloud).
- [ ] Evidence bucket access logs ship to a separate, immutable log bucket.
- [ ] Manifest generated per quarter with SHA-256 of every evidence file.
- [ ] Manifest published to a read-only location separate from the evidence bucket.
- [ ] Evidence generation runs from a dedicated IAM role / service principal — not a human user.
- [ ] Alert fires if any `PutObject` to evidence bucket occurs outside the scheduled quarterly window.
- [ ] Cross-account evidence ingestion (publisher account ≠ reader account).

## References

- [AWS Audit Manager](https://docs.aws.amazon.com/audit-manager/latest/userguide/what-is.html)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [Azure Immutable Blob Storage](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-policy-configure-version-scope)
- [GCP Bucket Lock](https://cloud.google.com/storage/docs/bucket-lock)
- MITRE ATT&CK: T1565 Data Manipulation, T1070 Indicator Removal
- Cross-links: [../Storage-Data-Security/data-encryption-at-rest.md](../Storage-Data-Security/data-encryption-at-rest.md), [../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md)
