# Lab 01 — Audit Evidence Mini-Pack (Q1 Evidence Generator)

> **Level:** Intermediate
> **Duration:** 25–30 minutes
> **Cost:** Free (AWS Free Tier; S3 usage < $0.01)
> **Authorization scope:** Run only in your own AWS sandbox account. All bucket names and resource identifiers are placeholders. Delete all resources after the lab.

## 🔴 Red Team view — why evidence integrity matters

An attacker who compromises the evidence bucket can overwrite noncompliant findings with forged "all green" JSON, publish a new manifest to match, and the auditor sees a perfectly compliant quarter. The defense: Object Lock in COMPLIANCE mode makes every evidence file immutable — even the root account can't delete or overwrite it for the retention period. Combined with SHA-256 manifests published to a separate read-only location, tampering is detectable (manifest hash mismatch) even if the bucket were somehow modified.

## 🔵 Blue Team view — evidence as code

This lab mechanizes what most orgs do manually: run audit queries, format results, store them immutably, and publish an integrity manifest. Once this pipeline runs on a schedule (Lambda cron + S3 Object Lock), answering an auditor's question goes from "six weeks of emailing sysadmins" to "here's the S3 prefix — all files are SHA-256 signed and timestamped."

## Objective

Generate a "Q1 evidence pack" for 3 controls picked from the CIS AWS Foundations Benchmark, with cross-cloud equivalent queries. Write structured JSON evidence per control into a versioned, Object-Locked S3 bucket. Compute a SHA-256 of every evidence file and publish a signed manifest.

### Target controls

| CIS Control | Topic | AWS Config Rule | Azure Equivalent | GCP Equivalent |
|---|---|---|---|---|
| 1.1 | IAM access keys rotated within 90 days | `iam-user-unused-credentials-check` | Entra ID access review for key age | IAM Recommender `google.iam.policy.Recommender` |
| 1.4 | Root MFA enabled | `root-account-mfa-enabled` | `accounts with write on subscription should have MFA` (policy initiative) | `constraints/iam.mfaRequiredForRoot` |
| 3.1 | S3 public-read block enabled on all buckets | `s3-bucket-public-read-prohibited` | Storage account public access deny policy | `constraints/storage.publicAccessPrevention` |

## Prerequisites

- AWS CLI configured with sandbox credentials (`aws sts get-caller-identity` works)
- Python 3.9+ with `boto3` (`pip install boto3`)
- `jq` installed (`brew install jq` on macOS)
- Terraform CLI (for Object Lock bucket setup — can also use AWS CLI)
- `sha256sum` (coreutils on macOS: `brew install coreutils` and use `gsha256sum`)

## Step 1 — Create the evidence bucket with Object Lock

```bash
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export REGION="us-east-1"
export EVIDENCE_BUCKET="compliance-evidence-${AWS_ACCOUNT_ID}-${REGION}"

# Create bucket (Object Lock requires it at creation time)
aws s3api create-bucket \
  --bucket "${EVIDENCE_BUCKET}" \
  --region "${REGION}" \
  --object-lock-enabled-for-bucket

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket "${EVIDENCE_BUCKET}" \
  --versioning-configuration Status=Enabled

# Set Object Lock default retention (GOVERNANCE mode for lab — COMPLIANCE for production)
aws s3api put-object-lock-configuration \
  --bucket "${EVIDENCE_BUCKET}" \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "GOVERNANCE",
        "Years": 7
      }
    }
  }'

# Enable default encryption
aws s3api put-bucket-encryption \
  --bucket "${EVIDENCE_BUCKET}" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
    }]
  }'

# Enable access logging (to a separate log bucket)
# Optional for lab — in production, ship to a different account
aws s3api put-bucket-logging \
  --bucket "${EVIDENCE_BUCKET}" \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "access-logs-${AWS_ACCOUNT_ID}-${REGION}",
      "TargetPrefix": "evidence-bucket-access/"
    }
  }' 2>/dev/null || echo "Access log bucket not set up — skipping (optional)"

echo "Evidence bucket created: s3://${EVIDENCE_BUCKET}"
```

## Step 2 — Collect evidence for Control 1.1 (Access keys rotated within 90 days)

```python
#!/usr/bin/env python3
"""cis-1.1-evidence.py — Generate evidence for IAM access key rotation"""

import boto3, json, csv, datetime
from io import StringIO

iam = boto3.client("iam")
today = datetime.datetime.utcnow()
cutoff = today - datetime.timedelta(days=90)

# Generate credential report
iam.generate_credential_report()
import time; time.sleep(5)

report_csv = iam.get_credential_report()["Content"].decode("utf-8")
reader = csv.DictReader(StringIO(report_csv))

findings = []
for row in reader:
    if row["user"] == "<root_account>":
        continue
    for key_num in ["1", "2"]:
        if row.get(f"access_key_{key_num}_active") == "true":
            created_str = row.get(f"access_key_{key_num}_last_rotated")
            if created_str and created_str != "N/A":
                created = datetime.datetime.fromisoformat(created_str)
                age_days = (today - created).days
                rotated_within_90d = age_days <= 90
                findings.append({
                    "resource_id": f"{row['arn']}/AccessKey{key_num}",
                    "resource_type": "AWS::IAM::AccessKey",
                    "user": row["user"],
                    "user_arn": row["arn"],
                    "key_id": row.get(f"access_key_{key_num}_last_rotated") or "N/A",
                    "age_days": age_days,
                    "compliant": rotated_within_90d,
                    "mfa_active": row.get("mfa_active") == "true",
                    "evaluation_time": today.isoformat() + "Z"
                })

noncompliant = [f for f in findings if not f["compliant"]]
evidence = {
    "control_id": "CIS-1.1",
    "framework": "CIS AWS Foundations Benchmark v1.4.0",
    "title": "Ensure IAM access keys are rotated within 90 days",
    "period": "2026-Q1",
    "generated_at": today.isoformat() + "Z",
    "status": "COMPLIANT" if len(noncompliant) == 0 else "NONCOMPLIANT",
    "total_keys": len(findings),
    "noncompliant_keys": len(noncompliant),
    "evidence": findings[:20],  # truncated for lab
    "cross_cloud_equivalents": {
        "azure": "Entra ID — access review for service principal credential age",
        "gcp": "IAM Recommender — service account key age > 90d",
        "onprem": "AD — search for accounts with pwdLastSet > 90 days"
    }
}

with open("/tmp/cis-1.1-access-keys-2026-Q1.json", "w") as f:
    json.dump(evidence, f, indent=2, default=str)

print(f"CIS-1.1: {evidence['total_keys']} keys, {evidence['noncompliant_keys']} noncompliant")
```

```bash
python3 /tmp/cis-1.1-evidence.py
```

## Step 3 — Collect evidence for Control 1.4 (Root MFA enabled)

```python
#!/usr/bin/env python3
"""cis-1.4-evidence.py — Generate evidence for root MFA"""

import boto3, json, datetime

iam = boto3.client("iam")
today = datetime.datetime.utcnow()

# Check root account summary
summary = iam.get_account_summary()["SummaryMap"]
root_has_mfa = summary.get("AccountMFAEnabled", 0) == 1
root_has_access_keys = summary.get("AccountAccessKeysPresent", 0) > 0

evidence = {
    "control_id": "CIS-1.4",
    "framework": "CIS AWS Foundations Benchmark v1.4.0",
    "title": "Ensure MFA is enabled for root account",
    "period": "2026-Q1",
    "generated_at": today.isoformat() + "Z",
    "status": "COMPLIANT" if (root_has_mfa and not root_has_access_keys) else "NONCOMPLIANT",
    "details": {
        "root_mfa_enabled": root_has_mfa,
        "root_has_access_keys": root_has_access_keys,
        "account_id": boto3.client("sts").get_caller_identity()["Account"]
    },
    "cross_cloud_equivalents": {
        "azure": "Azure Policy: 'Accounts with write permissions on subscription should have MFA'",
        "gcp": "Org Policy constraint: constraints/iam.mfaRequiredForRoot",
        "onprem": "AD Domain Admin accounts enforced for smart card / MFA"
    }
}

with open("/tmp/cis-1.4-root-mfa-2026-Q1.json", "w") as f:
    json.dump(evidence, f, indent=2, default=str)

print(f"CIS-1.4: MFA={'ENABLED' if root_has_mfa else 'DISABLED'}, "
      f"AccessKeys={'PRESENT' if root_has_access_keys else 'NONE'}")
```

```bash
python3 /tmp/cis-1.4-evidence.py
```

## Step 4 — Collect evidence for Control 3.1 (S3 public-read block)

```python
#!/usr/bin/env python3
"""cis-3.1-evidence.py — Generate evidence for S3 public access block"""

import boto3, json, datetime

s3 = boto3.client("s3")
today = datetime.datetime.utcnow()

buckets = s3.list_buckets()["Buckets"]
findings = []

for bucket in buckets:
    bucket_name = bucket["Name"]
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        compliant = all([
            pab.get("BlockPublicAcls", False),
            pab.get("BlockPublicPolicy", False),
            pab.get("RestrictPublicBuckets", False),
            pab.get("IgnorePublicAcls", False)
        ])
        findings.append({
            "resource_id": f"arn:aws:s3:::{bucket_name}",
            "resource_type": "AWS::S3::Bucket",
            "block_public_acls": pab.get("BlockPublicAcls"),
            "block_public_policy": pab.get("BlockPublicPolicy"),
            "restrict_public_buckets": pab.get("RestrictPublicBuckets"),
            "ignore_public_acls": pab.get("IgnorePublicAcls"),
            "compliant": compliant,
            "evaluation_time": today.isoformat() + "Z"
        })
    except s3.exceptions.ClientError:
        findings.append({
            "resource_id": f"arn:aws:s3:::{bucket_name}",
            "resource_type": "AWS::S3::Bucket",
            "error": "No PublicAccessBlock configured",
            "compliant": False,
            "evaluation_time": today.isoformat() + "Z"
        })

noncompliant = [f for f in findings if not f["compliant"]]
evidence = {
    "control_id": "CIS-3.1",
    "framework": "CIS AWS Foundations Benchmark v1.4.0",
    "title": "Ensure S3 public access block is enabled on all buckets",
    "period": "2026-Q1",
    "generated_at": today.isoformat() + "Z",
    "status": "COMPLIANT" if len(noncompliant) == 0 else "NONCOMPLIANT",
    "total_buckets": len(findings),
    "noncompliant_buckets": len(noncompliant),
    "evidence": findings,
    "cross_cloud_equivalents": {
        "azure": "Azure Policy: 'Storage account public access should be disallowed'",
        "gcp": "Org Policy constraint: constraints/storage.publicAccessPrevention",
        "onprem": "MinIO WORM bucket + network ACL"
    }
}

with open("/tmp/cis-3.1-public-s3-block-2026-Q1.json", "w") as f:
    json.dump(evidence, f, indent=2, default=str)

print(f"CIS-3.1: {evidence['total_buckets']} buckets, {evidence['noncompliant_buckets']} noncompliant")
```

```bash
python3 /tmp/cis-3.1-evidence.py
```

## Step 5 — Upload evidence to bucket with Object Lock

```bash
# Upload all evidence files to Q1 prefix
for file in /tmp/cis-*.json; do
    key="2026-Q1/$(basename $file)"
    aws s3api put-object \
        --bucket "${EVIDENCE_BUCKET}" \
        --key "$key" \
        --body "$file" \
        --object-lock-mode GOVERNANCE \
        --object-lock-retain-until-date "$(date -u -v+7y +%Y-%m-%dT%H:%M:%SZ)" \
        --server-side-encryption AES256
    echo "Uploaded: $key"
done

# Verify uploads
aws s3 ls "s3://${EVIDENCE_BUCKET}/2026-Q1/"
```

## Step 6 — Compute SHA-256 manifest

```bash
#!/bin/bash
# Generate manifest.txt with SHA-256 of every evidence file
MANIFEST_FILE="/tmp/manifest-2026-Q1.txt"

echo "# Compliance Evidence Manifest — 2026-Q1" > "${MANIFEST_FILE}"
echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${MANIFEST_FILE}"
echo "# Account: ${AWS_ACCOUNT_ID}" >> "${MANIFEST_FILE}"
echo "" >> "${MANIFEST_FILE}"

for file in /tmp/cis-*.json; do
    fname=$(basename "$file")
    hash=$(sha256sum "$file" | awk '{print $1}')
    size=$(wc -c < "$file" | tr -d ' ')
    echo "${hash}  ${fname}  size=${size}" >> "${MANIFEST_FILE}"
done

echo "" >> "${MANIFEST_FILE}"
echo "# Verification: sha256sum -c <(grep -v '^#' manifest.txt)" >> "${MANIFEST_FILE}"

cat "${MANIFEST_FILE}"
```

```bash
# Upload manifest
aws s3api put-object \
    --bucket "${EVIDENCE_BUCKET}" \
    --key "2026-Q1/manifest.txt" \
    --body "/tmp/manifest-2026-Q1.txt" \
    --object-lock-mode GOVERNANCE \
    --object-lock-retain-until-date "$(date -u -v+7y +%Y-%m-%dT%H:%M:%SZ)" \
    --server-side-encryption AES256

echo "Manifest uploaded: s3://${EVIDENCE_BUCKET}/2026-Q1/manifest.txt"
```

## Step 7 — Verify integrity

```bash
# Download all evidence files and verify against manifest
mkdir -p /tmp/evidence-verify
aws s3 sync "s3://${EVIDENCE_BUCKET}/2026-Q1/" /tmp/evidence-verify/

cd /tmp/evidence-verify
grep -v '^#' manifest-2026-Q1.txt | while read -r hash fname rest; do
    actual=$(sha256sum "$fname" 2>/dev/null | awk '{print $1}')
    if [ "$hash" = "$actual" ]; then
        echo "✅ ${fname}"
    else
        echo "❌ TAMPERED: ${fname}  expected=${hash:0:12}  actual=${actual:0:12}"
    fi
done
```

## Step 8 — Cross-cloud evidence equivalents (for reference)

```bash
# Azure: Storage account public access check
az graph query -q "
  resources
  | where type =~ 'Microsoft.Storage/storageAccounts'
  | project name, resourceGroup, publicAccess = properties.allowBlobPublicAccess
" --output json > /tmp/azure-cross-cloud-cis-3.1.json

# GCP: Bucket public access prevention check
gcloud asset search-all-resources \
  --scope="organizations/000000000000" \
  --asset-types="storage.googleapis.com/Bucket" \
  --format="json" > /tmp/gcp-cross-cloud-cis-3.1.json 2>/dev/null || echo "GCP org not available — skipping"

# OnPrem (Linux): CIS-CAT or OpenSCAP evidence stub
oscap xccdf eval --profile cis_workstation_l1 \
  --results /tmp/oscap-results.xml \
  /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml 2>/dev/null || echo "OpenSCAP not installed — skipping"
```

## Expected output

```
Evidence bucket:        s3://compliance-evidence-111111111111-us-east-1/
Q1 prefix:              2026-Q1/
├── cis-1.1-access-keys-2026-Q1.json
├── cis-1.4-root-mfa-2026-Q1.json
├── cis-3.1-public-s3-block-2026-Q1.json
└── manifest.txt

Manifest verification:  ✅ cis-1.1-access-keys-2026-Q1.json
                        ✅ cis-1.4-root-mfa-2026-Q1.json
                        ✅ cis-3.1-public-s3-block-2026-Q1.json
```

## Teardown

```bash
# Remove Object Lock governance retention (if you have s3:BypassGovernanceRetention)
aws s3api delete-objects \
  --bucket "${EVIDENCE_BUCKET}" \
  --delete "$(aws s3api list-object-versions \
    --bucket "${EVIDENCE_BUCKET}" \
    --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')" \
  --bypass-governance-retention

# Delete the bucket
aws s3api delete-bucket --bucket "${EVIDENCE_BUCKET}"

# Clean up temp files
rm -f /tmp/cis-*.json /tmp/manifest-*.txt
rm -rf /tmp/evidence-verify

echo "Teardown complete. All resources deleted."
```

> ⚠️ If Object Lock in GOVERNANCE mode blocks delete, use the `--bypass-governance-retention` flag with a role that has `s3:BypassGovernanceRetention`. If you used COMPLIANCE mode, the objects are undeletable for 7 years — only use COMPLIANCE in production.

## Cross-cloud evidence checklist for auditors

| Control | AWS Evidence | Azure Evidence | GCP Evidence | Acceptance Criteria |
|---|---|---|---|---|
| CIS 1.1 | Credential report + access key age log | Entra ID credential expiry report | IAM Recommender output | No key older than 90 days; exceptions documented |
| CIS 1.4 | `get-account-summary` MFA status | Policy compliance: MFA on root/subscription owner | Org Policy constraint status | MFA required; no root access keys |
| CIS 3.1 | `get-public-access-block` per bucket | Policy compliance: blob public access denied | Org Policy constraint: `publicAccessPrevention` enforced | All 4 block settings = true |

## References

- [CIS AWS Foundations Benchmark v1.4.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- Cross-links: [../evidence-automation.md](evidence-automation.md), [../frameworks-overview-cis-nist-iso-pci.md](frameworks-overview-cis-nist-iso-pci.md)
