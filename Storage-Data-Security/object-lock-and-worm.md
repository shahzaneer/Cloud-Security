# 04 — Object Lock & WORM Immutability

> **Level:** Advanced
> **Prereqs:** [04-01 — Object Storage Primitives](./object-storage-primitives.md), [04-03 — Encryption at Rest & CMK](./encryption-at-rest-and-cmek.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Impact (Data Destruction, Inhibit System Recovery)
> **Authorization scope:** Run only against your own storage accounts / a dedicated sandbox bucket.

## What & why

WORM (Write Once, Read Many) immutability prevents any principal — including root/admin — from modifying or deleting an object for a fixed retention period. This defeats ransomware operators who compromise cloud admin credentials and attempt to destroy backups before encrypting production data. Object Lock is your last line of defense for backup integrity.

## The OnPrem reality

Physical WORM media: optical discs (CD-R, DVD-R), tape cartridges with a write-protect tab, or specialized tape libraries (IBM TS7700) that enforced retention via firmware. Once the physical tab was flipped or the tape was ejected and stored offsite, no logical command could overwrite it. The weakness: physical loss or insider with physical access to the tape vault.

```
OnPrem WORM workflow:
  1. Backup to LTO tape
  2. Eject tape → write-protect tab to "read-only"
  3. Transport to off-site vault
  4. Retention logged in physical inventory system
  5. After retention expiry → tape destroyed or re-initialized
```

## Core concepts

**Modes across clouds:**

| Cloud | Immutability feature | Modes | Legal hold | Retention period granularity | Can lock be removed early? |
|---|---|---|---|---|---|
| AWS | S3 Object Lock | GOVERNANCE, COMPLIANCE | Yes (separate from retention) | Seconds to years | GOVERNANCE: yes (with `s3:BypassGovernanceRetention`); COMPLIANCE: no |
| Azure | Immutable Blob Storage | Time-based retention, Legal hold | Yes (separate policy) | Days to years | Time-based: no (once locked); Legal hold: no (while tag exists) |
| GCP | Bucket Lock | Retention policy only | (as of June 2026, GCP Cloud Storage does not have a separate legal-hold API; retention policy is the sole WORM mechanism) | Seconds to years | No (once retention policy is locked) |
| OnPrem | Tape WORM | Write-protect tab | Offsite custody log | Tape shelf-life | Physical destruction only |

**GOVERNANCE vs COMPLIANCE (AWS):**

| Aspect | GOVERNANCE | COMPLIANCE |
|---|---|---|
| Who can shorten/remove | Users with `s3:BypassGovernanceRetention` | No one, not even root |
| Use case | Internal policy enforcement, accidental deletion prevention | Regulatory mandates (SEC 17a-4, FINRA) |
| IAM requirement | Specific permission | No permission exists to override |

## AWS

**Service:** S3 Object Lock. **Console path:** `S3 → <bucket> → Properties → Object Lock` (must be enabled at bucket creation).

```bash
# 1. Create bucket with Object Lock enabled (required at creation)
aws s3api create-bucket \
  --bucket example-security-lab-locked-111111111111 \
  --region us-east-1 \
  --object-lock-enabled-for-bucket

# 2. Enable versioning (required for Object Lock)
aws s3api put-bucket-versioning \
  --bucket example-security-lab-locked-111111111111 \
  --versioning-configuration Status=Enabled

# 3. Place a COMPLIANCE-mode retention on the bucket (default settings)
aws s3api put-object-retention \
  --bucket example-security-lab-locked-111111111111 \
  --key critical-backup.tar.gz \
  --retention '{"Mode":"COMPLIANCE","RetainUntilDate":"2027-06-22T00:00:00Z"}'

# 4. Optionally apply a legal hold (independent of retention)
aws s3api put-object-legal-hold \
  --bucket example-security-lab-locked-111111111111 \
  --key critical-backup.tar.gz \
  --legal-hold Status=ON

# 5. Apply a default retention policy to the bucket
aws s3api put-object-lock-configuration \
  --bucket example-security-lab-locked-111111111111 \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "GOVERNANCE",
        "Days": 90
      }
    }
  }'
```

**Terraform:**
```hcl
resource "aws_s3_bucket" "locked" {
  bucket = "example-security-lab-locked-111111111111"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "locked" {
  bucket = aws_s3_bucket.locked.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 90
    }
  }
}

resource "aws_s3_bucket_versioning" "locked" {
  bucket = aws_s3_bucket.locked.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "backup" {
  bucket                 = aws_s3_bucket.locked.id
  key                    = "critical-backup.tar.gz"
  source                 = "/tmp/critical-backup.tar.gz"
  object_lock_legal_hold_status = "ON"
  object_lock_mode       = "COMPLIANCE"
  object_lock_retain_until_date = "2027-06-22T00:00:00Z"
}
```

**Gotcha:** Object Lock must be enabled at bucket creation — you cannot add it to an existing bucket. Versioning is mandatory. If you change your mind about Object Lock after creation, you must create a new bucket and migrate data.

## Azure

**Service:** Immutable Blob Storage. **Console path:** `Storage accounts → <account> → Containers → <container> → Access policy`.

```bash
# 1. Create storage account with versioning enabled (required for immutable storage)
az storage account create \
  --name securitylabimm111111111111 \
  --resource-group rg-security-lab \
  --location eastus \
  --sku Standard_LRS \
  --enable-versioning true

# 2. Create container
az storage container create \
  --name immutable-backups \
  --account-name securitylabimm111111111111 \
  --auth-mode login

# 3. Set time-based retention policy (30 days, locked immediately)
az storage container immutability-policy create \
  --container-name immutable-backups \
  --account-name securitylabimm111111111111 \
  --period 30 \
  --auth-mode login

# 4. Lock the immutability policy (irreversible)
az storage container immutability-policy lock \
  --container-name immutable-backups \
  --account-name securitylabimm111111111111 \
  --if-match "<etag-from-create-response>"

# 5. Set legal hold on container
az storage container legal-hold set \
  --container-name immutable-backups \
  --account-name securitylabimm111111111111 \
  --tags "retain-for-litigation" \
  --auth-mode login
```

**Terraform:**
```hcl
resource "azurerm_storage_container" "immutable" {
  name                  = "immutable-backups"
  storage_account_name  = azurerm_storage_account.lab.name
}

resource "azurerm_storage_container_immutability_policy" "backups" {
  storage_container_resource_manager_id = azurerm_storage_container.immutable.resource_manager_id
  immutability_period_in_days           = 30
  protected_append_writes_all           = false
  locked                                = true
}
```

**Gotcha:** Azure has two immutable policy types: **time-based retention** (locked or unlocked) and **legal hold** (tag-based, indefinite). Once a time-based policy is locked, it cannot be shortened or removed. Legal holds persist until all associated tags are removed. `protected_append_writes_all=true` allows appending but not modifying existing blobs — useful for audit log blobs.

## GCP

**Service:** Bucket Lock. **Console path:** `Cloud Storage → <bucket> → Retention`.

> (as of June 2026, GCP Bucket Lock supports retention policies only; there is no dedicated legal-hold API equivalent to AWS S3 Legal Hold or Azure container legal hold. The GCP retention policy can approximate legal hold by setting a long retention duration, but it lacks "hold until removed" indefinite hold semantics.)

```bash
# 1. Create bucket with retention policy
gcloud storage buckets create gs://security-immutable-111111111111 \
  --location us-east1 \
  --retention-period 90d

# 2. Lock the retention policy (irreversible)
gcloud storage buckets update gs://security-immutable-111111111111 \
  --lock-retention-policy

# 3. Upload object — automatically inherits retention
gcloud storage cp /tmp/critical-backup.tar.gz gs://security-immutable-111111111111/

# 4. Check retention on object
gcloud storage objects describe gs://security-immutable-111111111111/critical-backup.tar.gz \
  --format="value(retentionExpirationTime)"
```

**Terraform:**
```hcl
resource "google_storage_bucket" "immutable" {
  name          = "security-immutable-111111111111"
  location      = "us-east1"
  force_destroy = false

  retention_policy {
    retention_period = 7776000  # 90 days in seconds
    is_locked         = true
  }
}
```

**Gotcha:** Once `is_locked=true` is set, the retention period can only be **increased**, never decreased or removed. `force_destroy` must be `false`. Deleting the project is the only way to destroy locked objects before retention expiry — and project deletion has a 30-day soft-delete grace period.

## OnPrem mapping

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Immutable primitive | WORM tape / optical media | S3 Object Lock | Immutable Blob Policy | Bucket Lock retention policy |
| Governance override | Supervisor key | `s3:BypassGovernanceRetention` | Unlocked policy can be changed | N/A (lock is final) |
| Legal hold | Offsite custody log | S3 Object Legal Hold | Container Legal Hold (tags) | (as of June 2026, not available natively; approximate via retention policy) |
| Minimum retention | Physical media shelf life | 1 second | 1 day | 1 second |
| Audit trail | Tape inventory system | CloudTrail `PutObjectRetention` | Activity Log `Put Blob Immutability Policy` | Cloud Audit Logs `storage.objects.update` |

## 🔴 Red Team view

An attacker with full admin credentials (including root) attempts to destroy backup data:

```bash
# Attacker enumerates locked bucket
aws s3 ls s3://example-security-lab-locked-111111111111/
# Output: critical-backup.tar.gz

# Attempt 1 — Delete the object
aws s3api delete-object \
  --bucket example-security-lab-locked-111111111111 \
  --key critical-backup.tar.gz
# Error: AccessDenied — Object is WORM protected
# CloudTrail logs: DeleteObject denied with error "AccessDenied"

# Attempt 2 — Remove retention before expiry (COMPLIANCE mode)
aws s3api put-object-retention \
  --bucket example-security-lab-locked-111111111111 \
  --key critical-backup.tar.gz \
  --retention '{"Mode":"COMPLIANCE","RetainUntilDate":"2026-06-21T00:00:00Z"}'
# Error: AccessDenied — Cannot shorten COMPLIANCE retention

# Attempt 3 — Try to delete bucket
aws s3api delete-bucket \
  --bucket example-security-lab-locked-111111111111
# Error: BucketNotEmpty — locked objects prevent deletion

# Attempt 4 — Overwrite with bogus data (versioned bucket)
aws s3 cp /tmp/defaced.txt s3://example-security-lab-locked-111111111111/critical-backup.tar.gz
# SUCCEEDS — but the original version is preserved with its lock
# Previous version remains immutable; new version has no lock by default
```

**Azure equivalent attack failure:**
```bash
az storage blob delete \
  --container-name immutable-backups \
  --name critical-backup.tar.gz \
  --account-name securitylabimm111111111111
# Error: Blob is protected by an immutability policy
```

**GCP equivalent attack failure:**
```bash
gcloud storage rm gs://security-immutable-111111111111/critical-backup.tar.gz
# Error: cannot delete object subject to retention policy
```

**Artifacts left:** CloudTrail records `DeleteObject` with `errorCode: "AccessDenied"` and `errorMessage: "Object is WORM protected"`. Azure Activity Log records a failed delete with status `Failed`. GCP Audit Logs record `storage.objects.delete` with `status.code = 7 (PERMISSION_DENIED)`.

**Attacker fallback — ransom the retention:** If an attacker cannot delete, they may threaten to overwrite all objects (flooding the bucket with garbage versions) to consume storage costs. This is mitigated by lifecycle policies that clean up old non-current versions after a window.

## 🔵 Blue Team view

**Preventive controls:**
```bash
# AWS SCP: require Object Lock on backup buckets
aws organizations create-policy --name RequireObjectLockOnBackup \
  --type SERVICE_CONTROL_POLICY \
  --content '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:CreateBucket"],"Resource":["*"],"Condition":{"StringLike":{"s3:ResourceTag/purpose":"backup"},"StringNotEquals":{"s3:object-lock-enabled":"true"}}}]}'
```

**Backup strategy using COMPLIANCE mode:**
```
1. Nightly backup → S3 bucket with Object Lock COMPLIANCE mode, 90-day retention
2. Separate bucket with GOVERNANCE mode + MFA-delete for operational recovery (7-day)
3. Cross-account replication to a dedicated security/audit account
4. Lifecycle policy: non-current versions expire after 30 days (limit attacker overwrite damage)
```

**Detection queries:**
```sql
-- AWS CloudTrail: failed DeleteObject on WORM-protected objects
SELECT eventTime, sourceIPAddress, userIdentity.arn, requestParameters.bucketName,
       requestParameters.key, errorMessage
FROM cloudtrail_logs
WHERE eventName = 'DeleteObject'
  AND errorCode = 'AccessDenied'
  AND errorMessage LIKE '%WORM%'
```

```kusto
// Azure: failed blob deletion due to immutability
StorageBlobLogs
| where OperationName == "DeleteBlob"
| where StatusCode == 409
| where StatusText contains "ImmutabilityPolicy"
| project TimeGenerated, CallerIpAddress, ObjectKey
```

```sql
-- GCP: failed object deletion due to retention
SELECT timestamp, protoPayload.authenticationInfo.principalEmail,
       resource.labels.object_name
FROM `project-id.cloud_audit_logs._AllLogs`
WHERE protoPayload.methodName = "storage.objects.delete"
  AND protoPayload.status.code != 0
```

**Response:**
1. If failed deletions are legitimate ransomware attempts: rotate all credentials, initiate incident response.
2. Validate that backup buckets retain their WORM configuration — attacker may try to disable Object Lock at creation time for new buckets.
3. Verify cross-region/cross-account replication is intact.
4. Check for mass overwrites (new non-current versions) that could indicate an attacker trying to flood storage capacity.

## Hands-on lab

1. Create a bucket/container with Object Lock / immutable retention enabled.
2. Upload a test file with a COMPLIANCE retention (or locked time-based policy for Azure/GCP).
3. Attempt to delete the file — confirm error.
4. Attempt to shorten the retention — confirm error.
5. Upload a second version of the file — confirm versioning preserves the original locked version.
6. List all versions to confirm the locked version is intact.
7. **Teardown:** Wait for retention to expire (use a 1-day retention for labs) or delete the entire test account/project. Object Lock prevents bucket deletion with locked objects — plan accordingly.

**Expected output:** Delete and retention-shorten attempts fail with permission/immutability errors. Original version intact after overwrite.

## Detection rules & checklists

```yaml
# Sigma rule — Attempted deletion of WORM-protected object
title: Delete Attempt on WORM-Protected Object
status: experimental
logsource:
  product: cloud
  service: object_storage
detection:
  selection_aws:
    eventName: DeleteObject
    errorCode: AccessDenied
    errorMessage|contains: 'WORM'
  selection_azure:
    OperationName: DeleteBlob
    StatusCode: 409
    StatusText|contains: 'Immutability'
  selection_gcp:
    methodName: storage.objects.delete
    status.code: 7
  condition: selection_aws or selection_azure or selection_gcp
level: high
```

```bash
# AWS: audit all buckets for Object Lock status
aws s3api list-buckets --query "Buckets[].Name" --output text | while read B; do
  LOCK=$(aws s3api get-object-lock-configuration --bucket "$B" \
    --query "ObjectLockConfiguration.ObjectLockEnabled" --output text 2>/dev/null)
  echo "$B: ${LOCK:-disabled}"
done

# GCP: list all buckets with retention policy + lock status
gcloud storage buckets list \
  --format="table(name, retentionPolicy.retentionPeriod, retentionPolicy.isLocked)"
```

## References

- [AWS S3 Object Lock — Compliance](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [Azure Immutable Blob Storage](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview)
- [GCP Bucket Lock](https://cloud.google.com/storage/docs/bucket-lock)
- See ATT&CK Cloud matrix for Impact: Data Destruction (T1485), Inhibit System Recovery
- Cross-ref: [04-05 — Snapshots & Backup Tampering](./snapshots-and-backup-tampering.md) for the snapshot/backup dimension of the same threat
