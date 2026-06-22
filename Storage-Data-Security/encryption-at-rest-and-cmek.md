# 03 — Encryption at Rest & Customer-Managed Keys

> **Level:** Intermediate
> **Prereqs:** [04-01 — Object Storage Primitives](./object-storage-primitives.md); ties with [05-* — Secrets & KMS](../Secrets-KMS/)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Impact
> **Authorization scope:** Run only against your own storage accounts / a dedicated sandbox bucket.

## What & why

Cloud objects and volumes are encrypted at rest by default using provider-managed keys (SSE-S3, Azure managed keys, Google-managed CMEK). But the cloud provider holds the key. Customer-Managed Keys (CMK/CMEK) let you hold the root of trust in your own KMS, enabling access revocation, independent audit, and rotation — critical for regulated workloads.

## The OnPrem reality

LUKS (Linux) or BitLocker (Windows) provided volume encryption with a passphrase or key file stored on a USB drive in a physical safe. Recovery meant physically retrieving that USB. Key rotation required re-encrypting the entire disk (`cryptsetup-reencrypt`). Separation of duties was a policy decision — the sysadmin with `sudo` on the box could also read `/etc/crypttab`.

```bash
# OnPrem LUKS setup
cryptsetup luksFormat /dev/sdb --key-file /secure/keyfile
cryptsetup luksOpen /dev/sdb secure_volume --key-file /secure/keyfile
mkfs.ext4 /dev/mapper/secure_volume
mount /dev/mapper/secure_volume /mnt/encrypted
```

## Core concepts

| Encryption type | Who holds key | Revocation | Audit trail | Rotate |
|---|---|---|---|---|
| SSE-S3 / Azure-managed / Google-managed (DMEK) | Cloud provider | No | Limited | Automatic |
| AWS KMS CMK / Azure Key Vault CMK / GCP CMEK | Customer | Yes | Full (key usage logs) | Customer-controlled |
| AWS KMS External / Azure MHSM / GCP EKM | Customer (HSM) | Yes | Full | Customer-controlled |
| Client-side (CSEK) | Customer (client) | Yes | Client-only | Customer-controlled |

**Key hierarchy per cloud:**

| Cloud | Key management service | Storage service support | DB support |
|---|---|---|---|
| AWS | AWS KMS (CMK) | S3 (SSE-KMS), EBS, EFS | RDS, DynamoDB, Redshift |
| Azure | Key Vault (CMK) | Blob, Files, Disk | Azure SQL, Cosmos DB |
| GCP | Cloud KMS (CMEK/CSEK) | Cloud Storage, Persistent Disk | Cloud SQL, BigQuery, Spanner |
| OnPrem | LUKS/BitLocker | dm-crypt volume | Plug-in TDE |

## AWS

**Service:** AWS KMS. **Console path:** `KMS → Customer managed keys → Create key`.

```bash
# 1. Create a symmetric CMK
aws kms create-key \
  --description "Storage encryption key" \
  --key-usage ENCRYPT_DECRYPT \
  --customer-master-key-spec SYMMETRIC_DEFAULT

# 2. Create alias for referencing
aws kms create-alias \
  --alias-name alias/storage-cmk \
  --target-key-id arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000

# 3. Enable automatic rotation (every 365 days for AWS-managed key material)
aws kms enable-key-rotation --key-id alias/storage-cmk

# 4. Create S3 bucket with SSE-KMS default encryption
aws s3api create-bucket \
  --bucket example-security-lab-111111111111 \
  --region us-east-1

aws s3api put-bucket-encryption \
  --bucket example-security-lab-111111111111 \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000"
      }
    }]
  }'

# 5. Upload — encryption is automatic
aws s3 cp /tmp/test.txt s3://example-security-lab-111111111111/test.txt
aws s3api head-object --bucket example-security-lab-111111111111 --key test.txt \
  --query 'ServerSideEncryption'  # outputs: aws:kms
```

**Terraform:**
```hcl
resource "aws_kms_key" "storage" {
  description         = "Storage CMK"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.storage.arn
    }
  }
}
```

**Gotcha:** SSE-KMS calls KMS on every upload AND download — large-scale GET workloads incur KMS API costs. Objects encrypted with a deleted/disabled CMK become permanently inaccessible; this is a feature (crypto-shredding) and a footgun.

## Azure

**Service:** Key Vault CMK for Storage. **Console path:** `Storage accounts → <account> → Encryption → Customer-managed keys`.

```bash
# 1. Create Key Vault and key
az keyvault create \
  --name kv-security-lab-00000000 \
  --resource-group rg-security-lab \
  --location eastus \
  --enable-purge-protection --enable-soft-delete

az keyvault key create \
  --vault-name kv-security-lab-00000000 \
  --name storage-cmk \
  --protection software

# 2. Get Key Vault URI for reference
KEY_URI=$(az keyvault key show \
  --vault-name kv-security-lab-00000000 \
  --name storage-cmk \
  --query key.kid -o tsv)

# 3. Assign CMK to storage account
az storage account update \
  --name securitylab111111111111 \
  --resource-group rg-security-lab \
  --encryption-key-source Microsoft.Keyvault \
  --encryption-key-vault $KEY_URI

# 4. Verify
az storage account show \
  --name securitylab111111111111 \
  --resource-group rg-security-lab \
  --query "encryption.keySource"
```

**Terraform:**
```hcl
resource "azurerm_key_vault_key" "storage" {
  name         = "storage-cmk"
  key_vault_id = azurerm_key_vault.lab.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "wrapKey", "unwrapKey"]
}

resource "azurerm_storage_account_customer_managed_key" "lab" {
  storage_account_id = azurerm_storage_account.lab.id
  key_vault_id       = azurerm_key_vault.lab.id
  key_name           = azurerm_key_vault_key.storage.name
}
```

**Gotcha:** Azure requires soft-delete and purge-protection on the Key Vault when used for storage CMK. If both are disabled and the key is deleted accidentally, data is unrecoverable.

## GCP

**Service:** Cloud KMS CMEK. **Console path:** `Cloud Storage → <bucket> → Configuration → Encryption`.

```bash
# 1. Create key ring and key
gcloud kms keyrings create storage-keyring --location us-east1
gcloud kms keys create storage-cmek \
  --location us-east1 \
  --keyring storage-keyring \
  --purpose encryption

# 2. Create bucket with CMEK
gcloud storage buckets create gs://security-lab-111111111111 \
  --location us-east1 \
  --default-encryption-key projects/example-project/locations/us-east1/keyRings/storage-keyring/cryptoKeys/storage-cmek

# 3. Enable automatic rotation (90-day default period)
gcloud kms keys update storage-cmek \
  --location us-east1 \
  --keyring storage-keyring \
  --rotation-period 7776000s \
  --next-rotation-time 2026-07-22T00:00:00Z

# 4. Verify
gcloud storage buckets describe gs://security-lab-111111111111 \
  --format="value(encryption.defaultKmsKeyName)"
```

**Terraform:**
```hcl
resource "google_kms_key_ring" "storage" {
  name     = "storage-keyring"
  location = "us-east1"
}

resource "google_kms_crypto_key" "storage" {
  name            = "storage-cmek"
  key_ring        = google_kms_key_ring.storage.id
  rotation_period = "7776000s"
}

resource "google_storage_bucket" "lab" {
  name     = "security-lab-111111111111"
  location = "us-east1"
  encryption {
    default_kms_key_name = google_kms_crypto_key.storage.id
  }
}
```

**Gotcha:** GCP CSEK (Customer-Supplied Encryption Key) passes the raw key in the API call — GCP never stores it. If you lose the CSEK, data is permanently unrecoverable. CMEK is the safer production choice; CSEK is for extreme data residency/sovereignty scenarios.

## OnPrem mapping

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Encryption primitive | LUKS/BitLocker | SSE-S3 (AES-256) | Storage Service Encryption | Google-managed CMEK (AES-256) |
| CMK location | USB in safe | AWS KMS | Key Vault (software/HSM) | Cloud KMS / Cloud HSM |
| Rotation | Manual re-encrypt | `enable-key-rotation` (365d) | Key auto-rotation (configurable) | `--rotation-period` (min 1d) |
| Crypto-shred | `cryptsetup luksErase` | Disable + schedule key deletion | Disable key + purge | Disable + destroy crypto key version |
| Access audit | syslog | CloudTrail `kms:Decrypt` | Key Vault diagnostics logs | Cloud Audit Logs |

## 🔴 Red Team view

An attacker who compromises AWS credentials with `kms:Encrypt` and `kms:Decrypt` on the CMK can exfiltrate data even when encryption is "customer-managed." The power of CMK is **revocation** — not preventing access by a current authorized principal.

**Contained attack — Steal data using valid CMK access:**
```bash
# Attacker has stolen IAM credentials with kms:Decrypt
# They sync the bucket contents — decryption happens server-side
aws s3 sync s3://example-security-lab-111111111111 /tmp/exfiltrated/

# Clean up: attacker downloads and deletes in parallel to avoid detection
# CloudTrail shows rapid sequence of GetObject + DeleteObject
```

**Rotation break attack (contained narrative):**
```
An attacker with persistent access discovers that CMK rotation only creates
a new key version. If the attacker does NOT have visibility into v_N+1 because
it was created AFTER compromise, they lose access. But if the attacker has
"DescribeKey" and can list all enabled key versions, they can trivially encrypt
with any version. The real defense is: key rotation + periodic revocation of
old versions. An attacker who does NOT rotate a compromised key is detectable
by the absence of expected rotation events.
```

**Contained CLI — Detect missing rotation:**
```bash
# Check if key rotation is enabled (Blue perspective — what attacker would disable)
aws kms get-key-rotation-status --key-id alias/storage-cmk
# If false and key is production CMK → alert
```

**Artifacts left:** CloudTrail records every `kms:Decrypt` as "Decrypt" event on the specific CMK. High-volume decrypt activity from a single IP/principal that has never performed those operations is anomalous. Disabling key rotation leaves `DisableKeyRotation` in CloudTrail.

## 🔵 Blue Team view

**Preventive controls:**
```bash
# AWS SCP: deny disabling key rotation on CMKs
aws organizations create-policy \
  --name DenyDisableKeyRotation \
  --type SERVICE_CONTROL_POLICY \
  --content '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["kms:DisableKeyRotation"],"Resource":["*"]}]}'

# Azure Policy: require CMK on storage accounts (audit if absent)
az policy definition create \
  --name "audit-storage-cmk" \
  --rules '{"if":{"field":"Microsoft.Storage/storageAccounts/encryption.keySource","notEquals":"Microsoft.Keyvault"},"then":{"effect":"audit"}}'
```

**Detection queries:**
```sql
-- AWS CloudTrail: unexpected DisableKeyRotation
SELECT eventTime, userIdentity.arn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'DisableKeyRotation'

-- AWS CloudTrail: anomalous decrypt volume (>100 decryptions in 5 min from single principal)
SELECT userIdentity.arn, COUNT(*) as decrypt_count,
       MIN(eventTime) as first, MAX(eventTime) as last
FROM cloudtrail_logs
WHERE eventName = 'Decrypt'
  AND eventTime > now() - interval '5 minutes'
GROUP BY userIdentity.arn
HAVING COUNT(*) > 100
```

```kusto
// Azure Key Vault: key rotation disabled
AzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName == "KeyRotateScheduledDisabled"
| project TimeGenerated, CallerIPAddress, identity_claim
```

```sql
-- GCP Cloud Audit Logs: key version disabled
SELECT timestamp, protoPayload.authenticationInfo.principalEmail
FROM `project-id.cloud_audit_logs._AllLogs`
WHERE protoPayload.methodName = "DisableCryptoKeyVersion"
```

**Response:**
1. Re-enable key rotation immediately.
2. Check if any key versions were disabled/deleted during the window.
3. Rotate the CMK manually to cut access for any exfiltrated key material.
4. Review all `kms:Decrypt` / `KeyVault UnwrapKey` activity for the compromised window.

## Hands-on lab

1. Create a CMK/CMEK in your cloud's KMS.
2. Enable automatic rotation on it.
3. Create a bucket/container with that CMK as the default encryption key.
4. Upload a test object, verify the encryption header (`aws:kms`, `Microsoft.Keyvault`, CMEK key name).
5. Download the object — verify it decrypts transparently (the cloud handles it).
6. Attempt to disable key rotation — note the API call.
7. **Teardown:** Schedule key deletion (7-day minimum window) and delete the bucket.

**Expected output:** Object upload shows encryption key ARN/URI in metadata. Decryption is transparent. Disable rotation API call is captured in logs.

## Detection rules & checklists

```yaml
# Sigma rule — CMK/CMEK key rotation disabled
title: Cloud KMS Key Rotation Disabled
status: experimental
logsource:
  product: cloud
  service: key_management
detection:
  selection_aws:
    eventName: DisableKeyRotation
  selection_azure:
    OperationName: "KeyRotateScheduledDisabled"
  selection_gcp:
    methodName: "DisableCryptoKeyVersion"
    resource.labels|contains: "keyRings"
  condition: selection_aws or selection_azure or selection_gcp
level: high
```

```bash
# Audit: check CMK/CMEK usage on all buckets in account
aws s3api list-buckets --query "Buckets[].Name" --output text | while read B; do
  ENC=$(aws s3api get-bucket-encryption --bucket "$B" \
    --query "ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm" \
    --output text 2>/dev/null)
  echo "$B: ${ENC:-NONE}"
done

# GCP: audit all buckets for CMEK
gcloud storage buckets list --format="table(name, encryption.defaultKmsKeyName)"

# Azure: storage accounts without CMK
az storage account list --query "[?encryption.keySource!='Microsoft.Keyvault'].name" --output tsv
```

## References

- [AWS KMS key rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)
- [Azure Storage CMK](https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview)
- [GCP CMEK for Cloud Storage](https://cloud.google.com/storage/docs/encryption/customer-managed-keys)
- Cross-ref: [../Secrets-KMS/](../Secrets-KMS/) for key management depth
- See ATT&CK Cloud matrix for Credential Access (Unsecured Credentials)
