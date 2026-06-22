# 01 — Object Storage Primitives

> **Level:** Fundamental
> **Prereqs:** 00-Fundamentals (cloud account setup, CLI auth)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Discovery, Collection
> **Authorization scope:** Run only against your own storage accounts / a dedicated sandbox bucket.

## What & why

Object storage is the foundational durable storage layer in every cloud: blobs keyed by a unique identifier, accessible over HTTP/HTTPS. A cloud security engineer must understand the primitives — endpoint, namespace, ACLs, policies, versioning, public-access controls, lifecycle — because misconfiguration here is the #1 cause of cloud data breaches.

## The OnPrem reality

Before object storage, organizations used NAS appliances (NetApp, Isilon), Samba/CIFS shares, or NFS exports. Permissions were filesystem ACLs tied to POSIX uid/gid or Active Directory SIDs. A `chmod 777` or `no_root_squash` on `/exports/backups` was the equivalent of a public S3 bucket. The difference: on-prem shares were behind a firewall; cloud buckets live on the internet by design.

## Core concepts

| Primitive | AWS (S3) | Azure (Blob) | GCP (Cloud Storage) | OnPrem (NFS/SMB) |
|---|---|---|---|---|
| **Namespace** | Global bucket name | Storage account → container | Global bucket name | Export path |
| **Region scope** | Region-scoped (metadata global) | Region-scoped on account | Region/Dual/Multi | Datacenter-local |
| **Hierarchy** | Flat namespace, `/` delimiter convention | Flat + virtual directory via prefix | Flat namespace | Directory tree |
| **Public by default** | No (block-public on by default since 2023) | No (`allowBlobPublicAccess` disabled by default) | No (uniform bucket-level access) | No (behind firewall) |
| **Access key type** | ARN-based IAM policy + bucket policy + ACL | Shared key / SAS / AAD RBAC | IAM uniform / fine-grained | UID/GID + export options |
| **Versioning** | Optional, per-bucket | Optional, per-account (blob soft-delete + versioning) | Optional, per-bucket (object versioning) | Snapshots (ZFS, NetApp) |
| **Signed URL TTL** | 1 sec – 7 days (IAM), 1 sec – 7 days (presigned) | 1 min – unlimited (SAS) | 1 sec – 7 days (V4 signed) | N/A (auth handled at mount) |

## AWS

**Service:** S3 (Simple Storage Service). **Console path:** `S3 → Buckets → <name>`.

```bash
# Create bucket
aws s3api create-bucket \
  --bucket example-security-lab-111111111111 \
  --region us-east-1 \
  --create-bucket-configuration LocationConstraint=us-east-1

# Upload object
echo "security test data" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://example-security-lab-111111111111/test.txt

# List objects
aws s3 ls s3://example-security-lab-111111111111/
```

**Terraform:**
```hcl
resource "aws_s3_bucket" "lab" {
  bucket        = "example-security-lab-111111111111"
  force_destroy = true
}

resource "aws_s3_object" "test" {
  bucket  = aws_s3_bucket.lab.id
  key     = "test.txt"
  content = "security test data"
}
```

**Gotcha:** Bucket names are globally unique across all AWS accounts. A deleted bucket name may be re-registered by another account — bucket-sniping is a known attack vector.

## Azure

**Service:** Azure Blob Storage. **Console path:** `Storage accounts → <account> → Containers`.

```bash
# Create resource group + storage account
az group create --name rg-security-lab --location eastus

az storage account create \
  --name securitylab111111111111 \
  --resource-group rg-security-lab \
  --location eastus \
  --sku Standard_LRS \
  --allow-blob-public-access false

# Create container and upload
az storage container create \
  --name test-container \
  --account-name securitylab111111111111 \
  --auth-mode login

az storage blob upload \
  --container-name test-container \
  --name test.txt \
  --file /tmp/test.txt \
  --account-name securitylab111111111111 \
  --auth-mode login

# List blobs
az storage blob list \
  --container-name test-container \
  --account-name securitylab111111111111 \
  --auth-mode login \
  --output table
```

**Terraform:**
```hcl
resource "azurerm_storage_account" "lab" {
  name                     = "securitylab111111111111"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "test" {
  name                  = "test-container"
  storage_account_name  = azurerm_storage_account.lab.name
}
```

**Gotcha:** Storage account names are globally unique (lowercase, 3-24 chars). The `allow_nested_items_to_be_public` setting is the "block public access" toggle at the storage account level — introduced to replace older per-container controls.

## GCP

**Service:** Cloud Storage. **Console path:** `Cloud Storage → Buckets`.

```bash
# Create bucket
gcloud storage buckets create gs://security-lab-111111111111 \
  --location us-east1 \
  --uniform-bucket-level-access

# Upload object
gcloud storage cp /tmp/test.txt gs://security-lab-111111111111/test.txt

# List objects
gcloud storage ls gs://security-lab-111111111111/
```

**Terraform:**
```hcl
resource "google_storage_bucket" "lab" {
  name                        = "security-lab-111111111111"
  location                    = "us-east1"
  uniform_bucket_level_access = true
  force_destroy               = true
}

resource "google_storage_bucket_object" "test" {
  name   = "test.txt"
  bucket = google_storage_bucket.lab.name
  content = "security test data"
}
```

**Gotcha:** GCP bucket names are globally unique but also DNS-compliant (lowercase, dashes, dots). `uniform_bucket_level_access` is now the recommended default; the legacy fine-grained ACL model is the equivalent of S3 ACLs.

## OnPrem mapping

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Create share/bucket | `mkdir /exports/data` | `aws s3api create-bucket` | `az storage account create` | `gcloud storage buckets create` |
| Upload file | `cp file /exports/data/` | `aws s3 cp` | `az storage blob upload` | `gcloud storage cp` |
| List contents | `ls /exports/data/` | `aws s3 ls` | `az storage blob list` | `gcloud storage ls` |
| Set ACL | `chmod 755 /exports/data` | `aws s3api put-bucket-acl` | `az storage blob set-permissions` | `gcloud storage buckets add-iam-policy-binding` (uniform) |
| Prevent public | Firewall rule | Block Public Access | `allowBlobPublicAccess=false` | `uniform_bucket_level_access=true` |

## 🔴 Red Team view

On-prem, a misconfigured NFS export (`/etc/exports` with `*(rw,no_root_squash)`) let any tenant mount and enumerate. In a shared hosting environment, an attacker on a co-tenant VM would:

```bash
# OnPrem — co-tenant enumerating a misconfigured NFS export
showmount -e 192.168.1.100          # list exports
mount -t nfs 192.168.1.100:/exports/data /mnt/stolen
ls -laR /mnt/stolen                  # full directory listing
```

The cloud equivalent is discovering a bucket with a permissive policy. A contained recon attempt against a local mock bucket server:

```bash
# Simulated public bucket listing (localhost)
curl -s http://localhost:8000/?list-type=2 | xmllint --format -
```

**Artifacts left:** S3 server access logs record the `REST.GET.BUCKET` or `REST.HEAD.BUCKET` request with source IP. CloudTrail captures `ListObjects` / `GetBucketAcl` API calls. NFS logs (if enabled) show the mount request from the attacker's IP.

## 🔵 Blue Team view

**Prevention:**
- Maintain an inventory of every storage resource via IaC. No manual bucket creation.
- Enforce `uniform_bucket_level_access` (GCP), `allowBlobPublicAccess=false` (Azure), S3 Block Public Access (AWS) at the org/account level via SCP / Azure Policy / Org Policy.
- Require versioning and logging on all production buckets.

**Detection:**
- Alert on `s3:CreateBucket` in non-standard regions or outside IaC change windows.
- Monitor `ListBuckets` calls from unusual principals — a reconnaissance signal.
- CloudTrail query for unauthorized bucket creation:

```sql
-- AWS CloudTrail
SELECT eventTime, userIdentity.arn, requestParameters.bucketName
FROM cloudtrail_logs
WHERE eventName = 'CreateBucket'
  AND userIdentity.type != 'AssumedRole'
  AND userIdentity.arn NOT LIKE '%/terraform%'
```

**Response:**
- If a non-compliant bucket is detected: apply Block Public Access immediately, enable logging, capture existing ACLs for forensic review, then remediate the bucket policy to least privilege.

## Hands-on lab

1. Create one bucket/container in each cloud you have access to (use free tier).
2. Upload a test object with a known checksum.
3. List the object and verify the checksum.
4. Enable versioning on the bucket and upload a second version of the same object.
5. Retrieve both versions to confirm versioning works.
6. **Teardown:** Delete the test buckets and containers.

**Expected output:** Two object versions retrievable independently. No error on cross-version retrieval.

## Detection rules & checklists

```bash
# AWS: audit all buckets in account for versioning status
aws s3api list-buckets --query "Buckets[].Name" --output text | \
  xargs -I {} aws s3api get-bucket-versioning --bucket {} --query "{Bucket:'{}',Status:Status}" --output table

# Azure: list all storage accounts with public access enabled
az storage account list --query "[?allowBlobPublicAccess==\`true\`].{Name:name, RG:resourceGroup}" --output table

# GCP: list buckets without uniform access
gcloud storage buckets list --format="table(name, uniformBucketLevelAccess.enabled)"
```

```hcl
# OPA / Cloud Custodian: require versioning on all S3 buckets
policies:
  - name: s3-versioning-required
    resource: aws.s3
    filters:
      - type: versioning
        state: disabled
```

## References

- [AWS S3 Best Practices for Security](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [Azure Storage security guide](https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations)
- [GCP Cloud Storage access control](https://cloud.google.com/storage/docs/access-control)
- See ATT&CK Cloud matrix for Discovery (Cloud Storage Object Discovery)
- Cross-ref: [../IAM/assume-role-chains.md](../IAM/assume-role-chains.md) for the IAM primitives behind bucket policies
