# 01 — IaC State & Backend Security

> **Level:** Intermediate
> **Prereqs:** [02-01 — Identity Primitives Per Cloud](../IAM/identity-primitives-per-cloud.md), [04-01 — Storage Security Primitives](../Storage-Data-Security/storage-primitives.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Discovery, Collection, Exfiltration
> **Authorization scope:** Run only against your own sandbox accounts; state file examples use placeholder credentials.

## What & why

Terraform state is a JSON snapshot of every resource, attribute, and output — including plaintext secrets by default. Whoever reads your state file reads your entire infrastructure topology and every credential Terraform manages. Backend choice determines who can access it, whether it's encrypted, and how locking prevents corruption.

## The OnPrem reality

Pre-cloud, infrastructure configuration lived in disparate places: Ansible inventories encrypted with `ansible-vault`, CFEngine policy files on a shared NFS mount, Puppet manifests with passwords in comments, or a wiki page listing server IPs. There was no single "state" file — and therefore no single artifact whose compromise revealed the entire estate. Terraform unifies that into one high-value target.

## Core concepts

| Concept | Description | Risk if neglected |
|---|---|---|
| State file (`terraform.tfstate`) | JSON mapping of config → real-world resources | Full infra disclosure + secret leak |
| Backend | Where state is stored (S3, Azure Storage, GCS, etc.) | Unauthenticated read → total exposure |
| Locking | Prevents concurrent `apply` (DynamoDB / Lease Blob / Cloud Spanner) | State corruption, split-brain |
| Encryption at rest | Server-side or client-side encryption of state blob | Plaintext state readable by storage admins |
| Versioning | Object versioning on backend bucket/container | Enables rollback; also preserves leaked secrets forever |

## AWS

**Backend:** S3 bucket + DynamoDB table for locking. Every S3 state bucket needs: versioning, default SSE (KMS CMK preferred), block public access, and a restrictive bucket policy.

```hcl
# terraform backend — AWS
terraform {
  backend "s3" {
    bucket         = "tfstate-111111111111-us-east-1"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "tfstate-lock"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-..."
  }
}
```

```bash
# CLI: verify bucket configuration
aws s3api get-bucket-versioning --bucket tfstate-111111111111-us-east-1
aws s3api get-bucket-encryption  --bucket tfstate-111111111111-us-east-1
aws s3api get-public-access-block --bucket tfstate-111111111111-us-east-1

# CLI: verify DynamoDB lock table
aws dynamodb describe-table --table-name tfstate-lock
```

**Bucket policy — deny public access & restrict to deploy role:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::tfstate-111111111111-us-east-1",
        "arn:aws:s3:::tfstate-111111111111-us-east-1/*"
      ],
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    }
  ]
}
```

**Gotcha:** Even with SSE-KMS, `terraform state pull` decrypts and prints the full state to stdout. Anyone with `s3:GetObject` + `kms:Decrypt` gets plaintext.

## Azure

**Backend:** Azure Storage Account container + lease blob for locking.

```hcl
# terraform backend — Azure
terraform {
  backend "azurerm" {
    resource_group_name  = "rg-tfstate"
    storage_account_name = "tfstate00000000"
    container_name       = "tfstate"
    key                  = "prod.terraform.tfstate"
    use_azuread_auth     = true
  }
}
```

```bash
# CLI: verify storage account security
az storage account show \
  --name tfstate00000000 \
  --resource-group rg-tfstate \
  --query "{httpsOnly:enableHttpsTrafficOnly, publicAccess:allowBlobPublicAccess, minTLS:minimumTlsVersion}"

# Verify container is private
az storage container show-permission \
  --account-name tfstate00000000 \
  --name tfstate \
  --auth-mode login
```

**Critical settings:**
- `allowBlobPublicAccess = false` (default since 2020 but verify)
- `enableHttpsTrafficOnly = true`
- `minimumTlsVersion = "TLS1_2"`
- Enable soft delete for blob (7+ days) and container
- Use `use_azuread_auth = true` — never the storage account key

**Gotcha:** Azure Storage account keys grant full data-plane access. If someone has `Microsoft.Storage/storageAccounts/listKeys/action`, they can read state. Use Azure AD RBAC (`Storage Blob Data Contributor`) scoped to the container instead.

## GCP

**Backend:** GCS bucket + optional Cloud Spanner for locking (rare; most use GCS object versioning + default locking).

```hcl
# terraform backend — GCP
terraform {
  backend "gcs" {
    bucket          = "tfstate-000000000000-us-central1"
    prefix          = "prod"
    encryption_key  = "projects/my-project/locations/us-central1/keyRings/tfstate/cryptoKeys/tfstate-key"
  }
}
```

```bash
# CLI: verify bucket configuration
gcloud storage buckets describe gs://tfstate-000000000000-us-central1 \
  --format="json(encryption, versioning, iamConfiguration, retentionPolicy)"

# Verify no public access
gcloud storage buckets describe gs://tfstate-000000000000-us-central1 \
  --format="json(iamConfiguration.publicAccessPrevention)"
```

**Critical settings:**
- `publicAccessPrevention = enforced`
- `uniformBucketLevelAccess = true`
- KMS CMEK encryption on bucket
- Object versioning enabled
- Retention policy or object hold to prevent accidental/malicious deletion

**Gotcha:** GCS does not have native state locking. Without Cloud Spanner, concurrent `terraform apply` can corrupt state. Use a lock file convention or run from a single CI pipeline with serial deployments.

## OnPrem (self-managed)

OnPrem teams may use HashiCorp Terraform Cloud/Enterprise, or self-manage with Artifactory, MinIO, or Consul backends.

| Backend | Locking | Encryption | Authentication |
|---|---|---|---|
| Terraform Cloud/Enterprise | Built-in | At rest + in transit | TFC API token / SSO |
| Artifactory (generic repo) | None (add DynamoDB if AWS-adjacent) | HTTPS + repo-level | Artifactory API key |
| MinIO (S3-compatible) | None (use external DynamoDB) | SSE-C / KES | Access key + secret |
| Consul | Native lock via session | mTLS | Consul ACL token |
| Local + `terraform state push` | None | Filesystem encryption | OS permissions |

```hcl
# OnPrem — Consul backend
terraform {
  backend "consul" {
    address = "consul.internal.example.com:8500"
    scheme  = "https"
    path    = "terraform/state/prod"
    lock    = true
    ca_file = "/etc/ssl/consul-ca.pem"
  }
}
```

## Cross-cloud comparison

| Concern | AWS | Azure | GCP | OnPrem (Consul) |
|---|---|---|---|---|
| State storage | S3 | Storage Account blob | GCS bucket | Consul KV |
| Locking | DynamoDB table | Lease blob (automatic) | Cloud Spanner (optional) | Consul session lock |
| Encryption | SSE-KMS (CMK) | SSE with Microsoft-managed keys / CMK | CSEK / CMEK (KMS) | mTLS + disk |
| Public-access prevention | `BlockPublicAccess` | `allowBlobPublicAccess=false` | `publicAccessPrevention=enforced` | Network ACL + token |
| Auth | IAM role (instance/oidc) | Azure AD RBAC | IAM service account | Consul ACL token |
| Versioning | S3 bucket versioning | Blob soft delete + versioning (preview) | GCS object versioning | KV backup/restore |

## 🔴 Red Team view

State file exposure is a crown-jewel target. A single misconfigured backend gives an attacker the entire infrastructure map.

**Narrative scenario:** During reconnaissance, an attacker discovers a Terraform state backend with overly permissive access — for example, an S3 bucket with `s3:GetObject` open to `Principal: "*"` or an Azure Storage container with anonymous read. The attacker fetches the state file and gains:

- Every resource ARN/resource ID and their interconnections
- Database endpoint addresses and instance identifiers
- IAM role names, trust policies, and ARNs (for crafting `sts:AssumeRole` calls)
- Plaintext passwords if `sensitive = true` was omitted (see [terraform-secrets-in-state.md](./terraform-secrets-in-state.md))

**Contained state file snippet (placeholder values):**

```json
{
  "resources": [
    {
      "type": "aws_db_instance",
      "instances": [{
        "attributes": {
          "address": "prod-db.cy9qxp7kexample.us-east-1.rds.amazonaws.com",
          "username": "dbadmin",
          "password": "REDACTED-DO-NOT-USE-PLACEHOLDER",
          "port": 5432,
          "db_name": "prod_app"
        }
      }]
    },
    {
      "type": "aws_iam_access_key",
      "instances": [{
        "attributes": {
          "id": "AKIAIOSFODNN7EXAMPLE",
          "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        }
      }]
    }
  ]
}
```

**Artifacts left by attacker:**
- S3 `GetObject` in CloudTrail (event `s3.GetObject` for key `prod/terraform.tfstate`)
- Azure Storage `GetBlob` in Storage Analytics logs
- GCS `storage.objects.get` in Cloud Audit Logs
- Source IP, user agent, and timestamp — if logging is enabled (detection depends on it)

## 🔵 Blue Team view

**Preventive controls:**

1. **Deny public access at every layer:**
   ```bash
   # AWS SCP — deny s3:PutBucketAcl globally
   # Attach to root OU
   aws organizations create-policy \
     --name DenyS3PublicACL \
     --type SERVICE_CONTROL_POLICY \
     --content file://deny-s3-public-acl.json
   ```

2. **CMK + key policy that denies decryption to non-deployer roles:**
   ```json
   {
     "Sid": "OnlyDeployerRoleCanDecrypt",
     "Effect": "Deny",
     "Principal": "*",
     "Action": "kms:Decrypt",
     "Resource": "*",
     "Condition": {
       "StringNotLike": {
         "aws:PrincipalArn": "arn:aws:iam::111111111111:role/terraform-deploy-*"
       }
     }
   }
   ```

3. **Daily state-backend audit script:**
   ```bash
   #!/bin/bash
   # Check all state buckets for public access
   for bucket in $(aws s3api list-buckets --query "Buckets[?contains(Name,'tfstate')].Name" --output text); do
     public=$(aws s3api get-public-access-block --bucket "$bucket" \
       --query "PublicAccessBlockConfiguration.BlockPublicAcls" 2>/dev/null)
     if [ "$public" != "true" ]; then
       echo "ALERT: $bucket missing BlockPublicAccess"
     fi
   done
   ```

4. **Azure Policy to deny storage accounts without secure transfer:**
   ```json
   {
     "if": {
       "field": "name",
       "contains": "tfstate"
     },
     "then": {
       "effect": "deny"
     }
   }
   ```

5. **GCP Org Policy — deny public bucket creation:**
   ```bash
   gcloud org-policies set-policy policy-deny-public-buckets.yaml \
     --organization=000000000000
   ```

**Detection signals (log sources):**

| Signal | AWS (CloudTrail) | Azure (Activity Log) | GCP (Cloud Audit Logs) |
|---|---|---|---|
| State file read from unexpected IP | `s3.GetObject` + `sourceIPAddress` not in deployer CIDR | `GetBlob` + `callerIpAddress` anomaly | `storage.objects.get` + caller IP anomaly |
| State read from console (unusual) | `GetObject` + `userAgent` = `[S3Console/...]` | `GetBlob` from Portal | `storage.objects.get` from console |
| Bulk state download (exfil) | `GetObject` with high `bytesTransferred` | `GetBlob` with large `responseBodySize` | `storage.objects.get` with large object |
| KMS decrypt from unexpected principal | `kms:Decrypt` by non-deploy role | `KeyVaultDecrypt` by unexpected SP | `cloudkms.cryptoKeyVersions.useToDecrypt` |

## Hands-on lab

1. Create a Terraform backend with S3 + DynamoDB (or equivalent for your cloud):
   ```bash
   mkdir lab-state-backend && cd lab-state-backend
   cat > main.tf <<'EOF'
   resource "aws_s3_bucket" "state" {
     bucket = "tfstate-lab-$(aws sts get-caller-identity --query Account --output text)"
   }
   resource "aws_s3_bucket_versioning" "state" {
     bucket = aws_s3_bucket.state.id
     versioning_configuration { status = "Enabled" }
   }
   resource "aws_s3_bucket_public_access_block" "state" {
     bucket = aws_s3_bucket.state.id
     block_public_acls       = true
     block_public_policy     = true
     ignore_public_acls      = true
     restrict_public_buckets = true
   }
   EOF
   terraform init && terraform apply -auto-approve
   ```

2. Verify no anonymous access:
   ```bash
   curl -s -o /dev/null -w "%{http_code}" \
     "https://tfstate-lab-111111111111.s3.amazonaws.com/terraform.tfstate"
   # Expected: 403
   ```

3. Test the lock by running two concurrent `terraform apply` in separate terminals — one blocks.

4. **Teardown:** `terraform destroy -auto-approve`

## Detection rules & checklists

```yaml
# Cloud Custodian — detect public state bucket
policies:
  - name: tfstate-public-access
    resource: aws.s3
    filters:
      - type: bucket-policy
        key: "Statement[].Principal"
        value: "*"
        op: contains
      - "tag:TerraformState": "true"
    actions:
      - type: notify
        to: ["secops@example.com"]
```

```bash
# Audit one-liner: list all state buckets missing encryption
aws s3api list-buckets --query "Buckets[?contains(Name,'tfstate')].Name" --output text | \
  xargs -I {} sh -c 'aws s3api get-bucket-encryption --bucket {} 2>&1 || echo "{}: NO ENCRYPTION"'

# Azure: find storage accounts allowing HTTP
az storage account list --query "[?enableHttpsTrafficOnly==\`false\`].name"
```

**Checklist:**
- [ ] State bucket has `BlockPublicAccess` / `publicAccessPrevention` enforced
- [ ] CMK/CMEK encryption on bucket (not default SSE-S3/MMK)
- [ ] Versioning enabled (for rollback; accept the cost of baked-in secrets)
- [ ] Lock table/lease exists and is used
- [ ] Bucket policy denies non-HTTPS
- [ ] Only deployer role/service account has read/write to state
- [ ] CloudTrail / Activity Log / Audit Log enabled on backend resource
- [ ] Object lock / retention policy to prevent deletion

## References

- [Terraform S3 Backend Docs](https://developer.hashicorp.com/terraform/language/settings/backends/s3)
- [Terraform AzureRM Backend Docs](https://developer.hashicorp.com/terraform/language/settings/backends/azurerm)
- [Terraform GCS Backend Docs](https://developer.hashicorp.com/terraform/language/settings/backends/gcs)
- [AWS Foundational Security Best Practices — S3.1](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html)
- See ATT&CK Cloud matrix: Discovery (T1526), Unsecured Credentials (T1552)
- [02-04 — Long-Lived Keys vs Workload Identity](../IAM/long-lived-keys-vs-workload-identity.md)
- [06-02 — CloudTrail Activity & Data Events](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md)
