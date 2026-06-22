# Lab — Public Bucket Audit

> **Prereqs:** [04-01](./object-storage-primitives.md), [04-02](./public-exposure-and-block-public.md)
> **Duration:** ~30 min
> **Cost risk:** Minimal (free-tier eligible; <$0.01 for test objects)

## Objective

Stand up 3 buckets/containers per cloud with different public-access configurations, audit them programmatically, then apply Block Public Access universally and re-audit.

## Pre-flight

Ensure you have at least one cloud CLI authenticated:
- `aws sts get-caller-identity`
- `az account show`
- `gcloud auth list`

Install the Python SDKs:
```bash
pip install boto3 azure-storage-blob azure-identity google-cloud-storage
```

---

## Step 1: Terraform infrastructure

Create `lab.tf` for your cloud (choose one or all three):

### AWS

```hcl
provider "aws" { region = "us-east-1" }

resource "aws_s3_bucket" "private" {
  bucket = "lab-private-111111111111"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "private" {
  bucket = aws_s3_bucket.private.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "accidentally_public" {
  bucket = "lab-accidental-111111111111"
  force_destroy = true
}

resource "aws_s3_bucket_acl" "accidentally_public" {
  bucket = aws_s3_bucket.accidentally_public.id
  acl    = "public-read"  # THIS IS THE MISCONFIGURATION
}

resource "aws_s3_bucket" "misgranted_public" {
  bucket = "lab-misgranted-111111111111"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "misgranted_public" {
  bucket = aws_s3_bucket.misgranted_public.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = ["${aws_s3_bucket.misgranted_public.arn}/*"]
    }]
  })
}

resource "aws_s3_object" "test" {
  for_each = toset([
    aws_s3_bucket.private.id,
    aws_s3_bucket.accidentally_public.id,
    aws_s3_bucket.misgranted_public.id,
  ])
  bucket  = each.key
  key     = "test.txt"
  content = "security audit test"
}
```

### Azure

```hcl
provider "azurerm" { features {} }

resource "azurerm_resource_group" "lab" {
  name     = "rg-storage-audit-lab"
  location = "eastus"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "azurerm_storage_account" "private" {
  name                     = "labprivate${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "private" {
  name                 = "test-container"
  storage_account_name = azurerm_storage_account.private.name
}

resource "azurerm_storage_account" "accidentally_public" {
  name                     = "labaccid${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_nested_items_to_be_public = true  # MISCONFIGURATION
}

resource "azurerm_storage_container" "accidentally_public" {
  name                  = "test-container"
  storage_account_name  = azurerm_storage_account.accidentally_public.name
  container_access_type = "blob"
}

resource "azurerm_storage_account" "misgranted_public" {
  name                     = "labmisgra${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "misgranted_public" {
  name                  = "test-container"
  storage_account_name  = azurerm_storage_account.misgranted_public.name
  container_access_type = "container"  # PUBLIC LIST + READ
}

resource "azurerm_storage_blob" "test" {
  for_each = toset([
    azurerm_storage_container.private.id,
    azurerm_storage_container.accidentally_public.id,
    azurerm_storage_container.misgranted_public.id,
  ])
  name                   = "test.txt"
  storage_account_name   = replace(each.key, "/.*storageAccounts/([^/]+)/.*/", "$1")
  storage_container_name = "test-container"
  type                   = "Block"
  source_content         = "security audit test"
}
```

### GCP

```hcl
provider "google" { project = "example-project" }

resource "google_storage_bucket" "private" {
  name                        = "lab-private-111111111111"
  location                    = "us-east1"
  uniform_bucket_level_access = true
  force_destroy               = true
}

resource "google_storage_bucket" "accidentally_public" {
  name                        = "lab-accidental-111111111111"
  location                    = "us-east1"
  uniform_bucket_level_access = false  # FINE-GRAINED — allows per-object ACLs
  force_destroy               = true
}

resource "google_storage_bucket_object" "accidentally_public" {
  name   = "test.txt"
  bucket = google_storage_bucket.accidentally_public.name
  content = "security audit test"
  # Misconfiguration: ACL granting allUsers read
  predefined_acl = "publicRead"
}

resource "google_storage_bucket" "misgranted_public" {
  name                        = "lab-misgranted-111111111111"
  location                    = "us-east1"
  uniform_bucket_level_access = true
  force_destroy               = true
}

resource "google_storage_bucket_iam_member" "misgranted_public" {
  bucket = google_storage_bucket.misgranted_public.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"  # PUBLIC GRANT
}

resource "google_storage_bucket_object" "test" {
  for_each = toset([
    google_storage_bucket.private.name,
    google_storage_bucket.misgranted_public.name,
  ])
  name    = "test.txt"
  bucket  = each.key
  content = "security audit test"
}
```

Apply:
```bash
terraform init && terraform apply -auto-approve
```

---

## Step 2: Python audit script

Create `audit_public.py`:

```python
#!/usr/bin/env python3
"""Audit cloud storage for public exposure across AWS, Azure, and GCP."""

import json
import sys

# ---------- AWS ----------
def audit_aws():
    import boto3
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    results = []
    for b in buckets:
        name = b['Name']
        status = {'bucket': name, 'public_read': False, 'public_list': False, 'reason': ''}

        # Check Block Public Access
        try:
            bpa = s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
            if not bpa.get('BlockPublicPolicy') or not bpa.get('BlockPublicAcls'):
                status['reason'] += 'BPA_incomplete '
        except s3.exceptions.ClientError:
            status['reason'] += 'BPA_absent '

        # Check bucket ACL
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                uri = grant.get('Grantee', {}).get('URI', '')
                if 'AllUsers' in uri:
                    status['public_read'] = True
                    status['reason'] += 'ACL_AllUsers '
        except Exception:
            pass

        # Check bucket policy for Principal "*"
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)['Policy'])
            for stmt in policy.get('Statement', []):
                principal = stmt.get('Principal', {})
                if principal == '*' or principal == {'AWS': '*'}:
                    if 's3:GetObject' in str(stmt.get('Action', '')):
                        status['public_read'] = True
                        status['reason'] += 'Policy_PrincipalStar_GetObject '
                    if 's3:ListBucket' in str(stmt.get('Action', '')):
                        status['public_list'] = True
                        status['reason'] += 'Policy_PrincipalStar_ListBucket '
        except s3.exceptions.ClientError:
            pass

        results.append(status)
    return results

# ---------- Azure ----------
def audit_azure():
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.storage.models import StorageAccountCheckNameAvailabilityParameters

    cred = DefaultAzureCredential()
    sub_id = cred.get_token("https://management.azure.com/.default").token  # simplistic; use az CLI fallback
    # Use az CLI for simplicity instead of SDK subscription enumeration
    import subprocess
    cmd = ["az", "storage", "account", "list",
           "--query", "[].{name:name, rg:resourceGroup, publicAccess:allowBlobPublicAccess}",
           "-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    accounts = json.loads(result.stdout)

    results = []
    for acct in accounts:
        name = acct['name']
        rg = acct['rg']
        status = {'bucket': name, 'public_read': False, 'public_list': False, 'reason': ''}

        if acct.get('publicAccess') is True:
            status['reason'] += 'allowBlobPublicAccess=true '

        # Check each container's public access level
        cmd2 = ["az", "storage", "container", "list",
                "--account-name", name,
                "--auth-mode", "login",
                "--query", "[].{cname:name, access:properties.publicAccess}",
                "-o", "json"]
        result2 = subprocess.run(cmd2, capture_output=True, text=True)
        containers = json.loads(result2.stdout) if result2.returncode == 0 else []

        for c in containers:
            access = c.get('access', 'None')
            if access == 'Container':
                status['public_read'] = True
                status['public_list'] = True
                status['reason'] += f'Container_{c["cname"]}_ContainerAccess '
            elif access == 'Blob':
                status['public_read'] = True
                status['reason'] += f'Container_{c["cname"]}_BlobAccess '

        results.append(status)
    return results

# ---------- GCP ----------
def audit_gcp():
    import subprocess
    cmd = ["gcloud", "storage", "buckets", "list",
           "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    buckets = json.loads(result.stdout) if result.returncode == 0 else []

    results = []
    for b in buckets:
        name = b['name']
        status = {'bucket': name, 'public_read': False, 'public_list': False, 'reason': ''}

        # Check uniform bucket-level access
        if not b.get('iamConfiguration', {}).get('uniformBucketLevelAccess', {}).get('enabled'):
            status['reason'] += 'fine_grained_ACLs '

        # Check IAM policy for allUsers/allAuthenticatedUsers
        cmd2 = ["gcloud", "storage", "buckets", "get-iam-policy", f"gs://{name}",
                "--format", "json"]
        result2 = subprocess.run(cmd2, capture_output=True, text=True)
        if result2.returncode == 0:
            policy = json.loads(result2.stdout)
            for binding in policy.get('bindings', []):
                if any('allUsers' in m for m in binding.get('members', [])):
                    if 'objectViewer' in binding.get('role', ''):
                        status['public_read'] = True
                        status['reason'] += f'IAM_allUsers_{binding["role"]} '
                if any('allAuthenticatedUsers' in m for m in binding.get('members', [])):
                    status['reason'] += f'IAM_allAuth_{binding["role"]} '

        # If fine-grained, check object ACLs for publicRead
        if not b.get('iamConfiguration', {}).get('uniformBucketLevelAccess', {}).get('enabled'):
            cmd3 = ["gcloud", "storage", "objects", "list", f"gs://{name}",
                    "--format", "json(acl)"]
            result3 = subprocess.run(cmd3, capture_output=True, text=True)
            if result3.returncode == 0:
                objects = json.loads(result3.stdout)
                for obj in objects:
                    for acl_entry in obj.get('acl', []):
                        if acl_entry.get('entity') == 'allUsers':
                            status['public_read'] = True
                            status['reason'] += 'object_ACL_allUsers '

        results.append(status)
    return results

# ---------- Main ----------
def main():
    all_results = {}

    print("=" * 60)
    print("PUBLIC BUCKET AUDIT — BEFORE BLOCK PUBLIC ACCESS")
    print("=" * 60)

    try:
        all_results['AWS'] = audit_aws()
    except Exception as e:
        print(f"AWS audit error: {e}")

    try:
        all_results['Azure'] = audit_azure()
    except Exception as e:
        print(f"Azure audit error: {e}")

    try:
        all_results['GCP'] = audit_gcp()
    except Exception as e:
        print(f"GCP audit error: {e}")

    for cloud, results in all_results.items():
        print(f"\n--- {cloud} ---")
        public_found = [r for r in results if r['public_read'] or r['public_list']]
        for r in results:
            flag = "PUBLIC" if r['public_read'] or r['public_list'] else "OK"
            print(f"  [{flag}] {r['bucket']}")
            if r['reason']:
                print(f"         Reason: {r['reason'].strip()}")

        if public_found:
            print(f"\n  => {len(public_found)} public resources found in {cloud}")
        else:
            print(f"\n  => No public resources in {cloud}")

if __name__ == '__main__':
    main()
```

Run the audit:
```bash
python3 audit_public.py
```

**Expected output (before remediation):**
```
[OK] lab-private-111111111111
[PUBLIC] lab-accidental-111111111111
         Reason: ACL_AllUsers
[PUBLIC] lab-misgranted-111111111111
         Reason: Policy_PrincipalStar_GetObject
=> 2 public resources found in AWS
```

---

## Step 3: Apply Block Public Access

### AWS
```bash
# Apply to each bucket
aws s3api put-public-access-block --bucket lab-private-111111111111 \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws s3api put-public-access-block --bucket lab-accidental-111111111111 \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws s3api put-public-access-block --bucket lab-misgranted-111111111111 \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### Azure
```bash
az storage account update --name <accidental-acct> --resource-group rg-storage-audit-lab --allow-blob-public-access false
az storage account update --name <misgranted-acct> --resource-group rg-storage-audit-lab --allow-blob-public-access false
# Then set each container to private
az storage container set-permission --name test-container --account-name <accidental-acct> --public-access off --auth-mode login
az storage container set-permission --name test-container --account-name <misgranted-acct> --public-access off --auth-mode login
```

### GCP
```bash
gcloud storage buckets update gs://lab-accidental-111111111111 --uniform-bucket-level-access
gcloud storage buckets remove-iam-policy-binding gs://lab-misgranted-111111111111 \
  --member=allUsers --role=roles/storage.objectViewer
```

---

## Step 4: Re-audit

```bash
python3 audit_public.py
```

**Expected output (after remediation):**
```
[OK] lab-private-111111111111
[OK] lab-accidental-111111111111
[OK] lab-misgranted-111111111111
=> No public resources in AWS
```

---

## Step 5: Teardown

```bash
# AWS
aws s3 rm s3://lab-private-111111111111 --recursive
aws s3 rm s3://lab-accidental-111111111111 --recursive
aws s3 rm s3://lab-misgranted-111111111111 --recursive
aws s3api delete-bucket --bucket lab-private-111111111111
aws s3api delete-bucket --bucket lab-accidental-111111111111
aws s3api delete-bucket --bucket lab-misgranted-111111111111

# Azure / GCP
terraform destroy -auto-approve
```

## Troubleshooting

| Problem | Solution |
|---|---|
| `AccessDenied` when listing ACLs | You may need `s3:GetBucketAcl` IAM permission |
| Azure CLI `auth-mode login` fails | Run `az login` first |
| GCP `storage.buckets.getIamPolicy` denied | Ensure `roles/storage.admin` on the project |
| Python SDK import errors | Run `pip install -r requirements.txt` (create one with boto3, azure-storage-blob, azure-identity, google-cloud-storage, azure-mgmt-storage) |

## Expected key takeaways

1. Two distinct mechanisms cause public exposure: ACL grants and bucket/container policies.
2. Block Public Access overrides both.
3. Programmatic auditing catches what manual review misses.
4. The same audit logic ports across all three clouds with cloud-specific primitives.
