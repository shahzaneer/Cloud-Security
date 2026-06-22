# 02 — Public Exposure & Block Public Access

> **Level:** Intermediate
> **Prereqs:** [04-01 — Object Storage Primitives](./object-storage-primitives.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Discovery, Collection
> **Authorization scope:** Run only against your own storage accounts / a dedicated sandbox bucket.

## What & why

Public exposure of cloud storage is the #1 cloud breach class by volume. "Block Public Access" is a defense-in-depth control that overrides any per-object or per-bucket ACL granting public access. It must be layered: at the account/organization level, at the bucket/container level, and confirmed continuously via audit.

## The OnPrem reality

A PIX/ASA firewall rule opening port 2049 (NFS) to `0.0.0.0/0` with `no_root_squash` on the export. Or a Samba share with `guest ok = yes` and `read only = no`. The firewall was the only gate; once bypassed (or misconfigured), the data was fully exposed to any IP that could route to the share.

```bash
# OnPrem: anon mount via NFS
showmount -e fileserver.example.com
mount -t nfs fileserver.example.com:/exports/public /mnt/nfs_loot
```

## Core concepts

**Block Public Access primitives per cloud:**

| Layer | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| **Account/Org** | SCP denying `s3:PutBucketAcl` with public grants | Azure Policy denying `Microsoft.Storage/storageAccounts` with `allowBlobPublicAccess=true` | Org Policy `storage.uniformBucketLevelAccess` enforced | Firewall deny any-to-NFS ports |
| **Service-level** | S3 Block Public Access (account-wide) | Storage Account `allowBlobPublicAccess=false` | `uniform_bucket_level_access=true` enforced | NFS `exports(ro,root_squash)` |
| **Resource-level** | Bucket-level Block Public Access | Container ACL restricted | IAM-only (no ACLs on uniform) | Export-level no_root_squash check |
| **Audit** | `aws s3control get-public-access-block` | `az storage account show --query allowBlobPublicAccess` | `gcloud storage buckets describe --format="value(iamConfiguration.uniformBucketLevelAccess.enabled)"` | `showmount -e localhost` + `exportfs -v` |

**Key insight:** Public access can be granted via three distinct mechanisms — bucket/container ACL, bucket policy, or object ACL — and Block Public Access must cover all three.

## AWS

**Service:** S3 Block Public Access (BPA). **Console path:** `S3 → Block Public Access settings for this account`.

```bash
# Enable account-wide Block Public Access
aws s3control put-public-access-block \
  --account-id 111111111111 \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable on a single bucket
aws s3api put-public-access-block \
  --bucket example-security-lab-111111111111 \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Audit: find any bucket where BPA is not fully blocking
aws s3api list-buckets --query "Buckets[].Name" --output text | while read B; do
  BLOCKED=$(aws s3api get-public-access-block --bucket "$B" \
    --query "PublicAccessBlockConfiguration.BlockPublicPolicy" 2>/dev/null)
  if [ "$BLOCKED" != "true" ]; then echo "EXPOSED: $B"; fi
done
```

**Terraform:**
```hcl
resource "aws_s3_bucket_public_access_block" "lab" {
  bucket                  = aws_s3_bucket.lab.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
```

**Gotcha:** `RestrictPublicBuckets=true` prevents cross-account access even if a bucket policy authorizes `"Principal": "*"` — this is the strongest setting. Enabling BPA at account level does not retroactively apply to existing buckets; audit is required.

## Azure

**Service:** Storage Account `allowBlobPublicAccess`. **Console path:** `Storage accounts → <account> → Configuration → Allow blob public access: Disabled`.

```bash
# Disable public access on a storage account
az storage account update \
  --name securitylab111111111111 \
  --resource-group rg-security-lab \
  --allow-blob-public-access false

# Audit: find storage accounts with public blob access enabled
az storage account list \
  --query "[?allowBlobPublicAccess==\`true\`].{Name:name, RG:resourceGroup}" \
  --output table

# Audit per-container public access
az storage container list \
  --account-name securitylab111111111111 \
  --auth-mode login \
  --query "[?properties.publicAccess!='None'].{Name:name, Access:properties.publicAccess}" \
  --output table
```

**Azure Policy (deny):**
```json
{
  "if": {
    "field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess",
    "equals": "true"
  },
  "then": {
    "effect": "deny"
  }
}
```

**Gotcha:** Azure has three container public access levels: `None`, `Blob` (anonymous read on blobs only), `Container` (anonymous read on blobs + listing). Even with `allowBlobPublicAccess=false` at the account level, existing containers with public access retain their permissions — test after enabling.

## GCP

**Service:** Uniform Bucket-Level Access. **Console path:** `Cloud Storage → <bucket> → Permissions`.

```bash
# Enable uniform bucket-level access (only way to disable ACL-based public)
gcloud storage buckets update gs://security-lab-111111111111 \
  --uniform-bucket-level-access

# Audit: list bucket IAM for allUsers / allAuthenticatedUsers
gcloud storage buckets get-iam-policy gs://security-lab-111111111111 \
  --format=json | jq '.bindings[] | select(.members[] | contains("allUsers") or contains("allAuthenticatedUsers"))'

# Org Policy: enforce uniform access across project/org
gcloud resource-manager org-policies set-policy \
  --organization=000000000000 \
  policy.yaml
```

**policy.yaml for Org Policy:**
```yaml
constraint: constraints/storage.uniformBucketLevelAccess
booleanPolicy:
  enforced: true
```

**Gotcha:** GCP uses IAM for access control when uniform access is enabled; there are no ACLs left to block. The legacy fine-grained ACL model (`uniform_bucket_level_access=false`) supports per-object ACLs with `allUsers` grants, identical in risk to S3 ACL public grants.

## OnPrem mapping

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Deny anonymous access | Firewall + NFS `root_squash`, Samba `guest ok=no` | S3 Block Public Access | `allowBlobPublicAccess=false` | `uniform_bucket_level_access=true` |
| Enforce at scale | Config mgmt (Ansible `lineinfile`) | SCP + Account BPA | Azure Policy | Org Policy |
| Detect exposed shares | `showmount -e` scan, `nmap -p 2049` sweep | Trusted Advisor / Config rule `s3-bucket-public-read-prohibited` | Defender for Cloud `Storage accounts should prevent shared key access` | Security Command Center `STORAGE_BUCKET_PUBLIC` |
| Log anonymous access | nfsstat / rpcdebug | S3 server access logs + CloudTrail | Storage Analytics logs | Cloud Audit Logs |

## 🔴 Red Team view

How an attacker who compromises credentials (or finds a misconfiguration) blesses a bucket as public:

```bash
# Scenario: attacker has stolen IAM credentials and wants to exfiltrate data
# by temporarily granting public read, downloading, then removing the grant

# Step 1 — Grant public read ACL (contained, against own test bucket)
aws s3api put-bucket-acl \
  --bucket example-security-lab-111111111111 \
  --acl public-read

# Step 2 — Enumerate contents via anonymous HTTP
curl -s http://example-security-lab-111111111111.s3.amazonaws.com/

# Step 3 — Download all objects found
aws s3 sync s3://example-security-lab-111111111111 /tmp/exfiltrated/ --no-sign-request

# Step 4 — Remove public ACL to cover tracks
aws s3api put-bucket-acl \
  --bucket example-security-lab-111111111111 \
  --acl private
```

**Azure equivalent:**
```bash
az storage container set-permission \
  --name test-container \
  --account-name securitylab111111111111 \
  --public-access container
```

**GCP equivalent (requires fine-grained ACL mode):**
```bash
gcloud storage buckets add-iam-policy-binding gs://security-lab-111111111111 \
  --member=allUsers \
  --role=roles/storage.objectViewer
```

**Artifacts left:** CloudTrail records `PutBucketAcl` with `requestParameters.AccessControlPolicy` showing `xsi:type="Group"` and `URI="http://acs.amazonaws.com/groups/global/AllUsers"`. S3 server access logs record the subsequent anonymous `REST.GET.OBJECT` requests. Azure Activity Log captures `Set Container ACL`. GCP Audit Logs capture `SetIamPolicy`.

## 🔵 Blue Team view

**Preventive controls:**
```bash
# AWS SCP — deny s3:PutBucketAcl with public grants
aws organizations create-policy \
  --name DenyPublicBucketACL \
  --type SERVICE_CONTROL_POLICY \
  --content '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:PutBucketAcl"],"Resource":["*"],"Condition":{"StringEquals":{"s3:x-amz-acl":["public-read","public-read-write","authenticated-read"]}}}]}'
```

**Detection queries:**
```sql
-- AWS CloudTrail: any PutBucketAcl setting public-read
SELECT eventTime, sourceIPAddress, userIdentity.arn, requestParameters.bucketName
FROM cloudtrail_logs
WHERE eventName = 'PutBucketAcl'
  AND requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI
      LIKE '%AllUsers%'
```

```kusto
// Azure Activity Log: container public access set
ActivityLog
| where OperationNameValue == "Microsoft.Storage/storageAccounts/blobServices/containers/write"
| where Properties contains "publicAccess"
| where Properties contains "Blob" or Properties contains "Container"
| project TimeGenerated, Caller, ResourceId, Properties
```

```sql
-- GCP Logging: IAM policy binding for allUsers
SELECT timestamp, protoPayload.authenticationInfo.principalEmail,
       resource.labels.bucket_name
FROM `project-id.cloud_audit_logs._AllLogs`
WHERE protoPayload.methodName = "storage.setIamPermissions"
  AND protoPayload.request.policy.bindings.members LIKE "%allUsers%"
```

**Response steps:**
1. Immediately apply Block Public Access / disable `allowBlobPublicAccess` / enable `uniform_bucket_level_access`.
2. Revoke the IAM credentials used to make the change.
3. Review S3 server access logs / Storage Analytics / Cloud Audit Logs for any anonymous downloads during the exposure window.
4. Notify compliance if regulated data was potentially exposed.

## Hands-on lab

1. Create a bucket/container with Block Public Access fully enabled.
2. Attempt to set a public-read ACL on it — expect failure.
3. Create a second bucket with BPA disabled (sandbox only), set `public-read`, confirm listing works.
4. Enable BPA on that bucket and try the anonymous listing again — expect `403 AccessDenied`.
5. Run the audit one-liner from your cloud's section above to confirm zero publicly accessible resources.
6. **Teardown:** Delete all test buckets and containers.

## Detection rules & checklists

```yaml
# Sigma rule — Public ACL grant on cloud object store
title: Cloud Storage Public ACL Granted
status: experimental
description: Detects when a bucket/container ACL is set to allow public access
logsource:
  product: cloud
  service: object_storage
detection:
  selection_aws:
    eventName: PutBucketAcl
    requestParameters.AccessControlPolicy|contains: 'AllUsers'
  selection_azure:
    operationName: Set Container ACL
    Properties.publicAccess|re: 'Container|Blob'
  selection_gcp:
    methodName: storage.setIamPermissions
    members|contains: 'allUsers'
  condition: selection_aws or selection_azure or selection_gcp
falsepositives:
  - Authorized CDN origin configuration (validate the bucket is behind CloudFront/Azure CDN)
level: high
```

```bash
# Quick audit CLI one-liners per cloud
# AWS
aws s3api list-buckets --query "Buckets[].Name" --output text | \
  while read B; do STATUS=$(aws s3api get-bucket-acl --bucket "$B" \
    --query "Grants[?Grantee.URI=='http://acs.amazonaws.com/groups/global/AllUsers']" \
    --output text); [ -n "$STATUS" ] && echo "PUBLIC: $B"; done

# Azure
az storage account list --query "[?allowBlobPublicAccess==\`true\`].name" --output tsv | \
  while read ACCT; do echo "PUBLIC ENABLED: $ACCT"; done

# GCP
for B in $(gcloud storage buckets list --format="value(name)"); do
  gcloud storage buckets get-iam-policy "$B" --format=json 2>/dev/null | \
    jq -e '.bindings[]?.members[]? | select(contains("allUsers"))' >/dev/null && \
    echo "PUBLIC: $B"
done
```

## References

- [AWS Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Azure: Prevent anonymous public read access](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent)
- [GCP: Use uniform bucket-level access](https://cloud.google.com/storage/docs/uniform-bucket-level-access)
- [MITRE ATT&CK T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
