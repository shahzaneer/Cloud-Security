# Detection — Public Access Anomaly

> **Purpose:** Copy-pasteable detection queries and rules for identifying public access grants and enumeration anomalies on cloud object storage.
> **Clouds:** AWS · Azure · GCP

---

## AWS — CloudWatch Logs Insights

### Query 1: Public ACL grant via PutBucketAcl

```sql
fields @timestamp, sourceIPAddress, userIdentity.arn, requestParameters.bucketName
| filter eventName = 'PutBucketAcl'
| filter requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI like /AllUsers/
| sort @timestamp desc
| limit 50
```

### Query 2: Bucket policy with public principal

```sql
fields @timestamp, sourceIPAddress, userIdentity.arn, requestParameters.bucketName,
       requestParameters.policy
| filter eventName = 'PutBucketPolicy'
| filter requestParameters.policy like /"Principal"\s*:\s*"\*"/
| sort @timestamp desc
| limit 50
```

### Query 3: Unusual ListObjects volume (enumeration scan)

```sql
stats count(*) as list_count by userIdentity.arn, bin(5m) as window
| filter eventName in ('ListObjects', 'ListObjectsV2')
| sort list_count desc
| limit 20
```

### Query 4: HeadObject burst (metadata reconnaissance)

```sql
stats count(*) as head_count by userIdentity.arn, requestParameters.bucketName, bin(5m) as window
| filter eventName = 'HeadObject'
| filter head_count > 50
| sort head_count desc
| limit 20
```

### Query 5: Public bucket confirmed via GetBucketAcl

```sql
fields @timestamp, userIdentity.arn, requestParameters.bucketName
| filter eventName = 'GetBucketAcl'
| filter sourceIPAddress not like /10./
| filter sourceIPAddress not like /172.16./
| sort @timestamp desc
| limit 50
```

---

## Azure — KQL (Log Analytics / Sentinel)

### Query 1: Anonymous access granted on container

```kusto
ActivityLog
| where OperationNameValue == "Microsoft.Storage/storageAccounts/blobServices/containers/write"
| where Properties_d.publicAccess in ("Blob", "Container")
| extend ContainerName = tostring(Properties_d.name)
| extend PublicAccess = tostring(Properties_d.publicAccess)
| project TimeGenerated, Caller, ResourceId, ContainerName, PublicAccess
| order by TimeGenerated desc
```

### Query 2: Storage account with public blob access enabled

```kusto
ActivityLog
| where OperationNameValue == "Microsoft.Storage/storageAccounts/write"
| where Properties_d.allowBlobPublicAccess == true
| extend AccountName = tostring(Properties_d.name)
| project TimeGenerated, Caller, AccountName
| order by TimeGenerated desc
```

### Query 3: SAS token activity from unexpected IP

```kusto
StorageBlobLogs
| where AuthenticationType == "SAS"
| where CallerIpAddress !startswith "10." and CallerIpAddress !startswith "172.16."
| project TimeGenerated, AccountName, ObjectKey, OperationName, CallerIpAddress, UserAgentHeader
| order by TimeGenerated desc
```

### Query 4: Enumeration anomaly — high ListBlob / GetBlob ratio

```kusto
let timeframe = 1h;
StorageBlobLogs
| where TimeGenerated > ago(timeframe)
| summarize
    ListOps = countif(OperationName == "ListBlob"),
    GetOps = countif(OperationName == "GetBlob"),
    HeadOps = countif(OperationName == "GetBlobProperties")
    by CallerIpAddress, AccountName
| where ListOps > 50
| extend ScanRatio = (ListOps + HeadOps) * 1.0 / iif(GetOps == 0, 1, GetOps)
| where ScanRatio > 5
| project CallerIpAddress, AccountName, ListOps, GetOps, HeadOps, ScanRatio
| order by ScanRatio desc
```

### Query 5: Cross-tenant access to storage account

```kusto
StorageBlobLogs
| where AuthenticationType == "AccountKey"
| where CallerIpAddress !startswith "10." and CallerIpAddress !startswith "172.16."
| project TimeGenerated, AccountName, ObjectKey, OperationName, CallerIpAddress
| order by TimeGenerated desc
```

---

## GCP — Logging Query (Log Analytics / BigQuery)

### Query 1: IAM policy binding for allUsers on a bucket

```sql
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail,
  resource.labels.bucket_name,
  protoPayload.request.policy.bindings
FROM `project-id.cloud_audit_logs._AllLogs`
WHERE protoPayload.methodName = "storage.setIamPermissions"
  AND EXISTS (
    SELECT 1 FROM UNNEST(protoPayload.request.policy.bindings) AS binding
    WHERE "allUsers" IN UNNEST(binding.members)
  )
ORDER BY timestamp DESC
LIMIT 50
```

### Query 2: Object ACL set to publicRead (fine-grained only)

```sql
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail,
  resource.labels.bucket_name,
  resource.labels.object_name
FROM `project-id.cloud_audit_logs._AllLogs`
WHERE protoPayload.methodName = "storage.objects.update"
  AND protoPayload.request.predefinedAcl = "publicRead"
ORDER BY timestamp DESC
LIMIT 50
```

### Query 3: Bucket enumeration anomaly

```sql
SELECT
  protoPayload.authenticationInfo.principalEmail,
  resource.labels.bucket_name,
  COUNTIF(protoPayload.methodName = "storage.objects.list") AS list_ops,
  COUNTIF(protoPayload.methodName = "storage.objects.get") AS get_ops,
  TIMESTAMP_TRUNC(timestamp, HOUR) AS window
FROM `project-id.cloud_audit_logs._AllLogs`
WHERE timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
  AND resource.type = "gcs_bucket"
GROUP BY principalEmail, bucket_name, window
HAVING list_ops > 50 AND list_ops > get_ops * 5
ORDER BY list_ops DESC
```

### Query 4: Uniform bucket-level access disabled

```sql
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail,
  resource.labels.bucket_name
FROM `project-id.cloud_audit_logs._AllLogs`
WHERE protoPayload.methodName = "storage.buckets.update"
  AND protoPayload.request.bucket.iamConfiguration.uniformBucketLevelAccess.enabled = false
ORDER BY timestamp DESC
LIMIT 50
```

---

## Sigma Rules

### Rule 1: Cloud Storage Public ACL Granted

```yaml
title: Cloud Storage Public ACL Granted
id: 00000000-0000-0000-0000-000000000001
status: experimental
author: cloud-security-lab
date: 2026-06-22
description: |
  Detects when a bucket/container ACL or policy is modified to grant
  public read or list access to anonymous users.
logsource:
  product: cloud
  service: object_storage
detection:
  aws_acl:
    eventName: PutBucketAcl
    requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI|endswith: '/AllUsers'
  aws_policy:
    eventName: PutBucketPolicy
    requestParameters.policy|contains: '"Principal":"*"'
  azure_container:
    OperationNameValue: 'Microsoft.Storage/storageAccounts/blobServices/containers/write'
    Properties.publicAccess|re: 'Blob|Container'
  gcp_iam:
    methodName: storage.setIamPermissions
    members|contains: 'allUsers'
  gcp_acl:
    methodName: storage.objects.update
    request.predefinedAcl: publicRead
  condition: aws_acl or aws_policy or azure_container or gcp_iam or gcp_acl
falsepositives:
  - Authorized CDN origin configuration (validate bucket is behind CloudFront/verified CDN)
  - Internal documentation bucket with deliberate public-read (tag audit)
level: high
tags:
  - attack.t1530
  - attack.initial_access
```

### Rule 2: Cloud Storage Enumeration Anomaly

```yaml
title: Cloud Storage Enumeration Anomaly
id: 00000000-0000-0000-0000-000000000002
status: experimental
author: cloud-security-lab
date: 2026-06-22
description: |
  Detects high-volume List/Head operations relative to Get operations,
  indicative of an attacker enumerating storage contents.
logsource:
  product: cloud
  service: object_storage
detection:
  selection:
    eventName|re: 'ListObjects|ListBlob|storage\.objects\.list'
  timeframe: 15m
  condition: count() > 100
level: medium
tags:
  - attack.t1530
  - attack.discovery
```

### Rule 3: Anonymous Download from Cloud Storage

```yaml
title: Anonymous Download from Cloud Storage
id: 00000000-0000-0000-0000-000000000003
status: experimental
author: cloud-security-lab
date: 2026-06-22
description: |
  Detects successful anonymous (unauthenticated) object downloads,
  confirming a bucket is publicly readable and being exploited.
logsource:
  product: cloud
  service: object_storage
detection:
  aws:
    eventName: GetObject
    userIdentity.type: AWSAccount
    userIdentity.accountId: Anonymous
  azure:
    AuthenticationType: Anonymous
    OperationName: GetBlob
    StatusCode: 200
  gcp:
    methodName: storage.objects.get
    authenticationInfo.principalEmail: ''
  condition: aws or azure or gcp
level: critical
tags:
  - attack.t1530
  - attack.exfiltration
```

---

## Cloud Custodian (OPA-style) policies

### AWS: Deny buckets without Block Public Access

```yaml
policies:
  - name: s3-block-public-access-required
    resource: aws.s3
    filters:
      - type: check-public-block
        condition:
          BlockPublicAcls: false
          BlockPublicPolicy: false
    actions:
      - type: notify
        template: default
        to: ["security@example.com"]
        subject: "S3 bucket without full Block Public Access"
      - type: set-public-block
        state: true
```

### Azure: Audit containers with public access

```yaml
policies:
  - name: deny-container-public-access
    resource: azure.storage-container
    filters:
      - type: value
        key: properties.publicAccess
        op: ne
        value: "None"
    actions:
      - type: notify
        template: default
        to: ["security@example.com"]
```

### GCP: Require uniform bucket-level access

```yaml
policies:
  - name: require-uniform-bucket-access
    resource: gcp.bucket
    filters:
      - type: value
        key: iamConfiguration.uniformBucketLevelAccess.enabled
        value: false
    actions:
      - type: notify
        to: ["security@example.com"]
```

---

## CLI audit one-liners

```bash
# AWS — find all buckets with any AllUsers grant
aws s3api list-buckets --query "Buckets[].Name" --output text | while read B; do
  aws s3api get-bucket-acl --bucket "$B" \
    --query "Grants[?Grantee.URI=='http://acs.amazonaws.com/groups/global/AllUsers']" \
    --output text 2>/dev/null | grep -q . && echo "PUBLIC_ACL: $B"
  aws s3api get-bucket-policy-status --bucket "$B" \
    --query "PolicyStatus.IsPublic" --output text 2>/dev/null | grep -q true && echo "PUBLIC_POLICY: $B"
done

# Azure — find all storage accounts with public access enabled
az storage account list \
  --query "[?allowBlobPublicAccess==\`true\`].{name:name, rg:resourceGroup}" \
  --output table

# Azure — find containers with public access per account
for ACCT in $(az storage account list --query "[].name" -o tsv); do
  az storage container list --account-name "$ACCT" --auth-mode login \
    --query "[?properties.publicAccess!='None'].{Account:'$ACCT',Container:name,Access:properties.publicAccess}" \
    -o table 2>/dev/null
done

# GCP — find buckets with allUsers IAM
for B in $(gcloud storage buckets list --format="value(name)"); do
  gcloud storage buckets get-iam-policy "gs://$B" --format=json 2>/dev/null | \
    jq -e '.bindings[]?.members[]? | select(contains("allUsers"))' >/dev/null && \
    echo "PUBLIC_IAM: $B"
done

# GCP — find buckets without uniform access
gcloud storage buckets list \
  --format="table(name, iamConfiguration.uniformBucketLevelAccess.enabled)" \
  --filter="iamConfiguration.uniformBucketLevelAccess.enabled=false"
```

---

## Response playbook

When a public access grant is detected:

1. **Contain (15 min):**
   - AWS: `aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`
   - Azure: `az storage account update --name <acct> --resource-group <rg> --allow-blob-public-access false`
   - GCP: `gcloud storage buckets update gs://<name> --uniform-bucket-level-access` and `gcloud storage buckets remove-iam-policy-binding gs://<name> --member=allUsers --role=roles/storage.objectViewer`

2. **Investigate (1 hour):**
   - Review CloudTrail/Activity Log/Audit Logs for the `PutBucketAcl` / `PutContainerACL` / `SetIamPolicy` event that triggered the change.
   - Identify the principal that made the change — was it authorized? Within a change window?
   - Check storage access logs for anonymous downloads during the exposure window.

3. **Remediate (4 hours):**
   - If unauthorized: revoke the principal's credentials, rotate all access keys.
   - Run a full storage inventory scan across all accounts in the organization.
   - Enable automated detection (GuardDuty, Defender for Storage, Security Command Center).

4. **Report (24 hours):**
   - Document the exposure window, data accessed, and root cause.
   - Notify compliance/legal if regulated data was involved.
   - Update IaC to enforce Block Public Access at the org level.
