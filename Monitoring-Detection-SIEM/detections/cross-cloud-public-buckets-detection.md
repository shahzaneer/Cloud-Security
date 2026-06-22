# Detection 01 — Cross-Cloud Public Buckets

> **Level:** Intermediate
> **Prereqs:** 06-01, 06-07
> **Clouds:** AWS · Azure · GCP
> **Authorization scope:** Apply detection queries against your own sandbox account telemetry. Test by deliberately creating a public bucket/container in your sandbox, then immediately deleting it.

## Sigma rule — Cloud Storage Made Public

```yaml
title: Cloud Storage Bucket or Container Made Public
id: c7d8e9f0-1234-5678-9abc-def012345678
status: stable
description: |
  Detects when a cloud storage bucket (S3), blob container (Azure), or bucket (GCS)
  is made publicly accessible via IAM policy, bucket ACL, or container public access level.
author: detection-engineering
date: 2026-06-22
logsource:
  product: aws
  service: cloudtrail
detection:
  aws_s3_public_policy:
    eventSource: s3.amazonaws.com
    eventName: PutBucketPolicy
    requestParameters.bucketPolicy.Statement[].Principal: "*"
  aws_s3_public_acl:
    eventSource: s3.amazonaws.com
    eventName: PutBucketAcl
    requestParameters.AccessControlPolicy.AccessControlList.Grant[].Grantee.URI|contains: "AllUsers"
  azure_blob_public:
    operationName: Microsoft.Storage/storageAccounts/blobServices/containers/write
    properties.requestbody.properties.publicAccess: "Blob"
  azure_container_public:
    operationName: Microsoft.Storage/storageAccounts/blobServices/containers/write
    properties.requestbody.properties.publicAccess: "Container"
  gcp_allusers:
    protoPayload.methodName: storage.buckets.setIamPolicy
    protoPayload.serviceData.setIamPolicyRequest.policy.bindings[].members: "allUsers"
  gcp_allauthenticated:
    protoPayload.methodName: storage.buckets.setIamPolicy
    protoPayload.serviceData.setIamPolicyRequest.policy.bindings[].members: "allAuthenticatedUsers"
  condition: aws_s3_public_policy or aws_s3_public_acl or azure_blob_public or azure_container_public or gcp_allusers or gcp_allauthenticated
falsepositives:
  - Public website hosting bucket (deliberate)
  - CDN origin bucket with OAI (should not use allUsers on bucket policy — use OAI)
  - Temporary public share for customer delivery (add expiry + monitor)
level: high
tags:
  - attack.exfiltration
  - attack.t1530
  - detection-as-code
```

## Backend 1: AWS CloudWatch Logs Insights

```sql
-- CloudWatch Logs Insights — Public S3 bucket via PutBucketPolicy
fields @timestamp, eventName, userIdentity.arn, requestParameters.bucketName, sourceIPAddress
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutBucketPolicy", "PutBucketAcl"]
| filter (requestParameters.bucketPolicy like /"Principal":"\*"/ or
          requestParameters.bucketPolicy like /"Principal":\{"AWS":"\*"\}/ or
          requestParameters.AccessControlPolicy like /AllUsers/)

-- Alternative: query CloudTrail data events for public-read object puts
fields @timestamp, eventName, userIdentity.arn, requestParameters.key
| filter eventName = "PutObject"
| filter requestParameters.x-amz-acl in ["public-read", "public-read-write"]
```

## Backend 2: Azure Sentinel KQL

```kql
// Public Blob container created or modified
StorageBlobLogs
| where OperationName in ("PutContainer", "SetContainerAcl")
| where AuthenticationType == "AccountKey" or AuthenticationType == "SAS"
| project TimeGenerated, AccountName, OperationName, CallerIpAddress

// Azure Activity Log — container public access set
AzureActivity
| where OperationNameValue == "Microsoft.Storage/storageAccounts/blobServices/containers/write"
| where Properties contains "publicAccess"
| where Properties contains "\"Blob\"" or Properties contains "\"Container\""
| project TimeGenerated, Caller, ResourceId, OperationNameValue

// Sentinel analytics rule (scheduled, runs every hour)
let lookback = 1h;
AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue =~ "Microsoft.Storage/storageAccounts/blobServices/containers/write"
| extend publicAccess = extractjson("$.publicAccess", Properties, typeof(string))
| where publicAccess in~ ("Blob", "Container")
| extend AccountName = extractjson("$.accountName", Properties, typeof(string))
| project TimeGenerated, Caller, CallerIpAddress, AccountName, ResourceId, publicAccess
```

## Backend 3: GCP Cloud Logging query

```sql
-- GCP Logging / BigQuery — Public GCS bucket via setIamPolicy
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail,
  resource.labels.bucket_name,
  bindings.member,
  bindings.role
FROM `project-id-111111.audit_logs.cloudaudit_googleapis_com_activity`,
UNNEST(protoPayload.serviceData.setIamPolicyRequest.policy.bindings) AS bindings
WHERE protoPayload.methodName = "storage.buckets.setIamPolicy"
  AND bindings.member IN ("allUsers", "allAuthenticatedUsers")
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
ORDER BY timestamp DESC;

-- GCP Logging query language (Log Explorer)
protoPayload.methodName="storage.buckets.setIamPolicy"
protoPayload.serviceData.setIamPolicyRequest.policy.bindings.members="allUsers" OR "allAuthenticatedUsers"

-- Also check for bucket ACL changes (legacy ACL model)
protoPayload.methodName="storage.buckets.update"
protoPayload.request.bucket.defaultObjectAcl.role="READER"
protoPayload.request.bucket.defaultObjectAcl.entity="allUsers"
```

## Cloud Custodian policies (real-time remediation)

### AWS — auto-remediate public S3 buckets

```yaml
policies:
  - name: s3-public-bucket-remediate
    resource: aws.s3
    mode:
      type: cloudtrail
      events:
        - source: s3.amazonaws.com
          event: PutBucketPolicy
          ids: requestParameters.bucketName
        - source: s3.amazonaws.com
          event: PutBucketAcl
          ids: requestParameters.bucketName
    filters:
      - or:
        - type: bucket-policy
          key: "Statement[].Principal"
          value: "*"
          op: contains
        - type: grant-is
          key: "URI"
          value: "http://acs.amazonaws.com/groups/global/AllUsers"
    actions:
      - type: notify
        template: default
        subject: "[CRITICAL] Public S3 Bucket — Auto-Remediated"
        to: [security@example.com]
        transport:
          type: sqs
          queue: https://sqs.us-east-1.amazonaws.com/111111111111/sec-alerts
      - type: remove-statements
        statement_ids: matched
      - type: auto-tag-user
        tag: "AutoRemediated"
```

### Azure — auto-remediate public containers

```yaml
policies:
  - name: block-public-blob-container
    resource: azure.storage-container
    filters:
      - type: value
        key: properties.publicAccess
        value: "Blob"
        op: eq
      - type: value
        key: properties.publicAccess
        value: "Container"
        op: eq
    actions:
      - type: set-public-access
        access: "Off"
      - type: notify
        template: default
        to: [security@example.com]
```

### GCP — auto-remediate public buckets

```yaml
policies:
  - name: block-public-gcs-buckets
    resource: gcp.bucket
    filters:
      - type: iam-policy
        key: "bindings[?members[?contains(@, 'allUsers') || contains(@, 'allAuthenticatedUsers')]].role"
        value: present
    actions:
      - type: set-iam-policy
        remove:
          - members: ["allUsers", "allAuthenticatedUsers"]
            role: "*"
      - type: notify
        to: [security@example.com]
```

## AWS Config Rules (complementary)

```json
{
  "ConfigRuleName": "s3-bucket-public-read-prohibited",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}
```

## Azure Policy (complementary)

```json
{
  "policyRule": {
    "if": {
      "allOf": [
        {"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
        {"field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", "equals": "true"}
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```

## GCP Org Policy (complementary)

```bash
gcloud org-policies set-policy /tmp/deny-public-buckets.yaml \
  --organization organizations/111111111111
```

```
# Prevents uniform bucket-level IAM from being set to allUsers/allAuthenticatedUsers
# Equivalent constraint: (as of June 2026, `constraints/storage.uniformBucketLevelAccess` enforces uniform bucket-level access; also see `constraints/storage.publicAccessPrevention`)
```

> (as of June 2026, GCP has `constraints/storage.publicAccessPrevention` (enforce public access prevention) and `constraints/storage.uniformBucketLevelAccess` (enforce uniform bucket-level access). Check the current [GCP Org Policy constraints list](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints) for the latest constraint names.)

## Detection response runbook

1. **Triage (Tier 1, 15 min):**
   - Identify the bucket/container/resource from the alert.
   - Verify the resource IS public (not a false positive from a CDN OAI setup).
   - Check the principal that made the change and note `sourceIPAddress`.

2. **Containment (Tier 3, immediate):**
   - AWS: Remove the bucket policy statement or delete the bucket ACL grant.
   - Azure: Set container public access to `Off`.
   - GCP: Remove `allUsers` / `allAuthenticatedUsers` from IAM policy.
   - If Cloud Custodian is deployed, this is automated (step 1 & 2 are one action).

3. **Investigation (Tier 2, 60 min):**
   - Query bucket access logs / StorageBlobLogs / GCS Data Access logs for reads from the public.
   - If Data Access logging was not enabled, review VPC Flow Logs / NSG logs for unusual outbound volume.
   - Check if this was a deliberate change (Jira ticket) or unauthorized.

4. **Eradication:**
   - If unauthorized, quarantine the principal (attach deny policy / disable user).
   - Rotate any credentials the principal had access to.
   - Review all other buckets/containers in the same subscription/project for similar misconfigurations.

## 🔴 Red Team view

Making a bucket/container public is the #1 cloud exfiltration vector. Attackers use `s3:PutBucketPolicy` with `"Principal":"*"` or `gsutil iam ch allUsers:objectViewer` to make a bucket world-readable, then exfiltrate data out via standard HTTPS GET — indistinguishable from legitimate CDN traffic. This attack requires no malware, no reverse shell, and leaves almost no network-layer footprint beyond the initial API call and subsequent object reads. Without Data Access logging enabled, the read operations are invisible.

**Artifacts:** The `PutBucketPolicy` / `PutBucketAcl` / `storage.buckets.setIamPolicy` call is always logged (management event). Source IP, user agent, and principal are captured. The bucket policy itself persists until explicitly removed — serving as forensic evidence.

## 🔵 Blue Team view

Preventive controls are paramount: S3 Block Public Access at account level, Azure `allowBlobPublicAccess: false` by policy, GCP Organization Policy `constraints/storage.publicAccessPrevention`. Supplement with detection rules (this file) and auto-remediation via Cloud Custodian. Route all hits to Slack/PagerDuty as Critical severity — a public bucket with sensitive data is a data breach in progress. Run the detection query hourly, and additionally use AWS Config / Azure Policy / SCC Security Health Analytics as a continuous config scanner (detects public config even if the API call was missed).

## Testing the detection

### AWS — trigger event (contained, immediate teardown)

```bash
BUCKET="detection-test-$(date +%s)"
aws s3 mb s3://$BUCKET
aws s3api put-bucket-policy --bucket $BUCKET --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::'$BUCKET'/*"
  }]
}'

# Verify detection fired
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy --max-results 3

# IMMEDIATE TEARDOWN:
aws s3 rb s3://$BUCKET --force
```

### Azure — trigger event

```bash
az storage container create --name public-test --account-name salab111 --public-access blob

# Query Activity Log
az monitor activity-log list --resource-group rg-lab --query "[?authorization.action=='Microsoft.Storage/storageAccounts/blobServices/containers/write']" -o table

# IMMEDIATE TEARDOWN:
az storage container delete --name public-test --account-name salab111
```

### GCP — trigger event

```bash
gsutil mb gs://detection-test-$(date +%s)
gsutil iam ch allUsers:objectViewer gs://detection-test-$(date +%s)

# Query audit logs
gcloud logging read 'protoPayload.methodName="storage.buckets.setIamPolicy"' --limit 3

# IMMEDIATE TEARDOWN:
gsutil rm -r gs://detection-test-$(date +%s)
```

## References
- [../detection-as-code-sigma-and-custodian.md](../detection-as-code-sigma-and-custodian.md)
- [../Storage-Data-Security/storage-primitives.md](../Storage-Data-Security/storage-primitives.md)
- [../Storage-Data-Security/bucket-blob-container-misconfig.md](../Storage-Data-Security/bucket-blob-container-misconfig.md)
- [AWS S3 Bucket Public Access Block](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Azure Blob Storage anonymous access](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-overview)
- [GCP Public access prevention](https://cloud.google.com/storage/docs/public-access-prevention)
