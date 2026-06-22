# 09 — Public Resources by Policy

> **Level:** Intermediate
> **Prereqs:** [Identity Primitives per Cloud](identity-primitives-per-cloud.md) (Identity Primitives)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Collection, Discovery
> **Authorization scope:** Identity attacks only in your own sandbox accounts / sanctioned targets.

## What & why

Many cloud resources — S3 buckets, storage containers, BigQuery datasets — default to or can be accidentally made publicly accessible. A single public ACL on a data resource can expose sensitive data, and attackers actively scan for these. Detection must be programmatic and continuous.

## The OnPrem reality

On-prem equivalents were open network shares, misconfigured NFS exports (`/etc/exports` with `*(rw)`), FTP servers with anonymous access, and databases listening on `0.0.0.0:3306` with no firewall. Discovery was manual — nmap scans, Shodan queries, and internal pentests. Cloud makes it worse: APIs make accidental exposure one misclick away, and the blast radius is global.

## Cross-cloud public-by-default risk

| Resource | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Object storage | S3 (block public access not default on old buckets) | Blob Storage (public access off by default, per-container toggle) | Cloud Storage (not public by default; uniform bucket-level access) | NFS export / FTP anonymous |
| Database / data warehouse | RDS public accessibility toggle | SQL DB public endpoint toggle | BigQuery dataset `allAuthenticatedUsers` | MySQL bind-address 0.0.0.0 |
| Container registry | ECR (private by default; policy can add `*`) | ACR (admin-enabled optional; anonymous pull) | Artifact Registry (private by default; IAM-controlled) | Docker registry self-hosted |
| Compute | Security Group (default: deny all inbound) | NSG (default: deny all inbound) | VPC Firewall (default: deny all inbound) | iptables / hardware firewall |
| API endpoint | API Gateway (private by default) | API Management (private-only setting) | Cloud Endpoints (IAM-controlled by default) | Self-hosted API + reverse proxy |
| CloudFormation defaults | `PublicAccessBlockConfiguration` = null (no block) | ARM template: property-driven | Deployment Manager: property-driven | N/A |

### What "public" means per cloud

- **AWS S3:** A bucket policy with `Principal: "*"` + `Action: "s3:GetObject"` = public read. Also: ACL `AllUsers` group with `READ` permission.
- **Azure Blob:** Container access level set to `Blob` (anonymous read) or `Container` (anonymous read + list).
- **GCP Cloud Storage:** IAM binding with `allUsers` (anyone on internet) or `allAuthenticatedUsers` (any Google account) as member.

## AWS

**Scan for public S3 buckets:**

```bash
# Using AWS CLI
aws s3api list-buckets --query "Buckets[].Name" --output text | \
while read bucket; do
  result=$(aws s3api get-public-access-block --bucket "$bucket" --query "PublicAccessBlockConfiguration" 2>/dev/null)
  if [ $? -ne 0 ] || echo "$result" | jq -e '.RestrictPublicBuckets == false or .BlockPublicAcls == false' > /dev/null 2>&1; then
    echo "PUBLIC RISK: $bucket - BlockPublicAccess is incomplete"
  fi
  # Check bucket policy for "Principal": "*"
  policy=$(aws s3api get-bucket-policy --bucket "$bucket" 2>/dev/null)
  if echo "$policy" | jq -e '.Statement[] | select(.Principal == "*" or .Principal.AWS == "*")' > /dev/null 2>&1; then
    echo "PUBLIC POLICY: $bucket"
  fi
done
```

**Block public access at organization level (SCP):**

```json
{
  "Effect": "Deny",
  "Action": "s3:PutBucketPublicAccessBlock",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "s3:PublicAccessBlockConfiguration.RestrictPublicBuckets": "true"
    }
  }
}
```

This SCP denies any attempt to set `RestrictPublicBuckets` to `false` on any bucket in the account.

**AWS Config rule — public S3 detection:**

```json
{
  "ConfigRuleName": "s3-bucket-public-read-prohibited",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}
```

```bash
aws configservice put-config-rule --config-rule file://config-rule.json
```

## Azure

**Scan for public blob containers:**

```bash
# Enumerate storage accounts and check for public containers
az storage account list --query "[].{name:name, rg:resourceGroup}" -o tsv | \
while read name rg; do
  containers=$(az storage container list --account-name "$name" --auth-mode login 2>/dev/null)
  echo "$containers" | jq -r '.[] | select(.properties.publicAccess != null and .properties.publicAccess != "None") | "\(.name) publicAccess=\(.properties.publicAccess)"'
done
```

**Azure Policy — deny public blob containers:**

```json
{
  "properties": {
    "displayName": "Deny public blob containers",
    "policyRule": {
      "if": {
        "field": "type",
        "equals": "Microsoft.Storage/storageAccounts/blobServices/containers"
      },
      "then": {
        "effect": "deny"
      }
    }
  }
}
```

Assign at management group scope for org-wide enforcement.

## GCP

**Scan for public Cloud Storage buckets:**

```bash
gsutil ls -p project-id-111111 2>/dev/null | while read bucket; do
  iam=$(gsutil iam get "$bucket" 2>/dev/null)
  if echo "$iam" | grep -qE "allUsers|allAuthenticatedUsers"; then
    echo "PUBLIC: $bucket"
    echo "$iam" | grep -E "allUsers|allAuthenticatedUsers"
  fi
done
```

**Scan for public BigQuery datasets:**

```bash
bq ls --project_id project-id-111111 --format json | jq -r '.[].datasetReference.datasetId' | \
while read dataset; do
  access=$(bq show --format json "project-id-111111:$dataset" | jq '.access[] | select(.specialGroup)')
  if [ -n "$access" ]; then
    echo "PUBLIC ACCESS: $dataset -> $access"
  fi
done
```

**Org Policy — restrict public bucket IAM:**

```yaml
constraint: constraints/storage.publicAccessPrevention
booleanPolicy:
  enforced: true
```

```bash
gcloud org-policies set-policy \
  --organization 000000000000 \
  --policy-file prevent-public-buckets.yaml
```

**GCP Security Command Center — find public resources:**

```bash
gcloud scc findings list organizations/000000000000 \
  --filter "category=\"PUBLIC_BUCKET_ACL\"" --format json
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Public storage | Anonymous FTP, open CIFS share | S3 bucket policy with `Principal: "*"` | Blob container `publicAccess: Blob` | `allUsers` IAM binding on GCS |
| Detection scan | nmap NFS mount / smbclient list | `s3api get-public-access-block` | `az storage container list` | `gsutil iam get` / SCC findings |
| Preventive guard | Network segmentation + ACLs | SCP `s3:PutPublicAccessBlock` enforce | Azure Policy deny public containers | Org Policy `storage.publicAccessPrevention` |
| Default posture | Manual — no cloud-level control | Pre-2018 buckets: no block; new: block by default | Private by default (per-container toggle) | Private by default (uniform bucket-level access) |
| SIEM integration | Syslog aggregation | AWS Config → SNS → SIEM | Azure Policy compliance → Log Analytics | SCC findings → Pub/Sub → SIEM |

## 🔴 Red Team view

**Exploiting a "just one" public resource to pivot.** A high-privilege role requires accessing "just one" public bucket to perform a legitimate task. The attacker adds a minimal public ACL, gains temporary credentials from that bucket's metadata, then uses those credentials to enumerate the entire organization.

**Contained step-by-step (placeholder accounts):**

```bash
# 1. Attacker finds a role that can create S3 buckets but is otherwise restricted.
#    The trust policy allows bucket creation for a specific purpose.
aws s3 mb s3://audit-logs-backup-111111111111 --region us-east-1

# 2. Attacker sets a public bucket policy — "just for testing"
aws s3api put-bucket-policy --bucket audit-logs-backup-111111111111 --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": ["arn:aws:s3:::audit-logs-backup-111111111111","arn:aws:s3:::audit-logs-backup-111111111111/*"]
  }]
}'

# 3. A Lambda function in the same account reads this bucket, processing its contents.
#    The Lambda has an execution role with broad read across the org.
#    Attacker uploads a file to the public bucket. The Lambda reads it, and the attacker's
#    uploaded content triggers the Lambda to perform actions on the attacker's behalf.
#    This is a form of cross-service confused deputy.

# 4. Attacker places a crafted file in hidden region:
aws s3 cp payload.json s3://audit-logs-backup-111111111111/ --region ap-southeast-1
```

**Discovery of hidden/forgotten resources across regions:**

```bash
# Attacker enumerates all regions for public resources
for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  aws s3api list-buckets --query "Buckets[?starts_with(Name, 'prod-')].Name" --output text | \
  while read bucket; do
    aws s3api get-bucket-location --bucket "$bucket" --query "LocationConstraint" 2>/dev/null
    # Check if bucket is in unexpected region (not monitored)
  done
done
```

**Artifacts:**
- CloudTrail `PutBucketPolicy` event with `principal: "*"`.
- Bucket ACL modification events (`PutBucketAcl`).
- Access from anomalous IPs via the public policy (S3 Server Access Logs).
- `GetBucketLocation` enumeration calls from a single session across all regions (discovery pattern).

**Defensive pairing:** The SCP `Deny` on `s3:PutBucketPublicAccessBlock` blocks the initial public exposure. Even if the bucket is created, organization-level blocks prevent any public policy attachment.

## 🔵 Blue Team view

**Preventive guards — SCPs for public resource prevention:**

```json
{
  "Sid": "DenyPublicS3Policy",
  "Effect": "Deny",
  "Action": ["s3:PutBucketPolicy", "s3:PutBucketAcl"],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]
    }
  }
}
```

**Azure — Deny Assignment for public blob containers:**

```bash
az policy assignment create \
  --name deny-public-blob \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/...store-public-network-access" \
  --scope /providers/Microsoft.Management/managementGroups/root-mg
```

**GCP — Org Policy for public prevention:**

```bash
gcloud org-policies set-policy \
  --organization 000000000000 \
  --policy-file prevent-public.yaml
```

```yaml
# prevent-public.yaml
# Prevents allUsers/allAuthenticatedUsers IAM bindings
constraint: constraints/iam.allowedPolicyMemberDomains
listPolicy:
  allowedValues:
    - "example.com"
    - "is:gserviceaccount.com"
```

**Detection — continuous monitoring script:**

```bash
#!/bin/bash
# run every hour via cron / scheduled Lambda

# AWS
aws s3api list-buckets --query "Buckets[].Name" --output text | while read b; do
  policy=$(aws s3api get-bucket-policy-status --bucket "$b" --query "PolicyStatus.IsPublic" 2>/dev/null)
  [ "$policy" == "true" ] && echo "ALERT: Public S3 bucket: $b"
done

# Azure
az storage account list --query "[].{name:name,rg:resourceGroup}" -o tsv | while read name rg; do
  az storage container list --account-name "$name" --auth-mode login --query "[?properties.publicAccess != null && properties.publicAccess != 'None'].name" -o tsv | \
  while read container; do
    echo "ALERT: Public blob container: $name/$container"
  done
done

# GCP
gsutil ls -p project-id-111111 | while read bucket; do
  gsutil iam get "$bucket" 2>/dev/null | grep -qE "allUsers|allAuthenticatedUsers" && \
    echo "ALERT: Public GCS bucket: $bucket"
done
```

**Detection — SIEM queries:**

```
-- AWS CloudTrail: detect public bucket policy creation
SELECT eventTime, userIdentity.arn, requestParameters.bucketName
FROM cloudtrail_111111111111
WHERE eventName IN ('PutBucketPolicy', 'PutBucketAcl')
  AND (
    requestParameters.policy LIKE '%"Principal":"*"%'
    OR requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI LIKE '%AllUsers%'
  )

-- Azure Activity Log: detect container public access change
AzureActivity
| where OperationNameValue contains "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE"
| where Properties contains "publicAccess"
```

**Detection — AWS Config aggregator (organization-wide):**

```bash
aws configservice put-configuration-aggregator \
  --configuration-aggregator-name OrgAggregator \
  --organization-aggregation-source "RoleArn=arn:aws:iam::111111111111:role/ConfigAggregatorRole,AwsRegions=[us-east-1,eu-west-1,ap-southeast-1],AllAwsRegions=false"

# Query across all accounts for non-compliant S3 buckets
aws configservice select-aggregate-resource-config \
  --configuration-aggregator-name OrgAggregator \
  --expression "SELECT resourceId, awsRegion WHERE resourceType = 'AWS::S3::Bucket' AND configuration.publicAccessBlockConfiguration.restrictPublicBuckets = false"
```

**Response checklist:**
- [ ] Immediately apply `s3:PutPublicAccessBlock` with all four blocks enabled.
- [ ] Remove `Principal: "*"` from bucket policy (via CLI, not console).
- [ ] Enable S3 Server Access Logs if not already on.
- [ ] Review CloudTrail for what was read from the bucket during the exposure window.
- [ ] Notify data owners and security team.

## Hands-on lab

**Create a public bucket, detect it, then lock it down:**

```bash
# 1. Create a bucket (intentionally public)
BUCKET="lab-public-test-$(date +%s)"
aws s3 mb s3://$BUCKET
aws s3api put-public-access-block --bucket $BUCKET --public-access-block-configuration \
  BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false

# 2. Make it public
aws s3api put-bucket-policy --bucket $BUCKET --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::'"$BUCKET"'/*"
  }]
}'

# 3. Detect it
aws s3api get-bucket-policy-status --bucket $BUCKET --query "PolicyStatus.IsPublic"
# Expected: true

# 4. Lock it down — apply full block public access
aws s3api put-public-access-block --bucket $BUCKET --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# 5. Verify — should still show as public policy exists but now blocked
aws s3api get-bucket-policy-status --bucket $BUCKET
```

**Expected output:** After step 3, `IsPublic` is `true`. After step 4, the bucket's BlockPublicAccess overrides the policy — the bucket is effectively private.

**Teardown:**
```bash
aws s3api delete-bucket-policy --bucket $BUCKET
aws s3 rb s3://$BUCKET --force
```

## Detection rules & checklists

**Cloud Custodian — auto-remediate public buckets:**

```yaml
policies:
  - name: remediate-public-s3
    resource: aws.s3
    filters:
      - type: bucket-ssl
    actions:
      - type: set-public-access-block
        block_public_acls: true
        ignore_public_acls: true
        block_public_policy: true
        restrict_public_buckets: true
```

**GCP Org Policy — enforce public access prevention:**
```bash
gcloud org-policies enable-enforce \
  --organization 000000000000 \
  constraints/storage.publicAccessPrevention
```

**Checklist:**
- [ ] SCP denies `s3:PutBucketPolicy` with `Principal: "*"` at org level.
- [ ] Azure Policy denies public blob container creation.
- [ ] GCP Org Policy enforces `storage.publicAccessPrevention`.
- [ ] Continuous scanning (hourly) detects any drift from private posture.
- [ ] All new buckets/containers inherit org-level blocks by default.

## References
- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Azure Blob anonymous access](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure)
- [GCP public access prevention](https://cloud.google.com/storage/docs/using-public-access-prevention)
- [MITRE ATT&CK — Data from Cloud Storage (T1530)](https://attack.mitre.org/techniques/T1530/)
