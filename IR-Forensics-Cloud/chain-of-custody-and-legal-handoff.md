# 08 — Chain of Custody and Legal Handoff

> **Level:** Intermediate
> **Prereqs:** [11-04](./snapshot-and-memory-acquisition.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** N/A (legal/regulatory process)
> **Authorization scope:** Run only in your own sandbox account; all example account IDs are placeholders (`111111111111`, `00000000-0000-0000-0000-000000000000`).

## What & why

Chain of custody (CoC) is the documented, unbroken record of evidence handling from acquisition through storage to handoff. If CoC is broken, the evidence is inadmissible in legal proceedings, void for insurance claims, and useless for HR termination challenges. In cloud, CoC must be cryptographic — hash manifest, object lock, and access audit — not a paper form.

## The OnPrem reality

On-prem CoC relied on a physical form signed at each transfer: "I, Analyst Name, received Seagate HDD S/N XYZ from Analyst Name2 on 2026-06-22 at 14:00." The disk was stored in a tamper-evident bag in a locked evidence locker. Write-blocking was hardware-enforced. The paper trail was the evidence log.

## Core concepts

### Cloud CoC components

| Component | Purpose | How |
|-----------|---------|-----|
| Hash manifest | Prove evidence was not tampered with after acquisition | `sha256sum` on every artifact, stored in a separate, locked location |
| Timestamp | Prove *when* evidence was captured | Cloud service timestamp (CloudTrail event time, snapshot completion time) |
| Immutable storage | Prevent evidence deletion or modification | Object Lock (AWS), Immutable blob (Azure), Retention policy (GCP) |
| Access audit | Prove *who* accessed the evidence and when | CloudTrail on evidence bucket, read-access alerts |
| Cryptographic signing | Prove the capturing entity's identity | Sigstore / Rekor entry, or KMS-sign the hash manifest |
| Cross-region replication | Survive single-region disaster or attacker deletion attempt | S3 CRR, GCS dual-region, Azure GRS |

### Evidence envelope (manifest structure)

```json
{
  "incident_id": "inc-1719000000",
  "capture_date": "2026-06-22T14:30:00Z",
  "capture_principal": "arn:aws:sts::111111111111:assumed-role/IR-Responder/session-xyz",
  "evidence": [
    {
      "type": "ebs_snapshot",
      "id": "snap-0a1b2c3d4e5f67890",
      "volume_id": "vol-0a1b2c3d4e5f67890",
      "size_gb": 100,
      "hash": "sha256:abc123def456...",
      "capture_method": "aws ec2 create-snapshots",
      "creation_time": "2026-06-22T14:30:05Z"
    },
    {
      "type": "memory_dump",
      "file": "memory.lime",
      "hash": "sha256:789xyz012abc...",
      "hash_method": "sha256sum on instance before upload",
      "capture_method": "AVML v0.11.0 via SSM Run Command"
    },
    {
      "type": "cloudtrail_export",
      "file": "cloudtrail_inc-1719000000.json.gz",
      "hash": "sha256:def456ghi789...",
      "time_range": "2026-06-22T08:30:00Z - 2026-06-22T16:30:00Z"
    }
  ],
  "custody_transfers": [],
  "storage": {
    "bucket": "forensic-bucket-111111111111",
    "region": "us-east-1",
    "lock_config": "Object Lock GOVERNANCE, retain until 2026-06-22",
    "replication": "cross-region to us-west-2"
  }
}
```

## AWS

**Evidence preservation with Object Lock:**

```bash
#!/bin/bash
INCIDENT_ID="inc-1719000000"
EVIDENCE_BUCKET="forensic-bucket-111111111111"
MANIFEST_FILE="manifest-${INCIDENT_ID}.json"

echo "=== 1. Create hash manifest for all evidence ==="
cat > $MANIFEST_FILE <<EOF
{
  "incident_id": "$INCIDENT_ID",
  "capture_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "capture_principal": "$(aws sts get-caller-identity --query Arn --output text)",
  "evidence": []
}
EOF

add_to_manifest() {
    local file=$1 type=$2 description=$3
    local hash=$(sha256sum "$file" | cut -d' ' -f1)
    jq ".evidence += [{\"type\":\"$type\",\"file\":\"$(basename $file)\",\"hash\":\"sha256:$hash\",\"description\":\"$description\"}]" \
        $MANIFEST_FILE > tmp.json && mv tmp.json $MANIFEST_FILE
}

echo "=== 2. Upload evidence with hash ==="
for SNAP_ID in snap-0a1b2c3d4e5f67890 snap-0b2c3d4e5f6a7b8c90; do
    aws s3api put-object --bucket $EVIDENCE_BUCKET \
        --key "${INCIDENT_ID}/snapshot-ids.txt" \
        --body <(echo $SNAP_ID)
done

echo "=== 3. Upload and lock manifest ==="
MANIFEST_HASH=$(sha256sum $MANIFEST_FILE | cut -d' ' -f1)
aws s3 cp $MANIFEST_FILE "s3://${EVIDENCE_BUCKET}/${INCIDENT_ID}/${MANIFEST_FILE}"

aws s3api put-object-retention \
    --bucket $EVIDENCE_BUCKET \
    --key "${INCIDENT_ID}/${MANIFEST_FILE}" \
    --retention '{"Mode":"GOVERNANCE","RetainUntilDate":"2033-06-22T00:00:00Z"}'

echo "=== 4. Enable bucket access logging ==="
aws s3api put-bucket-logging \
    --bucket $EVIDENCE_BUCKET \
    --bucket-logging-status '{
        "LoggingEnabled": {
            "TargetBucket": "forensic-access-logs",
            "TargetPrefix": "access/"
        }
    }'

echo "=== 5. Create Rekor transparency log entry ==="
rekor-cli upload --artifact $MANIFEST_FILE --signature sig.pem --public-key key.pub
echo "Rekor UUID: $(rekor-cli upload ... | jq -r '.UUID')"

echo "=== 6. KMS-sign the manifest ==="
aws kms sign \
    --key-id alias/forensic-signing-key \
    --message-type RAW \
    --message fileb://$MANIFEST_FILE \
    --signing-algorithm RSASSA_PKCS1_V1_5_SHA_256 \
    --output text --query Signature > manifest-${INCIDENT_ID}.sig
```

**Gotcha:** S3 Object Lock cannot be enabled on an existing bucket; it must be configured at bucket creation. If your evidence bucket lacks Object Lock, create a new one before storing evidence.

## Azure

```bash
#!/bin/bash
INCIDENT_ID="inc-1719000000"
STORAGE_ACCT="forensicsacct"
CONTAINER="evidence"

echo "=== 1. Enable immutable blob storage ==="
az storage container immutability-policy create \
    --account-name $STORAGE_ACCT \
    --container-name $CONTAINER \
    --period 2555

echo "=== 2. Set legal hold on evidence container ==="
az storage container legal-hold set \
    --account-name $STORAGE_ACCT \
    --container-name $CONTAINER \
    --tag "incident-${INCIDENT_ID}"

echo "=== 3. Upload evidence with hash ==="
for FILE in memory.lime cloudtrail.json.gz; do
    HASH=$(sha256sum $FILE | cut -d' ' -f1)
    az storage blob upload \
        --account-name $STORAGE_ACCT \
        --container-name $CONTAINER \
        --name "${INCIDENT_ID}/${FILE}" \
        --file $FILE \
        --metadata hash="sha256:${HASH}" incident-id="$INCIDENT_ID"
done

echo "=== 4. Upload hash manifest ==="
az storage blob upload \
    --account-name $STORAGE_ACCT \
    --container-name $CONTAINER \
    --name "${INCIDENT_ID}/manifest.json" \
    --file manifest-${INCIDENT_ID}.json \
    --metadata incident-id="$INCIDENT_ID"

echo "=== 5. Enable blob access logging ==="
az storage logging update \
    --account-name $STORAGE_ACCT \
    --log rwdl \
    --retention 365
```

**Gotcha:** Azure immutable blob storage currently offers two modes: `Locked` (permanent, cannot be removed) and `Unlocked` (can be removed with appropriate permissions). For evidence, prefer `Locked` after validation. (as of June 2026, Azure legal hold is tag-based and persists until all tags are removed; time-bound policies can be unlocked or locked.)

## GCP

```bash
#!/bin/bash
INCIDENT_ID="inc-1719000000"
BUCKET="gs://forensic-bucket"

echo "=== 1. Set bucket retention policy ==="
gsutil retention set 7y $BUCKET

echo "=== 2. Upload evidence with hash metadata ==="
for FILE in memory.lime cloudtrail.json.gz; do
    HASH=$(sha256sum $FILE | cut -d' ' -f1)
    gsutil -h "x-goog-meta-hash:sha256:${HASH}" \
        -h "x-goog-meta-incident-id:${INCIDENT_ID}" \
        cp $FILE "${BUCKET}/${INCIDENT_ID}/${FILE}"
done

echo "=== 3. Upload manifest ==="
gsutil cp manifest-${INCIDENT_ID}.json "${BUCKET}/${INCIDENT_ID}/manifest.json"

echo "=== 4. Enable bucket access logging ==="
gsutil logging set on -b gs://forensic-access-logs $BUCKET

echo "=== 5. Lock bucket (prevents retention policy removal) ==="
gsutil retention lock $BUCKET
```

**Gotcha:** GCP bucket lock is permanent once applied — the retention policy cannot be shortened or removed. (as of June 2026, GCP does not have a direct "legal hold" API separate from retention policy; indefinite holds must be approximated via long retention durations on the retention policy.)

## OnPrem mapping (recap table)

| CoC concern | OnPrem | AWS | Azure | GCP |
|-------------|--------|-----|-------|-----|
| Tamper evidence | Write-blocker + tamper-evident bag | S3 Object Lock | Immutable blob + legal hold | Bucket retention lock |
| Hash verification | `sha256sum` at imaging station | `sha256sum` in-guest + upload | `sha256sum` + blob metadata | `sha256sum` + custom metadata |
| Access log | Physical sign-out sheet | S3 access logs / CloudTrail on bucket | Storage analytics logs | Cloud Audit Logs on bucket |
| Timestamp | NTP-synced log | AWS service timestamp (snapshot completionTime) | Azure service timestamp | GCP service timestamp |
| Cross-region survival | Offsite tape backup | S3 Cross-Region Replication | GRS / RA-GRS replication | Dual-region / multi-region bucket |
| Signing authority | Custodian signature on form | KMS Sign + Sigstore/Rekor | Azure Key Vault Sign | Cloud KMS Sign |
| Admissibility challenge | Paper form verified by two witnesses | Hash chain + Rekor transparency log + Object Lock > paper form | Hash + immutable blob + legal hold timeline | Hash + bucket retention + audit log timeline |
| Deletion protection | Physical secure storage | MFA Delete on versioned bucket | Soft delete + legal hold | Retention lock (permanent) |

## 🔴 Red Team view

Defenders must maintain CoC integrity, but attackers have an interest in breaking it:

**Evidence inadmissibility from broken CoC.** If a defender snapshots a compromised instance but fails to record the hash manifest, an attacker's legal team can challenge the evidence in court. The argument: "You produced a snapshot ID, but you cannot prove the data inside the snapshot is the same as what existed on the instance at the time of the alleged incident. The chain is broken."

**Snapshot contamination.** If the defender took the snapshot *after* the attacker detected IR activity (e.g., after `TerminateInstances` was attempted and failed, leaving the filesystem in an inconsistent state), the snapshot might contain attacker code that was mid-execution — useful forensically, but the defender must document the sequence precisely in the CoC to avoid the appearance of spoliation.

**Access-log tampering.** If the evidence bucket's access logs are stored in the same bucket (a common misconfiguration), the attacker with access to the evidence bucket can delete or modify the access logs → no proof of who touched the evidence → broken CoC.

**Artifacts:**
- Evidence bucket access log showing `DeleteObject` on `.json.gz` files.
- Evidence bucket access log stored in *same* bucket — circular dependency, spoliation risk.
- Missing `s3:PutObjectRetention` call in CloudTrail — Object Lock was never applied.

## 🔵 Blue Team view

### Evidence storage access separation

```bash
# Evidence bucket: NO delete permissions for any IAM principal except break-glass role
aws s3api put-bucket-policy --bucket forensic-bucket-111111111111 \
    --policy '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Principal": "*",
            "Action": ["s3:DeleteObject", "s3:DeleteBucket"],
            "Resource": ["arn:aws:s3:::forensic-bucket-111111111111", "arn:aws:s3:::forensic-bucket-111111111111/*"],
            "Condition": {
                "StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::111111111111:role/BreakGlassForensicDelete"}
            }
        }]
    }'

# Access logs: MUST go to a SEPARATE bucket
aws s3api put-bucket-logging \
    --bucket forensic-bucket-111111111111 \
    --bucket-logging-status '{
        "LoggingEnabled": {
            "TargetBucket": "forensic-access-logs-222222222222",
            "TargetPrefix": "evidence-access/"
        }
    }'
```

### Evidence access alert

```python
# Lambda triggered by S3 event on evidence bucket
def lambda_handler(event, context):
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        obj_key = record['s3']['object']['key']
        principal = record['userIdentity']['principalId']
        action = record['eventName']

        if action == 'GetObject':
            alert(f"🔵 EVIDENCE ACCESS: {principal} read {obj_key} from {bucket}")
        if action == 'DeleteObject':
            alert(f"❌ EVIDENCE DELETION ATTEMPT: {principal} tried to delete {obj_key} from {bucket}")
```

### CoC checklist (pre-handoff)

```
[ ] All evidence artifacts have SHA-256 hashes recorded in manifest
[ ] Manifest is signed via KMS / Sigstore and uploaded to evidence bucket
[ ] Object Lock / Immutable blob / Retention policy enabled on all evidence
[ ] Evidence bucket access logs going to a SEPARATE bucket
[ ] Cross-region replication configured and verified
[ ] MFA Delete enabled on evidence bucket (AWS)
[ ] Soft delete enabled on evidence container (Azure)
[ ] Rekor / transparency log entry created for manifest
[ ] Custody transfer form completed (PDF with digital signatures)
[ ] Legal hold applied (Azure) / retention lock applied (GCP)
[ ] Evidence bucket IAM: no delete permissions except break-glass
```

### Evidence handoff script

```bash
#!/bin/bash
INCIDENT_ID=$1
FROM_BUCKET="forensic-bucket-111111111111"
TO_BUCKET="legal-receiving-bucket-999999999999"
TO_ROLE="arn:aws:iam::999999999999:role/LegalEvidenceReceiver"

echo "=== 1. Verify manifest hash ==="
aws s3 cp "s3://${FROM_BUCKET}/${INCIDENT_ID}/manifest.json" /tmp/manifest.json
MANIFEST_HASH=$(sha256sum /tmp/manifest.json | cut -d' ' -f1)
jq -r '.evidence[] | "\(.file) \(.hash)"' /tmp/manifest.json | while read FILE HASH; do
    aws s3 cp "s3://${FROM_BUCKET}/${INCIDENT_ID}/${FILE}" /tmp/verify_${FILE}
    LOCAL_HASH="sha256:$(sha256sum /tmp/verify_${FILE} | cut -d' ' -f1)"
    if [ "$LOCAL_HASH" != "$HASH" ]; then
        echo "❌ HASH MISMATCH: $FILE — chain broken"
        exit 1
    fi
    echo "✅ $FILE hash verified"
done

echo "=== 2. Cross-account copy to legal team ==="
aws s3 cp "s3://${FROM_BUCKET}/${INCIDENT_ID}/" "s3://${TO_BUCKET}/${INCIDENT_ID}/" --recursive

echo "=== 3. Log custody transfer ==="
jq ".custody_transfers += [{
    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"from\": \"security-team@example.com\",
    \"to\": \"legal-team@example.com\",
    \"transfer_method\": \"cross-account S3 copy, role: $TO_ROLE\",
    \"manifest_hash_at_transfer\": \"sha256:$MANIFEST_HASH\"
}]" /tmp/manifest.json > /tmp/manifest_transferred.json

aws s3 cp /tmp/manifest_transferred.json "s3://${FROM_BUCKET}/${INCIDENT_ID}/manifest.json"
aws s3 cp /tmp/manifest_transferred.json "s3://${TO_BUCKET}/${INCIDENT_ID}/manifest.json"
```

## Hands-on lab

1. Create evidence bucket with Object Lock enabled (or immutable blob for Azure, retention policy for GCP).
2. Generate three artifacts: a JSON file, a binary blob, and a text file.
3. Compute SHA-256 hashes for each and build a manifest.
4. Upload all to evidence bucket with retention lock.
5. Attempt to delete an object — verify it fails due to lock.
6. Simulate custody transfer: copy to a second bucket, verify hashes match manifest.
7. Teardown: wait for retention period or use break-glass to delete.

## Detection rules & checklists

```yaml
title: Evidence Bucket Object Accessed
logsource:
  product: aws
  service: s3_access_logs
detection:
  selection:
    bucket: forensic-bucket-111111111111
    operation: REST.GET.OBJECT
  filter:
    requester: arn:aws:sts::111111111111:assumed-role/IR-Responder/*
  condition: selection and not filter
  severity: high
  description: "Non-IR-responder accessed evidence — possible chain contamination"
```

- [ ] Evidence bucket created with Object Lock at bucket creation time.
- [ ] Access logs directed to separate bucket — never self-logging.
- [ ] MFA Delete enabled on evidence bucket.
- [ ] Read-access alerts configured on evidence bucket.
- [ ] Quarterly chain-of-custody audit: pick a closed incident, verify all hashes match manifest.

## References

- [AWS S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [Azure immutable blob storage](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview)
- [GCP bucket retention policies](https://cloud.google.com/storage/docs/using-bucket-lock)
- [Sigstore / Rekor transparency log](https://docs.sigstore.dev/)
- [NIST SP 800-86 — Guide to Integrating Forensic Techniques](https://csrc.nist.gov/publications/detail/sp/800-86/final)
