# 07 — Pre-Signed URLs & Tokenized Access

> **Level:** Intermediate
> **Prereqs:** [04-02 — Public Exposure & Block Public Access](./public-exposure-and-block-public.md), [02-IAM — Assume Role Chains](../IAM/assume-role-chains.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Collection, Exfiltration
> **Authorization scope:** Run only against your own storage accounts / a dedicated sandbox bucket.

## What & why

Pre-signed URLs (AWS), SAS tokens (Azure), and Signed URLs (GCP) grant time-limited, scoped access to storage objects without requiring the caller to have IAM credentials. They are the primary mechanism for secure object sharing and application-to-storage access. Misconfigurations — infinite TTLs, full-scope tokens, tokens in source code — turn them into long-lived backdoor keys to your storage.

## The OnPrem reality

Nginx `X-Accel-Redirect` with HMAC-signed cookies was the on-prem pattern for private file delivery. The application server signed a redirect URL that Nginx validated internally. The browser never saw the real file path. Expiration was session-based; if the session cookie leaked, the attacker had access until the session expired.

```nginx
# OnPrem: Nginx internal redirect with HMAC
location /secure-files/ {
    internal;
    alias /mnt/private/;
}
location /download/ {
    set $secret "shared-hmac-secret";
    secure_link $arg_md5,$arg_expires;
    secure_link_md5 "$secret$uri$arg_expires";
    if ($secure_link = "") { return 403; }
    rewrite ^ /secure-files/$uri;
}
```

## Core concepts

| Aspect | AWS Pre-signed URL | Azure SAS Token | GCP Signed URL (V4) | OnPrem Signed Cookie |
|---|---|---|---|---|
| Auth mechanism | SigV4 HMAC from IAM credentials | Account key / user delegation key | Service account HMAC key | Server-side HMAC |
| Max TTL | 7 days (IAM); 7 days (presigned POST) | Unlimited (account key SAS); 7 days (user delegation SAS) | 7 days | Session-based |
| Scope | Per-object, per-operation (GET/PUT) | Account / service / container / blob; read/write/delete/list | Per-object, per-method | Per-URI |
| Revocation | Delete IAM principal or rotate key | Rotate account key; revoke user delegation key; stored access policy | Delete service account key | Server-side session invalidation |
| IP restriction | Condition in bucket policy (not in URL) | `sip` parameter in SAS token | Not in URL; via VPC SC or bucket-level policy | Server-side |
| Storage in URL | SigV4 signature in query string | `sig=` parameter + `sktid=` (key ID) | `X-Goog-Signature` header | Cookie |

## AWS

**Service:** S3 Pre-signed URLs. **Console path:** N/A (CLI/SDK only).

```bash
# Generate a pre-signed GET URL (5-min TTL, the most restrictive)
aws s3 presign s3://example-security-lab-111111111111/test.txt \
  --expires-in 300

# Output: https://example-security-lab-111111111111.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...&X-Amz-Date=...&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=...

# Generate a pre-signed PUT URL (upload-only)
aws s3 presign s3://example-security-lab-111111111111/uploads/payload.bin \
  --expires-in 900

# Use the URL to upload
curl -X PUT --upload-file payload.bin "https://example-security-lab-111111111111.s3.amazonaws.com/uploads/payload.bin?X-Amz-Algorithm=..."
```

**Python SDK (scoped GET, 5 min):**
```python
import boto3
s3 = boto3.client('s3')
url = s3.generate_presigned_url(
    ClientMethod='get_object',
    Params={'Bucket': 'example-security-lab-111111111111', 'Key': 'test.txt'},
    ExpiresIn=300
)
print(url)
```

**Gotcha:** The pre-signed URL inherits the permissions of the principal that created it at the moment of use (not creation). If the creator's IAM role is revoked, the URL becomes invalid. However, there is no native API to list or revoke all outstanding pre-signed URLs — you cannot "recall" them individually. For revocation, you must either delete the IAM principal that signed them or (better) rotate the credentials.

## Azure

**Service:** Shared Access Signature (SAS). **Console path:** `Storage accounts → <account> → Shared access signature`.

```bash
# Generate a user delegation SAS (most secure — tied to Azure AD user)
# Step 1: Get user delegation key (max 7 days)
EXPIRY=$(date -u -v+5M +%Y-%m-%dT%H:%M:%SZ)
az storage blob generate-sas \
  --account-name securitylab111111111111 \
  --container-name test-container \
  --name test.txt \
  --permissions r \
  --expiry $EXPIRY \
  --auth-mode login \
  --as-user \
  --output tsv

# Generate a service SAS with IP restriction (account key based — use sparingly)
az storage blob generate-sas \
  --account-name securitylab111111111111 \
  --container-name test-container \
  --name test.txt \
  --permissions r \
  --expiry $EXPIRY \
  --ip 203.0.113.5 \
  --output tsv

# Revoke all SAS tokens: rotate storage account keys
az storage account keys renew \
  --account-name securitylab111111111111 \
  --resource-group rg-security-lab \
  --key primary
```

**Terraform (stored access policy for controlled SAS revocation):**
```hcl
resource "azurerm_storage_management_policy" "sas_revoke" {
  storage_account_id = azurerm_storage_account.lab.id
}
```

**Gotcha:** There are three SAS types — **account SAS** (broad, uses account key), **service SAS** (container/blob level, also account key), and **user delegation SAS** (Azure AD user, 7-day max TTL, the recommended type). Account SAS tokens can have unlimited TTL. Rotating the storage account key invalidates all SAS tokens that used it — this is the only bulk-revocation mechanism available.

## GCP

**Service:** Signed URLs (V4). **Console path:** N/A (CLI/SDK only).

```bash
# Generate a signed URL with 5-min TTL (requires service account HMAC key)
gsutil signurl -d 5m \
  -u gs://security-lab-111111111111/test.txt \
  ~/service-account-key.json

# Output: gs://security-lab-111111111111/test.txt?x-goog-signature=...&x-goog-algorithm=GOOG4-RSA-SHA256&...

# Generate from Python (V4 signing)
gcloud storage sign-url gs://security-lab-111111111111/test.txt \
  --duration=5m \
  --http-verb=GET
```

**Python SDK (V4 signed URL):**
```python
from google.cloud import storage
client = storage.Client()
bucket = client.bucket('security-lab-111111111111')
blob = bucket.blob('test.txt')
url = blob.generate_signed_url(
    version='v4',
    expiration=300,
    method='GET'
)
print(url)
```

**Gotcha:** GCP signed URLs require either a service account HMAC key or workload identity federation token. The URL expires at the `X-Goog-Expires` timestamp. To revoke outstanding signed URLs, delete the service account HMAC key that signed them — this invalidates all URLs signed with that key.

## OnPrem mapping

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Generate token | HMAC cookie from server secret | `aws s3 presign` | `az storage blob generate-sas` | `gsutil signurl` / `gcloud storage sign-url` |
| Restrict to GET | `secure_link_md5` with method check | `--expires-in` (inherently single-method) | `--permissions r` | `--http-verb=GET` |
| Max TTL | Session cookie expiry | 7 days | 7 days (user delegation); unlimited (account SAS) | 7 days |
| Revoke all | Rotate HMAC secret | Delete IAM principal / rotate access key | Rotate storage account key | Delete service account HMAC key |
| IP restrict | Nginx `allow/deny` directives | Bucket policy condition (not URL) | `--ip` in SAS | Bucket-level / VPC SC |

## 🔴 Red Team view

Long-lived SAS tokens and pre-signed URLs in source code are a common information disclosure vector:

```bash
# Attacker discovers a SAS token in a public GitHub repo or .env file
# Token format example (fabricated — no valid key material):
export AZURE_SAS="sv=2022-11-02&ss=b&srt=sco&sp=rwdlac&se=2027-01-01T00:00:00Z&st=2024-01-01T00:00:00Z&spr=https&sig=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D"

# Attacker uses the token to enumerate containers
az storage blob list \
  --container-name default \
  --account-name exampletarget \
  --sas-token "$AZURE_SAS" \
  --output table

# Download everything
az storage blob download-batch \
  --destination /tmp/loot \
  --source default \
  --account-name exampletarget \
  --sas-token "$AZURE_SAS"
```

**AWS equivalent:**
```bash
# Leaked pre-signed URL found in log file
export PRESIGNED="https://example-bucket.s3.amazonaws.com/backup.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA...EXAMPLE...&X-Amz-Date=20260622T000000Z&X-Amz-Expires=604800&X-Amz-Signature=abc123..."

# Attacker downloads the object
curl -o backup.tar.gz "$PRESIGNED"
# Works as long as the URL has not expired and the signing principal still exists
```

**Discovery via gitleaks-style scanning:**
```bash
# Scan a repo for SAS tokens and pre-signed URLs
gitleaks detect --source /path/to/repo --verbose

# Manual grep patterns
grep -rPn '(sv=|sig=|X-Amz-Signature=|x-goog-signature=)' /path/to/repo/
```

**Artifacts left:** Storage access logs record the download from the attacker's IP using the SAS/signed URL. The token itself contains metadata (creation time, expiry, permissions) visible in plain text even without the signature — defenders can analyze leaked tokens to assess their risk profile. CloudTrail/Activity Log records the `GeneratePresignedUrl` / `GenerateSAS` API calls.

## 🔵 Blue Team view

**Detection — identify SAS tokens older than 24 hours:**
```bash
# Scan all storage accounts for long-lived SAS via Storage Explorer API
# (conceptual pattern — actual implementation requires enumerating SAS via 
#  Storage Analytics logs which record SAS usage, not creation)

# Azure: audit Storage Analytics logs for SAS token usage patterns
az storage logging update \
  --account-name securitylab111111111111 \
  --log rwd \
  --retention 30
```

**Query for SAS usage in Azure Log Analytics:**
```kusto
StorageBlobLogs
| where AuthenticationType == "SAS"
| extend SasExpiry = extract("se=([^&]+)", 1, Uri)
| extend SasTokenAge = datetime_diff('hour', now(), todatetime(SasExpiry))
| where SasTokenAge > 24
| project TimeGenerated, AccountName, ObjectKey, CallerIpAddress, SasTokenAge
```

**Preventive controls:**
```bash
# AWS SCP: deny generating pre-signed URLs longer than 1 hour
# (This is difficult to enforce natively — instead audit via CloudTrail)

# Azure Policy: audit SAS tokens with expiry > 24h
# (Can be enforced through a custom policy that monitors Storage Analytics)

# GCP: delete/replace HMAC keys periodically to force re-issuance
gcloud storage service-agent --project=example-project

# Universal: short-lived CI/CD token pattern
# Generate a new pre-signed URL at runtime rather than storing a long-lived token
```

**Response — SAS token compromise:**
1. Rotate the storage account key immediately (`az storage account keys renew`).
2. Identify the scope of the leaked token from the `sp=` (permissions) and `sr=` (resource) parameters visible in plain text.
3. Audit Storage Analytics logs for the leaked token's signature (the `sig=` value) to determine what was accessed.
4. Revoke any user delegation keys if the SAS was user-delegation type.
5. Scan all internal repositories for similar token patterns.

```bash
# Bulk SAS revocation via key rotation (Azure)
az storage account keys renew \
  --account-name securitylab111111111111 \
  --resource-group rg-security-lab \
  --key primary && \
az storage account keys renew \
  --account-name securitylab111111111111 \
  --resource-group rg-security-lab \
  --key secondary
```

```bash
# AWS: bulk pre-signed URL invalidation — rotate signing principal's access key
aws iam update-access-key \
  --user-name presigned-url-signer \
  --access-key-id AKIA0000000000000000 \
  --status Inactive
```

```bash
# GCP: delete HMAC key to invalidate all signed URLs from that key
gcloud storage hmac delete ACCESS_KEY_ID --project=example-project
```

## Hands-on lab

1. Upload a test object to a private bucket/container.
2. Generate a pre-signed URL / SAS token / signed URL with a 5-minute TTL and GET-only permission.
3. Use `curl` or `azcopy` to download the object via the URL — verify it works.
4. Wait 5 minutes and retry — verify the URL has expired (403/401).
5. Generate a SAS token with `--permissions rwdl` (full access) — note the scope difference.
6. Rotate the storage account key (Azure) or delete the signing principal's access key (AWS/GCP) — verify all outstanding URLs become invalid.
7. **Teardown:** Delete test objects and keys.

**Expected output:** Object downloads successfully within TTL window. Expired URL returns error. Key rotation invalidates pre-existing URLs immediately.

## Detection rules & checklists

```yaml
# Sigma rule — Long-lived SAS token or pre-signed URL generated
title: Long-Lived Storage Delegation Token Created
status: experimental
logsource:
  product: cloud
  service: object_storage
detection:
  selection_aws:
    eventName: PutObject
    requestParameters.X-Amz-Expires|gt: 3600
  selection_azure:
    # Detected via Storage Analytics — SAS with long expiry
    SasExpiryDelta|gt: 86400
  selection_gcp:
    # V4 signed URL with >1h expiry in audit log
    methodName: storage.objects.get
    protoPayload.request.expiration|gt: 3600
  condition: selection_aws or selection_azure or selection_gcp
level: medium
```

```bash
# CI/CD prevention: never store SAS/pre-signed URLs in env vars
# Instead generate at runtime with minimal TTL:

# AWS (in CI pipeline — 5 min for deployment artifact upload)
aws s3 presign s3://artifacts-bucket/release-v1.0.tar.gz \
  --expires-in 300

# Azure (user delegation SAS, 10 min)
EXPIRY=$(date -u -v+10M +%Y-%m-%dT%H:%M:%SZ)
az storage blob generate-sas \
  --account-name artifactsacct \
  --container-name releases \
  --name release-v1.0.tar.gz \
  --permissions r \
  --expiry $EXPIRY \
  --auth-mode login \
  --as-user

# GCP (service account, 5 min)
gcloud storage sign-url gs://artifacts-bucket/release-v1.0.tar.gz \
  --duration=5m --http-verb=GET
```

## References

- [AWS S3 pre-signed URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)
- [Azure SAS best practices](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview)
- [GCP Signed URLs (V4)](https://cloud.google.com/storage/docs/access-control/signed-urls)
- [MITRE ATT&CK T1552 — Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- Cross-ref: [04-02 — Public Exposure & Block Public Access](./public-exposure-and-block-public.md) for the permanent-access equivalent
