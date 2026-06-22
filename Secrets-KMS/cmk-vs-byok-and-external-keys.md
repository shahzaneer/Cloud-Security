# 09 — CMK vs. BYOK & External Keys

> **Level:** Advanced
> **Prereqs:** [05-01 — KMS, HSM & Vaults](./kms-hsm-and-vaults.md), [05-02 — Key Policies & Grants](./key-policies-and-grants.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Impact, Defense Evasion
> **Authorization scope:** Run only in your own sandbox accounts; BYOK import examples use placeholder key material.

## What & why

BYOK (Bring Your Own Key) / External Key Management (EKM) allows you to generate key material in your own HSM and import it into the cloud provider's KMS — or keep it entirely in your HSM and proxy cloud encryption operations to it. The tradeoff: compliance sovereignty (keys never leave your boundary) vs. availability risk (your HSM going down = your cloud data is locked). Only regulated industries (finance, healthcare, government) typically need BYOK/EKM; for everyone else, cloud-native CMK with rotation is sufficient and safer.

## The OnPrem reality

BYOK devices (NetApp, IBM, Thales) used RSA PKCS#11 wrapping. A data center team generated an RSA 2048 key pair in an HSM, exported the public wrapping key, and sent it to the cloud provider. The cloud provider wrapped a symmetric data key with that public key and returned the wrapped key. The import process was:
1. Generate key in on-prem HSM
2. Export public key → send to cloud vendor
3. Vendor wraps key → returns encrypted blob
4. Import encrypted blob with `rsa_unwrap` in on-prem HSM
5. Key material now exists in both places (HSM + cloud)

```bash
# OnPrem: generating BYOK wrapping key (PKCS#11 / SoftHSM2)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --keypairgen \
  --key-type RSA:2048 --label byok-wrap-key --token "lab-token" --pin 1234

pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --read-object \
  --type pubkey --label byok-wrap-key --token "lab-token" --pin 1234 \
  --output-file /tmp/byok-public-key.der

# Send /tmp/byok-public-key.der to cloud vendor
# Vendor wraps key material with this public key
# Import wrapped key into on-prem HSM
```

## Cross-cloud BYOK/EKM comparison

| Feature | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| BYOK name | Imported key material (KMS) | BYOK (Key Vault / Managed HSM) | Imported key (Cloud KMS) | N/A (you own the HSM) |
| External key name | AWS KMS External Key Store (XKS) | Azure Managed HSM with BYOK | Cloud EKM (External Key Manager) | FIPS 140-2 Level 3 HSM |
| Key generation | Customer HSM → wrap → import to KMS | Customer HSM → exchange key → Azure Key Vault | Customer HSM → import key material | On-prem HSM directly |
| Where key material lives | Imported: in KMS (cloud); XKS: in your HSM | BYOK: in Azure; Managed HSM: dedicated HSM | Imported: in Cloud KMS; EKM: in external HSM | Your datacenter |
| Crypto ops location | KMS (imported) / Your HSM (XKS) | Azure (BYOK) / MHSM (dedicated) | Cloud KMS (imported) / External HSM (EKM) | Your HSM |
| Failure mode | KMS unavailable (imported) / Your HSM down = data locked (XKS) | Key Vault unavailable / MHSM unavailable | Cloud KMS unavailable / External HSM down (EKM) | Your HSM down = all encryption fails |
| Latency | <10ms (imported) / 10–50ms + round-trip (XKS) | <10ms (BYOK) / <10ms (MHSM dedicated) | <10ms (imported) / variable + network latency (EKM) | Variable (local) |
| Compliance cert | FIPS 140-2 Level 2 (imported) / Level 3 (XKS) | Level 2 (BYOK) / Level 3 (MHSM) | Level 1 (imported) / Level 3 (EKM) | Level 3 (your hardware) |

## AWS

**Option 1: Import key material (BYOK — key lives in AWS KMS after import).**

```bash
# 1. Create a CMK with no key material (EXTERNAL origin)
aws kms create-key \
  --description "BYOK imported key" \
  --origin EXTERNAL \
  --region us-east-1

# Save KeyId from output

# 2. Download the wrapping (public) key and import token
aws kms get-parameters-for-import \
  --key-id "00000000-0000-0000-0000-000000000000" \
  --wrapping-algorithm RSAES_OAEP_SHA_256 \
  --wrapping-key-spec RSA_2048 \
  --region us-east-1

# Output contains:
#   ImportToken (base64) — one-time token valid 24h
#   PublicKey (base64) — wrapped in DER format
#   ParametersValidTo — expiry timestamp

# 3. On your HSM/openssl, generate a 256-bit symmetric key
openssl rand -out /tmp/plaintext-key-material.bin 32

# 4. Wrap the symmetric key with the AWS public wrapping key
openssl pkeyutl -encrypt \
  -in /tmp/plaintext-key-material.bin \
  -out /tmp/wrapped-key-material.bin \
  -inkey /tmp/public-key.pem \
  -keyform PEM \
  -pubin \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256

# 5. Import the wrapped key material into KMS
aws kms import-key-material \
  --key-id "00000000-0000-0000-0000-000000000000" \
  --encrypted-key-material fileb:///tmp/wrapped-key-material.bin \
  --import-token fileb:///tmp/import-token.bin \
  --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE \
  --region us-east-1

# Key state changes from PENDING_IMPORT → ENABLED
# ⚠️ Manual rotation required — no auto-rotation for imported keys
# To rotate: re-import new key material
```

**Option 2: External Key Store (XKS) — key material stays in your HSM.**

```
> (as of June 2026, XKS requires specific HSM vendor partnerships and KMIP connectivity.
>   Supported HSM vendors include Thales, Entrust, and Fortanix.
>   XKS has per-region proxy endpoints and adds ~10-50ms latency per operation.
>   Check current AWS KMS documentation for the latest supported vendor list.)

Architecture:
  AWS Service (S3, EBS) ──▶ AWS KMS ──▶ XKS Proxy (your VPC endpoint)
                                              │
                                        Your HSM (Thales/Entrust/Fortanix)
                                              │
                                    Key material never leaves HSM
```

```bash
# Conceptual XKS setup (abbreviated — verify details against current docs)
aws kms create-custom-key-store \
  --custom-key-store-name "on-prem-hsm" \
  --xks-proxy-connectivity VPC_ENDPOINT_SERVICE \
  --xks-proxy-uri-endpoint "https://xks-proxy.internal.example.com" \
  --xks-proxy-uri-path "/kms/xks/v1" \
  --xks-proxy-authentication-credential "AccessKeyId=placeholder,SecretAccessKey=placeholder"

aws kms connect-custom-key-store \
  --custom-key-store-id "cks-00000000000000000"
```

## Azure

**BYOK into Key Vault / Managed HSM:**

```bash
# Azure BYOK process (high-level — verify current tooling)
# > (as of June 2026, Azure Key Vault BYOK supports RSA 2048-bit key exchange keys
# >   and HSM vendors including Thales, nCipher/Entrust, and Utimaco. Use the
# >   `azure-byok-tool` or Azure CLI `az keyvault key import --byok-file`.
# >   Check current Azure Key Vault documentation for supported wrapping algorithms.)

# 1. Generate a key exchange key (KEK) in on-prem HSM
#    (RSA 2048, HSM-protected)

# 2. Upload the KEK to Azure Key Vault (used only for wrapping)
az keyvault key import \
  --vault-name lab-vault-003 \
  --name byok-exchange-key \
  --byok-file /path/to/byok-exchange-key.byok

# 3. Azure wraps the target key material with your KEK
#    Returns a wrapped blob you can transfer to your vault

# 4. Import the wrapped key (key material now in Azure)
az keyvault key import \
  --vault-name lab-vault-003 \
  --name production-key \
  --byok-file /path/to/wrapped-key.byok

# Managed HSM (single-tenant dedicated HSM):
az keyvault create \
  --name lab-hsm-001 \
  --resource-group security-lab-hsm \
  --location eastus \
  --hsm-name lab-hsm-001 \
  --administrators "00000000-0000-0000-0000-000000000000"
# BYOK into Managed HSM follows similar wrapping flow
```

**Azure MHSM BYOK security domain:**

```
> (as of June 2026, Azure Managed HSM security domain recovery uses Shamir's Secret
>   Sharing across ≥3 RSA keys (quorum-based). If all security domain keys are lost,
>   the HSM data is irrevocably unrecoverable. The security domain must be downloaded
>   during initial HSM provisioning.)
```

## GCP

**Cloud KMS Imported Key + Cloud EKM:**

```bash
# Option 1: Import key material (BYOK)
gcloud kms keys create imported-app-key \
  --keyring app-keyring \
  --location global \
  --purpose encryption \
  --protection-level software \
  --skip-initial-version-creation

# Get wrapping key
gcloud kms keys versions create \
  --key imported-app-key \
  --keyring app-keyring \
  --location global \
  --wrapping-key-file /tmp/wrapping-key.pub

# Wrap key material with wrapping key (on HSM/openssl)
# Import wrapped key
gcloud kms keys versions import \
  --key imported-app-key \
  --keyring app-keyring \
  --location global \
  --import-job import-job-1 \
  --rsa-aes-wrapped-key-file /tmp/wrapped-key.bin
```

```bash
# Option 2: Cloud EKM — key material in external HSM
# > (as of June 2026, GCP Cloud EKM supported partners include Fortanix, Thales, and Entrust.
# >   Check GCP Cloud EKM documentation for the current full partner list.)

gcloud kms keyrings create ekm-keyring \
  --location global

gcloud kms keys create ekm-app-key \
  --keyring ekm-keyring \
  --location global \
  --purpose encryption \
  --protection-level external \
  --external-key-uri "https://ekm.example.com/v1/key/placeholder-key-id"

# All encrypt/decrypt ops route to external HSM via EKM
# ⚠️ EKM HSM must be reachable (network) — if unreachable, encrypt/decrypt FAILS
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Key generation | On-prem HSM (PKCS#11) | `create-key --origin EXTERNAL` | On-prem HSM → BYOK tool | `keys create --skip-initial-version-creation` |
| Wrapping algorithm | RSA OAEP SHA-256 (PKCS#11) | `RSAES_OAEP_SHA_256` | RSA OAEP (tool-specific) | RSA OAEP via import job |
| Import token expiry | N/A | 24 hours | Key-dependent | Import job timeout |
| Key rotation | Manual only | Manual only (imported) | Manual only (BYOK) | Manual only (imported) |
| Auto-rotation | No (BYOK) | No (imported/EXTERNAL) | No (BYOK) | No (imported) |
| EKM/External proxy | N/A (local) | XKS via VPC endpoint | N/A (MHSM is dedicated Azure HSM) | Cloud EKM |
| Latency risk | 0ms (local) | XKS: +10-50ms | BYOK: +0ms (imported); MHSM: <10ms | EKM: +network round-trip |
| Disaster recovery | HSM HA pair | XKS: multi-region proxy or lockout | MHSM: managed by Azure (HA built-in) | EKM: HSM HA required on-prem |

## 🔴 Red Team view

**EKM outage = data availability outage. The attacker who DoS's the on-prem HSM has effectively DoS'd your cloud data.**

When you use XKS or Cloud EKM, every `kms:Decrypt` call requires a live round-trip to your on-prem HSM. If the HSM becomes unreachable — due to a network partition, power failure, or deliberate DoS attack — your encrypted data in the cloud becomes unreadable. The attacker doesn't need to steal keys; they just need to break the HSM connectivity.

```
Attack scenario:
  1. Attacker identifies that organization uses XKS/EKM via CloudTrail patterns
     (kms:Decrypt with xksProxyUri in error logs or high-latency decrypts)
  2. Attacker DDoS's the public IP of the XKS proxy or compromises the VPN tunnel
  3. HSM unreachable from cloud → kms:Decrypt times out
  4. No S3 SSE-KMS reads, no EBS volume attachments, no RDS decryption
  5. Application errors cascade — data unavailable

Worst case: Permanent lockout if:
  - BYOK key material was imported WITH expiration
  - Key expires before connectivity restored
  - No local backup copy of imported key material exists
```

**Defensive pair — multi-AZ proxy + break-glass copy:**

```bash
# AWS XKS: deploy proxy endpoints in ≥3 AZs
# Each proxy has independent network path to HSM

# Break-glass: maintain a SEPARATE CMK (non-XKS) for emergency failover
# Encrypt critical data with BOTH keys (dual encryption envelope)
aws kms encrypt --key-id alias/xks-key --plaintext "$DATA" > /tmp/xks-encrypted.bin
aws kms encrypt --key-id alias/break-glass-cmk --plaintext "$DATA" > /tmp/fallback-encrypted.bin

# If XKS HSM is unreachable, decrypt via fallback CMK
aws kms decrypt --ciphertext-blob fileb:///tmp/fallback-encrypted.bin
```

**Artifacts of reconnaissance:**
- CloudTrail: repeated `kms:Decrypt` failures with `XksProxyUnreachable` or `XksProxyTimeout` errors
- VPC Flow Logs: SYN floods to XKS proxy endpoints
- Latency metrics: `kms:Decrypt` p99 spike from <20ms to >5000ms

## 🔵 Blue Team view

**Pre-deployment BYOK checklist:**

- [ ] Document the EXACT key generation procedure (not "someone in Infosec has the HSM pin")
- [ ] Verify key material export can be reproduced (test a throwaway key import first)
- [ ] Set key material expiration to a date before audit cycle — forces rotation cadence
- [ ] Deploy XKS/EKM proxy across ≥3 Availability Zones (or GCP zones)
- [ ] Maintain a non-EKM fallback CMK for critical data (dual-encryption envelope)
- [ ] Test break-glass failover quarterly — simulate HSM outage, verify fallback decrypt works
- [ ] Alert on `XksProxyUnreachable` / `EkmConnectionFailed` CloudTrail events
- [ ] Monitor `kms:Decrypt` latency — alert on p99 > 100ms for EKM keys

**CloudTrail alert on XKS failure:**

```
fields @timestamp, errorMessage, sourceIPAddress
| filter eventName = "Decrypt"
| filter errorMessage like /XksProxy/
| stats count(*) by bin(5m)
| filter count > 0
```

**Multi-region fallback architecture:**

```hcl
# Terraform: dual-encryption with regional fallback
resource "aws_kms_key" "xks" {
  description = "Primary XKS-backed key"
  custom_key_store_id = aws_kms_custom_key_store.on_prem.id
}

resource "aws_kms_key" "fallback" {
  description = "Fallback AWS-native CMK for DR"
  enable_key_rotation = true
}

# S3 bucket with dual encryption
# Objects encrypted with xks key — decrypt falls back to cmk if xks unreachable
resource "aws_s3_bucket_server_side_encryption_configuration" "dual" {
  bucket = aws_s3_bucket.critical_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.xks.arn
    }
  }
}
```

**Break-glass drill script:**

```bash
#!/bin/bash
# Quarterly: simulate HSM outage, test fallback decrypt

# 1. Encrypt test object with XKS key
echo -n "drill-$(date -Iseconds)" > /tmp/drill.txt
aws s3 cp /tmp/drill.txt s3://critical-data-bucket/drill/test.txt \
  --sse aws:kms --sse-kms-key-id alias/xks-key

# 2. Download encrypted object (no KMS decrypt needed for download)
aws s3 cp s3://critical-data-bucket/drill/test.txt /tmp/encrypted-test.bin

# 3. Attempt decrypt with XKS (should succeed in normal state)
aws kms decrypt --ciphertext-blob fileb:///tmp/encrypted-test.bin \
  --key-id alias/xks-key --query Plaintext --output text | base64 -d
# Expected: drill-2026-...

# 4. Simulate XKS outage (disconnect proxy — admin action)
# ... network disconnect ...

# 5. Attempt decrypt with XKS — SHOULD FAIL
aws kms decrypt --ciphertext-blob fileb:///tmp/encrypted-test.bin \
  --key-id alias/xks-key 2>&1 | grep XksProxyUnreachable
echo "XKS FAILOVER TEST: PASS (XKS unreachable as expected)"

# 6. Decrypt with fallback CMK (if dual-encrypted)
# Fallback should work without XKS connectivity
echo "BREAK-GLASS DRILL: PASS"
```

## Hands-on lab

```bash
# 1. Create an external-origin CMK (no key material yet)
aws kms create-key \
  --description "BYOK lab key" \
  --origin EXTERNAL \
  --region us-east-1

KEY_ID=$(aws kms list-keys --region us-east-1 --query \
  "Keys[?contains(KeyArn, 'alias') == \`false\`] | sort_by(@, &CreationDate)[-1].KeyId" --output text)

# 2. Get import parameters
aws kms get-parameters-for-import \
  --key-id "$KEY_ID" \
  --wrapping-algorithm RSAES_OAEP_SHA_256 \
  --wrapping-key-spec RSA_2048 \
  --region us-east-1 > /tmp/import-params.json

# 3. Simulate key generation and wrapping (local openssl)
jq -r .PublicKey /tmp/import-params.json | base64 -d > /tmp/wrapping-key.der
openssl rsa -pubin -inform DER -in /tmp/wrapping-key.der -outform PEM -out /tmp/wrapping-key.pem

dd if=/dev/urandom of=/tmp/key-material.bin bs=32 count=1

openssl pkeyutl -encrypt \
  -in /tmp/key-material.bin \
  -out /tmp/wrapped-key.bin \
  -inkey /tmp/wrapping-key.pem \
  -pubin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256

# 4. Import
jq -r .ImportToken /tmp/import-params.json | base64 -d > /tmp/import-token.bin
aws kms import-key-material \
  --key-id "$KEY_ID" \
  --encrypted-key-material fileb:///tmp/wrapped-key.bin \
  --import-token fileb:///tmp/import-token.bin \
  --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE \
  --region us-east-1

# 5. Test encrypt/decrypt with imported key
echo -n "byok-test-data" | base64 > /tmp/plain.txt
aws kms encrypt --key-id "$KEY_ID" --plaintext fileb:///tmp/plain.txt --region us-east-1
echo "BYOK IMPORT: SUCCESS"

# 6. Delete imported key material (simulate material expiration)
aws kms delete-imported-key-material --key-id "$KEY_ID" --region us-east-1
# Key state changes to PENDING_IMPORT — any data encrypted with this key
# is now PERMANENTLY undecryptable unless you re-import the SAME key material

# Teardown
aws kms schedule-key-deletion --key-id "$KEY_ID" --pending-window-in-days 7 --region us-east-1
```

## Detection rules & checklists

```yaml
# Sigma-style: External Key Store connection failure
title: KMS External Key Store Unreachable
logsource:
  service: cloudtrail
  events:
    eventSource: kms.amazonaws.com
    eventName: Decrypt
detection:
  selection:
    errorMessage|contains: "XksProxy"
  condition: selection
  severity: critical
```

```bash
# CLI audit: find keys with imported (external) origin
aws kms list-keys --region us-east-1 --query "Keys[].KeyId" --output text | while read key; do
  ORIGIN=$(aws kms describe-key --key-id "$key" --region us-east-1 \
    --query "KeyMetadata.Origin" --output text)
  if [ "$ORIGIN" = "EXTERNAL" ]; then
    EXPIRATION=$(aws kms describe-key --key-id "$key" --region us-east-1 \
      --query "KeyMetadata.ExpirationModel" --output text 2>/dev/null)
    echo "EXTERNAL KEY: $key (expiration: ${EXPIRATION:-NONE})"
  fi
done

# Azure: check for BYOK keys
az keyvault key list --vault-name lab-vault-003 \
  --query "[?key.kty=='RSA-HSM'].kid"

# GCP: find EKM-backed keys
gcloud kms keys list --location global --keyring ekm-keyring \
  --filter "protectionLevel=EXTERNAL"
```

## References

- [AWS KMS Imported Key Material](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html)
- [AWS KMS External Key Store (XKS)](https://docs.aws.amazon.com/kms/latest/developerguide/xks.html)
- [Azure Key Vault BYOK](https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification)
- [Azure Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/)
- [GCP Cloud EKM](https://cloud.google.com/kms/docs/ekm)
- [GCP Importing keys into Cloud KMS](https://cloud.google.com/kms/docs/importing-keys)
- [FIPS 140-2 Validation](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
- Cross-link: [04-03 — Encryption at Rest & CMK](../Storage-Data-Security/encryption-at-rest-and-cmek.md)
