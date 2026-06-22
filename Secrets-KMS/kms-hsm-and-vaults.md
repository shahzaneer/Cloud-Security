# 01 — KMS, HSM & Vaults

> **Level:** Intermediate
> **Prereqs:** [00-04 — Cryptography Essentials](../Fundamentals/cryptography-essentials.md), [00-05 — Shared Responsibility Model](../Fundamentals/shared-responsibility-model.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Defense Evasion
> **Authorization scope:** Run only in your own sandbox accounts; use placeholder key IDs and ciphertext values throughout.

## What & why

A cryptographic key hierarchy establishes the trust boundary that holds your root-of-trust. KMS (Key Management Service) = cloud-managed multi-tenant key encryption. HSM (Hardware Security Module) = single-tenant dedicated hardware that protects keys in a FIPS 140-2 Level 3 boundary. Vault = a customer-controlled generic secret store that may or may not use KMS/HSM underneath. Cloud engineers must understand this tiering to select the right compliance level and identify when a secret is actually being decrypted a layer above where you think it is.

## The OnPrem reality

A Thales Luna HSM sat in a locked cage in the datacenter. Application servers connected via PKCS#11 over a dedicated VLAN. HashiCorp Vault ran as a cluster of 3–5 nodes, unsealed via Shamir key shards held by separate officers. Encryption operations required physical access to unseal after a restart. The key material never left the HSM boundary — applications called `CKM_AES_KEY_GEN` and received a handle, not the actual key bytes.

```bash
# OnPrem Vault transit encrypt with PKCS#11 backend
vault secrets enable -path=transit transit
vault write -f transit/keys/app-key type=aes256-gcm96
vault write transit/encrypt/app-key plaintext=$(echo -n "secret-data" | base64)

# OnPrem PKCS#11 key generation (softhsm2 for lab simulation)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --keygen \
  --key-type AES:32 --label "app-key" --token "lab-token" --pin 1234
```

## Core concepts

| Tier | Trust boundary | Performance | Compliance | Key material leaves? |
|---|---|---|---|---|
| Cloud KMS (multi-tenant) | Cloud provider's HSM fleet, logically isolated | High (shared HSM capacity) | FIPS 140-2 Level 2 | No — keys held in HSM backend |
| Cloud HSM (single-tenant) | Dedicated HSM, physically isolated | Medium (fixed capacity per HSM) | FIPS 140-2 Level 3 | No |
| External HSM (BYOK/EKM) | Your datacenter | Low (network latency) | Full chain of custody | No — keys in your cage |
| Vault (software) | Unseal keys + process memory | High (in-memory) | Varies | Yes — decrypted in memory |

### Key hierarchy visualization

```
Root Key (HSM — never leaves)
 └─→ Key Encryption Key (KEK) — wraps data keys
      └─→ Data Encryption Key (DEK) — encrypts actual data
           └─→ Ciphertext (envelope encryption)
```

KMS uses **envelope encryption**: a DEK is generated per encryption operation, the DEK encrypts the data, then the KEK (in KMS/HSM) encrypts the DEK. The encrypted DEK is stored alongside the ciphertext. Decrypting the ciphertext requires calling KMS to unwrap the DEK first.

## AWS

**Services:** AWS KMS (`kms:Encrypt`, `kms:Decrypt`), AWS CloudHSM (dedicated HSM cluster), AWS Secrets Manager (secret store atop KMS).

**Console path:** `KMS → Customer managed keys → Create key`

```bash
# Create a symmetric CMK in KMS
aws kms create-key \
  --description "App encryption key" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --region us-east-1

# Encrypt with encryption context (tied to the operation context)
aws kms encrypt \
  --key-id alias/app-key \
  --plaintext "$(echo -n 'payroll-data' | base64)" \
  --encryption-context "app=payroll,environment=prod" \
  --region us-east-1
# Output: CiphertextBlob (base64) — store alongside your data

# Decrypt — must supply the SAME encryption context
aws kms decrypt \
  --ciphertext-blob fileb://encrypted.bin \
  --encryption-context "app=payroll,environment=prod" \
  --region us-east-1

# List key versions
aws kms list-key-rotations --key-id alias/app-key --region us-east-1

# Enable automatic key rotation (yearly, new backing material)
aws kms enable-key-rotation --key-id alias/app-key --region us-east-1
```

**Encryption Context** is AWS KMS's defense against confused deputy and cross-service replay: it cryptographically binds key usage to a specific operation context. The context is logged in CloudTrail and is not a secret — it's a plaintext map that must match on both encrypt and decrypt sides.

```bash
# Without the correct context, decrypt fails — caller gets AccessDeniedException
aws kms decrypt \
  --ciphertext-blob fileb://encrypted.bin \
  --encryption-context "app=wrong-app" \
  --region us-east-1
# An error occurred (AccessDeniedException)
```

## Azure

**Services:** Azure Key Vault (Standard/Premium), Azure Managed HSM (single-tenant), Key Vault secrets/certificates/keys.

**Console path:** `Key Vaults → <vault> → Keys → Generate/Import`

```bash
# Create a Key Vault (Standard tier)
az keyvault create \
  --name lab-vault-001 \
  --resource-group security-lab \
  --location eastus \
  --sku standard

# Create a key with RSA 2048
az keyvault key create \
  --vault-name lab-vault-001 \
  --name app-key \
  --protection software \
  --kty RSA \
  --size 2048

# Encrypt using the key (returns base64 ciphertext)
az keyvault key encrypt \
  --vault-name lab-vault-001 \
  --name app-key \
  --algorithm RSA-OAEP-256 \
  --value "$(echo -n 'payroll-data' | base64)"

# Decrypt
az keyvault key decrypt \
  --vault-name lab-vault-001 \
  --name app-key \
  --algorithm RSA-OAEP-256 \
  --value "<ciphertext-base64>"

# List key versions
az keyvault key list-versions \
  --vault-name lab-vault-001 \
  --name app-key
```

**Azure Managed HSM** (Premium/HSM tier) provides single-tenant HSM. Create at the subscription level:

```bash
# Managed HSM creation (single-tenant — must use dedicated resource group per HSM)
az keyvault create \
  --name lab-hsm-001 \
  --resource-group security-lab-hsm \
  --location eastus \
  --hsm-name lab-hsm-001 \
  --administrators "00000000-0000-0000-0000-000000000000"
# > (as of June 2026, Azure Managed HSM supports RSA, EC, and AES key types with feature parity
# > to standard Key Vault for most operations; check the latest Azure Managed HSM documentation
# > for any remaining gaps)
```

Azure Key Vault uses **operation context** via the `--data-encryption-context` flag on wrap/unwrap operations (preview as of current):

```bash
az keyvault key encrypt \
  --vault-name lab-vault-001 \
  --name app-key \
  --algorithm RSA-OAEP-256 \
  --value "$(echo -n 'data' | base64)" \
  --data-encryption-context "app=payroll"
```

## GCP

**Services:** Cloud KMS (multi-tenant), Cloud HSM (FIPS 140-2 Level 3, single-tenant per key ring), Secret Manager (secret store atop KMS).

**Console path:** `Security → Key Management → Create key ring`

```bash
# Create a key ring (container for keys) and a key
gcloud kms keyrings create app-keyring --location global
gcloud kms keys create app-key \
  --keyring app-keyring \
  --location global \
  --purpose encryption \
  --protection-level software

# Encrypt (envelope encryption — KMS encrypts the DEK)
echo -n "payroll-data" > /tmp/plaintext.txt
gcloud kms encrypt \
  --key app-key \
  --keyring app-keyring \
  --location global \
  --plaintext-file /tmp/plaintext.txt \
  --ciphertext-file /tmp/ciphertext.txt

# Decrypt
gcloud kms decrypt \
  --key app-key \
  --keyring app-keyring \
  --location global \
  --ciphertext-file /tmp/ciphertext.txt \
  --plaintext-file /tmp/decrypted.txt

# List key versions
gcloud kms keys versions list \
  --key app-key \
  --keyring app-keyring \
  --location global

# Cloud HSM — change protection level at key creation
gcloud kms keys create app-key-hsm \
  --keyring app-keyring \
  --location global \
  --purpose encryption \
  --protection-level hsm
# > (as of June 2026, Cloud HSM key auto-rotation is supported; rotation period and
# > behavior are configured per key version. Check GCP KMS documentation for
# > current auto-rotation settings and limitations.)
```

GCP KMS supports **additional authenticated data (AAD)** — equivalent to AWS EncryptionContext:

```bash
gcloud kms encrypt \
  --key app-key --keyring app-keyring --location global \
  --plaintext-file /tmp/plaintext.txt \
  --additional-authenticated-data "app=payroll" \
  --ciphertext-file /tmp/ciphertext.txt
```

## OnPrem

**Tools:** HashiCorp Vault (transit engine), SoftHSM2 (lab HSM simulator), PKCS#11.

```bash
# Vault: enable transit engine
vault secrets enable transit
vault write -f transit/keys/app-key type=aes256-gcm96

# Encrypt (Vault manages DEK/KEK internally)
vault write transit/encrypt/app-key \
  plaintext=$(echo -n "payroll-data" | base64) \
  context=$(echo -n "app=payroll" | base64)

# Decrypt
vault write transit/decrypt/app-key \
  ciphertext="vault:v1:..." \
  context=$(echo -n "app=payroll" | base64)

# List key versions
vault read transit/keys/app-key

# SoftHSM2 PKCS#11 encrypt (lab simulation)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --encrypt --mechanism AES-CBC-PAD \
  --id 0001 --token "lab-token" --pin 1234 \
  --input-file /tmp/plaintext.txt --output-file /tmp/ciphertext.bin
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Multi-tenant KMS | HashiCorp Vault transit | AWS KMS | Key Vault (Standard) | Cloud KMS (software) |
| Single-tenant HSM | Thales Luna / nShield | AWS CloudHSM | Managed HSM | Cloud HSM |
| Secret store | Vault KV-V2 | Secrets Manager | Key Vault secrets | Secret Manager |
| Crypto interface | PKCS#11 / KMIP | KMIP (CloudHSM) | REST API | REST API / gRPC |
| Context binding | Vault transit `context` | `EncryptionContext` | `data-encryption-context` | `additional-authenticated-data` |
| Key rotation | `vault write transit/keys/rotate` | `enable-key-rotation` | Auto-rotate policy | `versions create` schedule |
| FIPS 140-2 Level | Hardware-dependent | Level 2 (KMS) / 3 (CloudHSM) | Level 2 (Standard) / 3 (MHSM) | Level 1 (software) / 3 (Cloud HSM) |

## 🔴 Red Team view

**Steal creds with `kms:Decrypt` on an over-permissive key.**

An attacker who gains access to a role with `kms:Decrypt` on a widely-permissive KMS key (key policy allows `Principal: "*"`) can grab ciphertext from S3 and decrypt it. CloudTrail will show the decrypt call — but if the key is also used by legitimate app traffic, the attacker's call blends into the noise.

### Contained example (AWS sandbox only)

```bash
# Phase 1: Recon — grab ciphertext from a known S3 path
aws s3 cp s3://example-security-lab-111111111111/backups/db-creds.enc /tmp/db-creds.enc

# Phase 2: Decrypt using a role that has kms:Decrypt (compromised Lambda role)
aws kms decrypt \
  --ciphertext-blob fileb:///tmp/db-creds.enc \
  --key-id alias/over-permissive-key \
  --encryption-context "app=legacy-app" \
  --region us-east-1
# Outputs plaintext DB creds

# Phase 3: Exfil — use those creds to access RDS
mysql -h example-rds.111111111111.us-east-1.rds.amazonaws.com -u admin -p"$LEAKED_PASS"
```

**Artifacts left:**
- CloudTrail: `kms:Decrypt` event with `sourceIPAddress` from Lambda ENI (not a normal human IP)
- S3 access log: `GetObject` on `db-creds.enc`
- CloudTrail spike: KMS decrypt calls from a principal that normally does only a handful/hour — suddenly 50/minute

### Defensive-pairing

```bash
# Key policy condition: only allow kms:Decrypt from S3's service principal
aws kms put-key-policy --key-id alias/over-permissive-key \
  --policy-name default \
  --policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"AWS":"arn:aws:iam::111111111111:root"},
      "Action":"kms:Decrypt",
      "Resource":"*",
      "Condition":{
        "StringEquals":{"kms:ViaService":"s3.us-east-1.amazonaws.com"}
      }
    }]
  }'
```

## 🔵 Blue Team view

**Detection signals:**
1. CloudTrail `kms:Decrypt` events from unusual principals (Lambda roles doing bulk decrypts)
2. `kms:Decrypt` volume spike — a key used 10x/day suddenly hits 500x/minute
3. `kms:Decrypt` from a previously unseen `sourceIPAddress` or VPC endpoint
4. `PutKeyPolicy` or `DeleteKeyPolicy` events modifying key trust

**Sample CloudWatch Logs Insights query:**

```
fields @timestamp, userIdentity.arn, sourceIPAddress, encryptionContext
| filter eventName = "Decrypt" and eventSource = "kms.amazonaws.com"
| stats count(*) as decrypt_count by userIdentity.arn, bin(5m)
| filter decrypt_count > 50
| sort decrypt_count desc
```

**Preventive controls:**

```bash
# SCP: Deny wildcard principals in KMS key policies
aws organizations create-policy \
  --name deny-kms-wildcard-principal \
  --type SERVICE_CONTROL_POLICY \
  --description "Deny KMS key policies allowing Principal:*" \
  --content '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Deny",
      "Action":["kms:PutKeyPolicy","kms:CreateKey"],
      "Resource":"*",
      "Condition":{
        "StringLike":{"kms:KeyPolicyPrincipal":"*"}
      }
    }]
  }'

# Per-key grant via IAM condition — pin decrypt to specific service
# Key policy: kms:ViaService condition ensures only authorized services call decrypt
```

**Response steps:**
1. Isolate the compromised principal: attach `DenyAll` IAM policy
2. Disable the key: `aws kms disable-key --key-id alias/over-permissive-key`
3. Rotate all secrets encrypted with that key
4. Audit the key's CloudTrail for 90-day decrypt history — identify all accessed ciphertexts

## Hands-on lab

**Goal:** Create a KMS key, encrypt/decrypt with context, test context mismatch, disable the key.

```bash
# 1. Create key
aws kms create-key --description "Lab rotation test" --region us-east-1
# Save KeyId from output as $KEY_ID

aws kms create-alias --alias-name alias/lab-test-key \
  --target-key-id "$KEY_ID" --region us-east-1

# 2. Encrypt with context
echo -n "lab-secret-$(date +%s)" | base64 > /tmp/plain.txt
aws kms encrypt --key-id alias/lab-test-key \
  --plaintext fileb:///tmp/plain.txt \
  --encryption-context "stage=test,tag=lab-01" > /tmp/enc.json

# 3. Decrypt with correct context
CIPHER=$(jq -r .CiphertextBlob /tmp/enc.json)
echo "$CIPHER" | base64 -d > /tmp/cipher.bin
aws kms decrypt --ciphertext-blob fileb:///tmp/cipher.bin \
  --encryption-context "stage=test,tag=lab-01"
# Expected: plaintext recovered

# 4. Test context mismatch — should fail
aws kms decrypt --ciphertext-blob fileb:///tmp/cipher.bin \
  --encryption-context "stage=wrong" 2>&1
# Expected: AccessDeniedException

# 5. Disable and test
aws kms disable-key --key-id alias/lab-test-key
aws kms decrypt --ciphertext-blob fileb:///tmp/cipher.bin \
  --encryption-context "stage=test,tag=lab-01" 2>&1
# Expected: DisabledException or KMSInvalidStateException

# Teardown
aws kms schedule-key-deletion --key-id alias/lab-test-key \
  --pending-window-in-days 7
```

## Detection rules & checklists

```yaml
# Sigma-style rule: anomalous KMS Decrypt volume
title: Anomalous KMS Decrypt Spikes
logsource:
  service: cloudtrail
  events:
    eventSource: kms.amazonaws.com
    eventName: Decrypt
detection:
  selection:
    userIdentity.type: "AssumedRole"
  timeframe: 15m
  condition: selection and count > 30
  severity: high
```

```bash
# CLI audit one-liner: find KMS keys with wildcard principal
aws kms list-keys --region us-east-1 --query "Keys[].KeyId" --output text | \
  xargs -I {} aws kms get-key-policy --key-id {} --policy-name default \
  --region us-east-1 --query 'Policy' --output text | \
  jq -r 'select(.Statement[].Principal.AWS == "*" or .Statement[].Principal == "*") | .id'
```

```bash
# Azure: audit key vaults with public network access
az keyvault list --query "[?properties.networkAcls.defaultAction=='Allow'].name"

# GCP: find keys with overly broad IAM bindings
gcloud kms keys list --location global --keyring app-keyring --format json | \
  jq '.[] | select(.purpose == "ENCRYPT_DECRYPT")'
```

## References

- [AWS KMS Developer Guide — Encryption Context](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context)
- [AWS CloudHSM Documentation](https://docs.aws.amazon.com/cloudhsm/latest/userguide/)
- [Azure Key Vault security](https://learn.microsoft.com/en-us/azure/key-vault/general/security-features)
- [GCP Cloud KMS Documentation](https://cloud.google.com/kms/docs)
- [HashiCorp Vault Transit Engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [PKCS#11 Specification (OASIS)](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.1/os/pkcs11-base-v3.1-os.html)
- Cross-link: [04-03 — Encryption at Rest & CMK](../Storage-Data-Security/encryption-at-rest-and-cmek.md)
