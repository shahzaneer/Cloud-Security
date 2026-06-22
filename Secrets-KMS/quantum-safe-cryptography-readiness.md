# 10 — Quantum-Safe Cryptography Readiness

> **Level:** Intermediate
> **Prereqs:** [KMS, HSM & Vaults](kms-hsm-and-vaults.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Collection, Exfiltration, Impact
> **Authorization scope:** Run only in your own sandbox accounts. All cryptographic operations use test keys and test data. No production key material referenced.

## What & why

Quantum-safe cryptography (post-quantum cryptography, PQC) replaces today's RSA/ECDH algorithms with lattice-based, hash-based, and code-based schemes that resist cryptanalytic attacks from large-scale quantum computers. The "harvest now, decrypt later" threat means encrypted data captured today can be stored until a cryptographically-relevant quantum computer exists — likely within the 10–15 year horizon (as of June 2026). Organizations handling data with long-term sensitivity (medical records, national security, financial records) must begin their PQC migration now.

## The OnPrem reality

On-prem crypto relied on RSA-2048 and ECDH (P-256) for key exchange, digital signatures, and PKI throughout. No on-prem deployment plan existed for algorithm agility — certificates used RSA by default, HSMs supported RSA/ECC exclusively, and TLS libraries assumed traditional asymmetric primitives. The migration to PQC requires replacing hardware, updating TLS stacks, and re-issuing every certificate. This is a 5–10 year project; 2026 is not too early to start.

## Core concepts

### NIST PQC standardization (as of June 2026)

| Algorithm | Type | Use case | Standard status | Key size |
|---|---|---|---|---|
| CRYSTALS-Kyber | Lattice-based KEM | Key encapsulation (replaces ECDH/RSA) | FIPS 203 (final, Aug 2024) | Public: 1184 bytes, Private: 2400 bytes |
| CRYSTALS-Dilithium | Lattice-based signature | Digital signatures (replaces ECDSA/RSA-PSS) | FIPS 204 (final, Aug 2024) | Public: 2592 bytes, Signature: 4595 bytes |
| SPHINCS+ | Hash-based signature | Digital signatures (stateless) | FIPS 205 (final, Aug 2024) | Signature: 16–49 KB |
| FALCON | Lattice-based signature | Digital signatures (compact) | Draft standard | Signature: ~700 bytes |
| Classic McEliece | Code-based KEM | Key encapsulation (conservative) | Draft standard | Public: ~261 KB |

### The quantum threat timeline

```
2026: NIST PQC standards finalized (Kyber, Dilithium, SPHINCS+)
2027-2029: Cloud KMS begins PQC key support (preview/GA)
2028-2031: TLS 1.3 with PQC cipher suites deployed
2030-2035: Cryptographically-relevant quantum computer likely
2035+: RSA/ECC no longer considered secure for long-term data
```

### "Harvest Now, Decrypt Later" (HNDL)

An adversary captures encrypted network traffic today (VPN, TLS, encrypted S3 objects) and stores it. In 10–15 years, a quantum computer breaks the RSA/ECDH key exchange, decrypting all captured data retroactively. This makes any data with long-term confidentiality requirements immediately at risk, even if the quantum computer doesn't exist yet.

**Data at risk:** Medical records (30+ year retention), government classified documents (25–50 years), financial loan records (30 years), source code repositories (indefinite IP value), PKI root CA private keys (10–20 years).

## AWS

### AWS KMS PQC readiness (as of June 2026)

AWS KMS supports hybrid key exchange (ECDH + Kyber) in the AWS Encryption SDK and ACM for TLS certificates. Pure PQC KMS keys are in preview:

```bash
# AWS KMS — create a symmetric key (PQC-ready via hybrid key exchange in transit)
aws kms create-key --description "PQC-aware symmetric key" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT

# AWS Encryption SDK — use hybrid post-quantum key exchange
# Python example:
# from aws_encryption_sdk import EncryptionSDKClient
# client = EncryptionSDKClient(commitment_policy=...)
# Use algorithm suite with post-quantum KEM (when available)
```

**ACM PQC certificates (preview path):**
- ACM supports hybrid certificates (ECDSA-primary, Dilithium-secondary) for TLS endpoints.
- As of June 2026, this is available for ALB and CloudFront through the ACM console in preview regions.

**Gotcha:** AWS KMS CMKs are symmetric (AES-256-GCM). Grover's algorithm gives a quadratic speedup for symmetric keys, reducing AES-256 to effectively AES-128 strength. Moving to AES-256-GCM is sufficient for symmetric encryption even in the PQC era. The risk is in asymmetric key exchange (TLS key agreement), not in the symmetric data keys.

### AWS TLS PQC — hybrid key exchange

```bash
# CloudFront + ALB: hybrid PQC TLS (ECDHE + Kyber-512) as of June 2026 (preview)
# Request hybrid cipher in TLS client:
curl --ciphers "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256" \
  --curves X25519Kyber768Draft00 \
  https://your-cloudfront-distribution.cloudfront.net
```

## Azure

### Azure Key Vault PQC readiness

Azure's PQC roadmap includes hybrid key exchange for Key Vault TLS connections and early access to PQC algorithms in Managed HSM:

```bash
# Azure Key Vault — HSM-backed key (PQC-ready for symmetric)
az keyvault key create \
  --vault-name quantum-vault \
  --name pqc-test-key \
  --protection hsm \
  --kty RSA-HSM  # Today: RSA; PQC KEM key types in preview

# Azure Managed HSM — quantum-safe algorithm support (preview)
az keyvault key create \
  --vault-name managed-hsm \
  --name pqc-kem-key \
  --kty KYBER-768  # Preview as of June 2026
```

**Gotcha:** Azure SQL TDE uses AES-256 symmetric encryption with service-managed or customer-managed keys. The symmetric encryption is quantum-safe (AES-256). The risk is in the key wrapping (RSA key transport) — Azure is moving to Kyber-based key wrapping for TDE key exchange in the 2026–2027 roadmap.

### Entra ID PQC — certificate-based auth

```bash
# Entra ID CBA (Certificate-Based Authentication) — future PQC support
# Prepare for Dilithium-based client certificates by inventorying all CBA users
az ad user list --filter "certificateUserIds ne null" \
  --query "[].{User:userPrincipalName,CertSubject:certificateUserIds}" -o table
```

## GCP

### Cloud KMS PQC readiness

GCP Cloud KMS supports NIST PQC algorithms in the Quantum-Safe Key initiative:

```bash
# GCP Cloud KMS — create a PQC key ring
gcloud kms keyrings create pqc-keyring \
  --location global

# Create a PQC key (Kyber-768 for key encapsulation)
gcloud kms keys create kyber-768-key \
  --location global \
  --keyring pqc-keyring \
  --purpose asymmetric-encryption \
  --default-algorithm pqc-kyber-768  # Preview as of June 2026

# List available PQC algorithms
gcloud kms keys list-algorithms --location global
```

**Gotcha:** GCP was the first major cloud to announce native PQC algorithm support in KMS (May 2024). The Kyber-768 implementation in Cloud KMS uses a hybrid mode that wraps a traditional symmetric data key with a Kyber-768 public key — maintaining backward compatibility with existing envelope-encryption workflows.

### GCP TLS PQC — hybrid key exchange

```bash
# GCP HTTPS Load Balancer: hybrid PQC TLS (P-256 + Kyber-512) as of June 2026
gcloud compute ssl-policies create pqc-ssl-policy \
  --profile MODERN \
  --min-tls-version 1.3

gcloud compute target-https-proxies update lb-proxy \
  --ssl-policy pqc-ssl-policy
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| PQC KEM algorithms | OpenSSL 3.x with OQS-OpenSSL plugin | KMS Kyber (preview) + Encryption SDK hybrid | Managed HSM KYBER-768 (preview) | Cloud KMS pqc-kyber-768 (preview) |
| PQC signature algorithms | OQS-OpenSSL | ACM hybrid cert (preview) | Key Vault (roadmap) | Cloud KMS (roadmap) |
| Hybrid TLS | Nginx/Apache + OQS-OpenSSL | ALB/CloudFront hybrid cipher (preview) | Application Gateway (roadmap) | HTTPS LB (preview) |
| Symmetric encryption safety | AES-256 adequate after Grover | AWS KMS AES-256-GCM CMK (safe) | Azure Key Vault AES-256 (safe) | Cloud KMS AES-256-GCM (safe) |
| Crypto inventory | Spreadsheet / CMDB | CloudTrail + KMS key list | Key Vault key inventory | Cloud KMS key inventory |
| Migration timeline risk | Dependency on OpenSSL/LibreSSL update cycle | AWS-managed — faster adoption | Azure-managed — roadmap-driven | GCP-managed — earliest mover |

## 🔴 Red Team view

### "Harvest Now, Decrypt Later" — the real-world attack

The HNDL attack does not require a quantum computer today. It only requires:

1. **Passive bulk collection:** Capture TLS-encrypted traffic at ISP/IXP scale or tap cloud inter-region links.
2. **Selective storage:** Store encrypted data that will still have value in 10–15 years.
3. **Quantum decryption (future):** Use Shor's algorithm on a future CRQC (cryptographically-relevant quantum computer) to recover the RSA/ECDH private key from the captured key exchange, then decrypt all stored traffic.

### What an attacker captures today

```bash
# Attacker with network access tcpdumps TLS-encrypted traffic
tcpdump -i eth0 -w harvested-traffic.pcap 'port 443'
# Stores the pcap for future quantum decryption
aws s3 cp harvested-traffic.pcap s3://attacker-long-term-storage/
```

**Specifically vulnerable protocols:**
- TLS 1.2 with RSA key exchange (not forward-secret — one RSA key decrypts ALL sessions)
- TLS 1.2 with ECDHE key exchange (forward-secret, but ECDH can be broken by quantum)
- S/MIME encrypted email (RSA key transport)
- PGP/GPG encrypted files (RSA/ECDH public key encryption)
- SSH key exchange (ECDH — quantum-vulnerable)
- VPN (IKEv2 with ECDH)

### Attacker TTP — targeting hybrid transition gaps

Attackers look for the weakest link during PQC migration:

```bash
# Attacker forces TLS 1.2 downgrade to avoid PQC cipher suite
openssl s_client -connect target.com:443 -tls1_2 \
  -cipher 'ECDHE-RSA-AES256-GCM-SHA384'
# Even though the server supports PQC ciphers, the client can select a quantum-vulnerable one
# unless the server enforces minimum PQC requirement
```

**This works because:** During migration, servers support BOTH traditional and PQC ciphers for backward compatibility. An active attacker downgrades the connection to the traditional cipher, captures the ECDH key exchange, and stores it for future quantum decryption.

**Artifacts left:** Server-side TLS logs show cipher suite negotiation. If the server supports PQC ciphers but a client selected a non-PQC cipher, that's an anomaly. Detection: alert on TLS connections that negotiated a non-PQC cipher when PQC is available.

## 🔵 Blue Team view

### Crypto asset inventory

Before migrating to PQC, you must know what crypto you have:

```bash
# AWS: inventory all KMS keys, their specs, and rotation status
aws kms list-keys --query 'Keys[*].KeyId' --output text | \
  xargs -n1 aws kms describe-key --key-id | \
  jq '{KeyId: .KeyMetadata.KeyId, Spec: .KeyMetadata.KeySpec, Usage: .KeyMetadata.KeyUsage, Rotation: .KeyMetadata.RotationEnabled}' > crypto-inventory.json

# Azure: list all Key Vault keys by algorithm type
az keyvault key list --vault-name your-vault --query '[].{Name:name,Kty:kty,Expires:attributes.expires}' -o table

# GCP: list all KMS keys and their purposes
gcloud kms keys list --location global --keyring all-keyrings --format json | \
  jq '.[] | {name, purpose, algorithm}' > gcp-crypto-inventory.json
```

**Inventory fields per key:**
- Key ID / ARN / resource identifier
- Algorithm family (RSA, ECC, AES) and key size
- Purpose (encryption, signing, key-encrypting)
- Data classification of data protected by this key
- Required security lifetime (how long must data stay confidential?)
- Owner / team / application

### Hybrid schemes for early adopters

Use hybrid key exchange where available — this combines a traditional ECDH key share with a PQC Kyber key share:

```
Hybrid KEM (Key Encapsulation Mechanism):
  shared_secret = KDF( ECDH_shared_secret || Kyber_shared_secret )
```

If either algorithm is broken, the other protects the data. This is the safest path during the transition.

```bash
# OpenSSL 3.x with OQS-OpenSSL provider for hybrid TLS
openssl s_server -cert server.pem -key server.key \
  -curves X25519Kyber768Draft00 \
  -www -accept 4433

# Client connection with hybrid cipher
openssl s_client -curves X25519Kyber768Draft00 \
  -connect localhost:4433
```

### Crypto agility design principles

1. **Algorithm identifiers, not hardcoded algorithms:**
```python
# Bad: hardcoded algorithm
key = RSA.generate(2048)

# Good: configurable algorithm identifier
key = generate_key(config["asymmetric"]["key_agreement"]["algorithm"])  # "RSA-2048" → "Kyber-768"
```

2. **Key lifecycle versioning:** Every key gets a `key_version` with algorithm metadata, so the key manager can identify which keys need re-wrapping for PQC migration.

3. **Protocol version negotiation logging:** Log which cipher suite was negotiated for every TLS connection. This provides an inventory of which clients are still using quantum-vulnerable ciphers.

### PQC migration roadmap

| Phase | Timeline | Actions |
|---|---|---|
| Discovery | 2026 | Crypto inventory, identify HNDL-vulnerable data, assess cloud KMS PQC preview |
| Experimentation | 2026–2027 | Test Hybdrid PQC TLS in non-prod, test Kyber key wrapping in KMS preview |
| Dual-stack deployment | 2027–2029 | Enable hybrid cipher suites in production, support both PQC and traditional |
| Enforcement | 2029–2031 | Require PQC cipher for long-lived connections, deprecate RSA-only key exchange |
| Full migration | 2031+ | Rotate all asymmetric keys to PQC, retire RSA/ECC for all new deployments |

## Hands-on lab

1. Set up a test environment with OpenSSL and OQS-OpenSSL:
```bash
# Clone and build OQS-OpenSSL
git clone https://github.com/open-quantum-safe/openssl.git oqs-openssl
cd oqs-openssl
./Configure darwin64-x86_64-cc && make -j8
```

2. Generate a Kyber-768 keypair and encapsulate a shared secret:
```bash
# Generate Kyber keypair
./apps/openssl genpkey -algorithm kyber768 -out kyber_priv.pem
./apps/openssl pkey -in kyber_priv.pem -pubout -out kyber_pub.pem

# Encapsulate (encrypt) a shared secret to the Kyber public key
./apps/openssl pkeyutl -encrypt -inkey kyber_pub.pem \
  -in plaintext.txt -out ciphertext.enc

# Decapsulate (decrypt) with the Kyber private key
./apps/openssl pkeyutl -decrypt -inkey kyber_priv.pem \
  -in ciphertext.enc -out decrypted.txt
```

3. Test hybrid TLS with Kyber + ECDH:
```bash
# Start server with hybrid cipher
./apps/openssl s_server -cert server.crt -key server.key \
  -curves X25519Kyber768Draft00 -www -accept 4433 &

# Connect with hybrid cipher
./apps/openssl s_client -curves X25519Kyber768Draft00 -connect localhost:4433
```

4. Inventory your own cloud KMS keys for PQC readiness:
```bash
# AWS
aws kms list-keys | jq -r '.Keys[].KeyId' | while read key; do
  aws kms describe-key --key-id "$key" | jq '{Id: .KeyMetadata.KeyId, Spec: .KeyMetadata.KeySpec, Origin: .KeyMetadata.Origin}'
done

# GCP (if you have a project)
gcloud kms keys list --location global --keyring default
```

**Teardown:** Stop the test server, delete key files:
```bash
kill %1
rm kyber_priv.pem kyber_pub.pem plaintext.txt ciphertext.enc decrypted.txt server.crt server.key
```

## Detection rules & checklists

**Checklist:**
- [ ] Crypto asset inventory completed: all KMS keys, certificates, and TLS endpoints cataloged.
- [ ] Data classified by required confidentiality lifetime: data needing protection beyond 2035 flagged for PQC migration.
- [ ] Hybrid PQC TLS tested in non-production environment.
- [ ] All production TLS endpoints logging negotiated cipher suites (monitor for non-PQC when PQC is available).
- [ ] KMS key wrapping methods inventoried: any RSA key transport flagged for Kyber migration.
- [ ] Root CA and intermediate CA key lifetimes assessed: certificate chains valid beyond 2035 need PQC migration planning.
- [ ] PQC migration budget included in FY2027 budgeting cycle.

## References
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 — ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 — SLH-DSA (SPHINCS+)](https://csrc.nist.gov/pubs/fips/205/final)
- [AWS Post-Quantum Cryptography](https://aws.amazon.com/security/post-quantum-cryptography/)
- [Azure Quantum-Safe Cryptography](https://azure.microsoft.com/en-us/solutions/quantum-computing/)
- [GCP Cloud KMS PQC Support](https://cloud.google.com/kms/docs/post-quantum-cryptography)
- [Open Quantum Safe (OQS) Project](https://openquantumsafe.org/)
- [MITRE ATT&CK — Data from Information Repositories (T1213)](https://attack.mitre.org/techniques/T1213/)
- [NSA — Announcing the Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.pdf)
