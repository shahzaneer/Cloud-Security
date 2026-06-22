# 02 — CIA Triad in the Cloud

> **Level:** Fundamental
> **Prereqs:** 01-shared-responsibility
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Collection, Impact, Exfiltration, Resource Development
> **Authorization scope:** Run only in your own sandbox account. Deliberately break and restore your own resources only.

## What & why
Confidentiality, Integrity, and Availability remain the three failure primitives in cloud — but each takes a provider-specific shape (bucket ACLs, AMI lifecycle, control-plane outages). If you can't state a misconfiguration as a CIA violation, you can't prioritize it.

## The OnPrem reality
- **Confidentiality:** Disk-level encryption (LUKS/BitLocker), physical door locks, VLAN isolation.
- **Integrity:** Offline backups, tape rotation, checksum verification on restore.
- **Availability:** Dual PSU, RAID arrays, generator power, redundant uplinks.

Small-datacenter version: one rack, one set of disks, one admin — if the admin leaves, all three pillars collapse simultaneously.

## Core concepts

### Confidentiality
**Definition:** Only authorized principals can read the data.
**Cloud failure example:** A public S3 bucket exposes customer PII because `BlockPublicAccess` was never set.
**Control family:** Encryption at rest, encryption in transit, IAM, bucket policies, network segmentation, key management.

### Integrity
**Definition:** Data and systems are not modified by unauthorized actors.
**Cloud failure example:** An attacker gains write access to a CI pipeline's AMI image and replaces it with a backdoored copy.
**Control family:** Immutable infrastructure, checksum/signing, object versioning, MFA-delete, code signing, tamper-proof logging.

### Availability
**Definition:** Authorized principals can access the service when needed.
**Cloud failure example:** A misconfigured IAM policy denies all principals including admins (`Deny *:*` with no condition), or an attacker deletes the base AMI used by an autoscaling group.
**Control family:** Redundancy (multi-AZ/region), backup/restore, DDoS protection, IAM guardrails, break-glass accounts.

## Cross-cloud comparison

### Confidentiality

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Encryption at rest | LUKS, BitLocker, self-managed HSMs | KMS + S3 SSE (SSE-S3, SSE-KMS, SSE-C) | Azure Storage Service Encryption + Key Vault | CMEK + CSEK on Cloud Storage, KMS |
| Encryption in transit | Self-managed TLS certs, IPsec | ACM, TLS on ALB/NLB/CloudFront | Azure Key Vault certs, TLS on App Gateway | Managed SSL certs, TLS on Cloud Load Balancing |
| Key management | Self-managed HSM or software | AWS KMS (multi-region, external store) | Azure Key Vault (Managed HSM option) | Cloud KMS (software/hardware key, EKM) |
| Access control | LDAP groups, file ACLs | IAM policies, bucket policies, presigned URLs | Azure RBAC, SAS tokens, Shared Key | IAM, signed URLs, ACLs (legacy) |
| Secrets storage | Vault (Hashicorp), env files | AWS Secrets Manager, SSM Parameter Store | Azure Key Vault, App Configuration | Secret Manager |
| Public-access prevention | Firewall rules, VLAN, IP allowlists | S3 Block Public Access, SCP `s3:PutPublicBlock` | Storage account "Allow Blob Public Access" = false | `publicAccessPrevention=Enforced` on Cloud Storage |

### Integrity

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Immutable storage | WORM tape drives | S3 Object Lock (WORM), Glacier Vault Lock | Immutable Blob Storage (legal hold) | Cloud Storage Bucket Lock |
| Versioning | Backup rotation scheme | S3 versioning, MFA-delete | Blob versioning, soft-delete | Object versioning, soft-delete |
| Code/artifact signing | GPG, sigstore | Signer (AWS Signer for containers, Lambda code signing) | Azure Attestation | Binary Authorization (sign images for GKE/Cloud Run) |
| Immutable infrastructure | Golden images, config mgmt | EC2 Image Builder + deploy new AMIs | Azure Image Builder + deploy new VMs | Packer images + deploy new instances |
| Database integrity | Self-managed replication + checksums | RDS multi-AZ, DynamoDB streams | SQL DB geo-replication, Cosmos DB change feed | Cloud SQL HA, Spanner TrueTime |

### Availability

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Compute redundancy | Dual PSU, spare servers | Multi-AZ autoscaling, EC2 recovery | Availability Sets/Zones, VMSS | Managed instance groups, regional MIGs |
| Storage redundancy | RAID, second SAN | S3 99.999999999% durability, EBS snapshots | Azure Storage geo-redundancy | Cloud Storage multi-region / dual-region |
| DDoS protection | On-prem firewall/scrubber | AWS Shield (Standard free, Advanced paid) | Azure DDoS Protection (Basic free, Standard paid) | Cloud Armor (L3/L4 always on, L7 configurable) |
| DNS resilience | Self-hosted DNS, secondary DNS | Route 53 (anycast), health checks | Azure DNS, Traffic Manager | Cloud DNS (anycast), health checks |
| Accidental deletion protection | Manual backup verification | S3 versioning + MFA-delete, deletion protection on RDS | Soft-delete, resource locks | Bucket versioning, deletion protection flags |
| Break-glass access | Physical console / KVM | Cross-account emergency role with MFA | Emergency access accounts in Entra ID | Break-glass SA in separate project |

## 🔴 Red Team view

### Confidentiality attack — Anonymous bucket enumeration (contained)

```bash
# Attacker probes a bucket name pattern (placeholder):
aws s3 ls s3://example-corp-logs --no-sign-request
# If the bucket allows public ListBucket: log files exposed.
```

**Equivalent probes across providers:**
```bash
# Azure (anonymous Blob container listing):
curl -s "https://examplecorplogs.blob.core.windows.net/?comp=list&restype=container" | xmllint --format -

# GCP (anonymous bucket listing):
curl -s "https://storage.googleapis.com/storage/v1/b/example-corp-logs/o"
```

**Artifacts:** S3 server access logs / Azure Storage logs / GCP Cloud Audit Logs record the anonymous access. CloudTrail data events (if enabled) capture `ListBucket` / `GetObject` from unauthenticated principals.

**Detection & hardening:**
```bash
# AWS: Block public access at account level
aws s3control put-public-access-block --account-id 111111111111 \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Azure: Deny public blob access
az storage account update --name examplecorplogs --default-action Deny --allow-blob-public-access false

# GCP: Enforce public access prevention
gcloud storage buckets update gs://example-corp-logs --public-access-prevention --enforce
```

### Integrity attack — Image poisoning in CI (contained)

```bash
# Attacker with write access to an AMI registry overwrites a base image:
aws ec2 modify-image-attribute --image-id ami-00000000000000000 \
  --launch-permission '{"Add":[{"UserId":"111111111111"}]}'
# Combined with modifying the launch template: autoscaled instances boot the backdoored AMI.
```

**Detection:** CloudTrail `ModifyImageAttribute`, `CreateLaunchTemplateVersion`. GuardDuty `Backdoor:EC2/BackdooredAMI` finding.

**Hardening:** AMI lifecycle — never rely on mutable "latest." Pin AMI IDs. Use `imagebuilder` with pipeline to produce signed AMIs. Block `ec2:ModifyImageAttribute` for non-admin roles.

### Availability attack — Resource deletion / cryptolock (contained)

```bash
# Attacker with delete permission removes the base AMI tied to an ASG:
aws ec2 deregister-image --image-id ami-00000000000000000
# Autoscaling group can no longer launch — cascading to outage.
```

**Detection:** CloudTrail `DeregisterImage`. CloudWatch alarm on `GroupInServiceInstances` metric dropping.

**Hardening:** SCP to deny `ec2:DeregisterImage` on production AMI tags. MFA-delete on critical resources. See [blast-radius-and-fail-secure.md](./blast-radius-and-fail-secure.md) for privilege-boundary hardening.

## 🔵 Blue Team view

### Per-pillar preventive guardrail table

| Pillar | Preventive control | How |
|--------|-------------------|-----|
| Confidentiality | Account-level public access block | SCP `s3:PutPublicAccessBlock`, Azure Policy "Deny public blob", Org Policy `storage.publicAccessPrevention=Enforced` |
| Confidentiality | Encryption by default | KMS CMK required for S3, Azure KV mandatory encryption, GCP CMEK org policy |
| Integrity | Immutable artifacts | AMI signing, container image signing (Binary Auth / Azure Attestation) |
| Integrity | MFA-delete | S3 MFA-delete, Azure resource locks, GCP deletion protection flags |
| Availability | Prevent resource deletion | SCP deny on `ec2:DeregisterImage` / `rds:DeleteDBInstance`, Azure resource locks, GCP `deletionProtection` |
| Availability | Multi-region DR | Cross-region backup replication, Route 53 failover, Azure Traffic Manager, GCP Cloud DNS failover |

### Detective signals per-pillar

```sql
-- AWS CloudTrail: public bucket exposure
SELECT eventTime, requestParameters.bucketName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName IN ('PutBucketAcl', 'PutBucketPolicy')
  AND requestParameters LIKE '%"uri":"http://acs.amazonaws.com/groups/global/AllUsers"%'
  AND date(eventTime) >= current_date - interval '7' day

-- AWS CloudTrail: AMI modification
SELECT eventTime, userIdentity.arn, requestParameters.imageId
FROM cloudtrail_logs
WHERE eventName IN ('ModifyImageAttribute', 'DeleteSnapshot', 'DeregisterImage')
  AND date(eventTime) >= current_date - interval '1' day

-- Azure Activity Log: storage account public access change
AzureActivity
| where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
| where Properties contains "allowBlobPublicAccess"

-- GCP Cloud Audit Logs: public bucket creation
protoPayload.methodName:"storage.buckets.update"
protoPayload.request.publicAccessPrevention = "inherited"
```

## Hands-on lab

1. **Pick one pillar** — e.g., Confidentiality.
2. **In AWS:** Create an S3 bucket. Upload a file. Set the bucket public via bucket policy. Verify with `curl`.
3. **In Azure:** Create a storage account with "Allow Blob Public Access" enabled. Create a container with public access. Verify with `curl`.
4. **In GCP:** Create a Cloud Storage bucket. Set IAM to `allUsers` with `roles/storage.objectViewer`. Verify with `curl`.
5. **Document** the exposure evidence (screenshots / terminal output).
6. **Restore** each to a secure state using the hardening commands above.
7. **Teardown:** delete all resources.

## Detection rules & checklists

- [ ] SCP / Azure Policy / Org Policy denying public-read on storage objects.
- [ ] CloudTrail data events enabled on all S3 buckets containing sensitive data.
- [ ] All AMIs / VM images / container images signed.
- [ ] MFA-delete on critical-versioned S3 buckets.
- [ ] Resource locks on production databases.
- [ ] Multi-AZ / multi-region deployment for all tier-1 services.
- [ ] Deletion protection enabled on RDS / Cloud SQL.

## References
- NIST CSF (Identify, Protect, Detect, Respond, Recover)
- CSA Cloud Controls Matrix (CCM)
- CIA Triad — NIST FIPS 199
- AWS Well-Architected Framework — Security Pillar
