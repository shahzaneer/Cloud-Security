# 01 — Shared Responsibility Model

> **Level:** Fundamental
> **Prereqs:** none
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Execution (cloud-matrix variants rely on mis-scoped ownership assumptions)
> **Authorization scope:** Run only in your own sandbox account.

## What & why
The shared responsibility model defines which security controls the cloud provider owns and which the customer owns. Cloud engineers who treat cloud like on-prem silently accept risks the provider never agreed to carry — especially OS patching, app-layer hardening, and identity hygiene.

## The OnPrem reality
You own everything: the building, the rack, the NIC, the hypervisor, the OS, the app stack, the data, the identity system, and the monitoring. One organization, one throat to choke.

| Layer | OnPrem responsibility |
|-------|----------------------|
| Physical security / racks / power / cooling | You |
| Network fabric / switches / cabling | You |
| Hypervisor / firmware | You |
| Guest OS / patching / hardening | You |
| Application stack / runtime | You |
| Identity & access | You |
| Data classification & encryption | You |
| Logging & monitoring | You |

## Core concepts

The line shifts by service model. The more managed the service, the more the provider owns.

```
               Physical  Hypervisor   OS   Platform   Data/Identity   App Code
 IaaS (EC2)   ──CSP────  ──CSP────  ─YOU─  ──YOU───   ───YOU───────  ──YOU──
 PaaS (RDS)   ──CSP────  ──CSP────  ─CSP─  ──CSP───   ───YOU───────  ──N/A──
 FaaS (Lambda)──CSP────  ──CSP────  ─CSP─  ──CSP───   ───YOU───────  ──YOU──
 SaaS (Gmail) ──CSP────  ──CSP────  ─CSP─  ──CSP───   ───CSP───────  ──N/A──
```

- **IaaS (Infrastructure as a Service):** CSP secures physical, network, hypervisor. You secure OS upward.
- **PaaS (Platform as a Service):** CSP secures through the platform layer. You secure data, identity, and application configuration.
- **FaaS (Function as a Service):** CSP secures everything except your code, environment variables, and IAM policy.
- **SaaS (Software as a Service):** CSP secures nearly everything; you manage user identities and data classification.

## AWS

| Service | Type | CSP owns | You own |
|---------|------|----------|---------|
| EC2 | IaaS | Physical, hypervisor, network | OS patching, app, firewall (SG), IAM, data |
| RDS | PaaS | Physical, hypervisor, OS, DB engine patching, backups (if enabled) | IAM, encryption keys, VPC placement, SG, data in transit |
| Lambda | FaaS | Physical, hypervisor, OS, runtime, scaling | Code, env vars, IAM role, VPC config, layer dependencies |
| S3 | PaaS (storage) | Physical, durability, replication | IAM/bucket policy, encryption, public-access blocks, data lifecycle |

**Console path:** AWS Management Console → each service dashboard → "Security" tab details the split.

**CLI quick-check:**
```bash
aws ec2 describe-instances --query 'Reservations[*].Instances[*].{Id:InstanceId,AMI:ImageId,Key:KeyName}'
```

**Canonical line:** AWS secures *of* the cloud; the customer secures *in* the cloud. The line is OS-and-up for IaaS, data-and-identity for everything.

**Gotcha:** IMDSv1 is default-on in many AMI configurations. Customers must explicitly enforce IMDSv2 via `HttpTokens=required` — AWS does not default to v2 everywhere.

## Azure

| Service | Type | CSP owns | You own |
|---------|------|----------|---------|
| Virtual Machine | IaaS | Physical, hypervisor, fabric | OS, patches, NSG, app, identity, data |
| SQL Database | PaaS | Physical, OS, SQL engine patching, HA | Firewall rules, AAD auth config, TDE keys, data |
| Functions | FaaS | Physical, OS, runtime, scaling | Code, App Settings (env vars), identity, host.json |
| Blob Storage | PaaS (storage) | Physical, durability, replication | RBAC, SAS token policies, encryption scope, public access |

**Console path:** Azure Portal → service resource → "Security" blade (or "Networking" / "Identity").

**CLI quick-check:**
```bash
az vm show --resource-group ExampleRG --name ExampleVM --query '{os:storageProfile.osDisk.osType,identity:identity}'
```

**Gotcha:** Blob Storage "Allow Blob Public Access" is enabled at the storage-account level by default. You must explicitly disable it — Azure won't.

## GCP

| Service | Type | CSP owns | You own |
|---------|------|----------|---------|
| Compute Engine | IaaS | Physical, hypervisor, network fabric | OS patching, firewall rules, IAM, app, data |
| Cloud SQL | PaaS | Physical, OS, DB engine, automated backups | IAM, SSL/TLS, network auth (Authorized Networks), data |
| Cloud Run | FaaS (container) | Physical, OS, runtime, scaling | Container image, IAM, service configuration, env vars |
| Cloud Storage | PaaS (storage) | Physical, durability, replication | IAM, uniform bucket-level access, CMEK, public prevention |

**Console path:** GCP Console → service → "IAM & Admin" or "Security" tab.

**CLI quick-check:**
```bash
gcloud compute instances describe example-instance --zone=us-central1-a \
  --format='value(metadata.items.key,metadata.items.value)'
```

**Gotcha:** Cloud Storage buckets default to "fine-grained" ACLs, which can lead to accidental public object exposure. Use uniform bucket-level access.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Physical security | ✅ You | ✅ CSP | ✅ CSP | ✅ CSP |
| Hypervisor patching | ✅ You | ✅ CSP | ✅ CSP | ✅ CSP |
| OS hardening | ✅ You | ⚠️ You (IaaS) / CSP (PaaS+) | ⚠️ You (IaaS) / CSP (PaaS+) | ⚠️ You (IaaS) / CSP (PaaS+) |
| App stack patching | ✅ You | ⚠️ You | ⚠️ You | ⚠️ You |
| Identity / IAM | ✅ You | ⚠️ You | ⚠️ You | ⚠️ You |
| Data encryption at rest | ✅ You | ⚠️ CSP provides, you configure keys | ⚠️ CSP provides, you configure keys | ⚠️ CSP provides, you configure keys |
| Data encryption in transit | ✅ You | ⚠️ You configure TLS/certs | ⚠️ You configure TLS/certs | ⚠️ You configure TLS/certs |
| Network segmentation | ✅ You | ⚠️ You (VPC, SG, NACL) | ⚠️ You (VNet, NSG) | ⚠️ You (VPC, firewall rules) |
| Logging & monitoring | ✅ You | ⚠️ CSP provides, you enable | ⚠️ CSP provides, you enable | ⚠️ CSP provides, you enable |

✅ = CSP owns / handles by default
⚠️ = Shared — customer must configure
You = Customer-only responsibility

## 🔴 Red Team view

Attackers exploit the gap between what a customer *assumes* the cloud handles and what the customer actually owns.

**Contained example — SSRF into IMDS on EC2:**

An application vulnerability allows a server-side request to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.

```bash
# Attacker sends (contained, against localhost test app):
curl -H 'Host: metadata.internal' http://localhost:8080/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

If the EC2 instance has an over-privileged IAM role, the attacker retrieves temporary credentials. The customer assumed AWS "secured the instance" — but IAM role scoping is the customer's job.

**Why this works:** Many engineers assume AWS patches the app, restricts outbound traffic, or prevents IMDS access from within the instance. None of that is true by default.

**Artifacts left:** CloudTrail records `GetCallerIdentity` and API calls using the instance role. VPC Flow Logs show connections to `169.254.169.254` from the instance.

**Immediate hardening (Blue):**
```bash
# Enforce IMDSv2 (token required, hop-limit 1):
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

IMDSv2 requires a PUT request to obtain a session token before any metadata access, blocking simple SSRF reads. See also [authn-authz-accountability.md](./authn-authz-accountability.md) for role assume-chain detection.

**Azure equivalent (contained):**
```bash
# Attacker probes the Azure Instance Metadata Service (IMDS):
curl -H 'Metadata: true' http://localhost:8080/proxy?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Detection: NSG flow logs + Azure Monitor for unexpected 169.254.169.254 traffic.
```

**GCP equivalent (contained):**
```bash
# Attacker probes GCP metadata server:
curl http://localhost:8080/proxy?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token -H 'Metadata-Flavor: Google'
# Detection: VPC Flow Logs + IAM audit logs for unusual service-account activity.
```

## 🔵 Blue Team view

Build an explicit responsibility inventory for every service in your stack. Never assume.

**Preventive controls:**

1. **Responsibility inventory template (CSV):**

```csv
service_name,service_model,csp_owns,we_own,last_reviewed,owner_team
EC2 web tier,IaaS,Physical/hypervisor/network,OS patching+SG+IAM+app,2026-06-01,Platform
RDS primary, PaaS,Physical/OS/DB-engine,IAM+KMS+VPC+SG+TLS-config,2026-06-01,Data
S3 logs bucket,PaaS,"Physical,durability,replication",Bucket-policy+encryption+lifecycle,2026-06-01,Security
```

2. **Detective controls:**
   - CloudTrail / Azure Activity Log / GCP Cloud Audit Logs — confirm every API call is attributable.
   - `GetCallerIdentity` storms — query for bursts of identity-check calls indicating stolen credentials (see [authn-authz-accountability.md](./authn-authz-accountability.md)).

3. **Preventive guardrails:**
```hcl
# Terraform: enforce IMDSv2 on all EC2
resource "aws_instance" "example" {
  metadata_options {
    http_tokens = "required"
    http_put_response_hop_limit = 1
  }
}
```

4. **Response steps:**
   - If a service-level compromise is detected, immediately review the responsibility line — identify what the customer owned that was breached.
   - Revoke IAM roles; rotate credentials.
   - Enforce IMDSv2 organization-wide via SCP.
   - Apply public-access-block to all S3 buckets / Azure Storage Accounts / GCP Cloud Storage buckets.

## Hands-on lab

1. **Deploy** a sample 3-tier app in your sandbox (EC2 web + RDS + S3 assets).
2. **Inventory** every resource in a CSV with columns: `resource, service_model, csp_owns, we_own, gap_identified`.
3. **Identify 3 gaps** where ownership assumptions are wrong (e.g., assumed AWS patches OS → false for EC2; assumed AWS prevents public S3 → false without explicit block; assumed Lambda runtime is patched → true, but dependencies in layer are yours).
4. **Fix one gap:** enforce IMDSv2 on the EC2 instance; apply account-level S3 public access block; apply an IAM role with least privilege.

**Teardown:** `terraform destroy` or delete resources via console.

## Detection rules & checklists

- [ ] For every production service, the CSV inventory exists and is reviewed quarterly.
- [ ] IMDSv2 enforced on all EC2 instances (`aws ec2 describe-instances --filters Name=metadata-options.http-tokens,Values=optional` — no results = good).
- [ ] S3 account-level public access block enabled.
- [ ] Azure storage accounts deny public blob access.
- [ ] GCP Cloud Storage uses uniform bucket-level access.
- [ ] No security group allows inbound 0.0.0.0/0 to ports other than 80/443 without explicit justification.

## References
- AWS Shared Responsibility Model: https://aws.amazon.com/compliance/shared-responsibility-model/
- Azure Shared Responsibility: https://docs.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility
- GCP Shared Responsibility: https://cloud.google.com/architecture/framework/security/shared-responsibility
- NIST SP 800-145 (Cloud Computing definition)
