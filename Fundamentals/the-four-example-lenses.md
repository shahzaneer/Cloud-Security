# 06 — The Four Example Lenses

> **Level:** Fundamental
> **Prereqs:** 01-shared-responsibility
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** None — this is a conventions lesson.
> **Authorization scope:** No offensive content. Conventions and reference material only.

## What & why
Every lesson in this curriculum uses four side-by-side columns: OnPrem / AWS / Azure / GCP. This lesson formalizes the naming convention so the reader knows what each column represents, which primitives map to which, and how to translate security knowledge across providers.

## Core concepts

### The same primitive has a different name in each cloud

Knowing the aliases lets you search docs, write policies, and translate existing controls across environments. The table below maps the most common primitives.

| Primitive | OnPrem | AWS | Azure | GCP |
|-----------|--------|-----|-------|-----|
| **Account / tenant** | AD Domain / Forest | AWS Account (12-digit ID) | Entra ID Tenant (GUID) + Subscription | Cloud Identity domain + Project |
| **User directory** | Active Directory / LDAP | IAM Identity Center (successor to AWS SSO), Managed AD | Entra ID (formerly AAD), Entra ID Domain Services | Cloud Identity, Managed Microsoft AD |
| **Machine identity** | Computer account in AD | IAM Role (for EC2/ECS), IRSA (for EKS) | Managed Identity (system/user-assigned) | Service Account, Workload Identity |
| **Network isolation** | VLAN, physical switch | VPC (Virtual Private Cloud) | VNet (Virtual Network) | VPC (Virtual Private Cloud) |
| **Subnet** | Subnet/CIDR block | Subnet (inside VPC, AZ-scoped) | Subnet (inside VNet) | Subnet (inside VPC, regional) |
| **Region** | Physical datacenter | Region (e.g., us-east-1) | Region (e.g., eastus) | Region (e.g., us-central1) |
| **Availability zone** | Rack/row/power domain | AZ (e.g., us-east-1a) | AZ (e.g., 1, 2, 3) | Zone (e.g., us-central1-a) |
| **Firewall (stateful)** | Stateful firewall appliance | Security Group (SG) — stateful, instance-level | Network Security Group (NSG) — stateful, NIC/subnet-level | Firewall rules (stateful, per-VPC) |
| **Firewall (stateless)** | Router ACL | Network ACL (NACL) — stateless, subnet-level | Application Security Group (ASG) + NSG augmentation | Hierarchical Firewall Policies |
| **Object storage** | NAS / SAN | S3 (Simple Storage Service) | Blob Storage | Cloud Storage (GCS) |
| **Block storage** | SAN / iSCSI LUN | EBS (Elastic Block Store) | Managed Disk | Persistent Disk |
| **Key management** | HSM, `openssl`, HashiCorp Vault | KMS (Key Management Service) | Key Vault | Cloud KMS |
| **Secrets storage** | HashiCorp Vault, env files | Secrets Manager, SSM Parameter Store | Key Vault (secrets) | Secret Manager |
| **Serverless compute** | N/A (cron + CLI scripts) | Lambda | Functions | Cloud Run / Cloud Functions |
| **Container orchestration** | Kubernetes (self-managed) | EKS (Elastic Kubernetes Service) | AKS (Azure Kubernetes Service) | GKE (Google Kubernetes Engine) |
| **IAM / Policy as code** | GPO, `sudoers` | IAM + SCP | RBAC + Azure Policy | IAM + Org Policy |
| **Logging / audit** | syslog, Windows Event Log | CloudTrail, CloudWatch | Activity Log, Azure Monitor, Log Analytics | Cloud Audit Logs, Cloud Logging |
| **Threat detection** | IDS/IPS (Snort, Zeek) | GuardDuty, Security Hub | Defender for Cloud, Sentinel | Event Threat Detection, Security Command Center |
| **Compliance / posture** | Manual spreadsheets | AWS Config, Audit Manager | Azure Policy, Defender for Cloud compliance | Security Command Center, Org Policies |
| **WAF** | ModSecurity, commercial appliance | AWS WAF (on CloudFront/ALB) | Azure WAF (on Front Door/App Gateway) | Cloud Armor |

### Provider identity cheat-sheet

| Provider | CLI tool | IaC provider | Console URL |
|----------|----------|-------------|-------------|
| OnPrem | `ssh`, `powershell`, `vcenter` | Terraform (vsphere, libvirt), Ansible | N/A (per tool) |
| AWS | `aws` CLI v2 | Terraform (`hashicorp/aws`), CDK, CloudFormation | https://console.aws.amazon.com |
| Azure | `az` CLI (`az login`) | Terraform (`hashicorp/azurerm`), Bicep, ARM | https://portal.azure.com |
| GCP | `gcloud` CLI (`gcloud auth login`) | Terraform (`hashicorp/google`), Deployment Manager | https://console.cloud.google.com |

### OnPrem
OnPrem represents the pre-cloud baseline: physical hardware, self-managed networks, Active Directory/LDAP, and manual change processes. Security is physical-access-plus-network-segmentation. The blast radius is typically the domain. Logging is fragmented across syslog, Windows Event Log, and appliance logs.

In this curriculum, the OnPrem column answers: "How did we solve this before cloud existed, and what mental models still apply?"

### AWS
AWS is the largest public cloud. Its IAM system is the primitives table's baseline: IAM Users (long-lived), IAM Roles (short-lived, assumeable), and SCPs (permission guardrails). AWS services have distinct names (EC2, S3, RDS) that rarely map 1:1 to other CSP services by name. The CLI is `aws`, and IaC is typically Terraform or CloudFormation.

### Azure
Azure is Microsoft's cloud, deeply integrated with Entra ID (identity) and the Microsoft ecosystem (Windows, Active Directory, Office 365). Azure RBAC scopes from Management Group → Subscription → Resource Group → Resource. The CLI is `az`. IaC is Terraform, Bicep (native), or ARM templates.

### GCP
GCP is Google's cloud, organized around projects (not accounts). IAM is fundamentally different from AWS: permissions are directly bound to resources, not to principals first. Workload Identity uses Kubernetes SA → GCP SA federation. The CLI is `gcloud`. IaC is typically Terraform or Deployment Manager.

## 🔴 Red Team view

Why knowing all three clouds multiplies offensive value:

- **Same misconfiguration class, different service name:** A public S3 bucket = public Azure Blob container = public GCP Cloud Storage bucket. The attacker who knows all three can search for all three. The `PutPublicAccessBlock=false` concept translates directly to `--allow-blob-public-access true` (Azure) and `publicAccessPrevention=inherited` (GCP).
- **Tool development scales:** Write a cloud enumeration tool once per cloud → cover 90% of the market.
- **Lateral movement across multi-cloud environments:** Many enterprises run 2+ clouds. Compromise the AWS environment → discover Azure creds in S3 → pivot to Azure → discover GCP service account key in Blob → pivot to GCP.
- **Pattern translation:** An SSRF-to-IMDS exploit on EC2 maps directly to Azure IMDS (`169.254.169.254`, `Metadata: true` header) and GCP metadata server (`metadata.google.internal`, `Metadata-Flavor: Google` header). The same vulnerability class works identically across all three.

### Contained example — multi-cloud enumeration script

```python
# enumerate_buckets.py — demonstrate that the same logic works across clouds
# Run ONLY against your own sandbox accounts.
import boto3, requests, subprocess, json

# AWS
def aws_enum():
    s3 = boto3.client('s3', aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
                      aws_secret_access_key='placeholder')
    buckets = s3.list_buckets()
    for b in buckets['Buckets']:
        try:
            acl = s3.get_bucket_acl(Bucket=b['Name'])
            for grant in acl['Grants']:
                if 'AllUsers' in str(grant.get('Grantee', {})):
                    print(f"[AWS] Public bucket: {b['Name']}")
        except:
            pass

# Azure — uses placeholder account
def azure_enum():
    # Use az CLI with your own sandbox subscription
    result = subprocess.run(
        ['az', 'storage', 'account', 'list', '--query',
         "[?allowBlobPublicAccess==`true`].[name, primaryEndpoints.blob]"],
        capture_output=True, text=True)
    print(f"[Azure] Public-accessible accounts: {result.stdout}")

# GCP — uses placeholder project
def gcp_enum():
    result = subprocess.run(
        ['gcloud', 'storage', 'buckets', 'list',
         '--format=json', '--project=placeholder-project'],
        capture_output=True, text=True)
    # Further check for publicAccessPrevention
    print(f"[GCP] Buckets: {result.stdout[:200]}")

print("Run only in your own sandbox.")
```

**Artifacts left:** Each cloud logs enumeration: CloudTrail `ListBuckets` / `GetBucketAcl`, Azure Activity Log `listStorageAccount`, GCP Cloud Audit Logs `storage.buckets.list`.

## 🔵 Blue Team view

Why defenders must know all three:

- **Avoid provider bias:** If you only know AWS, you'll miss the Azure Blob with public read because you're not checking `--allow-blob-public-access`. The same vulnerability class exists across all three with different CLI flags.
- **Unified detection posture:** Build a single misconfig detection rule that queries all three clouds. The concept is "is this storage object public?" — the implementation differs:
  - AWS: `aws s3api get-bucket-acl --bucket X | grep AllUsers`
  - Azure: `az storage account show --name X --query allowBlobPublicAccess`
  - GCP: `gcloud storage buckets describe gs://X --format='json(iamConfiguration.publicAccessPrevention)'`
- **Cross-cloud IAM drift:** A contractor given admin in Azure may have no AWS access today — but what happens when the org adopts AWS? Defenders must audit cross-cloud identity consistently.
- **Incident response in multi-cloud:** A single C2 domain might appear in VPC Flow Logs, NSG Flow Logs, and GCP VPC Flow Logs. Defenders need to query all three in the same investigation.

### Unified posture check script (defensive)

```bash
#!/bin/bash
# Run in your own sandbox org only.

echo "=== AWS Public Bucket Check ==="
aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\t' '\n' | while read bucket; do
  status=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null)
  if [ $? -ne 0 ]; then
    echo "  WARNING: No public access block on $bucket"
  fi
done

echo "=== Azure Public Blob Check ==="
az storage account list --query "[?allowBlobPublicAccess==\`true\`].name" -o tsv

echo "=== GCP Public Bucket Check ==="
gcloud storage buckets list --format="table(name, iamConfiguration.publicAccessPrevention)"
```

## Hands-on lab

Take your OnPrem knowledge and fill in the three remaining providers:

1. Pick an OnPrem primitive you know well (e.g., LDAP, NFS, VLAN, syslog, Kerberos, RADIUS).
2. Find its equivalent in AWS, Azure, and GCP. Use the [provider equivalence table](#the-same-primitive-has-a-different-name-in-each-cloud) as a starting point.
3. For each, write down:
   - The service name
   - The CLI command to list/inspect it
   - One security misconfiguration to check
4. Add rows to the table for any primitive not already listed.

**Example — for LDAP:**

| Primitive | OnPrem | AWS | Azure | GCP |
|-----------|--------|-----|-------|-----|
| LDAP / directory | OpenLDAP, AD | AWS Managed Microsoft AD, IAM Identity Center | Entra ID Domain Services, Entra ID | Managed Service for Microsoft AD, Cloud Identity |
| List users | `ldapsearch -x` | `aws iam list-users` | `az ad user list` | `gcloud identity groups memberships list` |
| Misconfig | Anonymous bind enabled | IAM user with console access + no MFA | Entra ID user with no Conditional Access policy | Service account with long-lived key |

**Teardown:** No resources to delete — this is a research/inventory lab.

## Detection rules & checklists

- [ ] You can name the four providers' equivalent services for: compute, object storage, key management, identity, firewall, and logging.
- [ ] You know the CLI command to list public resources in each cloud.
- [ ] You've identified at least 3 primitives from your OnPrem experience and mapped them to all three clouds.
- [ ] You can translate a security misconfiguration you find in one cloud (e.g., "S3 bucket public") into the equivalent check in the other two.

## References
- AWS CLI Command Reference: https://awscli.amazonaws.com/v2/documentation/api/latest/index.html
- Azure CLI Reference: https://docs.microsoft.com/en-us/cli/azure/reference-index
- GCloud CLI Reference: https://cloud.google.com/sdk/gcloud/reference
- Terraform Registry (aws, azurerm, google providers): https://registry.terraform.io/
