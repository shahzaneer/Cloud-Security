# 02 — Deploying the Reference Sandbox

> **Level:** Advanced
> **Prereqs:** Modules 03–08
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** N/A (build phase)
**Authorization scope:** Capstone labs are to be run only against learner-owned sandbox accounts. Placeholder accounts are used throughout. No live attack surfaces.

## What & why

The reference sandbox is a single Terraform module-per-cloud that provisions the deliberately-vulnerable organisation described in [13-01](./capstone-architecture-overview.md). Every resource is tagged with an intentional weakness so that both red and blue variants share identical infrastructure. This lesson provides module stubs that the learner completes with their own sandbox values — no pre-built exploit paths are shipped.

## The OnPrem reality

Spinning up a vulnerable lab on-prem meant: install Windows Server with default passwords, configure IIS with a known-vulnerable extension, join a domain, add a network share with `Everyone:FullControl`, and isolate the VLAN. Cloud sandboxing replaces VLAN isolation with dedicated sandbox accounts/projects.

## Cross-cloud resource map

| Resource | AWS | Azure | GCP | Intentional vuln class |
|---|---|---|---|---|
| Web tier compute | EC2 `t3.micro` (IMDSv1) | VMSS instance (IMDS enabled) | GCE `e2-micro` (IMDSv1) | SSRF→IMDS credential theft ([09-03](../Red-Team-Offense/initial-access-vectors.md)) |
| Serverless function | Lambda (Python 3.11) | Function App (Python 3.11) | Cloud Function (Python 3.11) | `iam:PassRole` to admin ([09-05](../Red-Team-Offense/privilege-escalation-catalogue.md)) |
| Container worker | ECS Fargate task | Container Instance | Cloud Run service | Runs with overly broad task role |
| Managed DB | RDS MySQL `db.t3.micro` | Azure SQL DB Basic | Cloud SQL PostgreSQL `db-f1-micro` | Publicly accessible (0.0.0.0/0 in SG/firewall) |
| Object store | S3 bucket | Storage Account blob container | GCS bucket | BlockPublicAccess OFF, one prefix `public-read` |
| CI runner creds | IAM user `ci-deployer` + key | App Registration + client secret | Service Account + JSON key | Long-lived, AdministratorAccess/Owner equivalent, leaked placeholder |
| Cross-account/tenant trust | AssumeRole trust policy with `*` principal | SP with cross-subscription RBAC `Owner` | SA with `roles/owner` on target project from external SA | Overly broad trust, no external-id condition |
| WORM bucket | S3 Object Lock governance mode | Blob immutability policy (locked) | GCS retention policy (locked) | Attacker cannot delete; produces denied event |
| Network | VPC + public subnet | VNet + public subnet | VPC + public subnet | No NACL/NSG/firewall restriction on outbound |

## AWS — Terraform module stub

> The learner substitutes `<your-sandbox-account-id>` and region. The snippet below shows the resource skeleton; you fill in the variables.

```hcl
# File: sandbox-aws/main.tf (module stub — learner completes)
#
# Provider assumed configured with sandbox credentials.
# aws configure --profile capstone-sandbox

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "sandbox_account_id" {
  type    = string
  default = "111111111111"  # ← learner replaces with own sandbox ID
}

variable "region" {
  type    = string
  default = "us-east-1"
}

# ── IAM: CI runner user with AdministratorAccess ──
resource "aws_iam_user" "ci_deployer" {
  name = "ci-deployer"
  tags = { "capstone:weakness" = "long-lived-key" }
}

resource "aws_iam_access_key" "ci_deployer_key" {
  user = aws_iam_user.ci_deployer.name
}

resource "aws_iam_user_policy_attachment" "ci_admin" {
  user       = aws_iam_user.ci_deployer.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ── SSRF-vulnerable EC2 with IMDSv1 ──
resource "aws_instance" "web_tier" {
  ami           = "ami-0c7217cdde2f8e6ab"  # Amazon Linux 2023 (us-east-1)
  instance_type = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.web_profile.name
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # ← IMDSv1 allowed (SSRF vector)
  }
  user_data = <<-EOF
    #!/bin/bash
    yum install -y python3 nginx
    # Deploy deliberately-vulnerable SSRF proxy app (learner provides app code)
    # App listens on :8080, proxies GET /fetch?url=<url>
  EOF
  tags = { "capstone:weakness" = "imdsv1-ssrf" }
}

resource "aws_iam_role" "web_role" {
  name = "vulnerable-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "web_admin" {
  role       = aws_iam_role.web_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # ← overly broad
}

resource "aws_iam_instance_profile" "web_profile" {
  name = "vulnerable-ec2-profile"
  role = aws_iam_role.web_role.name
}

# ── Lambda with PassRole escalation path ──
resource "aws_iam_role" "lambda_exec" {
  name = "ProdLambdaExecRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_passrole" {
  role = aws_iam_role.lambda_exec.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = "*"  # ← can pass any role, including admin
      },
      {
        Effect   = "Allow"
        Action   = ["lambda:CreateFunction", "lambda:InvokeFunction"]
        Resource = "*"
      }
    ]
  })
}

# ── S3: public + no BlockPublicAccess ──
resource "aws_s3_bucket" "data_bucket" {
  bucket = "capstone-data-${var.sandbox_account_id}"  # learner replaces
}

resource "aws_s3_bucket_public_access_block" "data_bucket" {
  bucket = aws_s3_bucket.data_bucket.id

  block_public_acls       = false  # ← deliberate weakness
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "data_bucket" {
  bucket = aws_s3_bucket.data_bucket.id
  acl    = "public-read"  # ← deliberate weakness
}

resource "aws_s3_bucket_object_lock_configuration" "data_worm" {
  bucket = aws_s3_bucket.data_bucket.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 30
    }
  }
}

resource "aws_s3_object" "worm_protected" {
  bucket                 = aws_s3_bucket.data_bucket.id
  key                    = "customer-data/records.json"
  source                 = "fixtures/records.json"  # learner provides
  object_lock_legal_hold_status = "ON"
  object_lock_mode       = "GOVERNANCE"
  object_lock_retain_until_date = "2030-01-01T00:00:00Z"
}

# ── Cross-account trust (overly broad) ──
resource "aws_iam_role" "cross_account" {
  name = "CrossAccountRole-SharedServices"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = "*" }  # ← deliberate weakness: any AWS principal
      Action = "sts:AssumeRole"
    }]
  })
  managed_policy_arns = ["arn:aws:iam::aws:policy/PowerUserAccess"]
}

# ── Publicly accessible RDS (stub) ──
resource "aws_db_instance" "app_db" {
  identifier        = "capstone-app-db"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  publicly_accessible = true  # ← deliberate weakness
  skip_final_snapshot = true
  tags = { "capstone:weakness" = "public-db" }
}

# ── Outputs — used by red lab for enumeration ──
output "ci_access_key_id" {
  value     = aws_iam_access_key.ci_deployer_key.id
  sensitive = true
}
output "bucket_name" {
  value = aws_s3_bucket.data_bucket.id
}
output "ec2_public_ip" {
  value = aws_instance.web_tier.public_ip
}
output "cross_account_role_arn" {
  value = aws_iam_role.cross_account.arn
}
```

### Deploy (AWS)

```bash
cd sandbox-aws
terraform init
terraform plan   # review the plan — confirm nothing unintended
terraform apply  # creates ~15 resources
```

## Azure — Terraform module stub

```hcl
# File: sandbox-azure/main.tf (module stub — learner completes)

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.0" }
  }
}

variable "sandbox_subscription_id" {
  type    = string
  default = "00000000-0000-0000-0000-000000000000"  # ← learner replaces
}

# ── Service Principal (CI runner) ──
resource "azuread_application" "ci_app" {
  display_name = "ci-deployer"
}

resource "azuread_service_principal" "ci_sp" {
  client_id = azuread_application.ci_app.client_id
}

resource "azuread_application_password" "ci_secret" {
  application_id = azuread_application.ci_app.id
  display_name   = "ci-leaked-secret"
}

resource "azurerm_role_assignment" "ci_owner" {
  scope                = "/subscriptions/${var.sandbox_subscription_id}"
  role_definition_name = "Owner"  # ← deliberate: full control
  principal_id         = azuread_service_principal.ci_sp.object_id
}

# ── VMSS with IMDS SSRF vector ──
resource "azurerm_linux_virtual_machine_scale_set" "web_tier" {
  name                = "capstone-web-vmss"
  resource_group_name = azurerm_resource_group.sandbox.name
  location            = azurerm_resource_group.sandbox.location
  sku                 = "Standard_B1s"
  instances           = 1
  admin_username      = "azureuser"

  admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  os_disk {
    storage_account_type = "Standard_LRS"
    caching              = "ReadWrite"
  }

  network_interface {
    name    = "web-nic"
    primary = true
    ip_configuration {
      name      = "internal"
      primary   = true
      subnet_id = azurerm_subnet.public.id
      public_ip_address {
        name = "web-public-ip"
      }
    }
  }

  custom_data = base64encode(<<-EOF
    #!/bin/bash
    apt-get update && apt-get install -y python3 nginx
    # Deploy vulnerable SSRF app (learner provides)
  EOF
  )

  tags = { "capstone:weakness" = "imds-ssrf" }
}

# ── Storage Account with public blob container ──
resource "azurerm_storage_account" "data" {
  name                     = "capstonedata${random_string.suffix.result}"  # learner replaces
  resource_group_name      = azurerm_resource_group.sandbox.name
  location                 = azurerm_resource_group.sandbox.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_nested_items_to_be_public = true  # ← deliberate weakness

  blob_properties {
    container_delete_retention_policy {
      days = 30
    }
  }
}

resource "azurerm_storage_container" "public" {
  name                  = "public-data"
  storage_account_name  = azurerm_storage_account.data.name
  container_access_type = "blob"  # ← deliberate: public read
}

resource "azurerm_storage_container" "immutable" {
  name                 = "immutable-records"
  storage_account_name = azurerm_storage_account.data.name
}

resource "azurerm_storage_management_policy" "immutability" {
  storage_account_id = azurerm_storage_account.data.id
  rule {
    name    = "locked"
    enabled = true
    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["immutable-records/"]
    }
    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than = 30
      }
    }
  }
}

# ── Runbook stub: apply immutable policy via az cli after deployment ──
# az storage container immutability-policy create \
#   --account-name capstonedataXXXX \
#   --container-name immutable-records \
#   --period 30

# ── Cross-subscription RBAC (overly broad) ──
resource "azurerm_role_assignment" "cross_sub_reader" {
  scope                = "/subscriptions/${var.sandbox_subscription_id}"
  role_definition_name = "Owner"  # ← deliberate: cross-sub owner without conditions
  principal_id         = azuread_service_principal.ci_sp.object_id
}
```

### Deploy (Azure)

```bash
cd sandbox-azure
az login --allow-no-subscriptions  # uses sandbox tenant
terraform init
terraform plan
terraform apply
```

## GCP — Terraform module stub

```hcl
# File: sandbox-gcp/main.tf (module stub — learner completes)

terraform {
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

variable "project_id" {
  type    = string
  default = "example-project"  # ← learner replaces
}

variable "region" {
  type    = string
  default = "us-central1"
}

# ── Service Account (CI runner) with Owner ──
resource "google_service_account" "ci_deployer" {
  account_id   = "ci-deployer"
  display_name = "CI Deployer (deliberately over-privileged)"
  project      = var.project_id
}

resource "google_service_account_key" "ci_key" {
  service_account_id = google_service_account.ci_deployer.name
}

resource "google_project_iam_member" "ci_owner" {
  project = var.project_id
  role    = "roles/owner"  # ← deliberate: full control
  member  = "serviceAccount:${google_service_account.ci_deployer.email}"
}

# ── GCE with IMDSv1 ──
resource "google_compute_instance" "web_tier" {
  name         = "capstone-web"
  machine_type = "e2-micro"
  zone         = "${var.region}-a"

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  network_interface {
    network = "default"
    access_config {}  # public IP
  }

  metadata = {
    "enable-oslogin" = "TRUE"
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    apt-get update && apt-get install -y python3 nginx
    # Deploy vulnerable SSRF app (learner provides)
  EOF

  tags = ["capstone-ssrf", "imds-v1"]
}

# ── GCS bucket: public + no uniform bucket-level access ──
resource "google_storage_bucket" "data_bucket" {
  name          = "capstone-data-${var.project_id}"  # learner replaces
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = false  # ← deliberate: allows object ACLs
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.data_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"  # ← deliberate: public
}

resource "google_storage_bucket" "worm_bucket" {
  name          = "capstone-worm-${var.project_id}"
  location      = var.region
  force_destroy = false

  retention_policy {
    retention_period = 2592000  # 30 days
    is_locked        = true
  }
}

# ── Cloud Function with tokenCreator escalation ──
resource "google_service_account" "func_sa" {
  account_id   = "prod-func-sa"
  display_name = "Production Function SA"
  project      = var.project_id
}

resource "google_project_iam_member" "func_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.func_sa.email}"
}

resource "google_project_iam_member" "func_token_creator" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"  # ← escalation path
  member  = "serviceAccount:${google_service_account.func_sa.email}"
}

resource "google_cloudfunctions_function" "app" {
  name        = "capstone-app"
  runtime     = "python311"
  entry_point = "handler"
  source_archive_bucket = google_storage_bucket.data_bucket.name
  source_archive_object = "function-source.zip"  # learner provides
  service_account_email = google_service_account.func_sa.email

  trigger_http = true
}

# ── Cross-project IAM (overly broad) ──
# Grant ci-deployer SA Owner on a second project (learner creates manually)
# gcloud projects add-iam-policy-binding shared-services-project \
#   --member="serviceAccount:ci-deployer@example-project.iam.gserviceaccount.com" \
#   --role="roles/owner"

# ── Outputs ──
output "ci_sa_email" {
  value = google_service_account.ci_deployer.email
}
output "ci_key_json" {
  value     = google_service_account_key.ci_key.private_key
  sensitive = true
}
output "bucket_name" {
  value = google_storage_bucket.data_bucket.name
}
output "web_instance_ip" {
  value = google_compute_instance.web_tier.network_interface[0].access_config[0].nat_ip
}
```

### Deploy (GCP)

```bash
cd sandbox-gcp
gcloud auth application-default login
terraform init
terraform plan
terraform apply
```

## OnPrem — lab VLAN

```bash
# On-prem lab equivalent for architecture reference only:
#
# VLAN 99 — Capstone Lab
# ┌──────────────────────────────────────────┐
# │ DC: win2019-capstone-dc                   │
# │   Weak GPO: password min length = 4       │
# │   User: ci-deployer / Passw0rd!           │
# │   Group: Domain Admins contains ci-deployer│
# ├──────────────────────────────────────────┤
# │ Web: win2019-capstone-web                 │
# │   IIS with vulnerable ISAPI filter         │
# │   SSRF via http://localhost:8080/ssrf?url=│
# │   Local Admin: ci-deployer                │
# ├──────────────────────────────────────────┤
# │ SQL: win2019-capstone-sql                 │
# │   sa password: P@ssw0rd123                │
# │   Public network interface                │
# ├──────────────────────────────────────────┤
# │ FileShare: \\capstone-files\data          │
# │   Everyone: FullControl                    │
# │   Volume Shadow Copy disabled              │
# └──────────────────────────────────────────┘
```

## 🔴 Red Team view

*No red section here — this file documents the infrastructure build. The red lab in [`labs/red/build-the-apt-lab.md`](./labs/red/build-the-apt-lab.md) uses this sandbox as the target.*

## 🔵 Blue Team view

### Post-deployment validation

After `terraform apply`, run a posture scanner to verify the sandbox has the expected intentional weaknesses. These should all fail — confirming the environment is ready for the blue lab.

```bash
# AWS — prowler
prowler aws --region us-east-1 --custom-checks-metadata-file /dev/null | tee capstone-pre-scan.json
# Expected failures (at minimum):
#   - check_s3_block_public_access (FAIL — BlockPublicAccess is OFF)
#   - check_iam_user_accesskey_rotated (FAIL — key older than 90d or never rotated)
#   - check_ec2_imdsv2_enabled (FAIL — IMDSv1 allowed)
#   - check_rds_instance_public_access (FAIL — 0.0.0.0/0 in security group)

# Azure — Pester / Azure CIS benchmark
# az policy-compliance scan | select failing-policy
# Expected failures:
#   - Storage account public access enabled
#   - VM managed identity not constrained

# GCP — Forseti / SCC
gcloud scc findings list --organization=ORGANIZATION_ID
# Expected findings:
#   - PUBLIC_BUCKET_ACL
#   - SERVICE_ACCOUNT_KEY_NOT_ROTATED
#   - COMPUTE_INSTANCE_HAS_SERVICE_ACCOUNT_FULL_ACCESS
```

### Baseline snapshot

```bash
# Take a pre-red-team baseline snapshot of the posture assessment
# This will be compared against the post-incident snapshot in the blue lab.
aws configservice describe-compliance-by-config-rule > capstone/pre-config-compliance.json
az policy state list > capstone/pre-policy-compliance.json
gcloud scc findings list --format=json > capstone/pre-scc-findings.json
```

## References

- [13-01 — Architecture Overview](./capstone-architecture-overview.md)
- [Module 08 — IaC Security](../IaC-Security/README.md) — CI/CD runner creds, terraform state
- [Module 04 — Storage & Data](../Storage-Data-Security/README.md) — object lock, public buckets
- [Module 03 — Compute/Container](../Compute-Container-Security/README.md) — IMDS, instance profiles
