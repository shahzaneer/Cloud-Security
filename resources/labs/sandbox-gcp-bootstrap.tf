# =============================================================================
# sandbox-gcp-bootstrap.tf
# Purpose: Minimal Terraform to bootstrap a learner's GCP project for the
#          curriculum. Enables required APIs, creates a scoped service account
#          for Terraform, and exports a key (with strong rotation warning).
#
# Curriculum cross-references:
#   - IAM/identity-primitives-per-cloud.md      (GCP IAM primitives)
#   - IAM/long-lived-keys-vs-workload-identity.md
#   - Monitoring-Detection-SIEM/gcp-cloud-audit-logs-and-scc.md
#   - Secrets-KMS/                              (KMS lab integration)
#   - Compute-Container-Security/eks-aks-gke-managed-vs-selfmanaged.md
#
# Usage:
#   # 1. Authenticate with GCP as a project owner
#   gcloud auth application-default login
#
#   # 2. Set your project ID
#   export TF_VAR_project_id="example-project"
#
#   # 3. Plan and apply
#   terraform init
#   terraform plan
#   terraform apply
#
#   # 4. After apply, a service account key JSON file is exported. Use it for
#   #    subsequent Terraform runs. ROTATE THE KEY every 30 days.
#   export GOOGLE_APPLICATION_CREDENTIALS="./sandbox-tf-sa-key.json"
#
# ⚠️  ALL PROJECT IDS ARE PLACEHOLDERS — replace `example-project` with your
#    actual GCP sandbox project ID before running.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }

  # --- Remote backend for GCS (configure post-bootstrap) ---------------------
  # After initial apply, uncomment and configure:
  #
  # backend "gcs" {
  #   bucket = "sandbox-tfstate-example-project"
  #   prefix = "bootstrap"
  # }
}

# ---- Provider ---------------------------------------------------------------

provider "google" {
  project = var.project_id
  region  = var.region
}

# ---- Input variables --------------------------------------------------------
variable "project_id" {
  description = "GCP project ID for the learner sandbox (placeholder: example-project)"
  type        = string
  default     = "example-project"
}

variable "region" {
  description = "Default GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Default GCP zone"
  type        = string
  default     = "us-central1-a"
}

# ---- Data sources -----------------------------------------------------------
data "google_project" "sandbox" {
  project_id = var.project_id
}

# =============================================================================
# 1. Enable required GCP APIs
#    Reference: IAM/identity-primitives-per-cloud.md (service enablement)
# =============================================================================

locals {
  # API list mapped to curriculum modules
  required_apis = [
    "cloudresourcemanager.googleapis.com",  # IAM / project management
    "iam.googleapis.com",                   # IAM policies & service accounts
    "compute.googleapis.com",               # Compute-Container-Security / VPC
    "storage.googleapis.com",               # Storage-Data-Security / GCS
    "cloudkms.googleapis.com",              # Secrets-KMS / key management
    "logging.googleapis.com",               # Monitoring-Detection-SIEM
    "monitoring.googleapis.com",            # Monitoring-Detection-SIEM
    "cloudbilling.googleapis.com",          # Necessary for budget alerts
    "container.googleapis.com",             # GKE labs (Compute-Container-Security)
  ]
}

resource "google_project_service" "apis" {
  for_each = toset(local.required_apis)

  project = var.project_id
  service = each.key

  # Don't disable APIs that were enabled outside of Terraform
  disable_on_destroy         = false
  disable_dependent_services = false
}

# =============================================================================
# 2. Service account for Terraform (CI/CD)
#    Reference: IAM/long-lived-keys-vs-workload-identity.md
#    Best practice: use Workload Identity Federation instead of exported keys.
#                   This key-based approach is for learner sandbox convenience.
# =============================================================================

resource "google_service_account" "terraform_sa" {
  account_id   = "sandbox-terraform-sa"
  display_name = "Sandbox Terraform Service Account"
  description  = "Service account used by Terraform for sandbox IaC deployments"
  project      = var.project_id

  depends_on = [
    google_project_service.apis["iam.googleapis.com"]
  ]
}

# Grant the Terraform SA broad admin roles for sandbox experimentation.
# In a production environment, scope these to least privilege.
resource "google_project_iam_member" "terraform_storage_admin" {
  project = var.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.terraform_sa.email}"
}

resource "google_project_iam_member" "terraform_compute_admin" {
  project = var.project_id
  role    = "roles/compute.admin"
  member  = "serviceAccount:${google_service_account.terraform_sa.email}"
}

resource "google_project_iam_member" "terraform_iam_admin" {
  project = var.project_id
  role    = "roles/resourcemanager.projectIamAdmin"
  member  = "serviceAccount:${google_service_account.terraform_sa.email}"
}

resource "google_project_iam_member" "terraform_kms_admin" {
  project = var.project_id
  role    = "roles/cloudkms.admin"
  member  = "serviceAccount:${google_service_account.terraform_sa.email}"
}

resource "google_project_iam_member" "terraform_logging_admin" {
  project = var.project_id
  role    = "roles/logging.admin"
  member  = "serviceAccount:${google_service_account.terraform_sa.email}"
}

# =============================================================================
# 3. Export service account key (with rotation warning)
# =============================================================================

resource "google_service_account_key" "terraform_sa_key" {
  service_account_id = google_service_account.terraform_sa.name

  # Key will be created on apply. Output must be treated as a secret.
  # Reference: Secrets-KMS/ — store this key in a secrets manager, not source control.
  #
  # ⚠️  ROTATION WARNING: Rotate this key every 30 days via Terraform taint + apply:
  #     terraform taint google_service_account_key.terraform_sa_key
  #     terraform apply
  #     Then delete the old key from GCP IAM → Service Accounts → Keys.
  #
  # For production: use Workload Identity Federation (IAM/federation-sso-and-external-providers.md)
  # instead of exported keys.
}

# =============================================================================
# 4. GCS bucket for remote Terraform state
# =============================================================================

resource "google_storage_bucket" "tfstate" {
  name          = "sandbox-tfstate-${var.project_id}"
  location      = var.region
  project       = var.project_id
  force_destroy = false                    # prevent accidental state loss

  # Enable versioning for state recovery
  versioning {
    enabled = true
  }

  # Uniform bucket-level access (no ACLs — managed via IAM only)
  uniform_bucket_level_access = true

  # Public access prevention (Storage-Data-Security/ module)
  public_access_prevention = "enforced"

  depends_on = [
    google_project_service.apis["storage.googleapis.com"]
  ]
}

# =============================================================================
# Outputs
# =============================================================================

output "project_id" {
  value       = data.google_project.sandbox.project_id
  description = "GCP sandbox project ID"
}

output "project_number" {
  value       = data.google_project.sandbox.number
  description = "GCP sandbox project number"
}

output "terraform_service_account_email" {
  value       = google_service_account.terraform_sa.email
  description = "Email of the Terraform service account"
}

output "state_bucket_name" {
  value       = google_storage_bucket.tfstate.name
  description = "GCS bucket for remote Terraform state"
}

output "enabled_apis" {
  value       = keys(local.required_apis)
  description = "List of enabled GCP APIs"
}

# ⚠️  SENSITIVE OUTPUT: Service account key JSON
#     Save this to a secure file and NEVER commit to version control.
#     Use `terraform output -json sa_private_key` | jq -r '.private_key' > sandbox-tf-sa-key.json
output "sa_private_key" {
  value       = google_service_account_key.terraform_sa_key.private_key
  description = "Service account private key — SENSITIVE: store in secrets manager, rotate every 30 days"
  sensitive   = true
}

output "sa_key_bootstrap_command" {
  value = <<EOT
  # After terraform apply, run the following to save the key file locally:
  terraform output -json sa_private_key | jq -r '.["'base64_decode'"]' > sandbox-tf-sa-key.json
  export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/sandbox-tf-sa-key.json"

  # ⚠️  This key is a long-lived credential. Rotate within 30 days.
  #     See: IAM/long-lived-keys-vs-workload-identity.md
EOT
  description = "Instructions for exporting and using the service account key"
}
