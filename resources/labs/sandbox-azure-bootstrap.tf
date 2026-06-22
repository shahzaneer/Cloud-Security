# =============================================================================
# sandbox-azure-bootstrap.tf
# Purpose: Minimal Terraform to bootstrap a learner's Azure subscription for
#          the curriculum. Creates a resource group, storage account for state
#          (with soft delete + versioning), key vault, and a service principal
#          for CI/CD automation.
#
# Curriculum cross-references:
#   - IAM/identity-primitives-per-cloud.md           (Azure AD & RBAC)
#   - IAM/federation-sso-and-external-providers.md   (Azure AD federation)
#   - Compute-Container-Security/eks-aks-gke-managed-vs-selfmanaged.md (AKS)
#   - Monitoring-Detection-SIEM/azure-log-analytics-and-sentinel.md
#   - Secrets-KMS/                                    (Key Vault integration)
#   - Storage-Data-Security/                           (storage security)
#
# Usage:
#   # 1. Login to Azure CLI
#   az login
#   az account set --subscription "00000000-0000-0000-0000-000000000000"
#
#   # 2. Plan and apply
#   terraform init
#   terraform plan -var="subscription_id=00000000-0000-0000-0000-000000000000"
#   terraform apply -var="subscription_id=00000000-0000-0000-0000-000000000000"
#
# ⚠️  ALL SUBSCRIPTION / TENANT IDS ARE PLACEHOLDERS.
#    Replace `00000000-0000-0000-0000-000000000000` with your actual values.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 2.0"
    }
  }

  # --- Backend block (deferred until state storage account exists) -----------
  # After first apply creates the storage account, uncomment and reconfigure:
  #
  # backend "azurerm" {
  #   resource_group_name  = "rg-sandbox-bootstrap"
  #   storage_account_name = "sandboxtfstate001"
  #   container_name       = "tfstate"
  #   key                  = "bootstrap.terraform.tfstate"
  # }
}

# ---- Provider config (authenticates via az CLI / managed identity) ----------

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }

  subscription_id = var.subscription_id
}

provider "azuread" {
  # Authenticates via the same az CLI context
}

# ---- Input variables --------------------------------------------------------
variable "subscription_id" {
  description = "Azure subscription ID (placeholder: 00000000-0000-0000-0000-000000000000)"
  type        = string
  default     = "00000000-0000-0000-0000-000000000000"
}

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "East US"
}

variable "tenant_id" {
  description = "Azure AD tenant ID (placeholder)"
  type        = string
  default     = "00000000-0000-0000-0000-000000000000"
}

# ---- Data sources -----------------------------------------------------------
data "azurerm_subscription" "primary" {}

data "azuread_client_config" "current" {}

# =============================================================================
# 1. Resource Group (logical container for everything)
# =============================================================================

resource "azurerm_resource_group" "sandbox" {
  name     = "rg-sandbox-bootstrap"
  location = var.location

  tags = {
    Curriculum = "cloud-security-ops"
    ManagedBy  = "terraform"
    Purpose    = "sandbox-bootstrap"
  }
}

# =============================================================================
# 2. Storage Account for remote Terraform state
#    Reference: Storage-Data-Security/ (storage security best practices)
# =============================================================================

resource "azurerm_storage_account" "tfstate" {
  name = "sandboxtfstate001"            # must be globally unique — change this
  resource_group_name      = azurerm_resource_group.sandbox.name
  location                 = azurerm_resource_group.sandbox.location
  account_tier             = "Standard"
  account_replication_type = "LRS"      # Locally-redundant — upgrade for production
  account_kind             = "StorageV2"

  # Enable hierarchical namespace only if you need Data Lake Gen2 features
  is_hierarchical_namespace_enabled = false

  # Require HTTPS — block plain-text HTTP
  enable_https_traffic_only = true

  # Minimum TLS version 1.2
  min_tls_version = "TLS1_2"

  # Blob soft delete (7 days) for state file recovery
  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 7
    }

    container_delete_retention_policy {
      days = 7
    }
  }

  # Shared Access Signature (SAS) expiry policy
  sas_policy {
    expiration_period = "30.00:00:00"   # 30 days max SAS token lifetime
    expiration_action = "Log"
  }

  tags = azurerm_resource_group.sandbox.tags
}

# Container for Terraform state blobs
resource "azurerm_storage_container" "tfstate" {
  name                  = "tfstate"
  storage_account_name  = azurerm_storage_account.tfstate.name
  container_access_type = "private"
}

# =============================================================================
# 3. Key Vault (for secrets, keys, and certs used across curriculum)
#    Reference: Secrets-KMS/ (Key Vault management)
# =============================================================================

resource "azurerm_key_vault" "sandbox" {
  name                       = "kv-sandbox-001"       # must be globally unique
  resource_group_name        = azurerm_resource_group.sandbox.name
  location                   = azurerm_resource_group.sandbox.location
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"            # free-tier friendly
  soft_delete_retention_days = 7

  # Enable purge protection for production labs
  purge_protection_enabled = false                   # set to true for prod

  # RBAC authorization (preferred over access policies)
  enable_rbac_authorization = true

  tags = azurerm_resource_group.sandbox.tags
}

# Grant the current user (Terraform runner) Key Vault Administrator role
resource "azurerm_role_assignment" "kv_admin_current_user" {
  scope                = azurerm_key_vault.sandbox.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azuread_client_config.current.object_id
}

# =============================================================================
# 4. Service Principal for CI/CD
#    Creates an Azure AD application + service principal that CI/CD pipelines
#    can use for IaC deployments. Reference: IAM/long-lived-keys-vs-workload-identity.md
# =============================================================================

resource "azuread_application" "sandbox_cicd" {
  display_name = "sandbox-cicd-sp"
  owners       = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal" "sandbox_cicd" {
  client_id = azuread_application.sandbox_cicd.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

# Generate a client secret for the SP (used by CI/CD pipelines)
# ⚠️  ROTATION WARNING: This secret expires in 1 year. Use Federated Credentials
#    (OIDC) for production instead — see IAM/federation-sso-and-external-providers.md
resource "azuread_application_password" "sandbox_cicd" {
  application_id = azuread_application.sandbox_cicd.id
  display_name   = "sandbox-cicd-secret"
}

# Grant the SP Contributor over the sandbox resource group
resource "azurerm_role_assignment" "cicd_contributor" {
  scope                = azurerm_resource_group.sandbox.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.sandbox_cicd.object_id
}

# Also grant Key Vault Secrets User so the pipeline can read secrets
resource "azurerm_role_assignment" "cicd_kv_secrets_user" {
  scope                = azurerm_key_vault.sandbox.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azuread_service_principal.sandbox_cicd.object_id
}

# =============================================================================
# Outputs
# =============================================================================

output "subscription_id" {
  value       = data.azurerm_subscription.primary.subscription_id
  description = "Azure subscription ID"
}

output "resource_group_name" {
  value       = azurerm_resource_group.sandbox.name
  description = "Name of the sandbox resource group"
}

output "storage_account_name" {
  value       = azurerm_storage_account.tfstate.name
  description = "Storage account name for Terraform state"
}

output "storage_container_name" {
  value       = azurerm_storage_container.tfstate.name
  description = "Storage container for Terraform state blobs"
}

output "key_vault_name" {
  value       = azurerm_key_vault.sandbox.name
  description = "Key Vault name"
}

output "key_vault_uri" {
  value       = azurerm_key_vault.sandbox.vault_uri
  description = "Key Vault URI (use for secret references in IaC)"
}

output "service_principal_client_id" {
  value       = azuread_service_principal.sandbox_cicd.client_id
  description = "Service principal client ID for CI/CD"
}

output "service_principal_tenant_id" {
  value       = var.tenant_id
  description = "Azure AD tenant ID"
}

# ⚠️  SENSITIVE: Export the client secret to a secure location. Never commit.
output "service_principal_secret" {
  value       = azuread_application_password.sandbox_cicd.value
  description = "Service principal client secret — SENSITIVE: store in Key Vault"
  sensitive   = true
}
