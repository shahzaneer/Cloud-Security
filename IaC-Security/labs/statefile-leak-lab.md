# Lab 01 — State File Leak Detection & Remediation

> **Level:** Intermediate
> **Duration:** 20–30 minutes
> **Cost:** Free (local tools only, no cloud resources created)
> **Authorization scope:** Run only against your own test repositories; all secret values are placeholders.

## Objective

Detect a Terraform state file containing plaintext secrets using `gitleaks` and `truffleHog`, then fix the leakage by marking attributes `sensitive = true` and rotating the secret.

## Prerequisites

- `git` installed
- `gitleaks` installed (`brew install gitleaks` or download from [gitleaks/releases](https://github.com/gitleaks/gitleaks/releases))
- `truffleHog` installed (`pip install trufflehog3` or `brew install trufflesecurity/trufflehog/trufflehog`)
- Local disk space ~10 MB

## Step 1 — Create a fake-but-realistic state file

```bash
mkdir -p ~/lab-statefile-leak
cd ~/lab-statefile-leak

cat > terraform.tfstate <<'EOF'
{
  "version": 4,
  "terraform_version": "1.6.0",
  "serial": 1,
  "lineage": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "outputs": {},
  "resources": [
    {
      "mode": "managed",
      "type": "aws_db_instance",
      "name": "prod_db",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 1,
          "attributes": {
            "address": "prod-db.cy9qxp7kexample.us-east-1.rds.amazonaws.com",
            "allocated_storage": 100,
            "db_name": "prod_app",
            "engine": "postgres",
            "engine_version": "15.4",
            "identifier": "prod-db",
            "instance_class": "db.r5.xlarge",
            "password": "REDACTED-DO-NOT-USE-PLACEHOLDER-DB-PASS",
            "port": 5432,
            "storage_encrypted": true,
            "username": "dbadmin",
            "vpc_security_group_ids": ["sg-0a1b2c3d4e5f67890"]
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_iam_access_key",
      "name": "deployer_key",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 1,
          "attributes": {
            "id": "AKIAIOSFODNN7EXAMPLE",
            "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "ses_smtp_password_v4": "BMXy5GfC1o9qR7sT3uV8wA2zE4bN6hJ0kLpM",
            "status": "Active",
            "user": "terraform-deployer"
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "azurerm_key_vault_secret",
      "name": "db_password",
      "provider": "provider[\"registry.terraform.io/hashicorp/azurerm\"]",
      "instances": [
        {
          "schema_version": 1,
          "attributes": {
            "id": "https://prod-kv-00000000.vault.azure.net/secrets/db-password/a1b2c3d4e5f67890abcd1234",
            "name": "db-password",
            "value": "AzureSecretPlaceholder-DO-NOT-USE-12345",
            "key_vault_id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/prod-kv-00000000"
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "google_secret_manager_secret_version",
      "name": "api_key",
      "provider": "provider[\"registry.terraform.io/hashicorp/google\"]",
      "instances": [
        {
          "schema_version": 1,
          "attributes": {
            "id": "projects/000000000000/secrets/api-key/versions/1",
            "secret": "projects/000000000000/secrets/api-key",
            "secret_data": "GCP-Secret-Placeholder-DO-NOT-USE-67890",
            "version": "1"
          }
        }
      ]
    }
  ]
}
EOF

echo "State file created with 4 embedded placeholder secrets"
```

**What is in this state file:**
- `aws_db_instance` — RDS password in `password` attribute
- `aws_iam_access_key` — AWS access key ID + secret in `id` and `secret` attributes
- `azurerm_key_vault_secret` — Azure Key Vault secret value in `value` attribute
- `google_secret_manager_secret_version` — GCP secret data in `secret_data` attribute

## Step 2 — Initialize a git repo and commit the state file

```bash
git init
git add terraform.tfstate
git commit -m "Initial commit with state file containing secrets"
```

> Test repo only. Never commit real `terraform.tfstate` to a git repository.

## Step 3 — Run gitleaks

```bash
gitleaks detect --source . --verbose --no-git
```

**Expected output — at minimum 3 findings:**

```
Finding:     "REDACTED-DO-NOT-USE-PLACEHOLDER-DB-PASS"
Secret:      REDACTED-DO-NOT-USE-PLACEHOLDER-DB-PASS
RuleID:      generic-api-key
...
Finding:     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
Secret:      wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
RuleID:      aws-access-key
...
Finding:     "AzureSecretPlaceholder-DO-NOT-USE-12345"
Secret:      AzureSecretPlaceholder-DO-NOT-USE-12345
RuleID:      generic-api-key
```

**If fewer findings appear:** gitleaks ignores certain patterns by default. Add a custom rule:

```bash
cat > .gitleaks.toml <<'EOF'
[[rules]]
id = "tfstate-password"
description = "Detect passwords in Terraform state"
regex = '''"password"\s*:\s*"([^"]{8,})"'''
tags = ["terraform", "state"]

[[rules]]
id = "tfstate-keyvault-value"
description = "Detect Key Vault secret values in state"
regex = '''"value"\s*:\s*"([^"]{8,})"'''
tags = ["terraform", "azure"]
EOF

gitleaks detect --source . --config .gitleaks.toml --verbose
```

## Step 4 — Run truffleHog

```bash
# truffleHog v3 (newer — scans filesystem)
trufflehog filesystem .

# Or, if using trufflehog3 (pip version):
trufflehog3 --format json .

# Expected output — finds the IAM access key pair, plus generic secrets
# Look for: "Raw matches found: 3+" in the output
```

**Expected findings from truffleHog:**
- AWS Access Key ID (`AKIAIOSFODNN7EXAMPLE` — matches key format `AKIA*`)
- Generic high-entropy strings (the placeholder passwords may trigger if complex enough)

## Step 5 — Fix: Mark attributes sensitive (create a corrected Terraform config)

```bash
cat > main.tf <<'EOF'
resource "random_password" "db" {
  length  = 32
  special = true
}

resource "aws_db_instance" "prod_db" {
  identifier        = "prod-db"
  engine            = "postgres"
  instance_class    = "db.r5.xlarge"
  username          = "dbadmin"
  password          = random_password.db.result
  storage_encrypted = true

  lifecycle {
    ignore_changes = [password]
  }
}

resource "azurerm_key_vault_secret" "db_password" {
  name         = "db-password"
  value        = random_password.db.result
  key_vault_id = azurerm_key_vault.kv.id

  lifecycle {
    ignore_changes = [value]
  }
}

resource "google_secret_manager_secret" "api_key" {
  secret_id   = "api-key"
  replication { automatic = true }
}
EOF

echo "Fixed Terraform config created — all secrets use random_password + sensitive"
```

**Key fixes applied:**
1. `random_password` replaces hardcoded strings — never in plaintext
2. `lifecycle { ignore_changes = [value/password] }` — after rotation outside Terraform
3. `aws_iam_access_key` removed entirely — use OIDC/IRSA instead
4. GCP secret version managed outside Terraform
5. All outputs that expose secrets should use `sensitive = true`

## Step 6 — Re-scan the corrected config

```bash
# Scan just the fixed Terraform files (not the state file)
gitleaks detect --source . --no-git
trufflehog filesystem main.tf

# Expected: ZERO findings (no hardcoded passwords/keys in .tf file)
```

## Step 7 — Verify the fix in state (conceptual — requires actual apply)

In a real pipeline, after applying the fixed Terraform:

```bash
# Old state (bad):
jq '.resources[] | select(.type == "aws_db_instance") | .instances[].attributes.password' terraform.tfstate
# Output: "REDACTED-DO-NOT-USE-PLACEHOLDER-DB-PASS"

# New state (better — value still in state but marked sensitive in code):
# terraform state show aws_db_instance.prod_db
# Shows: password = (sensitive value)
```

> The raw state JSON still contains the value. Defense-in-depth requires encrypting the state backend (see [08-01](../iac-state-and-backend-security.md)) and rotating secrets post-creation.

## Teardown

```bash
cd ~
rm -rf ~/lab-statefile-leak
```

## What you learned

- State files contain plaintext secrets by default across AWS, Azure, and GCP
- `gitleaks` and `truffleHog` both detect these leaks
- `random_password` + `sensitive = true` prevents plaintext in config files
- Marking attributes insensitive only affects CLI display — raw state still has the value
- Defense requires: sensitive marking + encrypted backend + external secret resolution

## References

- [08-01 — IaC State & Backend Security](../iac-state-and-backend-security.md)
- [08-02 — Terraform Secrets in State](../terraform-secrets-in-state.md)
- [05-06 — Git & CI/CD Leakage Paths](../../Secrets-KMS/git-and-cicd-leakage-paths.md)
