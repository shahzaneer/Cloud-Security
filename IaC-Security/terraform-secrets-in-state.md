# 02 — Terraform Secrets in State

> **Level:** Intermediate
> **Prereqs:** [08-01 — IaC State & Backend Security](./iac-state-and-backend-security.md), [05-* — Secrets & KMS module](../Secrets-KMS/)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access (T1552 — Unsecured Credentials)
> **Authorization scope:** Run only against your own sandbox accounts; all secret values shown are placeholders.

## What & why

Terraform writes every resource attribute — including database passwords, API keys, and access secrets — into `terraform.tfstate` as plaintext JSON by default. Marking attributes `sensitive = true` suppresses console/stderr output but does **not** encrypt the value in state. The state file remains a plaintext secrets dump unless you use external secret resolution.

## The OnPrem reality

Puppet manifests often contained plaintext passwords in class parameters or commented-out defaults. Ansible vault files required manual `ansible-vault encrypt` — easy to forget. Chef data bags had encryption but were optional. In all cases, secrets at rest in config management tooling were an afterthought, not a default.

```puppet
# Pre-cloud: password in Puppet manifest comment (real-world pattern)
class profile::database {
  $db_password = 'SuperSecret123'  # ← committed to git
  # TODO: move to Hiera-eyaml
}
```

## Core concepts

| Mechanism | What it does | What it does NOT do |
|---|---|---|
| `sensitive = true` | Hides value from `terraform plan` / `apply` output | Does NOT encrypt value in state file |
| `random_password` resource | Generates password, marks output sensitive | Value still stored in state |
| External data source (`vault_generic_secret`) | Resolves secret at plan time via Vault | Value echoed into state unless handled |
| `terraform state pull \| jq` | Anyone with backend access reads plaintext | — |

## Leakage points by category

| Secret type | Terraform resource | Leaks into state? | Mitigation |
|---|---|---|---|
| DB password | `aws_db_instance.password` | Yes — attribute stored | Use `random_password` + `sensitive=true` + immediate rotation |
| IAM access key secret | `aws_iam_access_key.secret` | Yes (attribute) + Yes (output) | Never create long-lived keys via Terraform; use IRSA/OIDC |
| Key Vault secret value | `azurerm_key_vault_secret.value` | Yes — plaintext in state | Store secret version ID only; resolve value at runtime |
| GCP Secret Manager version | `google_secret_manager_secret_version.secret_data` | Yes — plaintext in state | Store version name only; resolve via SDK at runtime |
| Lambda env var | `aws_lambda_function.environment.variables.SECRET` | Yes | Use Secrets Manager / Parameter Store reference inside function |
| Kubernetes secret data | `kubernetes_secret.data` | Yes — base64-encoded plaintext | Use external-secrets operator; Terraform only creates namespace/RBAC |
| TLS private key | `tls_private_key.private_key_pem` | Yes | Generate outside Terraform; pass only public key |

## AWS

```hcl
# BAD: plaintext password in state
resource "aws_db_instance" "bad" {
  username = "admin"
  password = "SuperSecret123"  # ← plaintext in state forever
}

# GOOD: random_password + sensitive
resource "random_password" "db" {
  length  = 32
  special = true
}

resource "aws_db_instance" "good" {
  username = "admin"
  password = random_password.db.result  # sensitive via resource type
}

# Verify what's in state
# terraform state show aws_db_instance.bad   → shows password plaintext
# terraform state show aws_db_instance.good  → shows "(sensitive value)"
```

```bash
# CLI: check if state contains plaintext passwords
terraform state pull | jq '.resources[] | select(.type == "aws_db_instance") | .instances[].attributes.password'
# Output: "SuperSecret123"  ← BAD
# Output: null (if sensitive) ← GOOD (but value still in raw JSON)
```

**Gotcha:** Even with `sensitive = true`, the raw state JSON still contains the value. `terraform state pull` and `terraform state show` only redact it in human-readable output. A direct `s3:GetObject` fetches the raw state with all secrets.

## Azure

```hcl
# BAD: Key Vault secret value echoed to state
resource "azurerm_key_vault_secret" "bad" {
  name         = "db-password"
  value        = "SuperSecret123"  # ← in state forever
  key_vault_id = azurerm_key_vault.kv.id
}

# GOOD: store only; resolve value at runtime via SDK
resource "azurerm_key_vault_secret" "good" {
  name         = "db-password"
  value        = random_password.db.result
  key_vault_id = azurerm_key_vault.kv.id

  lifecycle {
    ignore_changes = [value]  # after initial set, rotate outside Terraform
  }
}

# Application reads at runtime (app code, not Terraform):
# az keyvault secret show --vault-name my-kv --name db-password --query value
```

**Azure-specific note:** `azurerm_key_vault_secret` writes the secret `value` into state as a plaintext attribute. The `azurerm_key_vault_secret` data source (reading an existing secret) does the same. Use `ignore_changes` + external rotation, or use Managed Identity at runtime to avoid Terraform ever touching the secret value.

## GCP

```hcl
# BAD: Secret Manager version data in state
resource "google_secret_manager_secret_version" "bad" {
  secret      = google_secret_manager_secret.db.id
  secret_data = "SuperSecret123"  # ← in state forever
}

# GOOD: create secret skeleton; add version outside Terraform
resource "google_secret_manager_secret" "db" {
  secret_id = "db-password"
  replication {
    automatic = true
  }
}

# Secret version added via gcloud CLI (not Terraform)
# gcloud secrets versions add db-password --data-file=/tmp/password.txt
```

```bash
# GCP: verify secret version data is NOT in state
terraform state pull | jq '.resources[] | select(.type == "google_secret_manager_secret_version")'
# Should return empty — because version is managed outside Terraform
```

## OnPrem (Vault + Terraform)

```hcl
# BAD: Vault provider echoes secret to state
data "vault_generic_secret" "bad" {
  path = "secret/db"
}
# data.vault_generic_secret.bad.data["password"] is now in state

# GOOD: Vault agent sidecar or envconsul at runtime
# Terraform never touches the secret — pod/VM gets it at boot
```

| Concern | AWS | Azure | GCP | OnPrem (Vault) |
|---|---|---|---|---|
| DB password resource | `aws_db_instance.password` → state | `azurerm_mssql_database` — password attr | `google_sql_database_instance` — `root_password` | Vault dynamic DB creds |
| Secret store resource | `aws_secretsmanager_secret_version.secret_string` → state | `azurerm_key_vault_secret.value` → state | `google_secret_manager_secret_version.secret_data` → state | `vault_generic_secret` → state |
| Ephemeral resolution | Lambda ext / Parameter Store | Managed Identity + `az keyvault` SDK | Workload Identity + Secret Manager SDK | Vault Agent sidecar |
| State encryption of secrets | Not encrypted; SSE-KMS on bucket only | Not encrypted; SSE on blob only | Not encrypted; CMEK on bucket only | Not encrypted; Consul ACL controls access |

## 🔴 Red Team view

An attacker who gets read access to the state backend (via misconfigured bucket, leaked CI credential, or insider) can extract all plaintext secrets with simple tooling.

**Contained attacker workflow (local state file):**

```bash
# Step 1: Pull state
terraform state pull > state.json

# Step 2: Extract all passwords across resource types
jq '[.resources[].instances[]?.attributes?
      | select(.password != null)
      | {type: .id, password}]' state.json

# Step 3: Extract IAM access keys
jq '[.resources[] | select(.type == "aws_iam_access_key")
      | .instances[].attributes
      | {id, secret}]' state.json

# Step 4: Extract Key Vault secrets (Azure)
jq '[.resources[] | select(.type == "azurerm_key_vault_secret")
      | .instances[].attributes
      | {name: .name, value}]' state.json
```

**Artifacts:**
- CloudTrail: `s3:GetObject` on state object by attacker principal
- CloudTrail: `kms:Decrypt` if SSE-KMS enabled (makes it more visible, actually)
- If the state was exfiltrated via `terraform state pull` from a CI runner: the runner's STS session in CloudTrail shows the pull

## 🔵 Blue Team view

**Preventive controls:**

1. **Never store the actual secret value — store version IDs:**

   ```hcl
   # AWS: store version ID, resolve at runtime
   resource "aws_secretsmanager_secret_version" "db" {
     secret_id     = aws_secretsmanager_secret.db.id
     secret_string = random_password.db.result

     lifecycle {
       ignore_changes = [secret_string]
     }
   }
   output "db_secret_version_id" {
     value = aws_secretsmanager_secret_version.db.version_id
   }
   ```

2. **Use `lifecycle { ignore_changes }` for post-rotation secrets:**
   ```hcl
   lifecycle {
     ignore_changes = [password, value, secret_data, secret_string]
   }
   ```

3. **Scheduled rotation via separate CI runbook — not in Terraform apply:**
   ```bash
   # Rotate RDS password outside Terraform
   aws rds modify-db-instance \
     --db-instance-identifier prod-db \
     --master-user-password "$(aws secretsmanager get-random-password --query RandomPassword --output text)"
   ```

4. **Pre-commit scan for `sensitive = true` missing:**
   ```python
   #!/usr/bin/env python3
   # Check every resource attribute that looks like a password/secret
   # and verify it's marked sensitive or uses random_password
   import sys, re
   with open(sys.argv[1]) as f:
       content = f.read()
   # Find resource blocks with password/secret attributes
   violations = re.findall(r'resource\s+"(\w+)"\s+"(\w+)".*?(password|secret|token|key)\s*=\s*"[^"]+".*?(?!sensitive)', content, re.DOTALL)
   if violations:
       print("VIOLATIONS: plaintext secrets detected")
       sys.exit(1)
   ```

5. **AWS CloudTrail alert — state access from non-deployer role:**
   ```yaml
   # Cloud Custodian
   - name: tfstate-access-anomaly
     resource: aws.s3
     filters:
       - type: event
         key: "detail.requestParameters.bucketName"
         value: "tfstate-*"
         op: regex
       - type: event
         key: "detail.userIdentity.arn"
         value: "arn:aws:sts::111111111111:assumed-role/terraform-deploy/*"
         op: not-regex
     actions:
       - type: notify
   ```

**Detection checklist:**
- [ ] All password/secret/token attributes marked `sensitive = true`
- [ ] `random_password` used for generated secrets instead of hardcoded strings
- [ ] Secret store resources have `ignore_changes` on value attributes
- [ ] Pre-commit or CI step scans Terraform for plaintext secret strings
- [ ] CloudTrail/Activity Log alerts on state file access from non-deployer roles
- [ ] No `aws_iam_access_key` created via Terraform (use OIDC/IRSA)

## Hands-on lab

1. Create a module that leaks a password:
   ```bash
   mkdir lab-secret-leak && cd lab-secret-leak
   cat > main.tf <<'EOF'
   resource "random_string" "password" {
     length  = 16
     special = false
   }
   resource "local_file" "leak" {
     content  = "password=${random_string.password.result}"
     filename = "./leaked.txt"
   }
   EOF
   terraform init && terraform apply -auto-approve
   ```

2. Inspect the state:
   ```bash
   terraform state pull | jq '.resources[] | select(.type == "random_string") | .instances[].attributes.result'
   # Shows the plaintext password
   ```

3. Fix with `sensitive`:
   ```hcl
   resource "random_password" "password" {
     length  = 16
     special = true
   }
   output "password" {
     value     = random_password.password.result
     sensitive = true
   }
   ```

4. Re-run and verify state still contains the value but output is redacted:
   ```bash
   terraform state pull | jq '.outputs.password.value'
   # Still shows plaintext — sensitive only affects CLI display
   ```

5. **Teardown:** `terraform destroy -auto-approve`

## References

- [Terraform Sensitive Variables](https://developer.hashicorp.com/terraform/tutorials/configuration-language/sensitive-variables)
- [Terraform State Cheatsheet](https://developer.hashicorp.com/terraform/cli/state)
- [AWS Secrets Manager with Terraform](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_version)
- See ATT&CK: T1552.001 (Credentials in Files), T1552.004 (Private Keys)
- [05-03 — Secret Stores Per Cloud](../Secrets-KMS/secret-stores-per-cloud.md)
- [05-05 — Env Vars vs Mounted Secrets](../Secrets-KMS/env-vars-vs-mounted-secrets.md)
