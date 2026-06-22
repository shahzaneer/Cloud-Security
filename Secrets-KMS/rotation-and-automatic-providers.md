# 04 — Rotation & Automatic Providers

> **Level:** Intermediate–Advanced
> **Prereqs:** [05-03 — Secret Stores Per Cloud](./secret-stores-per-cloud.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Persistence
> **Authorization scope:** Run only in your own sandbox accounts; all DB endpoints and credentials are placeholders.

## What & why

Manual secret rotation is the discipline nobody keeps. Automatic rotation — where the cloud provider or a scheduled function replaces the credential in both the secret store and the target system simultaneously — is the only rotation that actually happens at scale. Rotation limits the window of compromise: a stolen credential is valid only until the next rotation cycle.

## The OnPrem reality

Cron scripts rotating DB users. The canonical quarterly rotation email: "We rotate every 90 days." In practice: DBA runs a SQL script that creates a new user, updates Vault, restarts half the application servers — and the other half fails because nobody updated their cached credentials. Dynamic secrets (Vault database engine) solved the atomic-renewal problem by generating short-lived credentials on demand, but introduced Vault as a single point of failure.

```bash
# OnPrem: manual rotation (the bad old way)
psql -h db.internal.example.com -U admin -c "ALTER USER app_user PASSWORD 'new-placeholder-pass-456'"

vault kv put secret/production/db-creds password="new-placeholder-pass-456"

# Restart apps (some fail, some miss, drift occurs)

# OnPrem: dynamic secrets (the better way)
vault read database/creds/readonly
# Returns: username=v-token-readonly-xyz, password=auto-gen-pw
# Lease expires in 1h — credentials auto-revoke, app requests fresh ones
```

## Cross-cloud comparison

| Feature | AWS Secrets Manager | Azure Key Vault | GCP Secret Manager | OnPrem Vault |
|---|---|---|---|---|
| Built-in rotation? | Yes — Lambda rotation function | Yes — rotation policy (preview for some resources) | No built-in; needs Cloud Scheduler + Cloud Function | Yes — dynamic secrets engine |
| Rotation schedule | Configurable (days/hours), cron expression | `rotationPolicy` with `expiryTime` + auto-rotate | Manual via scheduler | Lease TTL (seconds to days) |
| Supported targets | RDS, Redshift, DocumentDB (built-in templates) | Storage account keys, SQL DB (limited list) | Any (custom function) | 30+ databases via plugins |
| Atomic replace | Two-phase (AWSPENDING → AWSCURRENT) | Version-based; old version remains until rotation completes | Manual version add + enable | Lease creates new, expires old |
| Rotation failure handling | CloudWatch alarm on `StartSecretRotation` failure | Activity Log alert | Cloud Monitoring alert on scheduler failure | Lease expiry — credential revoked regardless |
| Custom rotation support | Yes — custom Lambda | Limited — extend via Event Grid | Yes — custom Cloud Function | Yes — custom plugins |

## AWS

AWS Secrets Manager rotation uses a **Lambda function** invoked on schedule. The built-in RDS rotation template works in two phases:

```
AWSCURRENT (v1 — live) → AWSPENDING (v2 — test) → AWSCURRENT (v2 — live) + AWSPREVIOUS (v1)
```

```bash
# 1. Enable rotation for an RDS secret (built-in single-user rotation)
aws secretsmanager rotate-secret \
  --secret-id "production/db/app-db" \
  --rotation-lambda-arn "arn:aws:lambda:us-east-1:111111111111:function:SecretsManagerRotationTemplate" \
  --rotation-rules "{\"AutomaticallyAfterDays\": 30}" \
  --region us-east-1

# 2. Immediate rotation (manual trigger for testing)
aws secretsmanager rotate-secret \
  --secret-id "production/db/app-db" \
  --rotate-immediately \
  --region us-east-1

# 3. Describe rotation status
aws secretsmanager describe-secret \
  --secret-id "production/db/app-db" \
  --query "{RotationEnabled: RotationEnabled, RotationRules: RotationRules, LastRotated: LastRotatedDate}" \
  --region us-east-1

# 4. Cancel rotation (if stuck in AWSPENDING)
aws secretsmanager cancel-rotate-secret \
  --secret-id "production/db/app-db" \
  --region us-east-1
```

**Custom rotation Lambda template:**

```python
import boto3
import json

def lambda_handler(event, context):
    arn = event['SecretId']
    step = event['Step']  # createSecret, setSecret, testSecret, finishSecret

    client = boto3.client('secretsmanager')

    if step == 'createSecret':
        # Generate new password, put AWSPENDING version
        new_pass = "generated-rotated-pass-placeholder"
        client.put_secret_value(
            SecretId=arn,
            SecretString=json.dumps({"password": new_pass}),
            VersionStages=['AWSPENDING']
        )

    elif step == 'setSecret':
        # Update the actual database with the new password
        pass

    elif step == 'testSecret':
        # Test connectivity with new password (AWSPENDING)
        pass

    elif step == 'finishSecret':
        # Promote AWSPENDING → AWSCURRENT
        client.update_secret_version_stage(
            SecretId=arn,
            VersionStage='AWSCURRENT',
            MoveToVersionId=event['VersionId']
        )
```

**Terraform:**

```hcl
resource "aws_secretsmanager_secret_rotation" "db" {
  secret_id           = aws_secretsmanager_secret.app_db.id
  rotation_lambda_arn = aws_lambda_function.rotation.arn

  rotation_rules {
    automatically_after_days = 30
  }
}

resource "aws_lambda_permission" "allow_secretsmanager" {
  statement_id  = "AllowSecretsManagerInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotation.function_name
  principal     = "secretsmanager.amazonaws.com"
}
```

## Azure

Azure Key Vault rotation uses a **rotation policy** — currently preview, more limited than AWS.

```bash
# Set a rotation policy for a key (keys, not secrets as of current)
# (as of June 2026, Azure Key Vault rotation policies are GA for keys; automatic secret
# rotation is available via the `RotationPolicy` resource type — check current Azure
# Key Vault documentation for the latest GA status on secret rotation)
az keyvault key rotation-policy update \
  --vault-name lab-vault-003 \
  --name app-key \
  --value '{
    "lifetimeActions": [{
      "trigger": {"timeAfterCreate": "P30D"},
      "action": {"type": "Rotate"}
    }],
    "attributes": {"expiryTime": "P90D"}
  }'

# Immediate rotate
az keyvault key rotate \
  --vault-name lab-vault-003 \
  --name app-key

# For secrets: manual rotation via version update
az keyvault secret set \
  --vault-name lab-vault-003 \
  --name "production-db-password" \
  --value "new-placeholder-password-789"

# For automated rotation: Event Grid + Azure Function
# Trigger on Key Vault SecretNearExpiry event
az eventgrid event-subscription create \
  --name rotation-trigger \
  --source-resource-id "/subscriptions/.../resourceGroups/security-lab/providers/Microsoft.KeyVault/vaults/lab-vault-003" \
  --endpoint "/subscriptions/.../resourceGroups/security-lab/providers/Microsoft.Web/sites/rotation-func/functions/RotateSecret" \
  --included-event-types "Microsoft.KeyVault.SecretNearExpiry"
```

## GCP

GCP Secret Manager has **no built-in rotation**. Rotation is implemented via Cloud Scheduler + Cloud Function.

```bash
# Manual rotation (add new version)
echo -n "new-placeholder-password-789" | \
  gcloud secrets versions add production-db-password --data-file=-

# Disable old version
gcloud secrets versions disable 1 --secret production-db-password

# Automated: Cloud Scheduler → Pub/Sub → Cloud Function → rotates secret
gcloud scheduler jobs create pubsub rotate-db-password \
  --schedule "0 2 * * *" \
  --topic rotation-trigger \
  --message-body '{"secret":"production-db-password","target":"example-db"}'

# Cloud Function snippet (Python)
from google.cloud import secretmanager
from google.cloud.secretmanager_v1 import SecretManagerServiceClient

def rotate_secret(event, context):
    client = SecretManagerServiceClient()
    secret_path = f"projects/my-project/secrets/production-db-password"

    new_pass = "generated-rotated-pass-placeholder"
    client.add_secret_version(
        parent=secret_path,
        payload=secretmanager.SecretPayload(data=new_pass.encode())
    )

    # Disable previous versions
    for version in client.list_secret_versions(parent=secret_path):
        if version.state == secretmanager.SecretVersion.State.ENABLED and version.name.endswith('/1'):
            client.disable_secret_version(name=version.name)
```

## OnPrem (HashiCorp Vault)

```bash
# Dynamic DB secrets — auto-create, auto-revoke
vault write database/config/postgres \
  plugin_name=postgresql-database-plugin \
  allowed_roles="readonly" \
  connection_url="postgresql://{{username}}:{{password}}@db.internal.example.com:5432/postgres" \
  username="vault_admin" \
  password="placeholder-vault-admin-pw"

vault write database/roles/readonly \
  db_name=postgres \
  creation_statements="CREATE USER \"{{name}}\" WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl=1h max_ttl=24h

vault read database/creds/readonly
# Credentials valid for 1h, auto-revoked on expiry

# Static secret rotation via cron or Vault agent
# vault write -f transit/keys/app-key/rotate
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Trigger | `vault read` creates new creds on demand | `secretsmanager rotate-secret` | `az keyvault key rotate` | `gcloud secrets versions add` |
| Schedule | Lease TTL auto-expire | `AutomaticallyAfterDays` | `rotationPolicy.lifetimeActions` | Cloud Scheduler |
| Test phase | N/A (dynamic — atomic) | `testSecret` Lambda step | N/A | Custom Cloud Function |
| Failure response | Credential auto-revoked on lease expiry | CloudWatch alarm | Activity Log | Cloud Monitoring alert |
| Atomic switch | Old creds expire, new creds exist simultaneously (brief overlap) | `finishSecret` promotes AWSPENDING → AWSCURRENT | Version list: latest is current | Enable new version, disable old |

## 🔴 Red Team view

**Rotate vs. grabby-hoarder — the stale credential window.** If an attacker captures a credential and the rotation happens *before* all applications have picked up the new credential, the system enters a "dual-valid" state where both old and new credentials work. In a poorly designed rotation, this window can be indefinite.

```
Timeline:
t0: Attacker steals DB password from env dump
t1: Rotation starts (AWSPENDING created, DB updated with new password)
t2: Rotation completes (AWSCURRENT swapped)
t3: App-A restarts — picks up new password
t4: App-B still running with cached old password from t0
t5: Attacker can still authenticate WITH THE OLD PASSWORD because:
    a) DB didn't force existing connections to close
    b) Old credential wasn't explicitly revoked (only replaced)
```

**Narrative attack scenario:** An attacker compromises a developer's machine at t0, captures the DB password through a process environment dump (`/proc/$PID/environ`). Rotation fires at midnight. The attacker observes rotation in CloudTrail (`StartSecretRotation`). At t+1 day, they test the old password — it still works because the DBA used `ALTER USER ... PASSWORD` (which does NOT terminate existing connections in PostgreSQL) rather than `pg_terminate_backend` for sessions using the old password.

**Defensive pair — proper rotation must include revocation of old credential:**

```sql
-- AWS RDS rotation Lambda should include:
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE usename = 'old_app_user' AND pid <> pg_backend_pid();

DROP USER IF EXISTS old_app_user;
```

**Artifacts left by attacker using stale credential:**
- DB general log: logins from an IP not matching any application server
- DB general log: connections using a password hash that matches the *previous* hash (rotated out)
- CloudTrail: no `GetSecretValue` call preceding the DB login — attacker didn't fetch the new secret

## 🔵 Blue Team view

**Detection signals:**
1. CloudTrail `StartSecretRotation` failure → possible attacker interference or target system unavailable
2. DB login using old (pre-rotation) credential hash after rotation completed
3. Secret rotation Lambda CloudWatch Logs with `ERROR` — can indicate `setSecret` or `testSecret` phase failure
4. Gap > 2x rotation interval without a `RotateSecret` event

**Sample CloudWatch alert on rotation failure:**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name secret-rotation-failed \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value=SecretsManagerRotationTemplate \
  --alarm-actions arn:aws:sns:us-east-1:111111111111:security-alerts
```

**Periodic "test restore" drill:**

```bash
# Synthetic DB login proof — does the current secret actually work?
SECRET=$(aws secretsmanager get-secret-value \
  --secret-id "production/db/app-db" \
  --query "SecretString" --output text)
USER=$(echo "$SECRET" | jq -r '.username')
PASS=$(echo "$SECRET" | jq -r '.password')
HOST=$(echo "$SECRET" | jq -r '.host')

psql -h "$HOST" -U "$USER" -c "SELECT 1 AS rotation_test;" && echo "OK" || echo "FAIL"
# Run this after every rotation and alert on FAIL
```

**Preventive controls:**
- Set `AutomaticallyAfterDays` ≤ 30 for production credentials
- Always include connection termination in the `setSecret` phase of custom rotation Lambdas
- Use IAM conditions to restrict who can call `StartSecretRotation` / `RotateSecret`
- Enable AWS Config rule `secretsmanager-rotation-enabled-check`

## Hands-on lab

```bash
# 1. Create a secret
aws secretsmanager create-secret \
  --name "lab/rotation-test" \
  --secret-string '{"user":"lab","password":"lab-initial-pass"}' \
  --region us-east-1

# 2. Enable rotation (requires pre-created Lambda — use mock for lab)
aws secretsmanager rotate-secret \
  --secret-id "lab/rotation-test" \
  --rotation-rules '{"AutomaticallyAfterDays": 7}' \
  --region us-east-1

# 3. Describe — check rotation status
aws secretsmanager describe-secret --secret-id "lab/rotation-test" \
  --query "RotationEnabled" --region us-east-1

# 4. Manual immediate rotate
aws secretsmanager rotate-secret --secret-id "lab/rotation-test" \
  --rotate-immediately --region us-east-1

# 5. Check version history post-rotation
aws secretsmanager list-secret-version-ids \
  --secret-id "lab/rotation-test" --region us-east-1

# Teardown
aws secretsmanager delete-secret --secret-id "lab/rotation-test" \
  --recovery-window-in-days 7 --region us-east-1
```

## Detection rules & checklists

```yaml
# Sigma-style: secret rotation failure
title: Secret Rotation Failed
logsource:
  service: cloudtrail
  events:
    eventSource: secretsmanager.amazonaws.com
    eventName: StartSecretRotation
detection:
  failure:
    errorMessage: "*"
  condition: failure
  severity: high
```

```bash
# CLI audit: list secrets WITHOUT rotation enabled
aws secretsmanager list-secrets --region us-east-1 \
  --query "SecretList[?RotationEnabled==\`false\`].Name" --output text

# Azure: find keys without rotation policy (KQL for Resource Graph)
# resources | where type =~ 'Microsoft.KeyVault/vaults/keys' | where isnull(properties.rotationPolicy)
```

## References

- [AWS Secrets Manager Rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html)
- [AWS Rotation Lambda Templates](https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_available-rotation-templates.html)
- [Azure Key Vault key rotation](https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation)
- [GCP Secret Manager Add Version](https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets)
- [HashiCorp Vault Dynamic Secrets](https://developer.hashicorp.com/vault/docs/secrets/databases)
- Cross-links: [04-03 — Encryption at Rest & CMK](../Storage-Data-Security/encryption-at-rest-and-cmek.md), [05-08 — Revocation](./revocation-and-break-glass-keys.md)
