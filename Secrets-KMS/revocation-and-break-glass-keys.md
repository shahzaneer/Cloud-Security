# 08 — Revocation & Break-Glass Keys

> **Level:** Advanced
> **Prereqs:** [05-01](./kms-hsm-and-vaults.md) through [05-06](./git-and-cicd-leakage-paths.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Impact, Defense Evasion
> **Authorization scope:** Run only in your own sandbox accounts; all key IDs and tokens are placeholders.

## What & why

When a credential is known-compromised, can you revoke it instantly across every consumer — CloudFront cache, Lambda functions, K8s sidecars, long-lived database connection pools? Revocation speed is the kill-switch test. TTL physics (STS token caches, connection pool reuse, sidecar polling intervals) determines how long an attacker retains access *after* you think you've locked the door.

## The OnPrem reality

Active Directory password reset + Kerberos TGT revocation. When an admin reset a user's password, the new password took effect immediately for *new* authentication. But existing Kerberos Ticket Granting Tickets (TGTs) lived for their full 10-hour lifetime. A compromised account's TGT was still valid for up to 10 hours after the password reset — and only an explicit `klist purge` on every Domain Controller or a PAC validation change could force re-authentication. The 10-hour attacker grace period was baked into the protocol.

```bash
# OnPrem AD: password reset doesn't kill existing sessions
net user attacker-user NewPassword123 /domain
# Attacker's existing TGT still valid
# Need explicit revocation:
# Option 1: Disable account (kills all auth)
# Option 2: Wait for TGT expiry (up to 10h)
# Option 3: Force Kerberos armoring / PAC validation (complex)
```

## Core concepts — revocation latency

```
Event: "Revoke!"
  │
  ├── 0s: IAM key disabled (AWS) / Key Vault secret updated (Azure)
  │       └─ New API calls REJECTED immediately
  │
  ├── 1–60s: K8s sidecar cache TTL — External Secrets Operator refreshes
  │       └─ Pod still using old credential until sidecar reloads
  │
  ├── 1–12h: STS token TTL — temporary session credentials
  │       └─ ⚠️ Attacker's cached STS token still valid until expiry
  │
  ├── 1–24h: CloudFront / CDN edge cache
  │       └─ Signed URL/cookie still accepted until cache invalidation
  │
  └── Indefinite: Application-level connection pools
         └─ DB connection opened with old password stays valid until reconnect
```

## Cross-cloud revocation primitives

| Primitive | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| IAM key deactivation | `iam update-access-key --status Inactive` (immediate) | `az ad app credential reset` (immediate) | `gcloud iam service-accounts keys disable` (immediate) | `net user /active:no` |
| KMS key disable | `kms disable-key` (cached decrypts may still work) | `az keyvault key disable` | `gcloud kms keys versions disable` | `vault write transit/keys/rotate` (new key active) |
| Secret update | `secretsmanager put-secret-value` → apps reload | `az keyvault secret set` (immediate read) | `gcloud secrets versions add` (immediate access) | `vault kv put` |
| Session token revoke | `iam delete-role` / SCP (effective after STS chain expires) | `az ad signed-in-user revoke-sign-in-sessions` | `gcloud auth revoke` (client-side only) | Kerberos `kadmin` TGT revocation |
| CDN token invalidation | CloudFront invalidation (5-15 min propagation) | CDN purge (1-5 min) | Cloud CDN cache invalidation (minutes) | Varnish `ban` / Squid `purge` |
| Connection pool kill | RDS `kill` session + `terminate_backend` | Azure SQL `KILL` session | Cloud SQL `pg_terminate_backend` | `kill -9` + TCP RST |

## AWS

```bash
# Full revocation sequence for a leaked IAM access key
# Step 1: Deactivate the key (0s — immediate for new API calls)
aws iam update-access-key \
  --user-name compromised-user \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive

# Step 2: List all active sessions for the user
aws iam list-access-keys --user-name compromised-user
aws iam list-signing-certificates --user-name compromised-user
aws iam list-ssh-public-keys --user-name compromised-user

# Step 3: Disable the KMS key used by compromised workloads
aws kms disable-key --key-id alias/compromised-key
# ⚠️ NOTE: Existing data encrypted with this key cannot be decrypted
# until the key is re-enabled. Data that was already decrypted and cached
# by the application is UNAFFECTED.

# Step 4: Rotate all secrets the compromised principal had access to
aws secretsmanager rotate-secret --secret-id "production/db/app-db" --rotate-immediately

# Step 5: Find and revoke active sessions (CloudTrail)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user \
  --start-time "$(date -v-24H -u +%s)" \
  --end-time "$(date -u +%s)" \
  --query "Events[].CloudTrailEvent" --output text | \
  jq -r '.sourceIPAddress' | sort -u

# Step 6: Attach explicit deny policy
aws iam put-user-policy \
  --user-name compromised-user \
  --policy-name EmergencyDenyAll \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
```

**STS token TTL — the defender's enemy:**

```bash
# Default STS session: 1h minimum, 12h maximum
# If attacker assumed a role at t0, they have 12h of valid credentials

# Mitigation: Set max session duration to 15 minutes for sensitive roles
aws iam update-role \
  --role-name sensitive-role \
  --max-session-duration 900  # 15 minutes

# For existing sessions: there is NO revoke-sts-session API
# Solutions:
# 1. SCP deny on the role (takes minutes to propagate across regions)
# 2. Delete the role entirely (drastic, breaks all consumers)
# 3. Use IAM policy condition to check session creation time
```

## Azure

```bash
# Full revocation sequence
# Step 1: Revoke user sessions (Microsoft Graph)
az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/users/00000000-0000-0000-0000-000000000000/revokeSignInSessions"

# Step 2: Remove role assignments
az role assignment delete \
  --assignee "00000000-0000-0000-0000-000000000000" \
  --scope "/subscriptions/00000000-0000-0000-0000-000000000000"

# Step 3: Disable Key Vault key
az keyvault key set-attributes \
  --vault-name lab-vault-003 \
  --name compromised-key \
  --enabled false

# Step 4: Rotate secrets accessible to compromised identity
az keyvault secret set \
  --vault-name lab-vault-003 \
  --name "production-db-password" \
  --value "emergency-rotated-pass-placeholder"

# Step 5: Revoke managed identity tokens (if applicable)
az identity list --resource-group security-lab
# Managed identity tokens are cached on VMs; restart the VM to force new token
```

## GCP

```bash
# Full revocation sequence
# Step 1: Disable service account key
gcloud iam service-accounts keys disable \
  KEY_ID \
  --iam-account="compromised-sa@my-project.iam.gserviceaccount.com"

# Step 2: Disable CMEK key version (blocks new decrypt operations)
gcloud kms keys versions disable 1 \
  --key compromised-key \
  --keyring app-keyring \
  --location global
# (as of June 2026, disabling a CMEK key version blocks new decrypt operations by preventing
# KMS from serving the key, but existing DEK caches on the client side may continue
# decrypting locally until the cache expires or is cleared)

# Step 3: Remove IAM bindings
gcloud projects remove-iam-policy-binding my-project \
  --member "serviceAccount:compromised-sa@my-project.iam.gserviceaccount.com" \
  --role "roles/editor"

# Step 4: Revoke OAuth tokens (non-IAM)
gcloud auth revoke --all
# Client-side only — server-side token revoke requires Identity Platform / OAuth consent screen

# Step 5: Rotate secret
echo -n "emergency-rotated-pass-placeholder" | \
  gcloud secrets versions add production-db-password --data-file=-
gcloud secrets versions disable 1 --secret production-db-password
```

## OnPrem (HashiCorp Vault)

```bash
# Revoke all tokens from a specific policy
vault token revoke -mode=path auth/token/create/app-policy

# Revoke dynamic database credentials
vault lease revoke -prefix database/creds/readonly

# Rotate transit encryption key (old ciphertexts decryptable via old key version)
vault write -f transit/keys/app-key/rotate

# Disable a secret engine entirely (extreme measure)
vault secrets disable secret/
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| IAM key revoke | `net user /active:no` | `update-access-key --status Inactive` | `az ad app credential reset` | `keys disable` |
| KMS disable | `vault write transit/keys/rotate` | `kms disable-key` | `keyvault key set-attributes --enabled false` | `keys versions disable` |
| Session kill | Kerberos TGT revocation (delayed) | No session kill; rely on STS expiry | `revokeSignInSessions` (Graph API) | OAuth token revoke (limited) |
| Token TTL reduction | Group Policy: `MaxTicketAge` | `max-session-duration` on role | Access token lifetime policy | `--max-token-lifetime` |
| Cache bust | Restart app / send SIGHUP | Lambda cold start / CloudFront invalidation | App Service restart / CDN purge | Cloud CDN invalidation |
| Connection pool kill | `kill -9` + `tcpkill` | `pg_terminate_backend` on RDS | `KILL` on Azure SQL | `pg_terminate_backend` on Cloud SQL |

## 🔴 Red Team view

**Defender rotates; attacker has cached STS token with 12h TTL — unaffected.**

The physics of token TTL is the defender's most painful lesson. When an IAM access key is disabled, STS temporary credentials issued *before* the disable remain valid until they naturally expire. An attacker who compromised a role and obtained STS credentials at t0 retains full access until t0+12h — even after the underlying IAM key is disabled and the KMS key is turned off.

```
Timeline:
  t0:      Attacker compromises role via phishing, assumes role, gets STS token (12h TTL)
  t0+30m:  Defender detects anomaly
  t0+31m:  Defender disables the IAM access key
  t0+32m:  Defender disables KMS keys
  t0+33m:  Defender rotates DB passwords
  t0+40m:  Attacker's STS token STILL WORKS — pulls data from S3, decrypts via cached DEKs
  t0+12h:  STS token expires — attacker locked out
```

**What the attacker does during the 12h grace window:**

1. Exfiltrates S3 data (STS credentials still valid for `s3:GetObject`)
2. Opens new DB connections using old password (connection pool not yet rotated)
3. Creates new IAM users/roles (if the compromised role has `iam:CreateUser`)
4. Modifies CloudTrail to disable logging (`cloudtrail:StopLogging`)
5. Places a backdoor: new access keys for a different user

**Defensive pair — reduce STS TTL + force session invalidation:**

```bash
# 1. Set max session duration to 15 min (down from 12h)
aws iam update-role --role-name sensitive-role --max-session-duration 900

# 2. Use SCP to block the compromised role at the Org level
# (Effective in minutes, blocks all API calls regardless of STS token validity)
aws organizations attach-policy \
  --policy-id p-emergency-block \
  --target-id ou-production

# The SCP:
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "ArnEquals": {
        "aws:PrincipalArn": "arn:aws:iam::111111111111:role/compromised-role"
      }
    }
  }]
}
```

**Artifacts left by attacker with cached credentials:**
- CloudTrail: API calls continuing *after* IAM key was disabled (using STS temp creds)
- CloudTrail: mismatch between `userIdentity.accessKeyId` (STS session) and disabled long-lived keys
- VPC Flow Logs: sustained data exfiltration traffic over 12h window

## 🔵 Blue Team view

**Defense 1: Cap STS token TTL at ≤1h for all roles.**

```bash
# SCP: deny session durations longer than 1 hour
aws organizations create-policy \
  --name max-session-duration-1h \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Deny",
      "Action":"sts:AssumeRole",
      "Resource":"*",
      "Condition":{
        "NumericGreaterThan":{"sts:DurationSeconds":3600}
      }
    }]
  }'
```

**Defense 2: K8s Secret Rotation Controller (External Secrets Operator).**

```yaml
# ExternalSecret — auto-refreshes from AWS Secrets Manager every 5 minutes
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  refreshInterval: 5m
  secretStoreRef:
    name: aws-secretsmanager
    kind: ClusterSecretStore
  target:
    name: db-creds-k8s
    creationPolicy: Owner
  data:
  - secretKey: password
    remoteRef:
      key: production/db/app-db
      property: password

# When the secret rotates in Secrets Manager:
# - External Secrets Operator detects the change within 5 min
# - Updates the K8s secret
# - Configure a reloader to restart pods on secret change
```

```yaml
# Reloader annotation — restart pods when secret changes
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    secret.reloader.stakater.com/reload: "db-creds-k8s"
spec:
  # ... pod template picks up new secret on restart
```

**Defense 3: Periodic break-glass key test.**

```bash
#!/bin/bash
# Test: can we disable and re-enable a test KMS key without data loss?
KEY_ID="arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000"

# Encrypt test data
echo -n "break-glass-test-$(date +%s)" | base64 > /tmp/test-plain.txt
aws kms encrypt --key-id "$KEY_ID" --plaintext fileb:///tmp/test-plain.txt > /tmp/test-cipher.json
CIPHER=$(cat /tmp/test-cipher.json | jq -r .CiphertextBlob | base64 -d > /tmp/test-cipher.bin)

# Disable
aws kms disable-key --key-id "$KEY_ID"

# Verify: decrypt should FAIL
aws kms decrypt --ciphertext-blob fileb:///tmp/test-cipher.bin 2>&1 | grep DisabledException
echo "DISABLE TEST: PASS"

# Re-enable
aws kms enable-key --key-id "$KEY_ID"

# Verify: decrypt should now SUCCEED
aws kms decrypt --ciphertext-blob fileb:///tmp/test-cipher.bin --query Plaintext --output text | base64 -d
echo "RE-ENABLE TEST: PASS"
```

**Response playbook (runbook order):**

| Step | Action | Time to effect | Blast radius |
|---|---|---|---|
| 1 | Disable long-lived IAM keys | 0s (instant) | New API calls blocked |
| 2 | Attach emergency SCP deny on compromised role | 1–5 min (Org propagation) | ALL API calls blocked, including cached STS |
| 3 | Rotate all KMS keys accessible to role | 0s (disable), manual re-encrypt | Data encrypted with disabled key unreadable |
| 4 | Rotate all secrets accessible to role | 0s (new version exists) | Apps need restart/reload |
| 5 | Revoke all active grants on keys | 0s | Service-to-service decrypts fail |
| 6 | Terminate DB connections for compromised user | 0s | In-flight transactions aborted |
| 7 | CloudFront/CloudFront invalidation (if CDN-signed URLs used) | 5–15 min | Cached content purged |
| 8 | Check CloudTrail for 90-day access audit | Hours | Identify scope of data accessed |

## Hands-on lab

```bash
# 1. Create a test IAM user and access key
aws iam create-user --user-name revocation-test-user
aws iam create-access-key --user-name revocation-test-user > /tmp/test-key.json
export KEY_ID=$(jq -r .AccessKey.AccessKeyId /tmp/test-key.json)
export SECRET=$(jq -r .AccessKey.SecretAccessKey /tmp/test-key.json)

# 2. Configure AWS CLI with the test user and make an API call
aws sts get-caller-identity --profile test-user
# Output: ARN of revocation-test-user — key works

# 3. Revoke (disable) the access key
aws iam update-access-key \
  --user-name revocation-test-user \
  --access-key-id "$KEY_ID" \
  --status Inactive

# 4. Try the same API call again
aws sts get-caller-identity --profile test-user 2>&1
# Expected: AccessDenied — "The security token included in the request is invalid"
# REVOCATION: IMMEDIATE for new API calls

# 5. Check STS session behavior (if user had an assumed role session)
# The user's own API calls are blocked instantly, but any STS tokens
# issued before the disable remain valid. This is the TTL gap.

# 6. Cleanup
aws iam delete-access-key --user-name revocation-test-user --access-key-id "$KEY_ID"
aws iam delete-user --user-name revocation-test-user
unset KEY_ID SECRET
```

## Detection rules & checklists

```yaml
# Sigma-style: API call after key revocation
title: API Call After IAM Key Disabled
logsource:
  service: cloudtrail
detection:
  api_call:
    eventSource: "*"
    userIdentity.accessKeyId: "*"
  condition:
    # Cross-reference: access key status == Inactive but still used
    # Requires enrichment from IAM key status data
  severity: critical
```

```bash
# CLI audit: find users with access keys older than 90 days
aws iam list-users --query "Users[].UserName" --output text | while read user; do
  aws iam list-access-keys --user-name "$user" --query \
    "AccessKeyMetadata[?Status=='Active' && CreateDate<'$(date -v-90d -u +%Y-%m-%d)'].[UserName,AccessKeyId,CreateDate]" \
    --output table
done

# Find roles without max-session-duration cap
aws iam list-roles --query "Roles[?MaxSessionDuration > 3600].[RoleName,MaxSessionDuration]" --output table
```

## References

- [AWS IAM — Managing Access Keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
- [AWS STS — Session Duration](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html#id_roles_use_view-role-max-session)
- [External Secrets Operator](https://external-secrets.io/latest/)
- [Azure revoke user sessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions)
- [GCP Disabling service account keys](https://cloud.google.com/iam/docs/managing-service-account-keys)
- Cross-links: [02-IAM](../IAM/), [05-04 — Rotation](./rotation-and-automatic-providers.md)
