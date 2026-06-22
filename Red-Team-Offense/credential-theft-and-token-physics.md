# 04 — Credential Theft & Token Physics

> **Level:** Advanced
> **Prereqs:** [Authn Flows & Tokens](../IAM/authn-flows-and-tokens.md), [Credential Theft & Token Physics](credential-theft-and-token-physics.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access (T1528, T1552, T1606), Defense Evasion
**Authorization scope:** Run only against your own sandbox accounts / sanctioned engagement with written authorization. All tokens, keys, and ARNs below are placeholder values.

## What & why
"Token physics" is the study of credential TTL, audience, scope, and replayability. For a red teamer, token lifetime = operational window. For a blue teamer, TTL = the radius of damage you can limit. Cloud tokens differ radically from static on-prem hashes: some expire in 15 minutes, some never expire, some are revocable with one API call.

## The OnPrem reality
On-prem credential theft centers on NTLM hashes (pass-the-hash), Kerberos tickets (golden/silver ticket), and cached domain credentials. These are stateless on the network: a stolen NTLM hash works until the password changes. Cloud tokens, by contrast, have *time* baked into their DNA — making both exploitation and defense fundamentally different.

## Core concepts

### Token lifecycle dimensions

| Dimension | Meaning | Attacker Implication | Defender Implication |
|---|---|---|---|
| **TTL** | How long the token lives | Shorter TTL = smaller window | Shorter TTL = less damage radius |
| **Audience** | Which service the token works for | Cross-service audience = more pivot surface | Restrict audience to exact service |
| **Scope** | What actions the token permits | Broader scope = more ops possible | Least-privilege scope per workload |
| **Replayability** | Can token be used multiple times? | Bearer tokens are replayable by design | Revoke on detection; short TTL limits replay |
| **Revocability** | Can defender kill token remotely? | Non-revocable tokens are "fire and forget" | Every token type must have a revoke API |
| **Refreshability** | Can attacker extend session? | Refresh token = long-term persistence | Revoke refresh token on compromise |

### Credential type × TTL cross-cloud matrix

| Credential Type | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| **Static access key** | No TTL (until rotated/revoked) | App secret (2y default, configurable) | SA key JSON (10y default as of June 2026; configurable at creation via `--valid-duration`) | NTLM hash (until password change) |
| **STS session token** | 15 min – 12 h (configurable via `DurationSeconds`) | N/A | N/A | Kerberos TGT (10 h default) |
| **OAuth 2.0 access token** | Cognito access token (1 h) | Entra access token (1 h default) | OAuth 2.0 access token (1 h) | Kerberos service ticket (10 h) |
| **OAuth 2.0 refresh token** | Cognito refresh token (30 d) | Entra refresh token (90 d default; as of June 2026, configurable via Conditional Access token lifetime policy and may vary by tenant) | OAuth 2.0 refresh token (until revoked) | N/A |
| **OIDC ID token** | Cognito ID token (1 h) | Entra ID token (1 h) | OIDC ID token (1 h) | N/A |
| **Managed identity token** | N/A (instance profile uses STS) | 24 h (Azure IMDS token) | 1 h (GCE metadata token) | N/A |
| **Pre-signed URL / SAS / Signed URL** | 1 s – 7 d (configurable) | 1 h – indefinite (SAS) | 1 h – 7 d (V4 signed URL) | N/A |

> (as of June 2026: Azure Entra ID refresh token default lifetime is 90 days for single-session tokens, configurable via Conditional Access token lifetime policies and authentication session controls. GCP SA key expiration defaults to no expiry unless `--valid-duration` is specified at creation. Always check the current provider documentation for latest defaults.)

## AWS

### STS session token physics

```bash
# Request an STS session token — minimum TTL
aws sts get-session-token --duration-seconds 900
# Returns credentials valid for 15 minutes

# Request an STS session token — maximum TTL
aws sts get-session-token --duration-seconds 43200
# Returns credentials valid for 12 hours (only if not restricted by SCP)

# Assume role — TTL controlled by role's MaxSessionDuration
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/TargetRole \
  --role-session-name pentest-session \
  --duration-seconds 3600

# The returned credentials contain:
# - AccessKeyId (ASIA... — temporary, always starts with ASIA)
# - SecretAccessKey
# - SessionToken (must be passed with every call)
# - Expiration (ISO 8601 timestamp)
```

### Token lifetime enforcement via SCP

```yaml
# SCP: deny STS sessions longer than 1 hour
{
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "*",
  "Condition": {
    "NumericGreaterThan": {
      "sts:DurationSeconds": 3600
    }
  }
}
```

### AWS credential type identification

```
# Access key prefix tells you the type:
# AKIA... — long-lived IAM user access key (no auto-expiry)
# ASIA... — temporary STS credential (always has expiration)
# AIDA... — IAM user ID (not a credential, but seen in ARNs)

aws sts get-caller-identity
# Check the Arn field:
# arn:aws:iam::111111111111:user/admin           → long-lived user
# arn:aws:sts::111111111111:assumed-role/Role/session → temporary, session name
# arn:aws:sts::111111111111:federated-user/user   → federated
```

### Token revocation in AWS

```bash
# Revoke an IAM user's access key
aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive --user-name admin

# Revoke all active sessions for a role (requires revoking the role's trust)
aws iam update-assume-role-policy --role-name TargetRole --policy-document file://deny-all-trust.json

# Revoke a specific STS session (add inline deny policy to the assumed-role session)
aws iam put-role-policy --role-name TargetRole --policy-name RevokeSession \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"sts:RoleSessionName":"pentest-session"}}}]}'
```

## Azure

### Entra token physics

```bash
# Decode an Azure access token (JWT) to inspect claims
az account get-access-token --resource https://management.azure.com | jq -r '.accessToken' | \
  cut -d'.' -f2 | base64 -d 2>/dev/null | jq '{aud: .aud, exp: .exp, iat: .iat, appid: .appid, tid: .tid}'

# Example output (placeholder):
# {
#   "aud": "https://management.azure.com",
#   "exp": 1719000000,
#   "iat": 1718996400,
#   "appid": "00000000-0000-0000-0000-000000000000",
#   "tid": "00000000-0000-0000-0000-000000000000"
# }

# Calculate remaining lifetime
python3 -c "
import time, json
exp = 1719000000
remaining = exp - time.time()
print(f'Token expires in {remaining:.0f}s ({remaining/60:.1f}m)')
"
```

### Conditional Access session controls

```bash
# Sign-in frequency — force re-auth every 4 hours
az rest --method PATCH \
  --uri 'https://graph.microsoft.com/v1.0/policies/conditionalAccessPolicies/<policy-id>' \
  --body '{"sessionControls":{"signInFrequency":{"value":4,"type":"hours"}}}'

# Persistent browser session — disable "Stay signed in?"
az rest --method PATCH \
  --uri 'https://graph.microsoft.com/v1.0/policies/conditionalAccessPolicies/<policy-id>' \
  --body '{"sessionControls":{"persistentBrowser":{"mode":"never"}}}'
```

### Token revocation in Azure

```bash
# Revoke all refresh tokens for a user
az ad user revoke-sign-in-sessions --id user@example-tenant.onmicrosoft.com

# Remove an app registration secret
az ad app credential reset --id 00000000-0000-0000-0000-000000000000 --append

# Revoke all sessions for a service principal
az rest --method POST \
  --uri 'https://graph.microsoft.com/v1.0/servicePrincipals/<sp-id>/revokeSignInSessions'
```

### Azure credential lifetime defaults

| Token Type | Default Lifetime | Configurable? | Revoke Mechanism |
|---|---|---|---|
| Access token | 1 hour | Via Conditional Access policy | Cannot revoke; wait for expiry |
| Refresh token (single session) | 90 days (configurable) | Via Conditional Access token lifetime policy | `revoke-sign-in-sessions` |
| Refresh token (multi-session) | Until revoked | Via Conditional Access | `revoke-sign-in-sessions` |
| App secret | 2 years max (user-specified) | Yes (on creation) | Delete or rotate the secret |
| Certificate (app auth) | Until cert expiry | Yes | Remove credential from app |
| Managed identity token | 24 hours | No | N/A (process-local only) |

## GCP

### Service account key & token physics

```bash
# Create a service account key (long-lived — 10y default)
gcloud iam service-accounts keys create sa-key.json \
  --iam-account=my-sa@example-project.iam.gserviceaccount.com

# Inspect the key metadata
cat sa-key.json | jq '{type: .type, client_email: .client_email, private_key_id: .private_key_id}'

# Generate an OAuth 2.0 access token (short-lived, 1h)
gcloud auth print-access-token

# Generate an ID token (shorter-lived)
gcloud auth print-identity-token

# Obtain a token with a specific service account impersonation
gcloud auth application-default login --impersonate-service-account \
  my-sa@example-project.iam.gserviceaccount.com

# Decode a GCP ID token payload
gcloud auth print-identity-token | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

### GCP token lifetime configuration

```bash
# Set organization policy: disallow SA key creation entirely
gcloud org-policies set-policy org-policy.yaml  # contains constraints/iam.disableServiceAccountKeyCreation

# Set organization policy: limit SA key expiry
gcloud org-policies set-policy org-policy.yaml  # contains constraints/iam.serviceAccountKeyExpiry

# Limit OAuth2 token lifetime via workload identity pool config
gcloud iam workload-identity-pools create-cred-config ... --service-account-token-lifetime-seconds=3600
```

### Token revocation in GCP

```bash
# Delete a specific SA key
gcloud iam service-accounts keys delete \
  abc123def456789 \
  --iam-account=my-sa@example-project.iam.gserviceaccount.com

# Delete ALL keys for an SA
gcloud iam service-accounts keys list \
  --iam-account=my-sa@example-project.iam.gserviceaccount.com \
  --format='value(name)' | xargs -I {} gcloud iam service-accounts keys delete {} \
  --iam-account=my-sa@example-project.iam.gserviceaccount.com

# Revoke all OAuth2 tokens for a user (admin action)
# Via Admin SDK: POST https://admin.googleapis.com/admin/directory/v1/users/user@example.com/tokens/revoke
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Static credential lifetime | Password expiry policy (90d) | IAM access key (no TTL) | App secret (2y max) | SA key (10y default) |
| Session token TTL | Kerberos TGT (10h) | STS session (15m–12h) | Access token (1h) | OAuth2 token (1h) |
| Token replay protection | PAC validation | STS token is bearer; TTL is protection | JWT bearer; CAE for continuous eval (as of June 2026, CAE is GA in Entra ID and can block token replay based on IP/device signals) | Bearer token; TTL is protection |
| Credential rotation automation | LAPS for local admin | `aws iam update-access-key` | `az ad app credential reset` | `gcloud iam sa keys rotate` |
| Bulk revocation | KRBTGT reset (breaks all Kerberos) | `UpdateAssumeRolePolicy` on role | `revokeSignInSessions` | Delete all SA keys |

## 🔴 Red Team view

### STS session physics: the attacker's clock

The attacker's operational timeline after credential theft:

```
T+0:00 — Obtain credentials (SSRF → IMDS, leaked key, phishing)
        Credentials: ASIA... AccessKeyId + Secret + SessionToken
        Expiration: T+1:00 (1-hour default AssumeRole session)

T+0:01 — aws sts get-caller-identity (verify creds work)
T+0:02 — aws iam list-roles (recon)
T+0:05 — aws iam list-users (enumerate targets)
T+0:10 — aws iam create-access-key --user-name target-user (persist; requires iam:CreateAccessKey)
        THIS EXTENDS YOUR WINDOW: new key has NO TTL

T+0:15 — aws sts assume-role --role-arn arn:aws:iam::111111111111:role/Target --duration-seconds 43200
        Now you have a 12-hour session (if no SCP cap)

T+0:55 — Session expires if not extended. All ASIA keys from first theft stop working.
```

**Key insight:** The attacker must either (a) create a long-lived key before the session expires, or (b) chain to another role with longer duration. Either action is logged.

### Token expiration artifact pattern

When an STS token expires mid-operation, the attacker's tooling throws `ExpiredToken` errors. CloudTrail records these as `AccessDenied` with error code `ExpiredToken`:

```json
{
  "errorCode": "ExpiredToken",
  "errorMessage": "The security token included in the request is expired"
}
```

Defenders can alert on `ExpiredToken` errors from principals that don't normally use temporary credentials — this indicates either a misconfigured automation or an attacker using stolen session credentials after expiry.

## 🔵 Blue Team view

### Fix TTL ceilings

1. **AWS: SCP to cap STS session duration**
   ```json
   {
     "Effect": "Deny",
     "Action": "sts:AssumeRole",
     "Resource": "*",
     "Condition": {
       "NumericGreaterThan": {"sts:DurationSeconds": 3600}
     }
   }
   ```

2. **AWS: Require MFA for any role assumption**
   ```json
   {
     "Effect": "Deny",
     "Action": "sts:AssumeRole",
     "Resource": "*",
     "Condition": {
       "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
     }
   }
   ```

3. **Azure: Conditional Access — re-auth every hour for privileged roles**
   ```bash
   az rest --method POST \
     --uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' \
     --body '{"displayName":"Privileged roles hourly reauth","state":"enabled","conditions":{"clientAppTypes":"all","applications":{"includeApplications":["All"]},"users":{"includeRoles":["Global Administrator"]}},"sessionControls":{"signInFrequency":{"value":1,"type":"hours","isEnabled":true}}}'
   ```

4. **GCP: Limit SA key creation via org policy**
   ```bash
   gcloud org-policies set-policy --organization=0000000000 org-policy-disable-sa-keys.yaml
   ```

### Preventing credential exfiltration via IMDS

```bash
# AWS: SCP requiring IMDSv2
{
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "ec2:MetadataHttpTokens": "required"
    }
  }
}

# Azure: Block IMDS access in AKS with NetworkPolicy
# GCP: Use Workload Identity Federation — no SA keys on instances
```

### Detection queries

**Detect long STS sessions:**
```sql
-- AWS CloudTrail Athena
SELECT useridentity.arn, requestparameters.durationseconds, eventtime
FROM cloudtrail_logs
WHERE eventname = 'AssumeRole'
  AND requestparameters.durationseconds > 3600
  AND eventtime > now() - interval '1' day;
```

**Detect key creation during suspicious session:**
```sql
SELECT useridentity.arn, eventname, sourceipaddress, eventtime
FROM cloudtrail_logs
WHERE eventname = 'CreateAccessKey'
  AND useridentity.arn LIKE '%:assumed-role/%'
  AND sourceipaddress NOT IN (SELECT cidr FROM corp_ip_ranges);
```

**Azure: Detect refresh token usage from new location:**
```kusto
// Azure Monitor / Log Analytics
SigninLogs
| where ResultType == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ConditionalAccessStatus == "notApplied"
| project TimeGenerated, UserPrincipalName, IPAddress, Location
```

### Response steps after credential theft confirmed

1. **Immediately revoke** the stolen credential type (key, token, secret).
2. **List all actions** the credential performed during its valid window:
   ```bash
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE
   ```
3. **Check for persistence artifacts** created during that window (new IAM users, trust policies, access keys).
4. **Rotate all credentials** the compromised principal had access to.
5. **Review SCPs** to ensure the token TTL ceiling is enforced org-wide.

## Hands-on lab

**Objective:** Observe STS session lifecycle — create, use, watch expire, detect in CloudTrail.

1. **Create a test role with short max session:**
   ```bash
   aws iam create-role --role-name token-physics-test \
     --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}]}'
   aws iam attach-role-policy --role-name token-physics-test \
     --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
   ```

2. **Assume the role with 900s (15 min) duration:**
   ```bash
   CREDS=$(aws sts assume-role --role-arn arn:aws:iam::111111111111:role/token-physics-test \
     --role-session-name lab-session \
     --duration-seconds 900 \
     --query 'Credentials.{AccessKeyId:AccessKeyId,SecretAccessKey:SecretAccessKey,SessionToken:SessionToken,Expiration:Expiration}' \
     --output json)
   echo "Expires: $(echo $CREDS | jq -r .Expiration)"
   ```

3. **Use the session and watch the clock:**
   ```bash
   export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
   export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
   export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)
   
   aws sts get-caller-identity
   # Wait 16 minutes, then retry — observe ExpiredToken error
   sleep 960
   aws sts get-caller-identity 2>&1  # Fails with ExpiredTokenException
   ```

4. **Check CloudTrail for both success and failure:**
   ```bash
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=AssumeRole \
     --max-results 5
   ```

**Expected output:** Successful `get-caller-identity`, then `ExpiredTokenException` after TTL expires.

**Teardown:**
```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
aws iam detach-role-policy --role-name token-physics-test --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam delete-role --role-name token-physics-test
```

## Detection rules & checklists

### Sigma rule: Long-duration STS session

```yaml
title: Unusually Long STS AssumeRole Session
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AssumeRole
    requestParameters.durationSeconds|numericalGreaterThan: 3600
  filter:
    userIdentity.invokedBy: "cloudformation.amazonaws.com"
  condition: selection and not filter
level: medium
```

### CLI audit one-liners

```bash
# AWS: List all IAM users with active access keys older than 90 days
aws iam list-users --query "Users[].UserName" | while read u; do
  aws iam list-access-keys --user-name "$u" --query \
    "AccessKeyMetadata[?Status=='Active' && CreateDate<'$(date -v-90d +%Y-%m-%d)'].[UserName,AccessKeyId,CreateDate]"
done

# Azure: List apps with secrets expiring in <30 days
az ad app list --query "[?passwordCredentials[?endDateTime<'$(date -v+30d +%Y-%m-%dT%H:%M:%SZ')]].displayName"

# GCP: List SA keys older than 90 days
gcloud iam service-accounts keys list --iam-account=my-sa@example-project.iam.gserviceaccount.com \
  --format='table(name, validAfterTime, validBeforeTime)'
```

### Preventive checklist

- [ ] SCP caps STS `DurationSeconds` ≤ 3600
- [ ] SCP requires `aws:MultiFactorAuthPresent` for `sts:AssumeRole`
- [ ] Entra Conditional Access enforces sign-in frequency ≤ 4h for admins
- [ ] GCP org policy disables SA key creation (use workload identity federation)
- [ ] All IAM user access keys rotated every 90 days (automated)
- [ ] Alert on `CreateAccessKey` by `assumed-role` (should be CI/CD only)
- [ ] Alert on `ExpiredToken` errors from human users

## References

- [AWS STS API Reference](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html)
- [AWS IAM Access Key Rotation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#rotating_access_keys)
- [Azure AD Token Lifetime Policies](https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes)
- [Azure AD Conditional Access](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview)
- [GCP Service Account Key Management](https://cloud.google.com/iam/docs/creating-managing-service-account-keys)
- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- See also: [IAM/assume-role-chains.md](../IAM/assume-role-chains.md)
