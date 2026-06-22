# 02 — Key Policies & Grants

> **Level:** Advanced
> **Prereqs:** [05-01 — KMS, HSM & Vaults](./kms-hsm-and-vaults.md); ties with [02-06 — Permission Boundaries & Quarantine](../IAM/permission-boundaries-and-quarantine.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Privilege Escalation, Lateral Movement, Defense Evasion
> **Authorization scope:** Run only in your own sandbox accounts; all examples use placeholder account numbers.

## What & why

KMS keys have their own resource-based policy that is **separate** from IAM identity policies. A key policy determines *who* can use the key and *how*. Grants are short-lived delegation tokens issued by AWS services (and users) to allow another principal temporary encrypt/decrypt access without modifying the key policy. Misunderstanding either mechanism leads to silently over-delegated keys — the #1 cause of KMS-related breaches.

## The OnPrem reality

No direct analog. The closest approximation is Active Directory delegation rights where a service account is granted "Reset Password" on a specific OU — the right exists independently of the service account's group memberships. Vault policies attached to a specific secret path are the nearest OnPrem equivalent: they control access at the secret-path level, not at the identity level.

## Core concepts

| Concept | AWS | Azure | GCP | OnPrem (Vault) |
|---|---|---|---|---|
| Resource policy on key | Key Policy (JSON) | Access Policy or RBAC on vault | IAM bindings on key resource | Vault policy (HCL) on path |
| Temporary delegation | Grant (`CreateGrant`) + `RetireGrant` | No direct equivalent; SAS tokens on storage keys | No grant-like ephemeral concept | Vault token with TTL + policy |
| Service integration | `kms:ViaService` condition | Managed identity federation | Service agent IAM role | AppRole for service |
| Cross-account access | Key policy `Principal: arn:aws:iam::222222222222:root` | Cross-tenant key vault access via RBAC | IAM policy on key allowing external SA | Vault policy with bound claims |

### AWS grant lifecycle

```
CreateGrant (principal_a → principal_b, operations=[Decrypt], retiring_principal=principal_a)
   │
   ├── principal_b can now call kms:Decrypt using the grant token
   │
   └── RetireGrant (principal_a, or retiring_principal, revokes grant)
```

Grants are NOT visible in the key policy. They are stored separately and can only be listed via `ListGrants`. AWS services use grants internally — e.g., when an EC2 instance with an encrypted EBS volume is launched, EC2 service calls `CreateGrant` on your behalf to allow the hypervisor `kms:Decrypt` for that specific volume.

## AWS

**Key policies** are the primary access control for a KMS key. Without a key policy that allows access, *even the account root user cannot use the key*, even if IAM policies grant `kms:*`.

```bash
# 1. Create a CMK with a restricted key policy
aws kms create-key \
  --policy '{
    "Version":"2012-10-17",
    "Id":"key-default-1",
    "Statement":[
      {
        "Sid":"Enable IAM policies in the account",
        "Effect":"Allow",
        "Principal":{"AWS":"arn:aws:iam::111111111111:root"},
        "Action":"kms:*",
        "Resource":"*"
      },
      {
        "Sid":"Allow S3 service to use key for encryption",
        "Effect":"Allow",
        "Principal":{"Service":"s3.us-east-1.amazonaws.com"},
        "Action":["kms:Encrypt","kms:Decrypt","kms:ReEncrypt*","kms:GenerateDataKey*","kms:DescribeKey"],
        "Resource":"*",
        "Condition":{
          "StringEquals":{"kms:CallerAccount":"111111111111"},
          "StringLike":{"kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::example-security-lab-111111111111/*"}
        }
      }
    ]
  }' \
  --description "Key with S3-only service restriction"

# 2. Key policy with kms:ViaService — only S3 can call Decrypt through KMS
aws kms put-key-policy \
  --key-id alias/restricted-key \
  --policy-name default \
  --policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"AWS":"arn:aws:iam::111111111111:root"},
      "Action":"kms:*",
      "Resource":"*"
    },{
      "Effect":"Allow",
      "Principal":{"AWS":"arn:aws:iam::111111111111:role/s3-reader-role"},
      "Action":"kms:Decrypt",
      "Resource":"*",
      "Condition":{
        "StringEquals":{"kms:ViaService":"s3.us-east-1.amazonaws.com"}
      }
    }]
  }'

# 3. CreateGrant — Lambda needs temporary decrypt access for a specific ciphertext
aws kms create-grant \
  --key-id alias/restricted-key \
  --grantee-principal arn:aws:iam::111111111111:role/lambda-processor-role \
  --operations Decrypt \
  --retiring-principal arn:aws:iam::111111111111:role/admin-role \
  --constraints EncryptionContextSubset="{app=processor}"

# GrantToken is returned — pass it to Lambda
# Lambda uses the grant token in its KMS call:
aws kms decrypt \
  --ciphertext-blob fileb:///tmp/data.enc \
  --grant-tokens "GRANT_TOKEN_FROM_CREATE_GRANT"

# 4. List active grants on a key
aws kms list-grants --key-id alias/restricted-key

# 5. RetireGrant (revoke)
aws kms retire-grant --key-id alias/restricted-key --grant-id "GRANT_ID"
```

**Terraform grant pattern:**

```hcl
resource "aws_kms_key" "app" {
  description = "Key for app data encryption"
  policy      = data.aws_iam_policy_document.key_policy.json
}

resource "aws_kms_grant" "lambda_decrypt" {
  name              = "lambda-temp-decrypt"
  key_id            = aws_kms_key.app.key_id
  grantee_principal = aws_iam_role.lambda_exec.arn
  operations        = ["Decrypt"]
  retiring_principal = aws_iam_role.admin.arn
  constraints {
    encryption_context_subset = {
      app = "processor"
    }
  }
}
```

**Critical gotcha:** The default key policy created via console includes `"Principal": {"AWS": "arn:aws:iam::ACCOUNT_ID:root"}` which enables *all* IAM principals in the account to use the key if their IAM policy allows it. This is convenient but removes the key policy as a defense layer.

## Azure

Azure Key Vault supports two access models:

1. **Access Policies** (legacy, being deprecated): per-vault, identity-based permissions
2. **RBAC** (Azure role-based access control): granular per-key/secret/certificate permissions

```bash
# 1. Create vault with RBAC model (recommended)
az keyvault create \
  --name lab-vault-002 \
  --resource-group security-lab \
  --location eastus \
  --enable-rbac-authorization true

# 2. Assign Key Vault Crypto Officer role at vault scope
az role assignment create \
  --assignee "00000000-0000-0000-0000-000000000000" \
  --role "Key Vault Crypto Officer" \
  --scope "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/security-lab/providers/Microsoft.KeyVault/vaults/lab-vault-002"

# 3. Assign Key Vault Crypto User role at key scope (more granular)
az role assignment create \
  --assignee "00000000-0000-0000-0000-000000000000" \
  --role "Key Vault Crypto User" \
  --scope "/subscriptions/.../vaults/lab-vault-002/keys/app-key"

# 4. Access Policy model (legacy — still supported)
az keyvault set-policy \
  --name lab-vault-002 \
  --object-id "00000000-0000-0000-0000-000000000000" \
  --key-permissions encrypt decrypt get list \
  --secret-permissions get list

# 5. List access policies
az keyvault show --name lab-vault-002 \
  --query "properties.accessPolicies"
```

> (as of June 2026, Azure RBAC for Key Vault is GA and is the recommended permission model; the access policy (legacy) model has no formal retirement date announced, but the Azure portal defaults to RBAC for new vaults. Microsoft recommends migrating existing vaults to RBAC.)

**Azure "grant-like" pattern — SAS tokens on storage account keys (not KMS but analogous):**

```bash
az storage account generate-sas \
  --account-name securitylabstorage \
  --permissions r \
  --expiry $(date -u -d "+1 hour" +%Y-%m-%dT%H:%MZ) \
  --services b \
  --resource-types o \
  --https-only
```

## GCP

Cloud KMS uses IAM roles bound per key — there is no grant-like ephemeral delegation primitive. For temporary access, use short-lived service account keys or Workload Identity Federation tokens.

```bash
# 1. Grant crypto key encrypter/decrypter role on a specific key
gcloud kms keys add-iam-policy-binding app-key \
  --keyring app-keyring \
  --location global \
  --member "serviceAccount:processor-sa@project-id.iam.gserviceaccount.com" \
  --role roles/cloudkms.cryptoKeyEncrypterDecrypter

# 2. More granular roles:
#    roles/cloudkms.cryptoKeyEncrypter — encrypt only
#    roles/cloudkms.cryptoKeyDecrypter — decrypt only
#    roles/cloudkms.publicKeyViewer — asymmetric public key access
#    roles/cloudkms.admin — full management

# 3. View current IAM bindings on a key
gcloud kms keys get-iam-policy app-key \
  --keyring app-keyring \
  --location global

# 4. Simulated "temporary access" via IAM conditions (time-bound)
gcloud kms keys add-iam-policy-binding app-key \
  --keyring app-keyring \
  --location global \
  --member "serviceAccount:processor-sa@project-id.iam.gserviceaccount.com" \
  --role roles/cloudkms.cryptoKeyDecrypter \
  --condition "expression=request.time < timestamp('2026-12-31T23:59:59Z'),title=temp-access-expiry"

# 5. Cloud HSM key handle — set per-call
gcloud kms keys versions describe 1 \
  --key app-key-hsm \
  --keyring app-keyring \
  --location global
```

## OnPrem (HashiCorp Vault)

```hcl
# Vault policy (HCL) attached to the transit path
path "transit/encrypt/app-key" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/app-key" {
  capabilities = ["create", "update"]
}

path "transit/keys/app-key" {
  capabilities = ["read"]
}

# Append to this policy: no decrypt allowed on root-key
path "transit/decrypt/root-key" {
  capabilities = ["deny"]
}
```

```bash
# Write policy and create a short-lived token
vault policy write app-transit-policy /path/to/policy.hcl
vault token create -policy=app-transit-policy -ttl=1h

# Or use AppRole with secret_id TTL
vault write auth/approle/role/app-processor \
  token_policies="app-transit-policy" \
  secret_id_ttl=10m \
  token_ttl=30m
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Key-level access control | Vault path policy | Key policy (JSON) | Key Vault RBAC / access policy | IAM bindings on KMS key |
| Temporary delegation | Vault token TTL | `CreateGrant` / `RetireGrant` | SAS tokens (storage, not KMS) | IAM conditions with time expression |
| Service-to-service | AppRole auto-login | `kms:ViaService` grant | Managed identity federation | Service agent role |
| Cross-account/tenant | Vault policy with bound claims | Cross-account key policy | Cross-tenant RBAC assignment | IAM policy allowing external SA |
| Revocation method | `vault token revoke` | `RetireGrant` / `RevokeGrant` | Remove role assignment | Remove IAM binding |
| Audit | Vault audit log | CloudTrail (`CreateGrant`, `ListGrants`) | Activity Log | Cloud Audit Logs |

## 🔴 Red Team view

**Scenario 1: `kms:CreateGrant` to another account.** An attacker with `kms:CreateGrant` on a CMK in account A (111111111111) creates a grant allowing a role in attacker-controlled account B (222222222222) to decrypt. Since grants are not visible in the key policy and often unmonitored, this creates a silent cross-account data access path.

```bash
# Attacker in account 111111111111 (compromised role) creates a grant to their own account
aws kms create-grant \
  --key-id arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000 \
  --grantee-principal arn:aws:iam::222222222222:role/attacker-controlled \
  --operations Decrypt \
  --retiring-principal arn:aws:iam::222222222222:role/attacker-controlled

# Now from account 222222222222:
aws kms decrypt \
  --key-id arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000 \
  --ciphertext-blob fileb://exfiltrated-ciphertext.enc \
  --grant-tokens "$GRANT_TOKEN"
```

**Detection paired:** CloudTrail logs `CreateGrant` events. A grant where `granteePrincipal` is in a *different* account than the `sessionIssuer` is an immediate high-severity alert.

**Scenario 2: Key policy allows `Principal: "*"`** — a real misconfiguration seen in production where teams copy-paste an S3 bucket policy template onto a KMS key, accidentally allowing any AWS principal to use the key.

```bash
# The dangerous policy:
# "Principal": {"AWS": "*"}
# "Action": "kms:Decrypt"
# "Resource": "*"

# Attacker from any account:
aws kms decrypt \
  --key-id arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000 \
  --ciphertext-blob fileb://stolen-ciphertext.enc
# Works — no account restriction
```

**Detection paired:** Use SCP to deny wildcard principals. Audit with AWS Config rule `KMS_CMK_NOT_SCHEDULED_FOR_DELETION` + custom rule checking for wildcard.

**Artifacts left:**
- CloudTrail: `CreateGrant` with cross-account `granteePrincipal`
- CloudTrail: `PutKeyPolicy` if policy is modified to add wildcard
- CloudTrail: `Decrypt` from external account ARN (visible in the `userIdentity` field)

## 🔵 Blue Team view

**Detection signals:**

```
# CloudTrail query — cross-account CreateGrant
fields @timestamp, userIdentity.arn, requestParameters.granteePrincipal
| filter eventName = "CreateGrant"
| filter requestParameters.granteePrincipal NOT LIKE /arn:aws:iam::111111111111/
| stats count(*) by userIdentity.arn, requestParameters.granteePrincipal
```

```
# CloudTrail query — PutKeyPolicy with wildcard Principal
fields @timestamp, userIdentity.arn, requestParameters.policy
| filter eventName = "PutKeyPolicy"
| filter requestParameters.policy LIKE /"Principal".*:.*"\*"/
```

**Preventive controls:**

```bash
# SCP: Deny KMS key policies with wildcard (AWS Organizations)
# Attach to root OU
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": ["kms:PutKeyPolicy", "kms:CreateKey"],
    "Resource": "*",
    "Condition": {
      "StringLike": {
        "kms:KeyPolicyPrincipal": "*"
      }
    }
  }]
}
```

```bash
# Periodic grant listing script
#!/bin/bash
KEYS=$(aws kms list-keys --query "Keys[].KeyId" --output text)
for key in $KEYS; do
  echo "=== Key: $key ==="
  aws kms list-grants --key-id "$key" \
    --query "Grants[?GranteePrincipal!=null].[GrantId,GranteePrincipal,Operations]" \
    --output table
done
```

**Response steps:**
1. Identify all grants on compromised key: `aws kms list-grants --key-id <key>`
2. Revoke suspicious grants: `aws kms revoke-grant --key-id <key> --grant-id <id>`
3. Disable key: `aws kms disable-key --key-id <key>`
4. Rotate all data encrypted with that key

## Hands-on lab

```bash
# 1. Create a key with only the default account-root policy
aws kms create-key --description "Grant lab key" --region us-east-1
KEY_ID="arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000"

# 2. Create a grant for a specific role (only Encrypt, not Decrypt)
aws kms create-grant \
  --key-id "$KEY_ID" \
  --grantee-principal arn:aws:iam::111111111111:role/test-decrypt-role \
  --operations Encrypt \
  --retiring-principal arn:aws:iam::111111111111:role/admin-role

# 3. List grants — verify it exists
aws kms list-grants --key-id "$KEY_ID"

# 4. Assume the grantee role and attempt Decrypt (should fail — grant only Encrypt)
aws kms encrypt --key-id "$KEY_ID" --plaintext "test"  # Works
aws kms decrypt --ciphertext-blob fileb:///tmp/test.enc  # Fails: AccessDenied

# 5. Revoke the grant
aws kms revoke-grant --key-id "$KEY_ID" --grant-id "<GRANT_ID_FROM_STEP_3>"

# 6. Verify grant is gone
aws kms list-grants --key-id "$KEY_ID"

# Teardown
aws kms schedule-key-deletion --key-id "$KEY_ID" --pending-window-in-days 7
```

## Detection rules & checklists

```yaml
# Sigma-style: KMS key policy modification detected
title: KMS Key Policy Modified
logsource:
  service: cloudtrail
  events:
    eventSource: kms.amazonaws.com
    eventName: ["PutKeyPolicy", "CreateGrant"]
detection:
  put_key_policy:
    eventName: PutKeyPolicy
  create_grant:
    eventName: CreateGrant
  condition: put_key_policy or create_grant
  severity: medium
```

```bash
# CLI audit one-liner: find keys with cross-account grants
aws kms list-keys --query "Keys[].KeyId" --output text --region us-east-1 | while read key; do
  aws kms list-grants --key-id "$key" --region us-east-1 --query \
    "Grants[?GranteePrincipal.contains(@, ':222222222222:')].[KeyId,GranteePrincipal]" --output text
done

# Azure: list all key vault access policies
az keyvault list --query "[].name" -o tsv | while read vault; do
  az keyvault show --name "$vault" --query "properties.accessPolicies"
done
```

## References

- [AWS KMS Key Policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html)
- [AWS KMS Grants](https://docs.aws.amazon.com/kms/latest/developerguide/grants.html)
- [Azure Key Vault RBAC Guide](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide)
- [GCP Cloud KMS IAM Roles](https://cloud.google.com/kms/docs/reference/permissions-and-roles)
- See ATT&CK Cloud matrix for Privilege Escalation
- Cross-link: [02-06 — Permission Boundaries & Quarantine](../IAM/permission-boundaries-and-quarantine.md)
