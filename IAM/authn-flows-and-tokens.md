# 02 — Authentication Flows & Tokens

> **Level:** Intermediate
> **Prereqs:** [Identity Primitives per Cloud](identity-primitives-per-cloud.md) (Identity Primitives Per Cloud)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Lateral Movement
> **Authorization scope:** Identity attacks only in your own sandbox accounts / sanctioned targets.

## What & why

How a request becomes authenticated: STS assume-role tokens, OAuth2/OIDC flows, JWT structures. Token lifetime and audience define attack surface — a misconfigured audience or long TTL hands an attacker a valid credential.

## The OnPrem reality

Kerberos was the dominant on-prem authn flow: a user authenticates to the KDC, receives a TGT (Ticket-Granting Ticket, lifetime ~10h by default), then trades that TGT for service tickets (STs) to access individual resources. The TGT was cached in memory (LSASS / `/tmp/krb5cc_*`), and root could extract it with Mimikatz. Silver tickets (forged STs) and Golden tickets (forged TGTs with the KRBTGT hash) were the ultimate attack artifacts. Cloud tokens inherit the same challenge: a stolen token is a stolen identity.

## Core concepts

### Token types comparison

| Property | AWS STS | Azure Entra | GCP OAuth2 | Kerberos (OnPrem) |
|---|---|---|---|---|
| Issuer | `sts.amazonaws.com` | `login.microsoftonline.com/{tenant}/v2.0` | `https://accounts.google.com/o/oauth2/v2/auth` | Domain KDC |
| Format | Proprietary (AccessKeyId + SecretAccessKey + SessionToken) | JWT (access_token + id_token) | JWT access_token | ASN.1 DER-encoded ticket |
| Default TTL | 1 hour (max 12h chained) | 1 hour (access); 1 hour (id) | 1 hour | 10 hours (TGT); 10 hours (ST) |
| Audience concept | Principal + role ARN (implicit) | `aud` claim (e.g., `https://management.azure.com`) | `aud` claim (e.g., `https://compute.googleapis.com`) | SPN (Service Principal Name) |
| Replay detection | Session token binds to exact region/IP (implicit) | Token binding optional; refresh token rotation | Refresh token rotation | ST is scoped to SPN + timestamp |
| Refresh mechanism | Re-assume role (no refresh token) | Refresh token (90d default, rolling expiry) | Refresh token (rolling expiry) | Re-authenticate to KDC for new TGT |

### OAuth2/OIDC grant flow (simplified)

```
Client App  ──(1) authorize request──▶  Identity Provider (IdP)
Client App  ◀──(2) authorization code──  Identity Provider (IdP)
Client App  ──(3) code + client_secret─▶ Token Endpoint
Client App  ◀──(4) access_token + id_token + refresh_token──  Token Endpoint
Client App  ──(5) access_token as Bearer──▶  Resource Server
```

The key security property: the authorization code is a one-time, short-lived (60s) intermediary; the client secret that exchanges it never hits the browser.

## AWS

AWS uses its own token format: the STS (Security Token Service) issues temporary credentials composed of `AccessKeyId`, `SecretAccessKey`, and `SessionToken`. The SessionToken is mandatory — the credential pair is invalid without it.

**Obtain an STS session token:**

```bash
aws sts get-session-token --duration-seconds 3600

# Output contains:
# AccessKeyId: ASIA...
# SecretAccessKey: ...
# SessionToken: FwoGZXIvYXdz...
# Expiration: 2026-06-22T11:00:00Z
```

**Assume a role:**

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/TargetRole \
  --role-session-name IntermediateRoleSession \
  --external-id "placeholder-external-id-12345"

# Decode the session with:
aws sts get-caller-identity
```

**Key properties of AWS STS tokens:**
- `ASIA*` prefix indicates temporary credentials (IAM Users get `AKIA*` static keys).
- No JWT — you cannot decode these offline to inspect claims.
- SessionToken is an opaque string that AWS validates server-side.
- Chained assume-role calls (role A → role B → role C) reduce maximum duration to 1 hour per hop (max 12h total).

## Azure

Azure Entra ID issues standard OAuth2 JWTs. The two primary tokens are:
- **access_token**: for `Authorization: Bearer` to ARM/Graph APIs
- **id_token**: OpenID Connect identity claims (name, email, groups)

**Obtain tokens via Managed Identity:**

```bash
# From inside an Azure VM with system-assigned managed identity
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com"

# Response (simplified):
# {
#   "access_token": "eyJ0eXAiOiJKV1Q...",
#   "expires_on": "1719000000",
#   "resource": "https://management.azure.com"
# }
```

**Decode the JWT:**

```bash
# Split on '.' and base64 decode the payload (second segment)
echo "eyJ0eXAiOiJKV1Q..." | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# Key claims to inspect:
# {
#   "aud": "https://management.azure.com",
#   "appid": "00000000-0000-0000-0000-000000000000",
#   "tid": "00000000-0000-0000-0000-000000000000",
#   "oid": "...",
#   "groups": ["..."],
#   "scp": "user_impersonation"
# }
```

**Service principal with secret → token:**

```bash
az login --service-principal \
  -u 00000000-0000-0000-0000-000000000000 \
  -p "PLACEHOLDER_CLIENT_SECRET" \
  --tenant example-tenant.onmicrosoft.com

az account get-access-token --resource https://management.azure.com
```

**Gotcha:** The `aud` (audience) claim in an Azure token does not restrict which API the token can call — it only states which resource the token was *intended* for. An attacker with an access token for `https://graph.microsoft.com` cannot use it against `https://management.azure.com` unless the app has the correct delegated permissions, but confusing these audiences is a common misconfiguration.

## GCP

GCP uses OAuth2 access tokens, issued by `https://www.googleapis.com/auth/...`. Each scope maps to a service API. A single token can have multiple scopes.

**Obtain an access token:**

```bash
# Using gcloud
gcloud auth print-access-token

# Using the metadata server (from inside GCE)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Decode JWT id_token (different from access_token — used for OIDC federation)
gcloud auth print-identity-token

# Print base64-decoded claims
gcloud auth print-identity-token | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

**Key GCP token properties:**
- `access_token` is opaque (not decodable as JWT, despite being base64).
- `id_token` is a full JWT with `aud`, `sub`, `email` claims — used for workload identity federation (see [long-lived-keys-vs-workload-identity.md](./long-lived-keys-vs-workload-identity.md)).
- Scopes are additive: if a token has `cloud-platform` scope, it covers most APIs.
- SA impersonation chains follow similar chaining rules to AWS assume-role (see [assume-role-chains-and-trust-graphs.md](./assume-role-chains-and-trust-graphs.md)).

## OnPrem mapping (recap table)

| Concern | OnPrem (Kerberos) | AWS (STS) | Azure (Entra OAuth2) | GCP (OAuth2) |
|---|---|---|---|---|
| Token type | TGT / ST (ASN.1) | STS credentials (opaque) | JWT access/id tokens | Opaque access + JWT id_token |
| Obtain token command | `kinit` / `psexec` | `aws sts assume-role` | `az account get-access-token` | `gcloud auth print-access-token` |
| Inspect claims | `klist -e` (enc type + lifetime) | No offline decode possible | `jwt.ms` or decode base64 | Decode id_token JWT payload |
| Max lifetime | 10h TGT; 10h ST | 1h (configurable up to 12h) | 1h default (configurable) | 1h default |
| Refresh | Re-auth to KDC | Re-assume role | Refresh token (90d rolling) | Refresh token (rolling) |
| Steal from compromised host | Dump LSASS (Mimikatz) | Read `~/.aws/credentials` or env vars | Read `~/.azure/msal_token_cache.json` | Read `gcloud` creds from metadata/implicit | Scopes (data plane) |

## 🔴 Red Team view

**Confused deputy attacks.** A confused deputy is a service that's tricked into misusing its authority on behalf of an attacker. In cloud terms: if Service A has permission to call Service B and an attacker can influence *what* Service A requests, the attacker gets Service B's data using Service A's permissions.

**Example — over-permissive audience in Azure:**

An app registration has delegated permission `Microsoft Graph: User.Read.All` with audience `https://graph.microsoft.com`. A developer copies the app registration and changes the redirect URI during a CI/CD configuration but forgets that the token's `aud` lists both the original app and the graph audience. If an attacker obtains an id_token intended for the CI app (audience = `api://ci-app-id`), but that same token is accepted by the graph because the app registration also holds `User.Read.All` grant — the attacker uses the token cross-context.

**Chained token forwarding:**

```bash
# In a compromised CI runner, the attacker extracts a token minted for terraform
curl -H "Authorization: Bearer $(curl -s \
  http://169.254.169.254/latest/meta-data/identity/oauth2/token?resource=https://management.azure.com \
  | jq -r .access_token)" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01"

# If the token has no audience restriction beyond management.azure.com,
# the attacker enumerates all subscriptions the MI can see.
```

**Contained example — AWS STS token replay:**

```bash
# Attacker obtains STS session token from a compromised Lambda env variable
export AWS_ACCESS_KEY_ID=ASIAEXAMPLEACCESSKEY
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY  
export AWS_SESSION_TOKEN=FwoGZXIvYXdzE...

# Verify the token is live
aws sts get-caller-identity

# Enumerate reachable roles (see assume-role-chains-and-trust-graphs.md)
aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS=='arn:aws:iam::111111111111:root']].RoleName"
```

**Artifacts:** CloudTrail records `AssumeRole` events with the `sourceIPAddress`, `userAgent`, and the `roleSessionName`. The STS token's `SessionToken` is ephemeral and will expire within the default 1-hour window, limiting the attack window if detected. Repeated `AssumeRole` calls in rapid succession from a single session are abnormal.

## 🔵 Blue Team view

**Preventive controls:**

1. **Audience pinning.** In Azure, use `accessTokenAcceptedVersion: 2` and validate the `aud` claim server-side. In OIDC federation (AWS/GCP), restrict the audience to the specific cloud provider (`sts.amazonaws.com` or `https://iam.googleapis.com/projects/...`).

2. **Token lifetime reduction.** Reduce STS session duration to 15 minutes for privileged operations. Azure: set token lifetime via Conditional Access session controls. GCP: use IAM Conditions with `duration` bounded.

3. **Condition-based token issuance.**
```json
// AWS trust policy with strict conditions
{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::111111111111:role/SourceRole"},
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "placeholder-external-id-12345"
    },
    "StringLike": {
      "aws:PrincipalArn": "arn:aws:iam::111111111111:role/SourceRole"
    }
  }
}
```

**Detection queries:**

```
-- AWS CloudTrail Lake: detect assume-role from unusual User-Agent
SELECT eventTime, userIdentity.arn, sourceIPAddress, userAgent
FROM "00000000-0000-0000-0000-000000000000"."CloudTrail_111111111111"
WHERE eventName = 'AssumeRole'
  AND userAgent NOT LIKE '%aws-cli%'
  AND userAgent NOT LIKE '%console.amazonaws.com%'
ORDER BY eventTime DESC
LIMIT 50

-- Azure Activity Log: detect non-standard token issuance
AzureActivity
| where OperationNameValue contains "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS"
| where Caller contains "appid"
```

**Monitoring signals:**
- `sts:AssumeRole` from IPs outside known corporate egress ranges.
- Token TTL requests > 1 hour (indicates automation trying to maximize persistence).
- Access token requests for audiences never used by your estate (e.g., `https://graph.microsoft.com` when only `management.azure.com` is expected).

## Hands-on lab

1. **Obtain and inspect AWS STS token:**
```bash
aws sts get-session-token --duration-seconds 900
# Record the Expiration time — verify it's ~15 minutes from now.
aws sts get-caller-identity
```

2. **Obtain and inspect Azure JWT:**
```bash
az login
TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)
echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '{aud,tid,oid,exp,iat}'
```

3. **Obtain and inspect GCP id_token:**
```bash
gcloud auth print-identity-token | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '{aud,sub,email,exp,iat}'
```

4. **Observe token expiry:** Wait 15 minutes and re-run the AWS `get-caller-identity` using the STS token credentials — confirm the error (`ExpiredToken`).

**Teardown:** Run `unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN` to clear the STS session from environment.

## Detection rules & checklists

**CSPM — flag tokens with TTL > 1 hour:**
```yaml
# Cloud Custodian policy
- name: assume-role-ttl-check
  resource: iam-role
  filters:
    - type: value
      key: max_session_duration
      value: 3600
      op: gt
```

**Checklist:**
- [ ] No role allows `MaxSessionDuration` > 1 hour without documented exception.
- [ ] All assume-role trust policies include `sts:ExternalId`.
- [ ] Conditional Access policies enforce session lifetime ≤ 1h for privileged roles.
- [ ] GCP Org Policy `constraints/iam.allowServiceAccountCredentialLifetimeExtension` enforced.

## References
- [AWS STS API](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html)
- [Azure AD token overview](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [GCP OAuth2 access tokens](https://cloud.google.com/docs/authentication/token-types)
- [MITRE ATT&CK — Unsecured Credentials (T1552)](https://attack.mitre.org/techniques/T1552/)
- [Confused deputy problem (AWS article)](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
