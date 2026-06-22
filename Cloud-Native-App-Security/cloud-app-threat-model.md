# 01 — Cloud App Threat Model

> **Level:** Intermediate
> **Prereqs:** `../Fundamentals/kill-chain-attack-mapping.md`, `../Compute-Container-Security/serverless-function-security.md`
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Discovery, Collection
> **Authorization scope:** Model only your own application in a sandbox account. Do not model third-party applications without permission.

## What & why

A threat model maps components, data flows, and trust boundaries before code ships. For cloud-native apps this means surfacing *implicit* trust boundaries — especially the one between application code and the cloud metadata/control plane — that many teams overlook.

## The OnPrem reality

OnPrem threat models centered on a 3-tier: WAF → Tomcat/NGINX reverse proxy → app server → database. No metadata service, no IAM-role-as-process-identity. Trust boundaries were physical network segments (DMZ, app VLAN, DB VLAN).

## Core concepts

### Canonical 3-tier cloud app

```
┌──────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Client  │───▶│  API Gateway │───▶│  App (server-│───▶│  Managed DB  │
│ (browser)│    │  + WAF       │    │  less/cont.) │    │  (RDS/SQL)   │
└──────────┘    └──────────────┘    └──────┬───────┘    └──────────────┘
                                           │
                               ┌───────────┼───────────┐
                               ▼           ▼           ▼
                        ┌──────────┐ ┌──────────┐ ┌──────────┐
                        │  Object  │ │  IdP     │ │ Secrets  │
                        │  Store   │ │ (Cognito/│ │ Manager  │
                        │  (S3/Blob│ │  Entra)  │ │ (ASM/Key │
                        │  /GCS)   │ │          │ │  Vault)  │
                        └──────────┘ └──────────┘ └──────────┘
```

### Cross-cloud component mapping

| Component | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| API Gateway + WAF | NGINX + ModSecurity CRS | API Gateway + WAF | API Management + Front Door WAF | Apigee / API Gateway + Cloud Armor |
| App runtime | Tomcat / Gunicorn | Lambda / ECS Fargate | Functions / Container Apps | Cloud Functions / Cloud Run |
| Managed DB | Self-hosted Postgres | RDS / Aurora | Azure SQL / Cosmos DB | Cloud SQL / Spanner |
| Object store | MinIO / NFS | S3 | Blob Storage | Cloud Storage |
| IdP | Keycloak / FreeIPA | Cognito | Entra External ID | Identity Platform |
| Secrets store | HashiCorp Vault | Secrets Manager | Key Vault | Secret Manager |
| Queue / Event Bus | RabbitMQ / Kafka | SQS / SNS / EventBridge | Service Bus / Event Grid | Pub/Sub / Eventarc |

### Trust boundaries (marked with ═══ in diagram above)

1. **Client ↔ API Gateway** — external to internal; first authN checkpoint
2. **API Gateway ↔ App** — internal but distinct; gateway may forward claims
3. **App ↔ Managed DB** — data plane; connection auth (IAM DB auth or static creds)
4. **App ↔ Metadata/Control Plane** — the overlooked one; app code can call cloud APIs using the compute's attached role
5. **App ↔ Secrets Manager** — runtime credential retrieval
6. **App ↔ IdP** — token validation, user-info lookup
7. **App ↔ Object Store** — multi-tenant data storage per user

### STRIDE per trust boundary

| Boundary | S (Spoofing) | T (Tampering) | R (Repudiation) | I (Info Disclosure) | D (DoS) | E (Elevation) |
|---|---|---|---|---|---|---|
| Client ↔ Gateway | Stolen JWT/session | Request body tamper in-flight | No signed requests → deny action | Token in URL params | Rate-limit bypass | Forged claims in JWT |
| Gateway ↔ App | Internal caller forgery | Header stripping | Missing correlation IDs | Internal traffic sniffable if no mTLS | Gateway timeout → queued poison | Gateway passes overscoped token |
| App ↔ Metadata | **Implicit trust** — app role assumed always | — | — | Credentials leaked via SSRF | Metadata request rate-limit | App role → broader account access |
| App ↔ DB | Stolen connection string | SQL injection still applies | No audit trail per app-user | Connection-scoped access too broad | Connection pool exhaustion | DB IAM auth over-privileged |
| App ↔ Object Store | Pre-signed URL reuse | Object overwrite without version lock | No per-user bucket logging | Public bucket via app logic bug | — | Bucket-wide write from app role |
| App ↔ IdP | Accept multi-tenant tokens | Audience field ignored | Unknown issuer accepted | Token introspection leaks user data | IdP throttling → app denial | Forged `iss` bypass |

## AWS

**Canonical 3-tier AWS:**

```
Client → CloudFront(+WAF) → API Gateway(REST) → Lambda
                                                      │
                         ┌────────────────────────────┤
                         ▼            ▼               ▼
                       RDS        S3 bucket      Cognito User Pool
                   (IAM DB auth)  (presigned)    (JWT authorizer)
```

**STRIDE highlights for AWS:**
- Lambda execution role (metadata via env var `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`) often grants `s3:*`, `dynamodb:*`, `sqs:*` to the whole account. Threat model must ask: *if this Lambda is compromised, what AWS APIs can it call?*
- API Gateway Lambda authorizer token source: `method.request.header.Authorization`. Misconfiguration here means unauthenticated requests pass.
- Trust boundary App→Metadata is the `169.254.169.254` hop. If the app makes outbound HTTP calls to user-supplied URLs, this boundary evaporates (see [07-05](ssrf-and-cloud-metadata-from-app.md)).

## Azure

**Canonical 3-tier Azure:**

```
Client → Front Door(+WAF) → API Management → Container Apps / Functions
                                                      │
                         ┌────────────────────────────┤
                         ▼            ▼               ▼
                    Azure SQL     Blob Storage    Entra External ID
                  (managed ident) (user deleg SAS) (verify JWT)
```

**STRIDE highlights for Azure:**
- Managed identity is injected as an environment variable `IDENTITY_ENDPOINT`. Localhost `169.254.169.254` also works. Both must appear in the data-flow diagram.
- API Management `validate-jwt` policy: audience must be pinned to your API's Application ID URI. A loose audience accepts tokens minted for any app in the tenant.
- Object store SAS tokens can be scoped to container, blob, or service — the app's choice directly impacts blast radius.

## GCP

**Canonical 3-tier GCP:**

```
Client → Cloud Load Balancing(+Armor) → API Gateway / Cloud Endpoints → Cloud Run
                                                                              │
                                    ┌─────────────────────────────────────────┤
                                    ▼            ▼               ▼
                               Cloud SQL    Cloud Storage    Identity Platform
                            (IAM connector)  (signed URL)    (Firebase Auth)
```

**STRIDE highlights for GCP:**
- Cloud Run service account becomes the identity for *every* outbound API call from the container. The threat model must list what APIs that service account can invoke.
- `metadata.google.internal` (DNS → `169.254.169.254`) is available inside Cloud Run. SSRF from the app reaches it.
- Endpoints ESPv2 validates JWT via OpenAPI `securityDefinitions`. Omitted `x-google-issuer` means any Google-issued JWT passes.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| App identity | Service account (LDAP/Kerberos) | IAM Role on Lambda/ECS task | Managed Identity on Function/Container | Service Account on Cloud Run |
| Metadata surface | None | `169.254.169.254` | `169.254.169.254` + `IDENTITY_ENDPOINT` | `metadata.google.internal` |
| Gateway authN | NGINX `auth_request` | Lambda/Cognito authorizer | `validate-jwt` policy | ESPv2 / API Gateway JWT |
| DB auth | Username/password in config | IAM DB auth token | Managed Identity → AAD auth | Cloud SQL IAM connector |
| Object auth | NFS permissions | IAM + bucket policy | RBAC + SAS | IAM + signed URLs |

## 🔴 Red Team view

**What the trust boundary hides:**

The boundary between app code and the metadata service is almost never drawn on threat models. Developers treat the app as "just a process," but in cloud it's a *process with a role*. An SSRF vulnerability in the app is effectively a credential-access technique.

**Attack narrative (contained thought experiment on your own sandbox):**

1. Recon: Find an endpoint that fetches arbitrary URLs — e.g., a PDF renderer that takes `?url=https://...`.
2. The threat model didn't flag this as crossing the App→Metadata boundary.
3. Attacker supplies `http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role` (IMDSv1).
4. The app's Lambda/EC2 role creds are returned in the HTTP response.
5. Attacker uses those creds to enumerate S3 buckets, DynamoDB tables, SQS queues — all within the trust boundary but outside the app code.

**Artifacts left:**
- CloudTrail `GetCallerIdentity` from an IP outside the VPC (or from the app subnet at unusual hours).
- Metadata access logged by VPC flow logs showing port 80/HTTP to `169.254.169.254`.
- The attacker's source IP in application access logs for the SSRF-vulnerable endpoint.
- If IMDSv2 is enforced, the attacker sees `401 Unauthorized` — a detection signal.

## 🔵 Blue Team view

**Establish explicit trust-boundary controls:**

1. **IMDSv2 required** — set `HttpTokens=required` on all EC2 instances. For Lambda, accept that the env var injection is the only path (no IMDS in Lambda).
2. **Metadata endpoint in threat model** — add "App → Cloud Metadata" as a formal trust boundary in every data-flow diagram. Annotate with: *"This boundary is breached if the app makes outbound HTTP to user-supplied URLs."*
3. **Minimal execution roles** — scope the Lambda/ECS task role to only the specific resources and actions needed. Use resource-level conditions (`s3:prefix`, `dynamodb:LeadingKeys`).
4. **VPC endpoints with policies** — route everything through VPC endpoints that enforce `aws:SourceVpc` or `aws:SourceVpce`. If the app tries to reach AWS APIs from outside the VPC, the call fails.
5. **Outbound allowlist** — the app should only make HTTP calls to an explicit allowlist of domains (your own IdP, your own object store). Block `169.254.169.254` at the network/OS level.

**Detection signals:**

| Signal | Source | Query sketch |
|---|---|---|
| Metadata endpoint hit from app subnet | VPC Flow Logs | `dstAddr = 169.254.169.254 AND srcSubnet = app-subnet AND NOT srcAddr IN (known-bastion)` |
| GetCallerIdentity from unusual IP | CloudTrail | `eventName = "GetCallerIdentity" AND sourceIPAddress NOT IN (vpc-cidr)` |
| App outbound HTTP to metadata | Application logs (if app logs outbound URLs) | URL contains `169.254.169.254` |
| Role usage spike after app request | Correlate CloudTrail with ALB access logs | Time-based join on 5-min window |

## Hands-on lab

See [`labs/ssrf-to-imds-lab.md`](labs/ssrf-to-imds-lab.md) for a reproducible SSRF → metadata attack against a local Flask app.

## Worked Example: Full STRIDE on the Canonical 3-Tier Cloud App

This section fills out a complete STRIDE threat table for the canonical architecture (LB → app runtime → managed DB + object store + secrets + IdP). Each cell contains at least two concrete threats with specific cloud services. Use this as a starter template for your own threat model artifacts.

### S — Spoofing

| # | Threat | OnPrem | AWS | Azure | GCP |
|---|--------|--------|-----|-------|-----|
| S1 | Attacker forges client JWT with stolen signing key | JWKS endpoint hosted on internal root CA | Cognito `kid` header manipulation; Lambda authorizer ignores `iss` | Entra External ID token accepted by misconfigured `validate-jwt` with loose `issuer` | Identity Platform without `x-google-issuer` in ESPv2; Firebase custom token abuse |
| S2 | Internal service impersonation at Gateway→App boundary | NGINX header injection spoofing `X-Forwarded-User` | API Gateway adds `X-Forwarded-Proto` but app trusts it without verification; VPC Lattice service-to-service auth omitted | API Management missing `validate-jwt` inbound policy; forwarded `X-MS-CLIENT-PRINCIPAL-ID` accepted blindly | ESPv2 running without `x-google-audiences`; Cloud Run `--no-allow-unauthenticated` omitted |
| S3 | Metadata service impersonation (App→Metadata) | N/A (no metadata service) | Attacker DNS-poisoned `169.254.169.254` on compromised instance; app resolves via `/etc/hosts` override | `169.254.169.254` + `IDENTITY_ENDPOINT` env var; attacker sets env var to controlled endpoint | `metadata.google.internal` in `/etc/hosts` pointed to attacker-controlled IP after kernel-level compromise |
| S4 | Pre-signed URL reuse across sessions | Hash-based token generation with predictable seed | S3 pre-signed URL with no `X-Amz-Expires` cap; URL leaked in client-side JavaScript | Azure SAS token with `st=2023-01-01&se=2030-12-31` (unbounded expiry); no stored access policy | GCS signed URL with `Expires` header set to max (+7 days); V4 signing key brute-force feasible if HMAC key leaked |

### T — Tampering

| # | Threat | OnPrem | AWS | Azure | GCP |
|---|--------|--------|-----|-------|-----|
| T1 | Request body modified between CloudFront/WAF and origin | TLS terminated at CDN edge; origin uses HTTP (plaintext) between CDN and ALB | CloudFront → ALB on port 80; attacker MITM within AWS backbone (low probability, but vetted in threat model) | Front Door → origin over HTTP; `X-Forwarded-For` stripped by intermediary | Cloud CDN → backend service without mTLS; `X-Cloud-Trace-Context` injected by untrusted proxy |
| T2 | Object overwrite in storage (versioning absent) | NFS mount with `no_root_squash` → any container can overwrite | S3 bucket without versioning or Object Lock; app writes `public-read` ACL via `PutObjectAcl` | Blob Storage without soft delete or versioning; container-level SAS grants `write` on all blobs | GCS bucket without object versioning or retention policy; `storage.objects.create` overwrites existing object silently |
| T3 | API Gateway policy modified by compromised CI/CD pipeline | NGINX config deployed via Ansible with no integrity check | API Gateway `aws apigateway put-rest-api` called by overscoped CodeBuild role | API Management policy XML pushed via `az apim api import` by DevOps SPN with `Contributor` on API Management | ESPv2 config deployed via Cloud Build service account with `roles/apigateway.admin` |
| T4 | Secrets Manager value rotated to attacker-controlled value | HashiCorp Vault `vault write secret/app/db-password value=attacker` by compromised orchestrator | `secretsmanager:PutSecretValue` with no `kms:Decrypt` resource-level condition for rotation role | Key Vault `az keyvault secret set` by SPN with `Key Vault Secrets Officer`; no RBAC separation between read and write | Secret Manager `secretmanager.versions.access` + `secretmanager.versions.add` on same SA; no version pinning in app |

### R — Repudiation

| # | Threat | OnPrem | AWS | Azure | GCP |
|---|--------|--------|-----|-------|-----|
| R1 | App action not attributable to specific end-user | App logs `user_id` but no signed audit trail; DB `updated_by` column nullable | RDS Data API with IAM DB auth — `rds-db:connect` maps to DB role not end-user; must propagate Cognito `sub` through app layer | Azure SQL with managed identity — `OBJECT_ID()` returns SPN, not end-user; must add `userId` column manually in schema | Cloud SQL IAM connector maps SA to DB user; end-user identity lost unless app layer injects `session_user()` parameter |
| R2 | Object store operation not logged per-principal | Self-hosted MinIO with audit logging disabled by default | S3 Server Access Logging not enabled; CloudTrail Data Events disabled — `s3:GetObject` not captured; Data Events cost opt-out by team | Blob Storage diagnostic settings not configured; `StorageRead` and `StorageWrite` logs not forwarded to Log Analytics workspace | GCS audit logging with `DATA_READ` and `DATA_WRITE` not configured; Admin Read logs only capture IAM changes, not object access |
| R3 | IdP token issuance not logged | FreeIPA with `audit` log to local disk only | Cognito CloudTrail captures `InitiateAuth` but not the resulting token content; no per-user token hash logging | Entra ID sign-in logs capture success/failure but `tokenIssuance` events require P2 license | Identity Platform `google.cloud.identitytoolkit.v1.AuthenticationService.SignIn` logs event but not JWT payload hash |

### I — Information Disclosure

| # | Threat | OnPrem | AWS | Azure | GCP |
|---|--------|--------|-----|-------|-----|
| I1 | App responses leak cloud resource identifiers | Error page shows internal IP `10.x.x.x` or LDAP DN | Lambda error stack trace returned via API Gateway with `AWS_ACCESS_KEY_ID` prefix in environment dump; `x-amzn-RequestId` in headers leaks Lambda ARN | Azure Functions runtime error page shows `InstrumentationKey` and storage account name in HTML body | Cloud Run `500` response includes `X-Cloud-Trace-Context` header with project ID prefix; stack trace with SA email |
| I2 | Object store enumeration via differentiated error codes | Apache directory listing enabled on static asset mount | `s3:GetObject` on non-existent key returns `NoSuchKey` vs `AccessDenied` (enumerates existence); Public bucket with `ListBucket` enabled | Blob `AnonymousAccess` returns `ContainerNotFound` vs `AuthenticationFailed` — allows container name enumeration | GCS returns `404 Not Found` vs `403 Forbidden` — bucket name enumeration; `allUsers` with `storage.objects.list` |
| I3 | DB connection parameters exposed in source code / environment | JDBC string in `web.xml` | RDS Proxy endpoint in Lambda env vars exposed via `lambda:GetFunctionConfiguration`; Secrets Manager ARN in `template.yaml` | SQL connection string with `User Id=sa` in App Service `appsettings.json` source control | Cloud SQL connection name in `cloudbuild.yaml`; `app.yaml` with instance connection name (not secret) |
| I4 | Metadata service credentials exfiltrated via SSRF | N/A | IMDSv1 `GET http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name` returns AKID + SecretKey + Token in plaintext | `GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com` returns JWT access token | `GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` returns OAuth2 access token; no token header required in some configurations |

### D — Denial of Service

| # | Threat | OnPrem | AWS | Azure | GCP |
|---|--------|--------|-----|-------|-----|
| D1 | API Gateway/WAF throttled by volumetric attack | NGINX `limit_req_zone` bypassed by distributed source IPs | API Gateway throttled: 10K req/sec per account soft limit; WAF unblockable if IPs rotate faster than rate-based rule window | API Management `rate-limit-by-key` evaded by IP rotation; Front Door WAF `anomalyScoring` threshold lifted by slow-and-low pattern | Cloud Armor rate-based rules with 60s sliding window evaded by 1 req/61s across 10K bot IPs |
| D2 | Lambda/Function cold start amplification | Keepalive connection pool to Tomcat exhausted → request queued at reverse proxy | Lambda reserved concurrency exhausted → `429 Too Many Requests`; EventBridge `PutEvents` throttled → events silently dropped (if DLQ not configured) | Functions `functionAppScaleLimit` hit → 429; Service Bus queue depth grows beyond `MaxDeliveryCount` → poison messages discarded | Cloud Run `--max-instances` cap hit → 429; Pub/Sub push subscription backlog grows beyond 7-day retention → messages lost |
| D3 | DB connection pool saturation from single identity | `max_connections=100` on Postgres; connection-per-request from app | RDS Proxy `MaxConnectionsPercent=90`; Lambda with default `max_connections=1` per instance creates `N` connections across concurrency burst | Azure SQL Database DTU model: `log_write_percent=100` stalls all connections; Hyperscale connection routing overload on read replicas | Cloud SQL `max_connections` default = `4000 / (memory_mb / 128)`; IAM connector with no pooling library → new connections per request |
| D4 | Storage request rate limit exceeded → app write failures | NFS server `nfsd` thread exhaustion | S3 `503 Slow Down` on >3500 PUT/COPY/POST/DELETE per second per prefix; no automatic retry with exponential backoff in app code | Storage account `503 Server Busy` on >20K requests/sec; Blob but no Queue/Table for retry mechanism | GCS `429 Too Many Requests` on >1000 writes/sec per bucket; `X-Retry-After` header ignored by gcloud SDK default retry |

### E — Elevation of Privilege

| # | Threat | OnPrem | AWS | Azure | GCP |
|---|--------|--------|-----|-------|-----|
| E1 | `iam:PassRole` allows Lambda to assume a more privileged role | N/A — no IAM role concept | Lambda execution role has `iam:PassRole` + `lambda:CreateFunction`; attacker creates new Lambda with `AdministratorAccess` role, then invokes it to escalate | Azure Function with `Microsoft.Web/sites/functions/write` + `Microsoft.Authorization/roleAssignments/write` → assigns Owner to itself | Cloud Run SA with `iam.serviceAccounts.actAs` + `run.services.create` → deploys new revision with `roles/editor` SA |
| E2 | S3 bucket policy modification via app role | N/A | App role with `s3:PutBucketPolicy`; SSRF → metadata → creds → `PutBucketPolicy Principal: *` → public bucket → data exfil | App managed identity with `Microsoft.Storage/storageAccounts/blobServices/containers/write` → sets container ACL to `blob` (public) | App SA with `storage.buckets.setIamPolicy` → adds `allUsers` with `roles/storage.objectViewer` |
| E3 | IdP token forgery via misconfigured trust | Keycloak realm `accessTokenLifespan=99999` → token never expires | Cognito Identity Pool accepts token from *any* OpenID provider (`Cognito` vs `Custom`); attacker registers own OIDC provider in pool | Entra ID B2B accepts guest token from any tenant (`"iss": "https://login.microsoftonline.com/attacker-tenant/v2.0"`); `allowedAudiences` wildcard | Identity Platform `oauthIdpConfig` with loose `clientId=*` → accepts token from attacker's OAuth app |
| E4 | Privilege escalation via managed policy attachment | `sudoers` file misconfig → `sudo -i` | `iam:AttachRolePolicy` + `iam:CreatePolicy` on app role; app code (via SSRF) calls `AttachRolePolicy` with `arn:aws:iam::aws:policy/AdministratorAccess` | `Microsoft.Authorization/roleAssignments/write` on app SPN; attacker adds `Owner` role at subscription scope | App SA with `resourcemanager.projects.setIamPolicy` adds itself as `roles/owner` on parent project |

### Service-per-category cheat sheet

| STRIDE | Top AWS service to scrutinize | Top Azure service | Top GCP service |
|--------|------------------------------|-------------------|-----------------|
| S — Spoofing | API Gateway authorizer + IAM trust policies | `validate-jwt` policy in APIM | ESPv2 `securityDefinitions` in OpenAPI spec |
| T — Tampering | S3 Object Lock + KMS CMK for encryption context | Blob immutable storage with WORM policy | GCS retention policy + `kmsKeyName` encryption |
| R — Repudiation | CloudTrail Data Events for S3/DynamoDB | Storage Analytics Logs + Log Analytics workspace | Data Access audit logs for GCS/Cloud SQL |
| I — Info Disclosure | SSRF → IMDS → credential leak | `IDENTITY_ENDPOINT` env var in App Service | `metadata.google.internal` in Cloud Run / GCE |
| D — DoS | S3 rate limits (3,500 PUT/sec per prefix) | API Management `rate-limit-by-key` + Service Bus DLQ | Cloud Armor adaptive protection + Pub/Sub dead letter topics |
| E — Elevation | `iam:PassRole` on Lambda execution role | `Microsoft.Authorization/roleAssignments/write` | `iam.serviceAccounts.actAs` on Cloud Run SA |

## Data-Flow Diagram Walkthrough (Trust Boundaries)

Below is the canonical 3-tier app with trust boundaries explicitly annotated. Each `════` boundary is a security decision point that must be defended with explicit controls.

```
                        TRUST BOUNDARY 1: PUBLIC ↔ INTERNAL
    ┌──────────┐           ══════════════════════            ┌──────────────────┐
    │  Client  │──────────▶║  EXTERNAL NETWORK  ║──────────▶│ API Gateway/WAF  │
    │ (browser)│           ══════════════════════            │  + CDN edge      │
    └──────────┘                                            └────────┬─────────┘
                         Controls:                                    │
                         • TLS 1.2+ termination                       │
                         • WAF rule set (OWASP Top 10)           ═════╧═════
                         • JWT/OAuth2 token validation           ║         ║
                         • Rate limiting per client IP           ║  TRUST BOUNDARY 2
                         • Bot detection                         ║  GATEWAY ↔ APP
                                                                 ║         ║
                                                     ┌───────────┴───╗     ║
                                                     │  App Runtime   ║     ║
                                                     │  (Lambda /     ║     ║
                                                     │  Cloud Run /   ║     ║
                                                     │  Container App)║     ║
                                                     └───┬───┬───┬───┘     ║
                           Controls:                      │   │   │         ║
                           • mTLS or VPC-internal         │   │   │         ║
                           • Auth header forwarding       │   │   └─────────╝
                           • Correlation ID propagation   │   │
                           • Minimal execution role       │   │
                                                          │   │
               ╔══════════════════════════════════════════╝   ╚══════════════╗
               ║  TRUST BOUNDARY 3: APP ↔ DATA PLANE                       ║
               ║                                                            ║
        ┌──────╨─────┐   ┌──────╨─────┐   ┌──────╨─────┐   ║  ┌──────╨─────┐
        │   Managed  │   │  Object    │   │    IdP     │   ║  │  Secrets   │
        │   Database │   │  Store     │   │  (Identity │   ║  │  Manager   │
        │  (RDS etc) │   │ (S3 etc)   │   │   Provider)│   ║  │  (KMS etc) │
        └────────────┘   └────────────┘   └────────────┘   ║  └────────────┘
                                                            ║
        Controls:                                           ║
        • IAM DB auth (no static creds)                     ║
        • Pre-signed URL with min TTL                       ║
        • JWT issuer/audience pinning                       ║
        • Secret rotation + version pinning                 ║
                                                            ║
               ╔════════════════════════════════════════════╝
               ║  TRUST BOUNDARY 4: APP ↔ CONTROL PLANE (METADATA)
               ║
        ┌──────╨─────────────────────────────────────────────┐
        │  Cloud Metadata Service (169.254.169.254 / equiv)  │
        │  → IAM credentials for attached compute role       │
        │  → Instance/function identity                      │
        └────────────────────────────────────────────────────┘
                    Controls:
                    • IMDSv2 required (PUT + token hop)
                    • Outbound network allowlist (block 169.254.169.254 from app egress)
                    • SSRF input validation on all user-supplied URLs
                    • NetworkPolicy / SecurityGroup: deny app subnet → metadata IP
                    • CloudTrail / Audit Log alert on GetCallerIdentity from non-VPC IP
```

### How to use this walkthrough in a threat-modeling session

1. **Print the diagram.** Tape it to a whiteboard.
2. **Walk each data flow left to right.** For each arrow, ask: _"What identity does the caller present? Is it claimed or verified? What if the caller is an attacker who already controls the source component?"_
3. **Mark cross-boundary calls in red.** Every arrow crossing a `════` line is a potential attack path. Prioritize boundaries where the caller identity changes (e.g., Client→Gateway: unauthenticated → authenticated).
4. **Map misconfigurations to boundaries.** For example, "S3 bucket policy allows `Principal: *`" maps to Boundary 3 (App↔Object Store). "API Gateway missing authorizer" maps to Boundary 1 (Client↔Gateway).
5. **Update the STRIDE table.** Add rows for threats discovered during the walkthrough. The table in the Worked Example above is a starting point, not exhaustive.

Cross-links: [SSRF and Cloud Metadata](../Network-Security/ssrf-and-imds-pivots.md) for Boundary 4 deep-dive; [Assume-Role Chains](../IAM/assume-role-chains.md) for Boundary 2 identity propagation.

## Common Threat Model Gaps in Cloud-Native Apps

These gaps appear in nearly every first-pass cloud threat model. Audit your model against this list before declaring it complete.

### Gap 1: The CI/CD Pipeline Isn't in the Diagram

Most teams draw the runtime architecture (LB → app → DB) and stop. But the CI/CD pipeline — CodeBuild, GitHub Actions, Cloud Build — is a *trusted path into production*. It deploys IAM policies, sets environment variables, and pushes container images. A compromised pipeline can inject a backdoored Lambda or modify the WAF policy to bypass all runtime controls.

**Fix:** Add a "Deployment → Runtime" trust boundary. Ask: *"Who can push to main? What IAM permissions does the CI/CD role have? Can it modify IAM policies on the production role?"*

### Gap 2: The Event Bus / Queue Is a Blind Spot

The diagram shows App → DB and App → Object Store, but omits the async path: App → SQS/SNS/EventBridge → downstream consumer. This path often has its own IAM role, its own dead-letter queue, and its own encryption key — all outside the diagram's scope.

**Fix:** Trace every event path end-to-end. For each queue/topic, ask: *"Who can publish? Who can subscribe? Is the message encrypted? Is there a DLQ, and who can read dead letters?"*

### Gap 3: The IdP Trust Model Is Assumed, Not Verified

Teams drop a Cognito/Entra/Identity Platform box on the diagram and assume it "handles auth." But the threat model must ask: *"What tokens does the IdP issue? What's in the JWT payload? Does the app validate audience, issuer, and expiry? What happens if the IdP is multi-tenant and accepts tokens from other tenants?"*

**Fix:** Document the exact JWT validation code path. List the fields validated (`iss`, `aud`, `exp`, `iat`, `token_use`). Flag any field that is accepted but not validated.

### Gap 4: Ephemeral Compute = Ephemeral Audit Trail

Lambda/Functions/Cloud Run instances live minutes, not months. If the app logs to stdout only, and the log group retention is 3 days, the audit trail for a breach discovered 2 weeks later is gone.

**Fix:** The threat model must annotate the log retention policy per component. Data-flow arrows should show log destinations (CloudWatch Logs, Log Analytics, Cloud Logging) and retention periods. A component with no persistent audit trail is a repudiation threat.

### Gap 5: The "Dev Only" Assumption

The threat model says "this is a dev account, no sensitive data, threat level is low." But the dev account has IAM roles that can `sts:AssumeRole` into production (for cross-account CI/CD). The dev account has a copy of the production RDS snapshot (for debugging). The dev account has the same third-party API keys as production (because someone copy-pasted the `.env` file).

**Fix:** The scope of the threat model must include cross-account trust relationships. If Account A trusts Account B's role, then Account B's threat model *is* Account A's threat model. Draw an arrow showing the `AssumeRole` trust and treat it as a boundary.

### Pre-Deployment Threat Model Checklist

- [ ] All four trust boundaries (Public, Gateway↔App, App↔Data Plane, App↔Control Plane) are explicitly drawn
- [ ] CI/CD pipeline and its IAM role appear in the diagram
- [ ] Every async path (queues, topics, event buses) is traced end-to-end
- [ ] JWT validation code path is documented: which fields are validated, which are ignored
- [ ] Log retention policy is annotated per component; no component has stdout-only logging with <90 day retention
- [ ] Cross-account `AssumeRole` trusts appear as data-flow arrows
- [ ] STRIDE table has at least 2 threats per category with specific cloud service names
- [ ] IMDS/control-plane boundary has an explicit control (IMDSv2, network block, or SSRF input validation)
- [ ] Every IAM role in the diagram lists its maximum blast radius (what resources can it access?)
- [ ] Pre-signed URLs and SAS tokens have explicit TTL and scope documented

## References

- OWASP Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- AWS Well-Architected — Security Pillar threat modeling: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/threat-modelling.html
- Microsoft Threat Modeling Tool (STRIDE): https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool
- ATT&CK Cloud Matrix: https://attack.mitre.org/matrices/enterprise/cloud/
- See also: `../Network-Security/ssrf-and-imds-pivots.md` for IMDS deep-dive.
- See also: `../IAM/authn-flows-and-tokens.md` for token validation patterns.
