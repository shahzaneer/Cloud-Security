# 02 — Recon, OSINT & Fingerprinting Cloud Tenants

> **Level:** Fundamental–Intermediate
> **Prereqs:** [Methodology & PTES For Cloud](methodology-and-PTES-for-cloud.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Reconnaissance (T1590, T1594, T1526), Discovery
**Authorization scope:** Run only against your own sandbox accounts / sanctioned engagement with written authorization. All targets use placeholders.

## What & why
Cloud recon enumerates a target's publicly exposed surface — S3 buckets, IAM roles, tenant metadata, storage URLs — and resolves IAM trust relationships that may be exploitable. Unlike network pentesting, cloud recon is API-driven: `ListRoles` replaces port scanning. Every enumeration call is logged; passive recon (DNS, certificate transparency) leaves zero target-side footprint.

## The OnPrem reality
Pre-cloud recon meant `whois` lookups, DNS zone transfers, Shodan IP scans, and SNMP enumeration. You'd map subnets, identify exposed services, and fingerprint OS versions. The network itself was the attack surface.

## Core concepts

### Recon layers in cloud

| Layer | Technique | Passive? | Target-Side Log |
|---|---|---|---|
| DNS / Cert Transparency | `crt.sh`, DNS brute-force subdomains | Yes | No |
| Service discovery | S3 bucket name brute-force, storage account enumeration | Semi | DNS query logs only |
| Tenant metadata | OpenID discovery, `sts:GetCallerIdentity` | No | CloudTrail / Audit log |
| IAM mapping | `ListRoles`, `ListUsers`, `get-iam-policy` | No | CloudTrail / Audit log |
| Trust graph | `ListRoles` → trust policy analysis | No | CloudTrail / Audit log |
| Org structure | `ListAccounts` (orgs), `ListSubscriptions` | No | CloudTrail / Audit log |

### Recon scope per cloud

| Target | AWS Lookup | Azure Lookup | GCP Lookup |
|---|---|---|---|
| Public storage | `s3://bucket-name` DNS resolution; `https://bucket-name.s3.amazonaws.com` | `https://storageaccountname.blob.core.windows.net` | `https://storage.googleapis.com/bucket-name` |
| IAM roles / SPs | `aws iam list-roles` (requires auth) | OpenID config `/.well-known/openid-configuration` (passive) | `gcloud projects get-iam-policy` (requires auth) |
| Account/tenant ID | `aws sts get-caller-identity` (with stolen key) or `aws organizations list-accounts` | `tenant-id` from OpenID discovery, `az account show` | `gcloud projects list`, `gcloud organizations list` |
| User enumeration | `aws iam list-users` | `az ad user list` or `Get-AzureADUser` | `gcloud iam service-accounts list` |
| Org structure | `aws organizations list-accounts` | `az account management-group list` | `gcloud organizations list` with `--filter` |

## AWS

### Passive recon — no AWS auth needed

```bash
# S3 bucket DNS fingerprint
dig +short example-bucket.s3.amazonaws.com

# Certificate transparency logs
curl -s 'https://crt.sh/?q=%.example.com&output=json' | jq '.[].name_value' | sort -u

# Check if an S3 bucket exists (DNS resolution is public)
aws s3 ls s3://example-bucket --no-sign-request 2>&1
# Returns 200-like response if bucket exists; AccessDenied or NoSuchBucket otherwise
```

### Authenticated recon — in your own sandbox

```bash
# Who am I?
aws sts get-caller-identity

# What accounts are in my org?
aws organizations list-accounts --query 'Accounts[].{Id:Id,Name:Name,Status:Status}'

# What IAM roles exist and who trusts them?
aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument.Statement[].Principal}' \
  --output table

# Enumerate all users and their attached policies
aws iam list-users --query 'Users[].UserName' | while read u; do
  echo "=== $u ==="
  aws iam list-attached-user-policies --user-name "$u"
done
```

### Recon toolkit for AWS

| Tool | What It Finds | Log Footprint |
|---|---|---|
| `cloudfox` | IAM users, roles, trust graphs, S3 buckets, EC2 metadata | High (many `List*`) |
| `ScoutSuite` | Full security posture scan | Very high |
| `pacu` (enum modules) | IAM, EC2, Lambda, CloudFormation enumeration | High |
| `aws_stealth_enum` | Low-noise S3 and IAM enumeration | Low |

### AWS-specific recon gotchas

- `ListRoles` returns **all roles** if you have `iam:ListRoles` — no filtering to "roles you can assume." This is a goldmine for trust graph mapping.
- `GetAccountAuthorizationDetails` returns the full IAM snapshot — policies, groups, users, roles — in one call. Requires `iam:GetAccountAuthorizationDetails`.
- Public S3 buckets are discoverable via DNS — no CloudTrail event for failed `s3 ls` attempts. But accessing objects via `s3:GetObject` generates data-plane events (if enabled).

## Azure

### Passive recon — no Azure auth needed

```bash
# OpenID Connect discovery — reveals tenant GUID
curl -s https://login.microsoftonline.com/example-tenant.onmicrosoft.com/.well-known/openid-configuration | \
  jq '{tenant: .token_endpoint}' | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

# Check if a storage account name exists (DNS resolution)
nslookup exampleblob.blob.core.windows.net

# Subdomain enumeration with certificate transparency
curl -s 'https://crt.sh/?q=%.example.com&output=json' | jq '.[].name_value' | sort -u
```

### Authenticated recon — in your own tenant

```bash
# Who am I? Get tenant + subscription info
az account show --query '{tenantId:tenantId, subscriptionId:id, name:name}'

# List all subscriptions accessible
az account subscription list --query '[].{Id:subscriptionId,Name:displayName}'

# List all service principals
az ad sp list --query '[].{AppId:appId, DisplayName:displayName}' --output table

# List all users
az ad user list --query '[].{UPN:userPrincipalName,Enabled:accountEnabled}' --output table

# List role assignments at subscription scope
az role assignment list --all --query '[].{Principal:principalName,Role:roleDefinitionName,Scope:scope}' -o table
```

### Recon toolkit for Azure

| Tool | What It Finds | Log Footprint |
|---|---|---|
| `AADInternals` | Azure AD tenant info, user enumeration, SP details | High (many Graph API calls) |
| `MicroBurst` | Storage account enumeration, public blob discovery | Moderate |
| `Stormspotter` | Azure resource graph visualization | High |
| `PurpleKnight` | Full security posture assessment | Very high |

## GCP

### Passive recon — no GCP auth needed

```bash
# Check for a public GCS bucket
curl -sI https://storage.googleapis.com/example-bucket

# Certificate transparency
curl -s 'https://crt.sh/?q=%.example.com&output=json' | jq '.[].name_value' | sort -u

# Org discovery via DNS
dig +short example.com TXT | grep google-site-verification
```

### Authenticated recon — in your own project

```bash
# Which project am I in?
gcloud config get-value project
gcloud projects describe $(gcloud config get-value project)

# List all projects in org
gcloud projects list --filter='parent.id=000000000000'

# IAM policy: who can do what?
gcloud projects get-iam-policy $(gcloud config get-value project) --format=json

# List all service accounts
gcloud iam service-accounts list

# List all IAM roles (custom + predefined)
gcloud iam roles list --project=$(gcloud config get-value project)
```

### Recon toolkit for GCP

| Tool | What It Finds | Log Footprint |
|---|---|---|
| `gcloud` CLI (native) | Project, IAM, resource enumeration | High (audited calls) |
| `ScoutSuite` | Full GCP posture scan | Very high |
| `Forseti Security` (legacy) | IAM policy analysis | High |
| `gcp_scanner` | Public resource discovery | Low |

## OnPrem mapping (recap table)

| Recon Target | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Public services | Shodan, nmap | S3 DNS resolution, `crt.sh` | Blob DNS resolution, `crt.sh` | GCS URL check, `crt.sh` |
| User enumeration | LDAP anonymous bind, RPC | `iam:ListUsers` | `az ad user list`, Graph API | `gcloud iam service-accounts list` |
| Trust mapping | AD trust (`nltest`) | `iam:ListRoles` → trust policy | RBAC role assignment list | `get-iam-policy` → member bindings |
| Org structure | LDAP OU tree | `organizations:ListAccounts` | Management group tree | Org hierarchy |
| Credential scan | Mimikatz, secretsdump | `GetAccountAuthorizationDetails` | App secret enumeration | SA key enumeration |

## 🔴 Red Team view

### Most revealing recon lookups

The three most impactful recon calls in cloud engagements:

1. **`GetAccountAuthorizationDetails` (AWS) / `get-iam-policy` (GCP) / `az role assignment list --all` (Azure)** — reveals who has what. Your entire privesc path is visible in one call.

2. **`ListRoles` (AWS) / `az ad sp list` (Azure) / `gcloud iam service-accounts list` (GCP)** — reveals what roles exist and (for AWS) their trust policies. Trust policies are the "who can become me" map that enables assume-role chains.

3. **Org walker (`ListAccounts` / `ListSubscriptions` / `projects list`)** — reveals sibling accounts/projects you might be able to pivot into. Cross-account assume-role with `Principal: "111111111111"` or trust on the org root means every account in the org can assume that role.

### Footprint of reconnaissance

Every authenticated recon call leaves a CloudTrail/AuditLog signature:

| Service | Event Names |
|---|---|
| AWS IAM | `GetAccountAuthorizationDetails`, `ListRoles`, `ListUsers`, `ListAttachedRolePolicies` |
| AWS STS | `GetCallerIdentity` |
| AWS EC2 | `DescribeInstances`, `DescribeSecurityGroups` |
| Azure AD | `List users`, `List servicePrincipals`, `List directoryRoleAssignments` |
| Azure Resource Graph | `POST /providers/Microsoft.ResourceGraph/resources` |
| GCP IAM | `GetIamPolicy`, `ListServiceAccounts`, `ListRoles` |

**User-Agent fingerprinting.** Recon tools have distinct User-Agent strings:
- `aws-cli/2.x.x` — standard CLI
- `cloudfox` — includes "cloudfox" in user-agent
- `Boto3` — Python SDK
- `AzureCli/x.x.x` — Azure CLI
- `gcloud/x.x.x` — GCloud CLI

Defenders can alert on unusual User-Agent + principal combinations (e.g., `cloudfox` running as a human user who normally only uses the console).

## 🔵 Blue Team view

### Detection signals

**1. Unusually wide `List*` spike from a single principal**

```sql
-- AWS CloudTrail (Athena)
SELECT useridentity.arn, COUNT(*) as list_count
FROM cloudtrail_logs
WHERE eventname LIKE 'List%' OR eventname LIKE 'Get%'
  AND eventtime > now() - interval '1' hour
GROUP BY useridentity.arn
HAVING COUNT(*) > 50
ORDER BY list_count DESC;
```

**2. First-time use of recon tool User-Agent by a human user**

```sql
-- AWS CloudTrail (Athena)
SELECT useridentity.arn, useragent
FROM cloudtrail_logs
WHERE useragent LIKE '%cloudfox%'
   OR useragent LIKE '%ScoutSuite%'
   OR useragent LIKE '%pacu%'
  AND eventtime > now() - interval '7' day;
```

**3. `GetAccountAuthorizationDetails` — this single call is high-signal recon**

```sql
-- Alert on any GetAccountAuthorizationDetails outside expected CI/CD roles
SELECT useridentity.arn, sourceipaddress, eventtime
FROM cloudtrail_logs
WHERE eventname = 'GetAccountAuthorizationDetails'
  AND useridentity.arn NOT LIKE '%ci-role%'
  AND useridentity.arn NOT LIKE '%terraform-role%';
```

### Honey tokens for recon detection

Deploy decoy credentials and resources that trigger alerts when enumerated or used:

| Cloud | Honey Token Type | Deployment | Alert Trigger |
|---|---|---|---|
| AWS | IAM access key (unused, no perms) | `AKIAIOSFODNN7EXAMPLE` stored in a `params.yml` in a test repo | `GetAccessKeyLastUsed` or usage via CloudTrail |
| AWS | S3 bucket named `prod-backup-XXXX` | Bucket with data event trail, public block ON | `s3:ListBucket` or `s3:GetObject` attempt |
| Azure | App registration with dummy secret | SP with name `prod-automation-sp` | Any sign-in or token issuance via Azure AD logs |
| Azure | Storage account with SAS token in repo | SAS URI in a public test repo | `ListBlobs` or `GetBlob` via storage logs |
| GCP | Service account key JSON | JSON file placed in test repo | `google.iam.admin.v1.GetServiceAccountKey` or any API call using it |
| GCP | GCS bucket with `prod-backup` name | Public bucket with logging | `storage.objects.list` or `storage.objects.get` |

### Preventive controls

1. **SCP: Deny `GetAccountAuthorizationDetails`** except for specific security tooling roles.
2. **SCP: Deny `iam:List*` for non-admin accounts** — least privilege means most users don't need to list all IAM entities.
3. **Enable CloudTrail Insights** — automatically detects anomalies in API call volume (e.g., sudden spike in `List*` calls).
4. **GuardDuty (AWS), Security Command Center (GCP), Microsoft Defender for Cloud (Azure)** — native threat detection for recon patterns.

### Canary token deployment

Use `canarytokens.org` or equivalent to embed trap tokens:

```bash
# AWS: create a canary IAM key
aws iam create-user --user-name canary-prod-admin --tags Key=canary,Value=true
aws iam create-access-key --user-name canary-prod-admin
# Store the key in a "leaked" location and alert on any usage

# Azure: create a canary app registration
az ad app create --display-name "canary-prod-automation" --tags "canary=true"

# GCP: create a canary SA key
gcloud iam service-accounts create canary-prod-admin \
  --display-name="Canary Production Admin"
gcloud iam service-accounts keys create canary-key.json \
  --iam-account=canary-prod-admin@example-project.iam.gserviceaccount.com
```

## Hands-on lab

**Objective:** Run a passive + authenticated recon pass on your sandbox and identify every CloudTrail event it generates.

1. **Passive recon** (no API calls to your target):
   ```bash
   curl -s 'https://crt.sh/?q=%.example.com&output=json' | jq '.[].name_value' | head -20
   dig +short $(gcloud config get-value project).appspot.com
   ```

2. **Authenticated recon** in your sandbox:
   ```bash
   # AWS
   aws sts get-caller-identity
   aws iam list-roles --max-items 10
   aws organizations list-accounts 2>/dev/null
   
   # Azure
   az account show
   az ad user list --top 5
   
   # GCP
   gcloud projects describe $(gcloud config get-value project)
   gcloud projects get-iam-policy $(gcloud config get-value project) --format=json | jq '.bindings[] | .members'
   ```

3. **Check CloudTrail/AuditLog for your events:**
   ```bash
   # AWS: wait 5 min, then
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=YOUR_USERNAME --max-results 20
   
   # Azure
   az monitor activity-log list --caller $(az account show --query user.name -o tsv) --offset 1h
   
   # GCP
   gcloud logging read "protoPayload.authenticationInfo.principalEmail:$(gcloud config get-value account)" --limit 20
   ```

**Expected output:** 15–40 log entries proving even `List*` calls are fully audited.

**Teardown:** No resources created.

## Detection rules & checklists

### Sigma rule: Reconnaissance API burst

```yaml
title: Cloud Reconnaissance List API Burst
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName|startswith:
      - 'List'
      - 'Describe'
      - 'GetAccount'
  timeframe: 5m
  condition: selection | count() by userIdentity.arn > 30
fields:
  - userIdentity.arn
  - sourceIPAddress
  - userAgent
falsepositives:
  - CI/CD pipeline enumeration
  - CloudFormation drift detection
  - Authorized security assessment tools
level: medium
```

### CLI audit one-liners

```bash
# AWS: Top enumerators in last 24h
aws cloudtrail lookup-events --query "Events[?EventName.contains(@, 'List') || EventName.contains(@, 'Describe')]"

# Azure: Recent sign-ins from unusual locations
az ad signed-in-user list --query "[?not_null(ipAddress)]"

# GCP: Recent IAM policy reads
gcloud logging read 'protoPayload.methodName=~"GetIamPolicy|ListServiceAccounts"' --limit 50
```

## References

- [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [Azure Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
- [GCP Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [cloudfox](https://github.com/BishopFox/cloudfox)
- [AADInternals](https://github.com/Gerenios/AADInternals)
- [crt.sh Certificate Transparency](https://crt.sh/)
- [Canarytokens](https://canarytokens.org/)
