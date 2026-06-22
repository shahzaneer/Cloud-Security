# 01 — Methodology & PTES for Cloud

> **Level:** Intermediate
> **Prereqs:** Modules 00–08
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** All — this is the framework that maps every tactic
**Authorization scope:** Run only against accounts/tenants you own or where you have written authorization from the account owner. All targets, ARNs, domains below use placeholders.

## What & why
Penetration Testing Execution Standard (PTES) provides a structured engagement framework. Adapted to cloud, the kill chain becomes: Recon → Initial Access → Persistence → Privilege Escalation → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact. Cloud shifts each phase: discovery is API-driven, persistence is IAM edits, and exfil leverages provider egress.

## The OnPrem reality
Pre-cloud PTES centered on network-layer pivots, service exploitation (MS08-067, EternalBlue), and C2 frameworks (Cobalt Strike, Empire). The target was a subnet or domain. Cloud engagements replace the subnet with the IAM trust graph; the "exploit" is often a misconfiguration, not a buffer overflow.

## Core concepts

### PTES phases mapped to cloud

| PTES Phase | OnPrem Example | AWS Cloud Analog | Azure Cloud Analog | GCP Cloud Analog |
|---|---|---|---|---|
| Pre-engagement | Scope IP ranges, RoE | Scope account IDs, regions, IAM role names | Scope tenant GUIDs, subscription IDs | Scope project IDs, org node |
| Intelligence Gathering | Shodan, whois, DNS brute | `cloudfox`, `aws organizations list-accounts`, public S3 buckets | `AADInternals`, OpenID discovery, public blob containers | `gcloud projects list`, public Cloud Storage buckets |
| Threat Modeling | Network diagrams, AD trust maps | IAM trust graphs (`sts:AssumeRole` between accounts) | Azure AD tenant trust, B2B guest chains | IAM policy inheritance, org hierarchy |
| Vulnerability Analysis | Nessus, Metasploit aux modules | ScoutSuite, Prowler, `cloudsploit` | `az cli` policy audit, `PurpleKnight` | Security Command Center, Forseti |
| Exploitation | Buffer overflow, pass-the-hash | `iam:PassRole` abuse, token theft from IMDS | OAuth consent grant phishing, MI abuse | `iam.serviceAccountTokenCreator` impersonation |
| Post-Exploitation | Mimikatz, golden ticket | STS session chaining, `CreateAccessKey` on users | Refresh token persistence, Logic App backdoors | Service account key creation, Cloud Scheduler persistence |
| Reporting | Vulnerabilities by host | IAM misconfigurations by principal ARN | Policy gaps by resource ID | IAM gaps by member/project |

### Rules of Engagement (RoE) template for cloud

Every cloud engagement scope document must include these fields — defenders should insist on every one:

| RoE Field | What It Means | AWS Example | Azure Example | GCP Example |
|---|---|---|---|---|
| **Account/Tenant ID** | Which account can be targeted | `111111111111` | `example-tenant.onmicrosoft.com` | `example-project` |
| **Scope tag** | Tag on resources you're allowed to touch | `Key=pentest,Value=authorized` | `pentest=authorized` | `labels.pentest=authorized` |
| **Exclusion list** | Resources never to touch | `arn:aws:ec2:us-east-1:111111111111:instance/i-prod-*` | `/subscriptions/0000.../resourceGroups/prod-*` | `//compute.googleapis.com/projects/example-project/zones/*/instances/prod-*` |
| **Authorized IP ranges** | Source IPs testers will use | `198.51.100.0/24` | `198.51.100.0/24` | `198.51.100.0/24` |
| **Alert point of contact** | Who to call if SOC detects activity | `soc@example.com` | `soc@example.com` | `soc@example.com` |
| **Bomb-and-exfil caveat** | Exfil only if fully logged | `Exfil allowed only via logged S3 presigned GET` | `Exfil only to logged storage account` | `Exfil only to logged GCS bucket` |
| **Credential access limit** | Max credential level you may obtain | `No root account key recovery` | `No Global Admin elevation beyond break-glass` | `No org-level SA key creation` |
| **Cleanup requirement** | What must be deleted after | `All IAM users/roles/keys created` | `All SPs, apps, resource groups created` | `All SAs, keys, resources created` |

## AWS

PTES in AWS starts with enumerating the organization structure:

```
aws organizations list-accounts --profile sandbox
aws sts get-caller-identity --profile sandbox
aws iam list-roles --profile sandbox --query 'Roles[?RoleName.contains(@, `Admin`)]'
```

All engagement activity must be scoped to a specific account ID. Use `aws sts get-caller-identity` before any command to confirm you're in the right account. CloudTrail logs every management-plane API call — your RoE must be shared with the SOC so they can suppress alerts during the engagement window.

### AWS-specific RoE constraints

- Never touch `arn:aws:iam::aws:policy/*` (AWS-managed policies).
- Never delete CloudTrail trails; if evasion is in scope, test against a non-production trail copy.
- IAM user/role creation must use a distinct path prefix: `/pentest/`.
- `sts:AssumeRole` across accounts only if the trust policy is part of the engagement model.

## Azure

Azure tenancy enumeration begins with the OpenID Connect discovery endpoint:

```
curl https://login.microsoftonline.com/example-tenant.onmicrosoft.com/.well-known/openid-configuration
az account show --query '{tenantId:tenantId,subscriptionId:id}'
az ad sp list --filter "displayname eq 'example-sp'" --query '[].appId'
```

Azure engagement scope must specify the tenant GUID and subscription IDs. The `az cli` user-agent string is logged in Azure AD sign-in logs and Azure Activity logs — defenders will see you.

### Azure-specific RoE constraints

- No modification of Conditional Access policies.
- No deletion of Azure AD audit log or diagnostic settings.
- SP creation must include `tags` with `pentest=true`.
- RBAC role assignments at subscription scope only with written authorization.

## GCP

GCP project enumeration:

```
gcloud projects describe example-project
gcloud organizations list
gcloud projects get-iam-policy example-project
gcloud iam service-accounts list --project example-project
```

### GCP-specific RoE constraints

- No modification of organization-level constraints (`gcloud org-policies`).
- No deletion of `cloudaudit.googleapis.com` audit logs.
- SA key creation only for SAs prefixed with `pentest-`.
- IAP tunnel usage only to explicitly in-scope instances.

## OnPrem mapping (recap table)

| PTES Phase | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Pre-engagement | IP ranges, hostnames | Account IDs, regions | Tenant GUIDs, subscription IDs | Project IDs, org node |
| Intelligence Gathering | Shodan, DNS, SNMP | `ListRoles`, public S3 buckets | OpenID discovery, public blobs | `get-iam-policy`, public GCS |
| Vulnerability Analysis | Nessus, nmap scripts | ScoutSuite, Prowler | `az policy`, PurpleKnight | Security Command Center |
| Exploitation | RCE, pass-the-hash | `PassRole`, token theft | OAuth phishing, MI abuse | SA impersonation |
| Post-Exploitation | Mimikatz, golden ticket | STS chaining, key creation | Refresh token persistence | SA key creation |
| Reporting | Per-host vulns | Per-principal ARN misconfigs | Per-resource policy gaps | Per-member IAM gaps |

## 🔴 Red Team view

### How the cloud changes PTES

**Discovery is API-driven.** You don't need to scan ports — you call `ListBuckets`, `ListRoles`, `ListUsers`. Every `List*` call is logged. The attacker's challenge is to minimize the "list blast" footprint.

**Persistence is IAM, not malware.** Instead of a registry Run key, you create a new IAM user access key. Instead of a kernel rootkit, you add a trust policy to a role. These are legitimate API calls that blend with normal admin activity.

**Exfil is egress, not a reverse shell.** You don't need a custom TCP tunnel when the victim's own S3 bucket, Azure Storage account, or GCS bucket provides perfectly legitimate HTTPS egress. Pre-signed URLs and shared access signatures are exfil primitives.

### Detecting PTES-phase activity

Each phase leaves a CloudTrail/AuditLog signature:

| PTES Phase | CloudTrail/AuditLog Signature |
|---|---|
| Recon | Spike in `List*` calls from single principal in short window |
| Initial Access | `CreateAccessKey`, `UpdateAssumeRolePolicy`, OAuth consent grant |
| Persistence | `CreateUser` + `CreateAccessKey`, `PutEventSourceMapping`, `CreateCloudFormationStack` |
| Privilege Escalation | `lambda:CreateFunction` + `iam:PassRole` by non-CI principal |
| Lateral Movement | `sts:AssumeRole` chain depth ≥ 3 |
| Exfil | `s3:GetObject` from unusual source IP, `PutObject` to external bucket |

## 🔵 Blue Team view

### What RoE fields defenders must insist on

Every sanctioned cloud engagement must provide these — push back on any that are missing:

1. **Scope tag enforcement.** Testers must tag every resource they create with `pentest=true`. This lets SOC query for leftover artifacts post-engagement:
   ```
   aws resourcegroupstaggingapi get-resources --tag-filters Key=pentest,Values=authorized
   ```

2. **Exclusion list with ARN-level granularity.** "Don't touch prod" isn't enough. Demand explicit ARNs, resource group names, or subscription IDs.

3. **Alert point of contact with escalation path.** Not just an email — a phone number and a 30-minute SLA for "stop the test" calls.

4. **Bomb-and-exfil clause.** "Exfil allowed only if every byte is logged" — meaning data exfil must transit a monitored channel (e.g., S3 with data events enabled), not an encrypted tunnel to an unknown IP.

5. **Credential tier ceiling.** Specify the maximum privilege level the testers may achieve: e.g., "No root account access, no break-glass Global Admin, no org-level SA."

6. **Cleanup attestation.** After the engagement, testers provide a signed list of every resource created, with proof of deletion.

### Detection check during an engagement

```
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=pentest-operator
az monitor activity-log list --caller pentest-sp --start-time 2026-06-01
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="pentest-user@example-project.iam.gserviceaccount.com"'
```

SOC should run these daily during the engagement window and correlate with the RoE's authorized IP ranges.

## Hands-on lab

**Objective:** Create a scope document for your sandbox and run a read-only enumeration pass.

1. Write an RoE document for your sandbox covering all 8 fields in the table above.
2. From your sandbox, run:

```bash
# AWS
aws sts get-caller-identity
aws iam list-roles --max-items 5
aws organizations list-accounts 2>/dev/null || echo "Not in organization"

# Azure
az account show --query '{tenantId:tenantId, name:name}'
az ad user list --top 5 --query '[].userPrincipalName'

# GCP
gcloud config get-value project
gcloud iam service-accounts list --limit 5
gcloud projects get-iam-policy $(gcloud config get-value project)
```

3. Capture all CloudTrail/AuditLog events generated. Verify the events exist in:
   - AWS: CloudTrail Event History
   - Azure: `az monitor activity-log list`
   - GCP: `gcloud logging read`

4. Write the event list into the RoE document as "observed footprint."

**Expected output:** A one-page RoE + a list of 15–30 CloudTrail events proving that even read-only recon generates observable log entries.

**Teardown:** Nothing to delete — all commands are read-only.

## Detection rules & checklists

### Cloud Custodian policy: detect untagged resources created during engagement

```yaml
policies:
  - name: pentest-untagged-resources
    resource: aws.iam-user
    filters:
      - type: value
        key: "tag:pentest"
        value: absent
      - type: event
        key: "detail.userIdentity.arn"
        op: regex
        value: ".*pentest-operator.*"
    actions:
      - type: notify
        template: pentest-violation
```

### CLI audit one-liners

```bash
# AWS: find all IAM entities created in last 24h without pentest tag
aws iam list-users --query "Users[?CreateDate>='$(date -v-1d +%Y-%m-%dT%H:%M:%SZ')].UserName"

# Azure: list recent RBAC role assignments
az role assignment list --all --query "[?not_null(scopedAt)]"

# GCP: list recent SA key creations
gcloud logging read 'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"' --limit 20
```

## Sample Rules of Engagement Document Walkthrough

Below is a fully filled-out RoE template. Every field illustrated with concrete values for all three clouds. Annotate each section with the rationale so operators and defenders understand *why* the constraint exists.

### Section 1: Engagement Metadata

| Field | Value | Rationale |
|-------|-------|-----------|
| Engagement ID | `PT-2026-06-AWS-AZ-GCP-001` | Unique per engagement; correlates all activity across clouds |
| Authorized firm | `RedSec Labs (LLC registered in DE)` | Legal entity performing the test |
| Client POC | `Jane CISO, jane.ciso@examplecorp.com, +1-555-0100` | Authorized signatory with budget authority |
| Technical POC | `Bob CloudSec, bob@examplecorp.com, +1-555-0101` | Point person for technical questions during engagement |
| Emergency stop | `SOC Lead: soc-lead@examplecorp.com, +1-555-0102` (PagerDuty escalation: +1-555-0199) | 30-min SLA to halt testing |

### Section 2: Scope — Authorized Targets

#### AWS Scope

```
Account IDs in scope:
  - 111111111111 (sandbox-dev)
  - 222222222222 (sandbox-staging)
  Not in scope: 333333333333 (prod), 444444444444 (audit/sec)

Services in scope:
  - EC2 (instances tagged pentest=true in us-east-1, us-west-2)
  - S3 (buckets with prefix pentest-*)
  - Lambda (functions with tag pentest=true)
  - IAM (roles with path /pentest/, users with path /pentest/)
  - RDS (instances tagged pentest=true, no production data)

Services explicitly out of scope:
  - AWS Organizations (no ListAccounts on org root)
  - Route 53 (no zone modifications)
  - KMS (no key rotation or deletion)
  - CloudTrail (no trail deletion; evasion in scope only on copy trail)
  - GuardDuty (no detector suspension)
```

#### Azure Scope

```
Tenant GUID:      00000000-0000-0000-0000-000000000000
Subscriptions:    /subscriptions/aaaa0000-aaaa-0000-aaaa-0000aaaa0000 (dev)
                  /subscriptions/bbbb0000-bbbb-0000-bbbb-0000bbbb0000 (staging)
Not in scope:     /subscriptions/cccc0000-cccc-0000-cccc-0000cccc0000 (prod)

Resources in scope:
  - VMs with tag pentest=true
  - Storage accounts with name prefix pentest
  - Azure Functions with tag pentest=true
  - Key Vaults with name prefix pentest-kv
  - Managed Identities with name prefix pentest-mi

Excluded:
  - Azure AD Conditional Access policies (no modification)
  - Azure AD Connect / Entra Connect Sync
  - Sentinel workspace (no alert suppression)
  - Defender for Cloud (no pricing tier changes)
```

#### GCP Scope

```
Organization:     000000000000
Projects:         example-dev-project, example-staging-project
Not in scope:     example-prod-project, example-audit-project

Resources in scope:
  - GCE instances with label pentest=true
  - Cloud Storage buckets with name prefix pentest-
  - Cloud Run services with label pentest=true
  - Cloud SQL instances with label pentest=true
  - Service accounts with displayName prefix pentest-

Excluded:
  - Organization-level IAM policies (no modification)
  - Cloud Audit Logs (no log sink deletion)
  - Security Command Center (no notification config changes)
  - VPC Service Controls perimeters (no perimeter updates)
```

### Section 3: Testing Window

| Item | Detail |
|------|--------|
| Start | 2026-06-23 09:00 UTC |
| End | 2026-07-07 18:00 UTC (2 calendar weeks) |
| Active testing hours | Mon–Fri, 09:00–18:00 UTC only |
| No-test windows | Weekends; 2026-07-04 (US holiday) |
| Blackout dates | None declared by client |

### Section 4: Authorized Source IP Ranges

```
Testers will originate all traffic from:
  - 198.51.100.0/24 (RedSec Labs primary NAT)
  - 203.0.113.0/28  (RedSec Labs secondary / backup exit)

All cloud activity will use userAgent prefix:
  - AWS: --user-agent "RedSecLabs-PT-2026-06/1.0"
  - Azure: --cli-user-agent "RedSecLabs-PT-2026-06/1.0"
  - GCP: --user-agent "RedSecLabs-PT-2026-06/1.0"

IPs may be rotated within the declared /24 and /28 blocks.
SOC must NOT blackhole traffic from these ranges during the engagement window.
```

### Section 5: Prohibited Actions (All Clouds)

| # | Prohibited Action | Reason |
|---|------------------|--------|
| 1 | Deletion of CloudTrail trails, Azure Activity Log settings, or GCP audit log sinks | Preserves the client's audit trail for post-engagement review |
| 2 | Modification or deletion of KMS CMKs, Key Vault keys, or Cloud KMS key rings | Irreversible data loss risk |
| 3 | Access to or enumeration of customer PII/PHI data in any data store | Legal/regulatory: GDPR, HIPAA, PCI-DSS |
| 4 | Modification of IAM policies on AWS-managed (`arn:aws:iam::aws:policy/*`) or equivalent provider-managed roles | Could break production even in dev/staging accounts |
| 5 | Denial-of-service attacks against the API Gateway, WAF, or CDN edge | Availability impact on shared infrastructure |
| 6 | Exploitation of third-party SaaS integrations (Slack, GitHub, Jira OAuth apps) | Outside authorized scope; requires separate vendor authorization |
| 7 | Physical or social-engineering attacks against employees | Out of scope unless explicitly included in separate RoE addendum |
| 8 | Creation of cryptocurrency mining resources | Unauthorized cost accrual; violates cloud provider AUP |
| 9 | Data exfiltration through any channel not pre-approved and logged | See Section 6 for allowed exfil channels |

### Section 6: Allowed Exfiltration Channels

```
Data exfiltration during the engagement is authorized ONLY through:
  - AWS: S3 pre-signed GET URL to bucket pentest-exfil-111111111111
         (CloudTrail Data Events enabled; SSE-S3 encryption)
  - Azure: SAS URL to storage account pentestexfil (diagnostic logging enabled)
  - GCP: Signed URL to GCS bucket pentest-exfil (Data Access audit logs enabled)

All exfil must be logged with:
  - Source resource ARN / Azure resource ID / GCP resource name
  - Object count and total byte count
  - Timestamp (UTC)

Any exfil outside these channels is a RoE violation and triggers the Emergency Stop.
```

### Section 7: Credential Access Ceiling

```
Maximum privilege testers may obtain:
  - AWS:   IAM role with AdministratorAccess at sandbox account scope only.
           No access to root account credentials.
           No AssumeRole into the organization management account.
  - Azure: Subscription-level Owner on dev subscription only.
           No Global Administrator in Entra ID.
           No break-glass account access.
  - GCP:   roles/owner at project level on dev project only.
           No organization-level roles.
           No service account key creation on org-level SAs.

Testers must NOT:
  - Extract long-lived IAM user access keys from the environment
  - Dump and exfiltrate the contents of .aws/credentials, .azure/, or gcloud config
  - Attempt to brute-force or phish MFA tokens
```

### Section 8: Cleanup Requirements

```
Within 72 hours of engagement end (by 2026-07-10 18:00 UTC), RedSec Labs will:

1. Delete all IAM users, roles, service principals, and service accounts created
   during the engagement (identifiable by /pentest/ path or pentest- prefix).

2. Delete all compute resources (EC2 instances, Azure VMs, GCE instances) tagged
   pentest=true.

3. Delete all storage resources (S3 buckets, Blob containers, GCS buckets) with
   pentest prefix, after confirming no client data was placed in them.

4. Revoke all access keys, SAS tokens, and signed URLs generated during the test.

5. Remove all IAM policy attachments, role assignments, and IAM bindings added
   by testers.

6. Provide a cleanup attestation document listing every resource created and its
   deletion status (ARN → deleted timestamp).

7. Provide a post-engagement report within 10 business days (by 2026-07-21).
```

### Section 9: Legal & Authorization

```
This engagement is authorized under contract #EXAMPLE-CORP-2026-045 signed 2026-06-15.

AWS:  Client has enabled "Penetration Testing" permission via AWS Support ticket #PT-123456.
Azure: Client has submitted penetration testing notification via Azure Portal
       (https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityAwarenessBlade).
       Ticket reference: MS-PT-2026-001.
GCP:   No prior notification required per GCP AUP (Section 3.1 — penetration testing permitted
       on customer's own projects without prior approval).

Testers carry professional liability insurance: RedSec Labs policy #PL-2026-987654.
```

## Engagement Pre-Flight Checklist

Before the first `aws s3 ls` or `az ad user list`, every operator must verify these items. Missing any one is a hard stop.

### 🔴 Operator Pre-Flight (run from tester workstation)

```bash
# ═══ 1. Confirm identity and target account ═══

# AWS
aws sts get-caller-identity --profile pentest-sandbox
# Expected: "Account": "111111111111" (must match RoE scope)

# Azure
az account show --query '{tenantId:tenantId, subscriptionId:id, user:user.name}'
# Expected: tenantId and subscriptionId match RoE

# GCP
gcloud config get-value project
gcloud auth list --filter=status:ACTIVE
# Expected: project matches RoE; SA/account is pentest-* identity

# ═══ 2. Verify logging is enabled on tester side ═══

# Start local packet capture (optional but recommended)
sudo tcpdump -i any -w pt-$(date +%Y%m%d-%H%M%S).pcap &
echo $! > /tmp/tcpdump.pid

# Start shell command logging
export PROMPT_COMMAND='history -a; echo "$(date +%s) $(whoami) $(pwd) $(history 1)" >> /tmp/pt-commands.log'

# ═══ 3. Confirm out-of-band communication channel ═══

# Verify Signal/WhatsApp group with client SOC POC is active
# Send test message: "PT-2026-06-AWS-AZ-GCP-001: comms check. Start in 5 min."
# Await acknowledgment before proceeding.

# ═══ 4. Set user-agent for all cloud CLIs ═══

# AWS
export AWS_EXECUTION_ENV="RedSecLabs-PT-2026-06"

# Azure
export AZURE_HTTP_USER_AGENT="RedSecLabs-PT-2026-06/1.0"

# GCP
export CLOUDSDK_CORE_CUSTOM_USER_AGENT="RedSecLabs-PT-2026-06/1.0"

# ═══ 5. Verify exclusion filters are configured ═══

# AWS (scripted filter to never touch prod account)
aws configure set profile.pentest-sandbox.role_arn arn:aws:iam::111111111111:role/pentest-operator
# Explicitly do NOT configure a profile for account 333333333333

# Azure (set default subscription to dev only)
az account set --subscription aaaa0000-aaaa-0000-aaaa-0000aaaa0000

# GCP (set project explicitly; never set org-level config)
gcloud config set project example-dev-project --installation
```

### 🔵 Defender Pre-Flight (run from SOC workstation)

```bash
# ═══ 1. Confirm pentest IP ranges in SIEM allowlist ═══
# Add 198.51.100.0/24 and 203.0.113.0/28 to alert suppression rules
# for duration of engagement window only

# ═══ 2. Create pentest audit collection ═══

# AWS: Ensure CloudTrail event history covers the engagement period
aws cloudtrail lookup-events --start-time 2026-06-23T00:00:00Z \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=*.amazonaws.com \
    --max-results 5
# (test query — confirms CloudTrail is collecting)

# Azure: Verify Log Analytics workspace is ingesting
az monitor log-analytics query \
    --workspace $(az monitor log-analytics workspace show -g security-rg -n sentinel-ws --query customerId -o tsv) \
    --analytics-query "AzureActivity | where TimeGenerated > ago(1h) | take 1"

# GCP: Verify audit logs are accessible
gcloud logging read "logName=projects/example-dev-project/logs/cloudaudit.googleapis.com" --limit 1

# ═══ 3. Confirm emergency stop procedure ═══
# Verify SOC PagerDuty rotation includes the engagement window
# Verify "stop-the-test" contact list is posted on SOC wall
# Run a comms test with tester OOB channel

# ═══ 4. Document baseline API call volume (for post-hoc comparison) ═══

# AWS
aws cloudtrail lookup-events --start-time 2026-06-16T00:00:00Z --end-time 2026-06-22T23:59:59Z \
    | jq '[.Events[] | .eventName] | group_by(.) | map({event: .[0], count: length})' \
    > /tmp/baseline-events.json

# Azure
az monitor activity-log list --start-time 2026-06-16 --end-time 2026-06-22 \
    --query "[].operationName.value" -o tsv | sort | uniq -c > /tmp/baseline-ops.txt

# GCP
gcloud logging read 'logName=projects/example-dev-project/logs/cloudaudit.googleapis.com' \
    --start-time=2026-06-16 --end-time=2026-06-22 \
    --format='json(protoPayload.methodName)' | jq -r '.[].protoPayload.methodName' \
    | sort | uniq -c > /tmp/baseline-methods.txt

# ═══ 5. Tag all existing resources for exclusion ═══
# (resources NOT tagged pentest=true are out of scope)

# AWS (tag production resources in scope accounts for exclusion clarity)
aws ec2 describe-instances --filters "Name=tag:pentest,Values=true" --query 'Reservations[].Instances[].InstanceId'

# Azure
az resource list --tag pentest=true --query '[].id'

# GCP
gcloud compute instances list --filter='labels.pentest=true'
```

### ⚠️ Hard Stop Conditions

If any of the following is true, do **not** commence testing:

| Condition | Resolution required before proceeding |
|-----------|--------------------------------------|
| `get-caller-identity` returns an account ID NOT in the RoE scope | Verify AWS profile, `AWS_PROFILE` env var, and credential source |
| Exclusion filters are not configured (e.g., prod subscription is the active default) | Set default subscription/project to dev account explicitly |
| OOB comms test receives no acknowledgment within 15 minutes | Escalate to client POC via phone; do not start testing |
| Defender-side logging baseline returns zero events | Escalate; logging may be broken — testing without audit trail is not allowed |
| Legal authorization documents are not on hand (digital or printed) | Halt; re-verify contract and cloud provider notification tickets |
| Tester source IP does not fall within the RoE-declared ranges | Verify VPN/NAT gateway; if using new IP, update RoE addendum before proceeding |

Cross-links: [IAM Reconnaissance](../IAM/) for pre-engagement enumeration; [IR Runbook](../IR-Forensics-Cloud/ir-runbook-cloud-aware.md) for SOC-side engagement monitoring.

## References

- [PTES Technical Guidelines](http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [Azure Activity Log schema](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema)
- [GCP Audit Logging](https://cloud.google.com/logging/docs/audit)
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [Prowler](https://github.com/prowler-cloud/prowler)
