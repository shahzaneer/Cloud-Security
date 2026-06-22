# 02 — Triage and Severity Per Cloud

> **Level:** Intermediate
> **Prereqs:** [11-01](./ir-runbook-cloud-aware.md), [06-Monitoring](../Monitoring-Detection-SIEM/)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Discovery, Initial Access
> **Authorization scope:** Run only in your own sandbox account; all example account IDs are placeholders (`111111111111`, `00000000-0000-0000-0000-000000000000`).

## What & why

Severity calls in cloud IR are high-availability decisions. A SEV-1 in AWS means "a publicly exposed S3 bucket with confirmed exfiltration" — not "someone ran `s3:ListBuckets` once." This lesson builds the per-cloud clarity matrix so triage analysts make consistent, defensible judgments under time pressure.

## The OnPrem reality

On-prem triage followed a tiered ping-pong model: Tier-1 frontline received the SIEM alert, Tier-2 performed root-cause, Tier-3 (engineering) executed containment. Escalation thresholds were static (e.g., "any Domain Admin logon → P1"). Cloud adds dimension: blast radius measured in IAM reach × data exposure surface × ephemeral velocity.

## Core concepts

### Severity scale definition

| SEV | Label | Definition | Max response time |
|-----|-------|-----------|-------------------|
| P1 | Critical | Active breach with confirmed data exfiltration or ongoing privilege escalation | 15 min to contain |
| P2 | High | Probable compromise, no confirmed exfil yet; public exposure of sensitive resource | 60 min |
| P3 | Medium | Suspicious activity or configuration drift that *could* escalate; GuardDuty Medium | 4 hours |
| P4 | Low | Reconnaissance noise, individual `List*` calls, misconfig without exposure | Next business day |

### Triage decision tree

```
Signal arrives
├── Resource publicly exposed? (Y/N)
│   ├── Y → P2 minimum; P1 if sensitive data present
│   └── N → continue
├── IAM credential used from anomalous location?
│   ├── Y → P2 minimum; P1 if privileged role
│   └── N → continue
├── Data transfer volume > baseline + 3σ?
│   ├── Y → P2 minimum; P1 if confirmed exfil to external IP
│   └── N → P3
└── Is this the Nth identical signal from same identity in 5 min?
    ├── Y → aggregate; do NOT inflate SEV (attacker noise suppression)
    └── N → escalate per above
```

## AWS

**SEV-1 concrete events:**
- GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` + outbound byte count > 100 MB
- Public S3 bucket (`BlockPublicAccess: false`) with `s3:GetObject` events from a non-corporate IP
- `iam:CreateAccessKey` from an IP not in the corporate range on a production role
- EC2 Security Group: ingress `0.0.0.0/0` on port 22/3389 + SSH/RDP login success from unknown IP

**SEV-2 events:**
- GuardDuty `Recon:IAMUser/MaliciousIPCaller.Custom`
- `iam:AttachRolePolicy` with `AdministratorAccess` — no confirmed usage yet
- S3 bucket ACL changed to `public-read` on a non-production bucket

**SEV-3 events:**
- GuardDuty Medium finding: port scan from internal subnet
- `s3:ListBuckets` from an IAM user with no prior history of that action

**Triage API schema mock:**

```json
{
  "signal_id": "sig-abc123",
  "source": "guardduty",
  "finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
  "severity_raw": 7.5,
  "resources": ["arn:aws:iam::111111111111:role/ProdAppRole"],
  "triage_output": {
    "sev": "P1",
    "rationale": "Instance credential used from non-corporate IP with confirmed outbound data",
    "containment_actions": ["deactivate_key", "snapshot_instance", "quarantine_sg"],
    "ttl_risk": "STS session may persist up to 3600s"
  }
}
```

## Azure

**SEV-1 concrete events:**
- Azure Defender alert `Suspicious process executed on VM` + outbound network connection to known C2 IP
- Storage account `AllowBlobPublicAccess: true` + anonymous read activity in diagnostic logs
- `Microsoft.Authorization/roleAssignments/write` granting `Owner` to external SPN + subsequent resource access
- NSG rule created with `DestinationPortRanges: *` and `SourceAddressPrefix: Internet`

**SEV-2 events:**
- Sentinel `Anomalous RDP sign-in` with Medium confidence
- `Microsoft.Storage/storageAccounts/regenerateKey/action` on production storage account
- Key Vault access from non-standard IP without MFA

**SEV-3 events:**
- `Microsoft.Network/networkWatchers/flowLogs/read` — excessive flow log queries (possible recon)
- Sentinel low-confidence brute-force against Azure AD

**Triage snippet:**

```bash
INCIDENT_ID="inc-$(date +%s)"
# Query Sentinel for correlated signals
az monitor log-analytics query \
    --workspace $(az monitor log-analytics workspace show \
        -g security-rg -n sentinel-ws --query customerId -o tsv) \
    --analytics-query "SecurityAlert | where TimeGenerated > ago(1h) | project AlertName, Severity, Entities" \
    -o table

az tag update --resource-id "/subscriptions/00000000-0000-0000-0000-000000000000" \
    --operation Merge --tags "incident-id=$INCIDENT_ID"
```

## GCP

**SEV-1 concrete events:**
- SCC finding `ACCESS_TOKEN_EXFILTRATION` or `CREDENTIALS_EXPOSED` with subsequent `compute.instances.setMetadata` call
- Cloud SQL instance with `authorizedNetworks: 0.0.0.0/0` + anomalous query volume from external IP
- `iam.serviceAccounts.getAccessToken` from a GCE instance whose metadata shows a non-GCP source IP
- GCS bucket IAM `allUsers` has `roles/storage.objectViewer` + confirmed download from non-org IP

**SEV-2 events:**
- SCC `IAM_ANOMALOUS_GRANT` — new `Owner` grant to external identity
- `compute.firewalls.create` with `0.0.0.0/0` source range on port 22
- GKE pod running with `hostNetwork: true` unexpectedly

**SEV-3 events:**
- SCC `PUBLIC_BUCKET_ACL` on empty or non-sensitive bucket
- `compute.instances.list` from a service account never previously used for compute API

**Triage snippet:**

```bash
INCIDENT_ID="inc-$(date +%s)"
# Pull recent SCC findings
gcloud scc findings list "organizations/000000000000" \
    --source="$(gcloud scc sources describe organizations/000000000000 \
        --source=1111111111111111111 --format='value(name)')" \
    --filter='state="ACTIVE" AND severity="HIGH" OR severity="CRITICAL"' \
    --format='table(finding.name, category, severity)'

gcloud compute instances add-labels compromised-instance \
    --zone=us-central1-a --labels=incident-id=$INCIDENT_ID
```

## OnPrem mapping (recap table)

| Severity signal | OnPrem | AWS | Azure | GCP |
|----------------|--------|-----|-------|-----|
| Credential exfil | DC event 4662 (DS replication) | GuardDuty InstanceCredExfil | Sentinel anomalous sign-in | SCC ACCESS_TOKEN_EXFILTRATION |
| Public data exposure | Open share on file server | S3 BlockPublicAccess=false | Storage blob public access | GCS allUsers grant |
| Privilege escalation | Event 4672 (special privs assigned) | iam:AttachRolePolicy AdminAccess | roleAssignments/write Owner | IAM_ANOMALOUS_GRANT |
| C2 callback | EDR process → external IP | GuardDuty Backdoor:EC2/C&CActivity.B | Defender suspicious process + network | SCC C2_DOMAIN_RESOLUTION |
| MSEV inflation guard | SIEM dedup on hostname | Dedupe on principalId + sourceIP in 5-min window | Dedupe on UserPrincipalName + IP | Dedupe on IAM identity + source IP |

## 🔴 Red Team view

Attackers aware of SEV scoring logic will weaponize noise to induce severity inflation:

**Technique: Dilution via `List*` API spam.** The attacker calls `s3:ListBuckets`, `ec2:DescribeInstances`, `iam:ListRoles` in rapid succession from the same compromised identity. Each call generates a separate GuardDuty/Sentinel/SCC finding. If the triage rule treats each finding independently, the defender ends up with 15 P3 alerts instead of one aggregated P3.

**Defense-aware: rapid same-action repetition.** `sts:GetCallerIdentity` repeated every 2 seconds. This creates a "credential-checking" baseline that attackers use to test credential validity, but it also generates log volume that can overwhelm the triage pipeline.

**Low-and-slow signature.** Instead of one burst, the attacker spreads `List*` calls across 6 hours, each below the volume threshold. Individual events are discarded; the pattern is invisible without long-window aggregation.

**Artifacts:** API call trails show an unusual `List*` / `Describe*` density from a single `principalId` in a short window. CloudTrail `eventSource` diversity is low; `userAgent` is consistent (the attacker's tool). Logs contain `errorCode: null` (successful calls).

## 🔵 Blue Team view

### Deduplication rules

Aggregate signals per identity per 5-minute bucket. If the same `principalId` + `sourceIP` generates N identical `List*` events, count as 1 signal, not N.

```python
# Triage deduplication pseudo-code
def score_signal(signal):
    identity = signal['principalId']
    ip = signal['sourceIPAddress']
    event_type = signal['eventName']
    bucket = floor_to_5min(signal['eventTime'])

    key = f"{identity}:{ip}:{event_type}:{bucket}"
    if key in recent_signals:
        return None  # duplicate; suppress
    recent_signals[key] = signal
    return classify_severity(signal)
```

### Calibration baseline

Establish a daily metric of `List*` / `Describe*` call volume per identity. Alert only when an identity exceeds its 7-day moving average + 3 standard deviations — not on every `List*` event.

### Cloud-native aggregation

- **AWS:** Use CloudWatch Contributor Insights to aggregate API call frequency per `principalId`.
- **Azure:** Sentinel query with `summarize count() by UserPrincipalName, bin(TimeGenerated, 5m)`.
- **GCP:** BigQuery windowed aggregation: `SELECT principalEmail, COUNT(*) FROM cloudaudit_googleapis_com_data_access WHERE ... GROUP BY principalEmail, TIMESTAMP_TRUNC(timestamp, MINUTE, 5)`.

### Triage automation template (Logic App / Lambda)

```
Input: signal JSON
  → Dedupe check (Redis/DynamoDB ttl=300s)
  → If duplicate → discard, log to metrics
  → Else → enrich (IAM role effective permissions, resource tags)
  → Run decision tree (public? privileged? data volume?)
  → Output: SEV score + recommended containment actions
```

## Expanded Severity Matrix — Per-Cloud Event Catalog

Triage analysts should memorize the P1 events; P2–P4 can be referenced. Each cell contains real event types from GuardDuty (AWS), Sentinel/Defender (Azure), and SCC (GCP).

### P1 — Critical (Active Breach / Confirmed Exfil)

| Cloud | Event Type | Source | Why P1 |
|-------|-----------|--------|--------|
| AWS | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` with `bytesOut > 100 MB` | GuardDuty + CloudTrail | Instance role creds stolen via SSRF and used from external IP with confirmed data movement |
| AWS | S3 `BlockPublicAccess: false` + `s3:GetObject` events from non-corporate IP range | S3 Server Access Logs + CloudTrail Data Events | Public bucket with active exfiltration by external actor |
| AWS | `iam:CreateAccessKey` called from IP not in corporate CIDR on production IAM user | CloudTrail | Attacker created long-term access key for persistence; credentials now exist outside your control |
| AWS | GuardDuty `Backdoor:EC2/C&CActivity.B!DNS` + VPC Flow Log shows TCP/443 to known C2 IP | GuardDuty + VPC Flow Logs | Compromised EC2 beaconing to attacker infrastructure |
| Azure | Sentinel `Suspicious process executed on VM` + outbound `NetworkPort: 443` to threat intel IP | Defender for Cloud + Sentinel | Host compromise with C2 callback in progress |
| Azure | Storage account `AllowBlobPublicAccess: true` + `GetBlob` operations from `UserAgent: "Mozilla/5.0"` with non-corporate IP | Storage Analytics Logs + Sentinel | Public blob container actively being read by unknown actor |
| Azure | `Microsoft.Authorization/roleAssignments/write` granting `Owner` to external SPN (`appId` external to tenant) + subsequent `ListKeys` on storage | Activity Log + Sentinel UEBA | Privilege escalation to Owner by external principal with data access follow-through |
| Azure | Sentinel `Rare subscription operations` + `Microsoft.Storage/storageAccounts/regenerateKey/action` from new IP | Sentinel Anomaly + Activity Log | Attacker regenerating storage keys for persistence after initial compromise |
| GCP | SCC `ACCESS_TOKEN_EXFILTRATION` finding + `iam.serviceAccounts.getAccessToken` from non-GCP source IP | SCC + Audit Logs | Service account credentials exfiltrated and used outside Google's network |
| GCP | GCS bucket `allUsers` = `roles/storage.objectViewer` + `storage.objects.get` from IP not in organization IP range | Cloud Audit Logs (Data Access) | Public bucket with active download by external entity |
| GCP | `compute.instances.setMetadata` adding SSH key to production instance + subsequent `compute.instances.getSerialPortOutput` | Audit Logs | Attacker added SSH key and accessed serial console (credential theft / persistence) |
| GCP | SCC `DEFENSE_EVASION:DEFENSE_EVASION` + Cloud Audit Logs sink deleted or modified | SCC + Audit Logs | Attacker disabling logging to cover tracks; confirmed active intrusion |

### P2 — High (Probable Compromise / Public Exposure Without Confirmed Exfil)

| Cloud | Event Type | Source | Why P2 |
|-------|-----------|--------|--------|
| AWS | `iam:AttachRolePolicy` with `AdministratorAccess` attached to non-admin role — no confirmed usage yet | CloudTrail | Privilege escalation occurred, but no follow-on API calls yet; contain before attacker returns |
| AWS | GuardDuty `Recon:IAMUser/MaliciousIPCaller.Custom` from IP flagged by threat intel | GuardDuty | Reconnaissance from known-malicious IP against IAM API; precursor to attack |
| AWS | S3 bucket ACL changed to `public-read` or bucket policy grants `Principal: *` with `s3:GetObject` | CloudTrail + S3 (bucket policy) | Bucket made public, no access events yet, but window is open |
| AWS | Security Group modified: `ingress 0.0.0.0/0` on port 22/3389 added to instance with `Name=prod-*` tag | CloudTrail + Config | Production instance exposed to internet on admin ports |
| Azure | Sentinel `Anomalous RDP sign-in` with Medium confidence + source IP in geo-anomalous region | Sentinel + Entra ID Sign-in Logs | Probable credential compromise; lateral movement possible |
| Azure | `Microsoft.Storage/storageAccounts/regenerateKey/action` on production storage account from new IP | Activity Log | Attacker regenerating keys; may have previous key material |
| Azure | Key Vault `SecretGet` from IP outside ExpressRoute/VPN ranges for the first time in 30 days | Key Vault Diagnostic Logs + Sentinel | Credential access from unusual location |
| Azure | NSG rule created with `DestinationPortRanges: *` and `SourceAddressPrefix: Internet` on production subnet | Activity Log + NSG Flow Logs | Firewall rule opened to all ports from internet |
| GCP | SCC `IAM_ANOMALOUS_GRANT` — new `roles/editor` or `roles/owner` binding to external email | SCC + Audit Logs | Suspicious IAM grant to external identity |
| GCP | `compute.firewalls.create` with `sourceRanges: 0.0.0.0/0` and `allowed[].ports: ["22","3389"]` on production VPC | Audit Logs | Firewall rule exposing admin ports to internet |
| GCP | GKE pod running with `hostNetwork: true` and `hostPID: true` unexpectedly (no deployment history) | Audit Logs + GKE Audit | Container breakout attempt or misconfigured workload with node-level access |
| GCP | `iam.serviceAccountKeys.create` on production SA from IP not in corporate CIDR | Audit Logs | Long-lived credential creation on production service account |

### P3 — Medium (Suspicious / Configuration Drift — Escalatable)

| Cloud | Event Type | Source | Why P3 |
|-------|-----------|--------|--------|
| AWS | GuardDuty Medium finding: `Recon:EC2/Portscan` from internal subnet | GuardDuty | Internal reconnaissance; may be attacker lateral movement or authorized vuln scan |
| AWS | `s3:ListBuckets` from IAM user with no prior history of S3 API calls | CloudTrail | Anomalous recon; could be compromised credential or curious insider |
| AWS | Config rule `restricted-ssh` NON_COMPLIANT: security group with `0.0.0.0/0` on port 22 in non-prod VPC | AWS Config | Configuration drift; lower severity because non-production, but still risk |
| AWS | `ec2:CreateVolume` from snapshot in different account | CloudTrail | Potential data exfiltration: copying EBS snapshot across accounts |
| Azure | Sentinel `Brute-force attack against Azure AD` with Low confidence (<10 failures) | Sentinel | Probing; low volume suggests targeted rather than spray attack |
| Azure | `Microsoft.Network/networkWatchers/flowLogs/read` executed by non-SOC principal | Activity Log | Possible attacker probing network topology via flow logs |
| Azure | App Service `WEBSITE_RUN_FROM_PACKAGE` URL changed to external storage account | Activity Log + Resource Logs | Code injection risk: app package source redirected |
| Azure | `Microsoft.Resources/subscriptions/resourceGroups/read` from SPN not previously seen using resource management API | Activity Log | Anomalous read-only recon from service principal |
| GCP | SCC `PUBLIC_BUCKET_ACL` on empty or non-sensitive bucket | SCC | Public exposure exists but data sensitivity is low; fix within 24h |
| GCP | `compute.instances.list` from SA never previously used for compute API calls | Audit Logs | Anomalous recon from service account; possible credential testing |
| GCP | `logging.sinks.update` modifying log filter to `severity >= CRITICAL` (excluding lower severities) | Audit Logs | Log filter narrowed — possible evasion prep but could be admin action |
| GCP | `projects.serviceAccounts.list` from SA not in CI/CD or admin group | Audit Logs | Enumeration of service accounts; reconnaissance phase |

### P4 — Low (Recon Noise / Isolated Misconfig — No Immediate Risk)

| Cloud | Event Type | Source | Why P4 |
|-------|-----------|--------|--------|
| AWS | Single `s3:ListBuckets` or `ec2:DescribeInstances` from a new IAM user during business hours | CloudTrail | Expected behavior for new developer; track for pattern |
| AWS | `sts:GetCallerIdentity` spike (5–10 calls/minute) from same principal | CloudTrail | Credential validation or SDK initialization burst; investigate if sustained |
| AWS | S3 bucket logging disabled on non-sensitive dev bucket | AWS Config | Best-practice violation; no immediate exposure |
| AWS | IAM user `AccessKeyLastUsed` > 90 days without rotation | IAM Credential Report | Credential hygiene issue; no indication of compromise |
| Azure | Single `az ad user list` from new CLI install (first-seen UserPrincipalName) | Entra ID Sign-in Logs | New CLI usage by existing user; likely legitimate |
| Azure | Resource group created with no `environment` tag | Activity Log + Azure Policy | Tagging policy violation; no security exposure |
| Azure | Storage account `minTlsVersion: TLS1_0` on dev account with no sensitive data | Azure Policy | Crypto hygiene issue; remediate during next sprint |
| Azure | `Microsoft.Web/sites/config/list/action` (reading app settings) from authorized dev | Activity Log | Normal developer activity; may expose connection strings if not careful |
| GCP | Single `gcloud projects describe` from new gcloud install | Audit Logs | First-use CLI activity; correlate with onboarding records |
| GCP | `storage.buckets.list` from user in developer group | Audit Logs | Expected enumeration during development |
| GCP | Cloud SQL instance with `requireSsl: false` on dev database | SCC | SSL not enforced; remediate during maintenance window |
| GCP | Service account key not rotated in 180 days | IAM Recommender | Credential lifecycle issue; no compromise indicated |

## Enhanced Triage Decision Tree

The tree below maps every signal through a structured decision path. It replaces gut-feel severity calls with reproducible logic. Print this and post it at each triage workstation.

```
                         ┌────────────────────────────┐
                         │    SIGNAL RECEIVED          │
                         │ (GuardDuty/Sentinel/SCC/    │
                         │  custom alert → SIEM)       │
                         └─────────────┬──────────────┘
                                       │
                         ┌─────────────▼──────────────┐
                         │ Q1: Is this a duplicate?    │
                         │ (same principalId + sourceIP│
                         │  + eventType within 5 min?) │
                         └──────┬──────────┬──────────┘
                                │ Y        │ N
                     ┌──────────▼──┐    ┌──▼──────────┐
                     │ SUPPRESS    │    │ Q2: Resource │
                     │ (log as     │    │ publicly     │
                     │  duplicate; │    │ exposed?     │
                     │  increment  │    └──┬───────┬───┘
                     │  counter)   │     Y │       │ N
                     └─────────────┘  ┌────▼───┐   │
                                      │Q3: Does│   │
                                      │resource│   │
                                      │contain │   │
                                      │PII/PHI/│   │
                                      │creds?  │   │
                                      └──┬──┬──┘   │
                                       Y │  │ N    │
                                  ┌──────▼┐ │ ┌────▼──────┐
                                  │ P1    │ │ │Q4: Public  │
                                  │Critical│ │ │access      │
                                  │Active │ │ │existed     │
                                  │exfil  │ │ │>1h?        │
                                  │possible│ │ └──┬─────┬───┘
                                  └────────┘ │  Y │     │ N
                                             │ ┌──▼──┐ ┌──▼──┐
                                             │ │ P2  │ │ P3  │
                                             │ │High │ │Med  │
                                             │ └─────┘ └─────┘
                                             │
                       ┌─────────────────────┘
                       ▼
              ┌─────────────────┐
              │ Q5: IAM        │
              │ credential used │
              │ from anomalous  │
              │ location?       │
              │ (geo-velo >     │
              │  1000km/h or   │
              │  first-seen IP) │
              └───┬─────────┬───┘
                Y │         │ N
        ┌─────────▼──┐      │
        │ Q6: Is the  │      │
        │ principal   │      │
        │ privileged? │      │
        │ (Admin/     │      │
        │  Owner/Org  │      │
        │  role?)     │      │
        └──┬──────┬───┘      │
          Y│      │N        │
    ┌──────▼┐ ┌───▼────┐    │
    │ P1    │ │ P2     │    │
    │Critical│ │High    │    │
    └───────┘ └────────┘    │
                            │
              ┌─────────────▼──────────────┐
              │ Q7: Data transfer volume   │
              │ > baseline mean + 3σ?      │
              │ (use CloudWatch Metrics /  │
              │  Storage Analytics / GCS   │
              │  usage logs)               │
              └───┬────────────┬───────────┘
                Y │            │ N
        ┌─────────▼──┐   ┌────▼──────────┐
        │ Q8: Dest IP │   │ Q9: Is this   │
        │ in threat   │   │ an IAM or     │
        │ intel feed? │   │ privilege     │
        └──┬──────┬───┘   │ escalation    │
          Y│      │N      │ event?        │
    ┌──────▼┐ ┌───▼────┐  │ (PassRole,    │
    │ P1    │ │ P2     │  │ AttachRole    │
    │Critical│ │High    │  │ Policy,       │
    └───────┘ └────────┘  │ roleAssign-   │
                          │ ments/write)  │
                          └──┬──────┬─────┘
                           Y │      │ N
                    ┌────────▼┐ ┌──▼──────┐
                    │ P2      │ │ Q10: Nth │
                    │High     │ │ identical│
                    └─────────┘ │ signal   │
                                │ from same│
                                │ identity │
                                │ in 5 min?│
                                └──┬───┬───┘
                                 Y │   │ N
                          ┌────────▼┐ ┌▼─────┐
                          │ AGGREGATE│ │ P3   │
                          │ do NOT   │ │Medium│
                          │ inflate  │ └──────┘
                          └──────────┘

LEAF-LEVEL RULES
────────────────
P1 if: public + sensitive data | privileged credential from anomalous IP |
       data transfer to threat-intel IP | confirmed exfil
P2 if: public without confirmed access | non-privileged credential anomaly |
       privilege escalation event | high data volume to unknown IP
P3 if: recon event below volume threshold | config drift without exposure |
       anomalous read-only API call | single low-confidence brute-force
P4 if: isolated recon | credential hygiene issue | tagging violation |
       dev-environment misconfig
```

### Severity Override Triggers

The decision tree can be overridden by a human triage lead when:

| Trigger | New SEV | Example |
|---------|---------|---------|
| Resource is a crown-jewel asset (pre-defined in asset inventory) | +1 severity | Dev S3 bucket with `public-read` is normally P3, but if it's `bucket-customer-data` on the crown-jewel list → P2 |
| Event occurs during a declared incident-freeze (e.g., product launch) | +1 severity | Any P3 during a launch blackout week → P2 |
| Event matches a known attack campaign from current threat intel | +1 severity | P2 `MaliciousIPCaller` from IP in active APT29 campaign → P1 |
| Testing window / authorized pentest in progress | -2 severity (suppress) | P1 alerted during authorized RoE window → logged but not paged |
| Event source is a known noisy service account (pre-registered in allowlist) | -1 severity | `s3:ListBuckets` from CI/CD SA → P4 from P3 |

## Triage Anti-Patterns

Common mistakes that derail cloud incident triage. Each one has cost real teams hours of response time.

### Anti-Pattern 1: Alert-Volume → Severity Inflation

**What happens:** A noisy GuardDuty/Sentinel/SCC finding fires 20 times in 10 minutes. The analyst treats each as an independent event and escalates all 20 as P3. The SOC drowns in duplicate tickets while the real P1 (buried in the noise) goes unnoticed.

**Why it's wrong:** Cloud APIs are inherently noisy. A single developer running `aws s3 ls` recursively generates `ListObjectsV2` per prefix. A CI/CD pipeline doing `ec2:DescribeInstances` with pagination fires multiple CloudTrail events.

**Fix:** Deploy deduplication *before* the ticket queue. Aggregate per `principalId + eventType + 5-min window`. Produce one ticket with `count: N`, not N tickets.

### Anti-Pattern 2: IAM Event = Automatic P1

**What happens:** Any `iam:AttachRolePolicy` or `roleAssignments/write` immediately triggers P1 regardless of context. The analyst pages the CISO at 3 AM for `iam:CreateRole` by Terraform in the CI/CD pipeline.

**Why it's wrong:** IAM changes are *normal* in cloud. Infrastructure-as-code pipelines create/update roles constantly. The threat is in unauthorized changes, not all changes.

**Fix:** Correlate IAM changes with the `userAgent` string. Terraform (`APN/1.0 HashiCorp`), Pulumi, CloudFormation, and CDK have known user-agents. IAM changes from these agents are CI/CD — normal. IAM changes from `aws-cli/2.x` or the console (`signin.amazonaws.com`) from an unknown IP are suspicious. Build a baseline of *who* makes IAM changes during *what hours*.

### Anti-Pattern 3: Public Bucket Finding = P1 (Always)

**What happens:** SCC `PUBLIC_BUCKET_ACL` or GuardDuty `Policy:IAMUser/S3BucketPublic` fires. Analyst immediately declares P1 and pages the on-call SRE. Investigation reveals the bucket is a static-asset CDN origin for a public website — it's *supposed* to be public.

**Why it's wrong:** Public buckets are legitimate for static websites, public datasets, software distributions, and CDN origins. The severity depends on what data is inside, not just the public access flag.

**Fix:** Enrich the finding with bucket tag data. Buckets tagged `data-classification: public` and `purpose: static-website` are P4. Buckets tagged `data-classification: restricted` or `data-classification: confidential` with public access → P1. Without tags, fetch the bucket inventory: list a few object keys, sample content types, check file extensions. The 2-minute enrichment beats a false P1 escalation.

### Anti-Pattern 4: Severity by Service, Not by Impact

**What happens:** The team builds a mapping table that says "all GuardDuty HIGH → P2, all GuardDuty MEDIUM → P3." The finding type is ignored. `Recon:EC2/Portscan` (MEDIUM) and `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` (MEDIUM) both become P3, even though the latter could be credential compromise.

**Why it's wrong:** Cloud security products have their own severity labels that don't map linearly to your triage severity. GuardDuty severity 7.0 might be a P2 in one context and P4 in another.

**Fix:** Your triage logic must key off the *finding type* (e.g., `InstanceCredentialExfiltration.OutsideAWS`), not the provider's severity score. The provider's severity is a *signal weight*, not a *business impact* rating. Use the decision tree above — it ignores the provider's label entirely.

### Anti-Pattern 5: No-Context Escalation

**What happens:** Triage analyst forwards the raw GuardDuty JSON to the L3 engineer with no enrichment. The engineer spends 20 minutes opening AWS Console, looking up the principal ARN, checking resource tags, and finding the VPC flow log — all work the L1/L2 analyst could have done.

**Why it's wrong:** This wastes L3 engineer time and increases mean-time-to-contain (MTTC). The L3 should receive a pre-enriched ticket that says *what* happened, *who* was involved, *what resources* are affected, and *what the blast radius could be*.

**Fix:** Enrich every signal before escalation. The L1/L2 triage step must add:

```json
{
  "enrichment": {
    "principal_type": "IAM Role / IAM User / Service Account / Managed Identity",
    "principal_effective_permissions": "s3:* on bucket X, dynamodb:GetItem on table Y",
    "resource_tags": {"env": "prod", "data-classification": "restricted"},
    "resource_network_location": "VPC vpc-abc123, subnet subnet-xyz789, public: false",
    "recent_activity_from_this_principal": "14 similar events in past 24h (baseline: 2/day)",
    "first_seen_for_this_principal": "2024-01-15 (18 months ago, not new)",
    "related_findings": ["GuardDuty finding gd-xxx 8 min earlier: Recon:IAMUser/..."]
  }
}
```

### Anti-Pattern 6: The "Wait and See" on P2 Events

**What happens:** A P2 fires — `iam:AttachRolePolicy` with `AdministratorAccess` from an unknown IP. The analyst decides to "monitor for 30 minutes" to see if anything else happens. 30 minutes later, the attacker has enumerated S3 buckets and initiated exfiltration.

**Why it's wrong:** Cloud attacks are fast. An attacker with `AdministratorAccess` can exfiltrate data in seconds. The 30-minute wait window is an eternity in cloud time. The "wait and see" reflex comes from on-prem incident response where attacker movement is constrained by network segmentation and logon times. Cloud has no such physics.

**Fix:** P2 events with privilege escalation characteristics should trigger *immediate* containment: revoke the session (`aws iam update-assume-role-policy` to deny, or `RevokeSessions` on the role), rotate credentials, and investigate concurrently. You can always roll back containment — you can't roll back exfiltration.

### Anti-Pattern 7: Ignoring Cross-Cloud Correlation

**What happens:** AWS triage analyst sees `InstanceCredentialExfiltration.OutsideAWS` (P1). Azure analyst sees `Anomalous RDP sign-in` (P2) from the same source IP. GCP analyst sees `ACCESS_TOKEN_EXFILTRATION` (P1) from the same IP. Three separate incidents are opened, three separate war rooms are convened, and nobody realizes it's the same attacker pivoting across all three clouds using credentials from a compromised developer laptop.

**Why it's wrong:** Multi-cloud enterprises have identity bridges (AWS SSO → Azure AD, GCP Workforce Identity Federation). An attacker who compromises one identity often has access to all three clouds. Siloed triage misses the big picture.

**Fix:** Route all cloud signals through a central SIEM/SOAR that correlates on `sourceIPAddress` and `principalId` across cloud providers. The SOAR playbook should ask: _"Is this source IP seen in any other cloud provider's audit logs in the past 24 hours?"_ If yes, open a single multi-cloud incident, not three separate ones.

Cross-links: [IR Runbook Cloud-Aware](./ir-runbook-cloud-aware.md) for per-cloud containment steps; [SSRF and IMDS Pivots](../Network-Security/ssrf-and-imds-pivots.md) for credential exfiltration triage; [Secrets Store Security](../Secrets-KMS/kms-hsm-and-vaults.md) for Key Vault / Secret Manager event triage.

## Hands-on lab

1. Generate 3 GuardDuty sample findings in your sandbox: `aws guardduty create-sample-findings --detector-id <id>`.
2. Write a Python script that consumes the findings via `aws guardduty list-findings` and classifies each per the decision tree above.
3. Simulate attacker noise: run 10 `aws s3 ls` calls in 1 minute using the same credentials. Verify your deduplication logic collapses them to 1 signal.
4. Teardown: no persistent resources.

## Detection rules & checklists

```yaml
# Sigma-style: SEV inflation from List* noise
title: Excessive List/Describe API Calls From Single Identity
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName|startswith:
      - 'List'
      - 'Describe'
      - 'Get'
  timeframe: 5m
  condition: selection | count() by principalId > 50
  severity: medium
```

- [ ] Triage decision tree printed at each analyst desk.
- [ ] Deduplication logic deployed before enabling new GuardDuty/Sentinel/SCC findings.
- [ ] Baseline `List*` call volume per identity recorded weekly.

## References

- [AWS GuardDuty finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types.html)
- [Azure Sentinel incident triage](https://learn.microsoft.com/en-us/azure/sentinel/investigate-incidents)
- [GCP SCC finding categories](https://cloud.google.com/security-command-center/docs/concepts-security-health-analytics-overview)
- See ATT&CK Cloud matrix for Discovery, Initial Access
