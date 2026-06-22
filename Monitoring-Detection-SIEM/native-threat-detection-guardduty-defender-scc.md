# 05 — Native Threat Detection: GuardDuty, Defender, SCC

> **Level:** Intermediate
> **Prereqs:** [The Security Log Mosaic per Cloud](the-security-log-mosaic-per-cloud.md), [Cloudtrail Activity & Data Events](cloudtrail-activity-and-data-events.md), [Azure Log Analytics & Sentinel](azure-log-analytics-and-sentinel.md), [GCP Cloud Audit Logs & Scc](gcp-cloud-audit-logs-and-scc.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Discovery, Credential Access, Lateral Movement, Execution
> **Authorization scope:** Enable GuardDuty/Defender/SCC only in your own sandbox accounts. Generate benign findings only (e.g., deliberately call `iam:CreateAccessKey` from a new IP to test detector triggers).

## What & why

Each cloud provider ships signature+ML-based threat detection that beats custom rules for common TTPs — cryptomining, unusual IAM credential exfiltration, SSH brute-force, Tor exit-node access. These services look at provider-internal telemetry you cannot replicate with log queries alone. The baseline detection coverage you get from enabling them (often one click) is unmatched.

## The OnPrem reality

Endpoint detection (CrowdStrike, SentinelOne, Defender for Endpoint) monitors syscalls, process trees, and network connections per host. Cloud-native threat detection adds the *control-plane* dimension — did an IAM user suddenly create access keys in a region they've never used? Did an EC2 instance start querying `bitcoin` DNS? No endpoint agent sees those.

## Cross-cloud detector comparison

| Threat category | AWS GuardDuty | Azure Defender for Cloud | GCP SCC Event Threat Detection | OnPrem EDR equivalent |
|---|---|---|---|---|---|
| IAM credential exfiltration | `CredentialExfiltration:IAMUser/AnomalousBehavior` | `Suspicious credential usage` alert | `iam:AnomalousServiceAccount` (as of June 2026, active SCC finding type) | UEBA on AD krbtgt anomalies |
| Cryptomining on compute | `CryptoCurrency:EC2/BitcoinTool.B!DNS` | `Cryptocurrency mining alert` | `exec:MaliciousExecutable` (as of June 2026, covered under exec-family findings) | Process + DNS monitoring |
| SSH/RDP brute-force | `UnauthorizedAccess:EC2/SSHBruteForce` | `Brute force attack against VM` | `network:BruteForce` (as of June 2026, covered under network-family findings) | syslog `/var/log/auth.log` |
| Reconnaissance — port scan from instance | `Recon:EC2/Portscan` | `Outbound port scan detected` | `network:PortScan` (as of June 2026, covered under network-family findings) | Zeek / Suricata IDS |
| Tor exit node access | `UnauthorizedAccess:EC2/TorClient` | `Communication with a known Tor exit node` | (as of June 2026, check current SCC Event Threat Detection coverage for Tor) | Firewall blocklist |
| Public S3 bucket | `Policy:S3/BucketPublicAccessGranted` | `Storage account publicly accessible` | `storage:BucketIsPublic` (as of June 2026, active SCC finding type) | File share permission audit |
| EKS/AKS/GKE compromise | `Impact:Kubernetes/SuccessfulAnonymousAccess` | `Kubernetes cluster exposed to internet` | `k8s:AnonymousAccess` (as of June 2026, covered under k8s-family findings) | Falco runtime rule |
| Anomalous IAM behavior | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` | `Suspicious process executed` (Defender for Servers) | `iam:AnomalousGrant` (as of June 2026, active SCC finding type) | Splunk `streamstats` deviations |

### What native detection catches that custom SIEM rules miss

| Native capability | Why custom rules can't replicate |
|---|---|
| DNS-based cryptomining detection | Provider watches DNS resolution from instance metadata — you never see DNS queries unless you enable Route 53 Resolver Query Logs |
| Instance credential exfiltration (IMDS v1) | GuardDuty sees the IMDS request pattern across VPC boundaries — your VPC Flow Logs show only IP:port |
| Cross-account `sts:AssumeRole` from known malicious CIDRs | Provider maintains threat intelligence feeds updated hourly — your SIEM doesn't have that feed unless you pay for it |
| Anomalous baseline per IAM principal | Provider trains per-account ML on your activity volume — replicating this in SIEM requires months of data engineering |

## AWS — GuardDuty

### Enable at organization level

```bash
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

aws guardduty create-members \
  --detector-id $(aws guardduty list-detectors --query DetectorIds[0] --output text) \
  --account-details '[{"AccountId":"222222222222","Email":"admin@example.com"},{"AccountId":"333333333333","Email":"admin@example.com"}]'

aws guardduty update-organization-configuration \
  --detector-id <detector-id> \
  --auto-enable \
  --data-sources S3Logs={AutoEnable=true},Kubernetes={AuditLogs={AutoEnable=true}}
```

### Terraform

```hcl
resource "aws_guardduty_detector" "org" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}

resource "aws_guardduty_organization_admin_account" "delegated" {
  admin_account_id = "111111111111"
}

resource "aws_guardduty_organization_configuration" "org" {
  detector_id = aws_guardduty_detector.org.id
  auto_enable_organization_members = "ALL"
}
```

### Forward findings to EventBridge

```bash
aws events put-rule \
  --name guardduty-findings \
  --event-pattern '{"source":["aws.guardduty"]}'

aws events put-targets \
  --rule guardduty-findings \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:111111111111:function:process-guardduty-finding"
```

### Sample finding JSON (benign — `Recon:EC2/Portscan`)

```json
{
  "accountId": "111111111111",
  "arn": "arn:aws:guardduty:us-east-1:111111111111:detector/detector-id/finding/abc123",
  "type": "Recon:EC2/Portscan",
  "severity": 3.0,
  "resource": {
    "instanceDetails": {
      "instanceId": "i-11111111111111111",
      "launchTime": "2026-06-22T00:00:00Z"
    }
  },
  "service": {
    "action": {
      "actionType": "PORT_SCAN",
      "portProbeAction": {
        "portProbeDetails": [{"localPortDetails": {"port": 22, "portName": "SSH"}}],
        "blocked": false
      }
    }
  }
}
```

## Azure — Microsoft Defender for Cloud

### Enable at subscription level

```bash
az security pricing create --name VirtualMachines --tier Standard
az security pricing create --name StorageAccounts --tier Standard
az security pricing create --name SqlServers --tier Standard
az security pricing create --name Containers --tier Standard
az security pricing create --name AppServices --tier Standard
az security pricing create --name KeyVaults --tier Standard
az security pricing create --name Dns --tier Standard

az security workspace-setting create \
  --name default \
  --target-workspace /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec-monitor/providers/Microsoft.OperationalInsights/workspaces/central-workspace
```

### Terraform

```hcl
resource "azurerm_security_center_subscription_pricing" "vms" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_setting" "mcas" {
  setting_name = "MCAS"
  enabled      = true
}
```

### Export alerts to Sentinel

Defender for Cloud alerts automatically appear in Microsoft Sentinel if the workspace is the same. No extra configuration needed — they show up as `SecurityAlert` table entries.

```kql
SecurityAlert
| where ProviderName == "Azure Security Center"
| where Severity >= 2
| project TimeGenerated, AlertName, CompromisedEntity, Severity, Entities
```

## GCP — Security Command Center Event Threat Detection

SCC Event Threat Detection is part of SCC Premium. It scans Cloud Audit Logs, Cloud DNS logs, and Cloud NAT logs for anomaly patterns.

### Enable SCC Premium

```bash
gcloud scc services enable \
  --organization organizations/111111111111 \
  --service SECURITY_COMMAND_CENTER

gcloud scc services enable \
  --organization organizations/111111111111 \
  --service EVENT_THREAT_DETECTION
```

### List active findings

```bash
gcloud scc findings list organizations/111111111111 \
  --filter "state=\"ACTIVE\" AND severity=\"HIGH\"" \
  --format "table(finding.name, finding.category, finding.resourceName, finding.severity)"
```

### Notification to Pub/Sub (equivalent to EventBridge forwarding)

```bash
gcloud pubsub topics create scc-findings
gcloud scc notifications create scc-notify \
  --organization organizations/111111111111 \
  --pubsub-topic projects/project-id-111111/topics/scc-findings \
  --filter "state=\"ACTIVE\" AND severity=\"HIGH\""
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| IDS/IPS | Snort / Suricata | GuardDuty VPC traffic analysis | Defender for Cloud network layer | SCC Event Threat Detection (NAT logs) |
| Host-based detection | OSSEC / Wazuh | GuardDuty + Security Hub integrations | Defender for Servers | SCC VM Threat Detection |
| IAM anomaly detection | UEBA on AD logs | GuardDuty `CredentialExfiltration` | Defender for Cloud + Sentinel UEBA | SCC `iam:Anomalous*` findings |
| Cryptomining detection | Process monitoring | GuardDuty `CryptoCurrency:*` | Defender for Cloud | SCC `exec:MaliciousExecutable` |
| Findings aggregation | Custom ELK dashboard | Security Hub | Defender for Cloud dashboard | SCC dashboard |
| Findings → SIEM | Logstash pipeline | EventBridge → Lambda | Auto-sync to Sentinel | Pub/Sub → Cloud Function |

## 🔴 Red Team view

### Evading GuardDuty: the SSRF → IMDS path

GuardDuty has strong detections for `CredentialExfiltration:IAMUser/AnomalousBehavior` — but it fires when a long-lived `AKIA*` key is used from a suspicious IP. Attackers avoid this by using SSRF on a web application to hit the instance metadata service instead:

```bash
# Traditional path (triggers GuardDuty):
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
aws iam create-access-key --user-name victim-user
# GuardDuty finding: CredentialExfiltration:IAMUser/AnomalousBehavior

# SSRF evasion path (bypasses GuardDuty IAM detector):
curl http://web-app.victim.internal/redirect?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role
# Now the attacker has the instance's STS credentials — no IAM key involved.
# GuardDuty may trigger Recon:EC2/SSRF or UnauthorizedAccess:EC2/SSRF if SSRF protection is on.
```

**What IS detected:** GuardDuty does detect `Recon:EC2/SSRF` — but only if the SSRF pattern matches its signatures. A slow, targeted SSRF from a compromised app may go undetected.

**Azure equivalent:** `http://169.254.169.254/metadata/identity/oauth2/token` — Defender for Cloud may fire `Suspicious URL request` if Defender for Servers is active.

**GCP equivalent:** `http://metadata.google.internal/` — SCC may detect unusual metadata access patterns.

### Artifacts

- Initial compromise (SSRF) generates VPC Flow Logs showing traffic from the app instance to `169.254.169.254` on port 80.
- If the attacker uses the stolen instance credentials for high-signal actions (`CreateAccessKey`, `AttachRolePolicy`), those are CloudTrail management events regardless.
- `aws:RequestedRegion` and `sourceIPAddress` in CloudTrail may deviate from normal baselines for that role.

## 🔵 Blue Team view

### Custom finding supplements — where native gaps exist

The table below shows TTPs not covered by native detectors, with custom rule examples:

| Undetected TTP | Custom supplement | Cloud |
|---|---|---|
| `iam:UpdateAssumeRolePolicy` to add external account | CloudWatch alarm on `UpdateAssumeRolePolicy` + cross-account trust | AWS |
| `storage.objects.setIamPolicy` making bucket public | SCC Security Health Analytics catches the config; supplement with Custom Detect on the IAM change | GCP |
| SAS token generation with read-all + long expiry | Azure Policy audit + KQL alert on `ListSas` + long expiry | Azure |
| `ecs:RegisterTaskDefinition` with privileged container | Custom CloudWatch rule on `RegisterTaskDefinition` with `"privileged": true` | AWS |

### Calibration: reducing false positives from native detectors

GuardDuty's `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` triggers when an IAM user calls `sts:AssumeRole` from outside the assigned VPC — but authorized cross-region failover pipelines can trigger it.

**Tune with GuardDuty trusted IP list:**

```bash
aws guardduty create-ip-set \
  --detector-id <id> \
  --name "trusted-cidrs" \
  --format TXT \
  --location "s3://guardduty-config-111111111111/trusted-ips.txt" \
  --activate
```

**Tune Azure Defender alerts** via suppression rules in the Defender portal, or assign lower severity in Sentinel analytics rules.

### Detection queries

```
# AWS CloudWatch — GuardDuty findings summary by type
fields @timestamp, type, severity, accountId
| filter source = "aws.guardduty"
| stats count() by type, bin(1h)

# Azure KQL — Defender alerts by severity
SecurityAlert
| where ProviderName has "Azure Security Center"
| summarize Count=count() by Severity, AlertName
| order by Count desc

# GCP — SCC findings by category
SELECT
  finding.category,
  COUNT(*) as count,
  MAX(finding.severity) as max_severity
FROM `project-id-111111.audit_logs.scc_findings`
GROUP BY finding.category
ORDER BY count DESC;
```

### Response steps

1. **Credential exfiltration finding:** Immediately rotate the affected credential. For IAM User keys, deactivate and delete. For IAM Role credentials, revoke active sessions via `RevokeSecurityGroupIngress`.
2. **Cryptomining finding:** Stop the instance (`aws ec2 stop-instances`), snapshot its volume for forensics, then isolate the VPC/subnet.
3. **Public resource finding:** Remove the public policy/ACL immediately. Search CloudTrail for the `PutBucketPolicy` or `storage.objects.setIamPolicy` call that made it public.
4. **Forward to SIEM:** Ensure the finding appears in your central dashboard alongside other telemetry.

## Hands-on lab

### AWS GuardDuty

1. Enable GuardDuty in your sandbox:
```bash
aws guardduty create-detector --enable
DETECTOR_ID=$(aws guardduty list-detectors --query DetectorIds[0] --output text)
```

2. Generate a benign finding — access a vulnerable EC2 security group or simply wait for GuardDuty to generate sample findings (free 30-day trial generates sample findings).

3. List findings after 24 hours:
```bash
aws guardduty list-findings --detector-id $DETECTOR_ID
aws guardduty get-findings --detector-id $DETECTOR_ID --finding-ids <id>
```

4. **Teardown:**
```bash
aws guardduty delete-detector --detector-id $DETECTOR_ID
```

### Azure Defender for Cloud

1. Enable Standard tier for VMs:
```bash
az security pricing create --name VirtualMachines --tier Standard
```

2. Check recommendations after 1-2 hours:
```bash
az security assessment list --query '[?status.code==`Unhealthy`].{Name:displayName,Resource:resourceDetails.Id}'
```

3. **Teardown:**
```bash
az security pricing create --name VirtualMachines --tier Free
```

## Detection rules & checklists

```
# Checklist
- [ ] GuardDuty enabled in all regions (organization auto-enroll)
- [ ] Defender for Cloud: all supported resources at Standard tier
- [ ] SCC Premium enabled with Event Threat Detection
- [ ] Findings forwarded to EventBridge / Sentinel / Pub/Sub
- [ ] Trusted IP lists calibrated to suppress known-good traffic
- [ ] Custom CloudWatch/KQL/Logging rules supplementing native gap areas
- [ ] Monthly tabletop: review 3 findings and trace them to source
- [ ] SCP/Policy prevents disabling GuardDuty or Defender
```

## References
- [AWS GuardDuty finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [Azure Defender for Cloud alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)
- [GCP SCC Event Threat Detection](https://cloud.google.com/security-command-center/docs/concepts-event-threat-detection-overview)
- [../Blue-Team-Defense/blue-team-basics.md](../Blue-Team-Defense/blue-team-basics.md)
- [../Red-Team-Offense/ssrf-and-imds-pivots.md](../Red-Team-Offense/ssrf-and-imds-pivots.md)
