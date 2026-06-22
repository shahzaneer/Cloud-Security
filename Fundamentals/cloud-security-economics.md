# 07 — Cloud Security Economics

> **Level:** Intermediate
> **Prereqs:** [Shared Responsibility Model](shared-responsibility.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Impact, Defense Evasion, Resource Development
> **Authorization scope:** Run only in your own sandbox accounts. Cost calculations use placeholder pricing figures for illustration.

## What & why

Cloud security economics quantifies the cost of preventive controls against the financial impact of a breach. Cloud engineers must justify security spend to management in dollar terms — not compliance abstractions — and understand how attacker behavior shifts when defenders cut corners to save money.

## The OnPrem reality

On-prem cost modeling was simple: hardware + licensing + in-house SOC salaries. Cloud introduces consumption-based pricing where every control (logging, scanning, encryption) carries a per-API-call or per-GB charge. A naive "turn everything on" approach can produce a seven-figure monthly bill. Conversely, disabling controls to hit budget targets creates predictable attacker entry points.

| Cost category | OnPrem | Cloud shift |
|---|---|---|
| Capital expenditure | Servers, HSMs, HA pairs | $0 (OpEx only) |
| Logging | Storage cost only | Per-event ingestion + retention tier |
| Monitoring/SIEM | Fixed license | Per-GB ingestion, per-asset coverage |
| Encryption | Software license or HSM purchase | Per-key + per-request on KMS |
| Breach cost | Legal, IR retainer, downtime | Same + egress fees + cross-account containment |

## Core concepts

### Breach cost calculators

| Calculator | Inputs | Output |
|---|---|---|
| IBM/Ponemon Cost of a Data Breach | Industry, region, breach size | Average total cost, per-record cost |
| AWS Pricing Calculator (Security) | GuardDuty, CloudTrail, Macie assumptions | Monthly recurring |
| Azure TCO Calculator | Sentinel, Defender for Cloud, Purview | 3-year projected |
| GCP Pricing Calculator | SCC, Chronicle, Cloud Audit Logs | Per-project estimate |

**Example estimate (as of June 2026):** A mid-size SaaS company running 500 EC2 instances across 3 AWS accounts with full GuardDuty + CloudTrail management events + Macie for 50TB S3 pays roughly $18,000–$24,000/month for native security tooling. The average cloud breach cost (IBM 2025 report) is $4.88M. The annual security tooling spend (~$264K) is ~5% of one breach.

### FinOps–Security intersection

- **Tagging for chargeback:** Tag every security resource (`cost-center=sec`, `env=prod`) so security spend is visible to workload owners.
- **Reserved capacity for logging:** CloudTrail Lake, Sentinel, Chronicle all offer committed-use discounts.
- **Log tiering:** Hot (30 days, fast query), warm (90 days, slower), cold (1 year+, restore latency). Move 80% of volume to cold storage.
- **Alert rationalization:** Every alert costs analyst time (~$50–$150 per triaged alert). Tune down noise before scaling up ingestion.

### Insurance premiums

Cyber insurance carriers now demand evidence of:
- MFA on all privileged accounts
- Immutable backups with tested restoration
- EDR/NDR on all cloud workloads
- Annual penetration test (as of June 2026, most carriers require cloud-specific pentest, not just web app)

Premiums typically drop 15–25% when these controls are attested. Absent controls, premiums rise 30–50% or coverage is denied.

## AWS

```bash
# Estimate monthly CloudTrail spend (management events)
aws cloudtrail get-trail-status --name example-trail
# Check GuardDuty coverage
aws guardduty list-detectors
# List Macie classification jobs (per-GB pricing)
aws macie2 describe-classification-job --job-id example-job-id
```

**Cost-cutting that attackers notice:**
- Disabling CloudTrail to save $0.35/100K events.
- Turning off GuardDuty in non-prod accounts ($1.00–$3.00/month per account saved).
- Not enabling S3 server-access logging (minimal cost, maximum blind spot).

**Console path:** AWS Billing → Cost Explorer → Filter by service "CloudTrail", "GuardDuty", "Macie".

## Azure

```bash
# Sentinel ingestion estimate
az monitor log-analytics workspace show \
  --resource-group sec-rg --workspace-name sec-workspace \
  --query "retentionInDays"

# Defender for Cloud coverage
az security pricing list --query "[].{Plan:name,Tier:pricingTier}" -o table
```

**Gotcha:** Sentinel ingestion is charged per GB. Microsoft 365 audit logs can exceed 100GB/month in a medium enterprise just from SharePoint/Teams activity. Filter before ingestion.

## GCP

```bash
# Cloud Audit Logs — check what's enabled (Data Access logs are expensive)
gcloud services list --enabled --filter="name:logging"
# SCC tier
gcloud scc settings describe --organization=111111111111 \
  --format="value(settings.state)"
```

**Gotcha:** GCP Data Access audit logs cost $0.50/GB ingested and can generate 100× the volume of Admin Activity logs. Start with Admin Activity + selected Data Access scopes.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Log storage | Fixed disk cost | S3 per-GB + CloudTrail per-event | Log Analytics per-GB + retention | Cloud Logging per-GB + retention |
| Threat detection | Fixed SOC tooling cost | GuardDuty per-1M events | Defender for Cloud per-asset | SCC Premium tier flat + per-asset |
| DLP scanning | Fixed license | Macie per-GB classified | Purview per-asset + per-GB | DLP API per-1M units |
| Breach cost factor | Egress fees N/A | Cross-account egress fees apply | Cross-region egress fees apply | Inter-region egress fees apply |
| Insurance discount | SOC 2 + pentest | + cloud-specific controls attestation | + Entra ID P2 + Conditional Access | + Org Policy + SCC Premium |

## 🔴 Red Team view

Attackers deliberately seek cost-cutting gaps because they produce predictable blind spots.

**Technique 1 — Detect disabled logging:**
```bash
# Attacker enumerates CloudTrail status to find unmonitored accounts
aws cloudtrail describe-trails --region us-east-1
# Response: "IsMultiRegionTrail": false, "IsOrganizationTrail": false
# This means some regions/accounts lack coverage — attacker pivots there.
```

**Technique 2 — Abuse free-tier overrides:**
Many accounts turn off S3 server-access logging to save <$5/month. The attacker now exfiltrates data via S3 with no record of which objects were accessed.

**Technique 3 — MFA gap from cost avoidance:**
Organizations that skip MFA for break-glass accounts or CI/CD service users to avoid FIDO2 hardware costs create a single un-MFA'd entry point. Attacker brute-forces the password on that one account.

**Contained example — CloudTrail disable then lateral move:**
```bash
# Step 1: Attacker gains role credential, checks trail status
aws cloudtrail describe-trails
# Step 2: If trail is single-region, attacker operates from unmonitored region
aws ec2 describe-instances --region af-south-1
# Step 3: No CloudTrail events generated for af-south-1 — IR team has zero visibility
```

**Artifacts left:** The `DescribeTrails` call itself may be logged (if it hits a monitored region). The region pivot shows in VPC Flow Logs if enabled. The absence of data from a region is a detection signal in itself.

## 🔵 Blue Team view

### Justifying spend to management

Present the equation:
```
Annual_breach_cost × likelihood_reduction = value_of_control
```

Example: A GuardDuty deployment costs $12,000/year. It reduces likelihood of undetected compromise from 15% to 3%. At a $4.88M breach cost, the expected savings are $4.88M × 0.12 = $585,600/year. ROI = 48:1.

### Cost-optimization without sacrificing security

**Tiered approach:**

| Tier | Controls | Monthly cost (500-instance org) |
|---|---|---|
| Minimum viable | CloudTrail mgmt events, MFA on all humans, S3 block public access, root account locked | ~$50 |
| Standard | All minimum + GuardDuty/Defender, config rules (managed), S3 access logs, KMS CMK on prod | ~$8,000 |
| Mature | All standard + CloudTrail data events (selective), Macie/Purview, WAF, drift detection, dedicated SIEM | ~$22,000 |
| Advanced | All mature + CloudTrail Lake, UEBA, full data event logging, red team retainers, DLP on all buckets | ~$45,000+ |

**Cost-cutting checklist — safe reductions:**
- [ ] Data events: enable only on S3 buckets containing PII, not all buckets.
- [ ] Log retention: 90 days hot, 1 year cold, 7 years archive (not all hot).
- [ ] Alert suppression: deduplicate identical alerts within a 15-minute window.
- [ ] Cross-account: security tooling in a dedicated security account, not per-workload account.
- [ ] Reserved capacity: commit to 1-year Sentinel/Chronicle ingestion for 30% discount.

**Cost-cutting checklist — dangerous reductions (never):**
- [x] Never disable login event logging on root/production accounts.
- [x] Never skip MFA on any account with write access.
- [x] Never disable native threat detection in the production subscription/org.
- [x] Never eliminate encryption on backup data.

### Budget anomaly detection

```bash
# AWS: detect CloudTrail spend spike (someone enabled data events on everything)
aws ce get-cost-and-usage \
  --time-period Start=2026-06-01,End=2026-06-23 \
  --granularity DAILY --metrics "UnblendedCost" \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["AWS CloudTrail"]}}'
```

If CloudTrail spend jumps 10× overnight, someone enabled data events org-wide — investigate whether it's authorized.

## Hands-on lab

1. In your sandbox AWS account, run the AWS Pricing Calculator for security services:
   - 1 CloudTrail org trail (management events)
   - GuardDuty in 1 region
   - Config rules (3 managed rules)
   - S3 (50GB with Macie classification)
2. Estimate monthly spend. Compare to the IBM breach cost figure ($4.88M).
3. Create a quick ROI spreadsheet: `annual_tooling_cost ÷ (breach_cost × 0.10 assumed risk reduction)`
4. Enable billing alerts at $50 threshold:
```bash
aws budgets create-budget \
  --account-id 111111111111 \
  --budget '{"BudgetName":"sec-tooling-cap","BudgetLimit":{"Amount":"200","Unit":"USD"},"TimeUnit":"MONTHLY","BudgetType":"COST"}'
```
5. Set an alert if CloudTrail cost exceeds $100/month.

**Teardown:** Delete the budget and any test resources. No persistent charges.

## Detection rules & checklists

**Budget anomaly rule (Cloud Custodian):**
```yaml
policies:
  - name: cloudtrail-spend-spike
    resource: account
    filters:
      - type: cost
        key: CloudTrail
        op: gt
        value: 200
```

**Checklist:**
- [ ] Billing alerts configured for security services at 150% of expected monthly cost.
- [ ] All security tooling tagged with `cost-center=security`.
- [ ] Log retention policy documented: hot/warm/cold tiering defined.
- [ ] Cyber insurance attestation current (MFA, backups, EDR, pentest).
- [ ] Annual security spend reviewed in budget cycle with breach-cost comparison.
- [ ] No production accounts without minimum viable controls due to cost concerns.

## References
- IBM Cost of a Data Breach Report 2025
- [AWS Security Services Pricing](https://aws.amazon.com/pricing/)
- [Azure Security Services Pricing](https://azure.microsoft.com/en-us/pricing/)
- [GCP Security Services Pricing](https://cloud.google.com/security/products)
- [FinOps Foundation — Security Tagging](https://www.finops.org/framework/capabilities/)
- [MITRE ATT&CK — Inhibit System Recovery (T1490)](https://attack.mitre.org/techniques/T1490/)
