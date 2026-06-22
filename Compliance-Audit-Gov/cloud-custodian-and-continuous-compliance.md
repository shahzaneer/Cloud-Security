# 08 — Cloud Custodian & Continuous Compliance

> **Level:** Advanced
> **Prereqs:** [Detection As Code Sigma & Custodian](../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md), [Policy As Code Rego Sentinel](../IaC-Security/policy-as-code-rego-sentinel.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Persistence
> **Authorization scope:** Cloud Custodian policies must be deployed only against your own sandbox accounts. Test policies in `dry-run` mode before applying.

## What & why

Cloud Custodian (cloudcustodian.io) is an open-source, stateless rules engine for cloud infrastructure. You write YAML policies, it runs them periodically or in real-time, and it generates compliance notifications, auto-remediation actions, and SIEM events. Goal: a single policy language across clouds that produces a daily compliance delta report — "what changed from green to red since yesterday?" Combined with native tools (AWS Config, Azure Policy, GCP SCC), you get double-sourced verification: if both agree, you're confident; if they disagree, you have a detection gap or a suppression bypass.

## The OnPrem reality

Pre-cloud, continuous compliance was `OpenSCAP` on a cron job + `Chef InSpec` in CI pipelines. Cloud Custodian fills the gap that OS-level scanners can't reach: cloud API-level configuration. The same YAML policy can check S3 bucket public access, Azure blob encryption, and GCP firewall rules — across accounts and regions.

## Tooling landscape

| Tool | Scope | Mode | Clouds | Strengths |
|---|---|---|---|---|
| **Cloud Custodian** | Cloud resource policy engine | Periodic (`type: periodic`) + real-time (`type: cloudtrail`/`type: azure-event-grid`/`type: gcp-audit`) | AWS (primary), Azure, GCP (growing) | Rich action library (notify, delete, tag, encrypt, snapshot), cross-account, SIEM export |
| **Chef InSpec** | Infrastructure compliance testing | On-demand in CI/CD pipeline | Cross-cloud + OnPrem | Audit resources via cloud SDKs; same profile tests AWS and Azure |
| **Prowler** | AWS CIS benchmark scanner | On-demand + periodic | AWS | ~270 checks mapped to CIS, GDPR, HIPAA, PCI DSS |
| **ScoutSuite** | Multi-cloud security posture assessment | On-demand | AWS, Azure, GCP | Single HTML report across clouds |
| **Azure Resource Graph Explorer** | Query-based compliance assessment | On-demand via `az graph query` | Azure | Near-real-time resource inventory |
| **GCP SCC + Asset Inventory** | Native posture + compliance | Continuous (SCC), on-demand (Asset Inventory) | GCP | Deep integration with Org Policy |
| **OPA/Rego + Terrascan** | IaC and runtime policy | CI admission | Cross-cloud + K8s | Policy-as-code, guardrail enforcement |
| **OpenSCAP** | OS hardening assessment | On-demand + periodic | OnPrem (Linux) | CIS/STIG profiles for RHEL/CentOS |

## Cloud Custodian policy structure

```yaml
policies:
  - name: cis-s3-public-access-block
    resource: aws.s3
    mode:
      type: periodic
      schedule: "rate(6 hours)"
      role: arn:aws:iam::111111111111:role/custodian-lambda-role
    filters:
      - type: bucket-attributes
        attr: PublicAccessBlock
        key: BlockPublicAcls
        value: false
      - or:
          - type: bucket-attributes
            attr: PublicAccessBlock
            key: BlockPublicAcls
            value: false
          - type: bucket-attributes
            attr: PublicAccessBlock
            key: BlockPublicPolicy
            value: false
          - type: bucket-attributes
            attr: PublicAccessBlock
            key: RestrictPublicBuckets
            value: false
    actions:
      - type: notify
        template: default
        subject: "[NONCOMPLIANT] S3 Public Access Block not fully enabled"
        to:
          - security@example.com
        transport:
          type: sqs
          queue: https://sqs.us-east-1.amazonaws.com/111111111111/custodian-notify
```

## AWS — Cloud Custodian deep dive

### Run a periodic scan

```bash
pip install c7n c7n_org

# Dry-run — see what would be flagged
custodian run --dryrun -s output/ policy.yml

# Run and output to S3
custodian run -s s3://custodian-reports-111111111111-us-east-1/output policy.yml

# Run across entire organization
c7n-org run -c accounts.yml -s output/ -u policy.yml
```

### Real-time event-based policy

```yaml
policies:
  - name: detect-s3-public-bucket-created
    resource: aws.s3
    mode:
      type: cloudtrail
      role: arn:aws:iam::111111111111:role/custodian-lambda-role
      events:
        - CreateBucket
        - PutBucketAcl
    filters:
      - type: bucket-attributes
        attr: PublicAccessBlock
        key: BlockPublicAcls
        value: false
    actions:
      - type: auto-tag-user
        tag: CreatorEmail
      - type: notify
        template: default
        subject: "[IMMEDIATE] Public S3 bucket detected"
        to:
          - pagerduty-alert@example.com
        transport:
          type: sns
          topic: arn:aws:sns:us-east-1:111111111111:custodian-critical
      - type: set-bucket-encryption
        crypto: AES256
```

### Daily compliance delta report

```bash
#!/bin/bash
# Generate delta between today's and yesterday's compliance snapshots
BUCKET="custodian-reports-111111111111-us-east-1"
DATE=$(date +%Y-%m-%d)
YESTERDAY=$(date -v-1d +%Y-%m-%d)

# Download yesterday's results
aws s3 cp "s3://${BUCKET}/resources-${YESTERDAY}.json" /tmp/yesterday.json 2>/dev/null || echo '[]' > /tmp/yesterday.json

# Run today's scan
custodian run -s "s3://${BUCKET}" --output-dir /tmp/today policy.yml

# Compute delta
python3 -c "
import json
yesterday = {r['Name']: r for r in json.load(open('/tmp/yesterday.json'))}
today = {r['Name']: r for r in json.load(open('/tmp/today/resources.json'))}
new_noncompliant = {k: v for k, v in today.items() if k not in yesterday}
new_compliant = {k: v for k, v in yesterday.items() if k not in today}
print(f'New noncompliant resources: {len(new_noncompliant)}')
print(f'Newly compliant resources: {len(new_compliant)}')
if new_noncompliant:
    for name, info in new_noncompliant.items():
        print(f'  - {name}')
"
```

## Azure — Cloud Custodian (via ARM plugin)

Cloud Custodian on Azure works with the `azure` provider. Support is narrower than AWS but covers common resources (VMs, storage, network, SQL).

```yaml
policies:
  - name: azure-storage-public-blob-access
    resource: azure.storage
    filters:
      - type: value
        key: properties.allowBlobPublicAccess
        value: true
    actions:
      - type: notify
        template: default
        to:
          - security-ops@example.com
        transport:
          type: queues
          queue: https://sqs.us-east-1.amazonaws.com/111111111111/custodian-azure

  - name: azure-vm-unencrypted-disk
    resource: azure.vm
    filters:
      - type: disk
        key: properties.encryptionSettingsCollection.enabled
        value: false
    actions:
      - type: notify
        template: default
        to:
          - security-ops@example.com
        transport:
          type: queues
          queue: https://sqs.us-east-1.amazonaws.com/111111111111/custodian-azure
```

```bash
custodian run -s azure-output/ azure-policy.yml --region westeurope
```

## GCP — Cloud Custodian (via GCP plugin)

```yaml
policies:
  - name: gcp-bucket-public-access
    resource: gcp.bucket
    filters:
      - type: iam-policy
        key: bindings[].members[]
        op: contains
        value: "allUsers"
    actions:
      - type: notify
        template: default
        to:
          - security-ops@example.com
        transport:
          type: pubsub
          topic: projects/sec-audit-project/topics/custodian-alerts

  - name: gcp-firewall-allow-all
    resource: gcp.firewall
    filters:
      - type: value
        key: sourceRanges[]
        op: contains
        value: "0.0.0.0/0"
      - type: value
        key: allowed[].ports[]
        op: contains
        value: "0-65535"
    actions:
      - type: notify
        template: default
        to:
          - security-ops@example.com
        transport:
          type: pubsub
          topic: projects/sec-audit-project/topics/custodian-alerts
```

```bash
custodian run -s gcp-output/ gcp-policy.yml
```

## OnPrem — Chef InSpec compliance profile

```ruby
# inspec profile: cis-compliance
control 'cis-1.4-root-mfa' do
  impact 1.0
  title 'Ensure MFA is enabled for root account'
  describe aws_iam_root_user do
    it { should have_mfa_enabled }
    it { should_not have_access_key }
  end
end

control 'cis-3.1-s3-public-access-block' do
  impact 1.0
  title 'Ensure S3 public access block is enabled on all buckets'
  aws_s3_buckets.bucket_names.each do |bucket|
    describe aws_s3_bucket(bucket) do
      its('public_access_block.block_public_acls') { should eq true }
      its('public_access_block.block_public_policy') { should eq true }
    end
  end
end
```

```bash
inspec exec cis-aws-profile --input-file=attrs.yml --reporter json:/tmp/inspec-aws.json
```

## 🔴 Red Team view — compliance drift window exploitation

**Attack vector:** Cloud Custodian policies run on a `periodic` schedule (e.g., every 6 hours). An attacker who knows the scan schedule can perform a misconfiguration immediately after the scan completes, giving them a nearly 6-hour window before detection. If the SIEM ingestion adds another 30 minutes, the effective window is ~6.5 hours.

**Contained exploitation:**

```bash
# Scenario: Cloud Custodian scans every 6 hours (00:00, 06:00, 12:00, 18:00 UTC)

# At 06:02 UTC — right after the scan completes:
aws s3api create-bucket --bucket exfil-stage-111111111111-us-east-1
aws s3api put-bucket-acl --bucket exfil-stage-111111111111-us-east-1 --acl public-read

# 06:02–12:00: Attacker uses the public bucket for staging (exfiltration, C2, data collection)
aws s3 cp sensitive-data.csv s3://exfil-stage-111111111111-us-east-1/sensitive-data.csv
# Data exfiltrated from public bucket — external IP reads objects

# 11:58: Attacker deletes the bucket, removing evidence
aws s3 rm s3://exfil-stage-111111111111-us-east-1 --recursive
aws s3api delete-bucket --bucket exfil-stage-111111111111-us-east-1

# 12:00: Scan runs, finds nothing — the bucket was created and destroyed within the gap
```

**Exploiting "suppression gap" where native Config + Custodian disagree:**

```bash
# Attacker suppresses a finding in Security Hub (T1562)
aws securityhub update-findings \
  --filters '{"Title": [{"Value": "S3.1 Block Public Access"}]}' \
  --workflow '{"Status": "SUPPRESSED"}' \
  --note '{"Text": "Approved exception", "UpdatedBy": "attacker@example.com"}'

# Security Hub dashboard: green for S3.1
# Cloud Custodian: still reports S3.1 as noncompliant in its separate scan
# If nobody reconciles the two sources, the suppression is permanent
```

**Artifacts left:**
- CloudTrail `CreateBucket` + `PutBucketAcl` + `DeleteBucket` events (even if bucket is gone, the trail persists)
- S3 data events (if enabled) show `GetObject` from external IPs
- VPC Flow Logs show data transfer to external IP during the window
- Cloud Custodian would NOT have a record (deleted before next scan)
- But CloudTrail data events are immutable — the attacker's actions are logged even if the bucket is gone

## 🔵 Blue Team view — double-sourced compliance + drift detection

### Make each policy short and double-sourced

```yaml
# Control S3.1 is checked by TWO sources independently:
# 1. AWS Config rule: s3-bucket-public-read-prohibited (native, real-time trigger on change)
# 2. Cloud Custodian: cis-s3-public-access-block (periodic, 6-hour, entirely separate)
# If they disagree, page the detection team.
```

### Disagreement detection

```python
# Nightly reconciliation: compare Config rule results with Custodian results
import boto3, json

config = boto3.client("config")
s3 = boto3.client("s3")

# Get Config rule compliance
config_result = config.get_compliance_details_by_config_rule(
    ConfigRuleName="s3-bucket-public-read-prohibited"
)["EvaluationResults"]

noncompliant_config = {r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"]
                       for r in config_result if r["ComplianceType"] == "NON_COMPLIANT"}

# Get Custodian results
custodian_result = json.loads(
    s3.get_object(Bucket="custodian-reports-111111111111-us-east-1",
                  Key="output/cis-s3-public-access-block/resources.json")["Body"].read()
)
noncompliant_custodian = {r["Name"] for r in custodian_result}

# Find disagreements
in_config_not_custodian = noncompliant_config - noncompliant_custodian
in_custodian_not_config = noncompliant_custodian - noncompliant_config

if in_config_not_custodian:
    print(f"ALERT: Config found noncompliant but Custodian missed: {in_config_not_custodian}")
if in_custodian_not_config:
    print(f"ALERT: Custodian found noncompliant but Config missed: {in_custodian_not_config}")
```

### SIEM export from Cloud Custodian

```yaml
policies:
  - name: cis-s3-public-access-block
    resource: aws.s3
    mode:
      type: periodic
      schedule: "rate(6 hours)"
    filters:
      - type: bucket-attributes
        attr: PublicAccessBlock
        key: BlockPublicAcls
        value: false
    actions:
      # Action 1: Send to SIEM (via S3 → Lambda → Splunk/Elastic)
      - type: put-metric
        key: PublicAccessBlockViolation
        value: 1
        op: inc
      # Action 2: Tag for ownership
      - type: auto-tag-user
        tag: Creator
      # Action 3: Notify security team
      - type: notify
        template: default
        to:
          - security@example.com
        transport:
          type: sqs
          queue: https://sqs.us-east-1.amazonaws.com/111111111111/custodian-notify
```

### Daily delta CSV report

```bash
#!/bin/bash
# custodian-delta-report.sh — emailed to security@example.com daily
aws s3 cp \
  s3://custodian-reports-111111111111-us-east-1/delta-$(date +%Y-%m-%d).csv \
  /tmp/delta.csv

if grep -q "NONCOMPLIANT" /tmp/delta.csv 2>/dev/null; then
  aws ses send-email \
    --from security-automation@example.com \
    --to security@example.com \
    --subject "Daily Compliance Delta — $(date +%Y-%m-%d) — NONCOMPLIANT FOUND" \
    --text "file:///tmp/delta.csv"
fi
```

## Hands-on lab — Cloud Custodian setup + delta report

**Duration:** 20 min. **Cost:** Free-tier Lambda + S3.

```bash
pip install c7n c7n_org

# Write a minimal policy
cat > test-policy.yml <<'EOF'
policies:
  - name: find-unencrypted-s3
    resource: aws.s3
    filters:
      - type: bucket-encryption
        state: false
    actions:
      - type: notify
        template: default
        subject: "[Custodian] Unencrypted S3 bucket found"
        to: [your-email@example.com]
        transport:
          type: sqs
          queue: https://sqs.us-east-1.amazonaws.com/111111111111/custodian-notify
EOF

# Dry run first
custodian run --dryrun -s ./output test-policy.yml

# Run for real
custodian run -s ./output test-policy.yml

# View results
cat ./output/find-unencrypted-s3/resources.json | jq .

# Teardown
rm -rf ./output test-policy.yml
```

## Detection rules & checklists

**Continuous compliance health check:**

- [ ] Cloud Custodian policies cover all critical resource types across all clouds.
- [ ] Policies run on both `periodic` (every 6 hours) AND real-time (`cloudtrail`/`event-grid`/`audit-log`) where possible.
- [ ] Output exported to SIEM daily.
- [ ] Daily delta report reviewed; new noncompliant resources investigated within 4 hours.
- [ ] Double-sourced verification: native Config rule + Custodian policy per critical control.
- [ ] Disagreement between native and Custodian results pages the detection team.
- [ ] Each policy has an action (not just notification): auto-tag, auto-encrypt, or auto-remediate.

**Sigma rule — Cloud Custodian finding suppressed but native config still noncompliant:**

```yaml
title: Compliance Drift Between Custodian and Native Config
id: a1b2c3d4-5000-4000-8000-e5f6a7b8c9d0
status: experimental
description: A control is green in one compliance source but red in another — possible suppression
logsource:
  application: compliance-engine
detection:
  selection:
    custodian_status: COMPLIANT
    config_rule_status: NON_COMPLIANT
    resource_type: AWS::S3::Bucket
  condition: selection
level: high
```

## References

- [Cloud Custodian Documentation](https://cloudcustodian.io/docs/)
- [Cloud Custodian — AWS Quickstart](https://cloudcustodian.io/docs/aws/gettingstarted.html)
- [Cloud Custodian — Azure Quickstart](https://cloudcustodian.io/docs/azure/gettingstarted.html)
- [Cloud Custodian — GCP Quickstart](https://cloudcustodian.io/docs/gcp/gettingstarted.html)
- [Chef InSpec — Cloud Resources](https://docs.chef.io/inspec/cloud/)
- [Prowler](https://github.com/prowler-cloud/prowler)
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- MITRE ATT&CK: T1562 Impair Defenses, T1565 Data Manipulation
- Cross-links: [../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md](../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md), [../Blue-Team-Defense/preventive-guardrails-as-code.md](../Blue-Team-Defense/preventive-guardrails-as-code.md)
