# 07 — Detection as Code: Sigma & Cloud Custodian

> **Level:** Advanced
> **Prereqs:** [The Security Log Mosaic per Cloud](the-security-log-mosaic-per-cloud.md), [Cloudtrail Activity & Data Events](cloudtrail-activity-and-data-events.md), [Azure Log Analytics & Sentinel](azure-log-analytics-and-sentinel.md), [GCP Cloud Audit Logs & Scc](gcp-cloud-audit-logs-and-scc.md), [Native Threat Detection Guardduty Defender Scc](native-threat-detection-guardduty-defender-scc.md), [Ingestion Pipeline SIEM Patterns](ingestion-pipeline-siem-patterns.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Discovery, Persistence, Privilege Escalation
> **Authorization scope:** Rules and policies tested against your own sandbox accounts and test resources. Sigma detection testing uses benign trigger events you deliberately generate.

## What & why

Detection as Code means security rules live in git, get versioned, reviewed, tested, and deployed through CI/CD — exactly like application code. Sigma provides a universal DSL for detection rules that targets Elastic, Splunk, Sentinel, QRadar, and more via converters. Cloud Custodian applies real-time policy enforcement against cloud resources. OPA/Rego extends this to Kubernetes admission and Terraform plan evaluation.

## The OnPrem reality

Sigma-only: you wrote generic Sigma rules targeting `EventID=4688` (Windows process creation) and `EventID=4625` (failed login), then ran `sigmac -t splunk` to convert them to SPL searches. Cloud Custodian had no on-prem equivalent — pre-cloud, you either had Chef/Ansible enforcing config drift, or nothing at all.

## Core concepts

### The Detection-as-Code triad

| Tool | Role | Input | Output | Cloud |
|---|---|---|---|---|
| Sigma | Universal detection rule DSL | `.yml` rule file | Splunk SPL, Elastic query, KQL, QRadar, etc. | Cross-cloud, cross-SIEM |
| Cloud Custodian | Cloud resource policy engine | `.yml` policy file | CloudWatch Events, AWS Config rules, Lambda | AWS native, Azure + GCP via plugins |
| OPA / Rego | Policy as code (admission + plan) | `.rego` policy file | Admission webhook allow/deny, Terraform plan violation | Cross-cloud + Kubernetes |

### Sigma rule anatomy

```yaml
title: Suspicious Root Account Usage
id: 8e3c5a2b-1111-2222-3333-444444444444
status: experimental
description: Detects usage of AWS root account
author: security-team
date: 2026-06-22
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.type: Root
    userIdentity.invokedBy:  # empty for actual root (not root-assumed via role)
  condition: selection
falsepositives:
  - Initial account setup (add to allowlist)
level: critical
tags:
  - attack.privilege_escalation
  - attack.t1078.004
```

### The Sigma conversion pipeline

```
sigma-cli convert -t <backend> -p <product> rule.yml
```

Supported backends: `splunk`, `elasticsearch`, `kibana`, `sentinel-rule`, `kusto`, `chronicle`, `qradar`, `logsource`, `opensearch`, and more.

## Cross-cloud Sigma rules

### Rule: "IAM User granted AdministratorAccess"

```yaml
title: IAM User Attached AdministratorAccess Policy
id: 6a84b985-d4bf-4ce1-bf36-1bb3b24a4ace
status: experimental
description: Detects when AdministratorAccess managed policy is attached to an IAM user
author: detection-as-code-team
date: 2026-06-22
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AttachUserPolicy
    requestParameters.policyArn|endswith: AdministratorAccess
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.privilege_escalation
```

**Convert to CloudWatch Logs Insights query:**

```bash
sigma convert -t logsource -p aws rule-adminaccess.yml
```

Output:
```
fields @timestamp, eventName, userIdentity.arn, requestParameters.userName
| filter eventName = "AttachUserPolicy"
| filter requestParameters.policyArn like /AdministratorAccess/
```

**Convert to Azure Sentinel KQL:**

Assuming an equivalent Azure rule:
```yaml
logsource:
  product: azure
  service: activity
detection:
  selection:
    operationName: Microsoft.Authorization/roleAssignments/write
    properties.requestbody.properties.roleDefinitionId|endswith: "Administrator"
```

```bash
sigma convert -t sentinel-rule -p azure rule-azure-adminrole.yml
```

**Convert to GCP Logging query:**

```bash
sigma convert -t chronicle -p gcp rule-gcp-adminrole.yml
```

### Rule: "Public S3 Bucket / Blob Container / GCS Bucket"

```yaml
title: Cloud Storage Bucket Made Public
id: b1a2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects when a cloud storage bucket/container is made publicly accessible
author: detection-as-code-team
date: 2026-06-22
logsource:
  product: aws
  service: cloudtrail
detection:
  aws_selection:
    eventName: PutBucketPolicy
    requestParameters.bucketPolicy.Statement[].Principal: "*"
  azure_selection:
    operationName: Microsoft.Storage/storageAccounts/blobServices/containers/write
    properties.requestbody.properties.publicAccess: "Blob"
  gcp_selection:
    protoPayload.methodName: storage.buckets.setIamPolicy
    protoPayload.serviceData.setIamPolicyRequest.policy.bindings[].members: "allUsers"
  condition: aws_selection or azure_selection or gcp_selection
level: high
```

## Cloud Custodian — real-time cloud governance

### Cloud Custodian policy: block public S3 buckets

```yaml
policies:
  - name: s3-public-bucket-auto-remediate
    resource: aws.s3
    mode:
      type: cloudtrail
      events:
        - source: s3.amazonaws.com
          event: PutBucketPolicy
          ids: requestParameters.bucketName
    filters:
      - type: bucket-policy
        key: "Statement[].Principal"
        value: "*"
        op: contains
    actions:
      - type: notify
        template: default
        subject: "[SECURITY] Public S3 Bucket Policy Detected"
        to:
          - security@example.com
          - soc-alerts@example.com
        transport:
          type: sqs
          queue: https://sqs.us-east-1.amazonaws.com/111111111111/security-alerts
      - type: auto-tag-user
        tag: SecurityContact
      - type: delete
```

### Cloud Custodian policy: block public Blob containers (Azure)

```yaml
policies:
  - name: block-public-blob-containers
    resource: azure.storage-container
    filters:
      - type: value
        key: properties.publicAccess
        value: "Blob"
        op: eq
    actions:
      - type: set-public-access
        access: "Off"
```

### Cloud Custodian policy: block public GCS buckets

```yaml
policies:
  - name: block-public-gcs-buckets
    resource: gcp.bucket
    filters:
      - type: iam-policy
        key: "bindings[?members[?contains(@, 'allUsers') || contains(@, 'allAuthenticatedUsers')]].role"
        value: empty
    actions:
      - type: set-iam-policy
        remove:
          - role: '*'
            members:
              - allUsers
              - allAuthenticatedUsers
```

## OPA / Rego — infrastructure-as-code guardrails

### OPA rule: deny 0.0.0.0/0 in any Security Group (AWS Terraform)

```rego
package terraform.security

deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_security_group"
  r.change.after.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
  msg = sprintf("SG %s allows 0.0.0.0/0 ingress", [r.address])
}

deny[msg] {
  r := input.resource_changes[_]
  r.type == "azurerm_network_security_rule"
  r.change.after.source_address_prefix == "*"
  r.change.after.destination_port_range == "22"
  msg = sprintf("NSG rule %s exposes SSH to all", [r.address])
}

deny[msg] {
  r := input.resource_changes[_]
  r.type == "google_compute_firewall"
  r.change.after.source_ranges[_] == "0.0.0.0/0"
  r.change.after.allow[_].ports[_] == "22"
  msg = sprintf("GCP firewall %s exposes SSH to all", [r.address])
}
```

Run against a Terraform plan:

```bash
terraform plan -out=tfplan
terraform show -json tfplan | opa eval --format pretty --stdin-input data.terraform
```

### OPA rule: deny pods with hostNetwork (Kubernetes admission)

```rego
package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Pod"
  input.request.object.spec.hostNetwork == true
  msg = sprintf("Pod %s in namespace %s requests hostNetwork", [input.request.object.metadata.name, input.request.namespace])
}
```

### Falco rule — runtime detection (additional tool)

Falco fills the gap Sigma (SIEM log rules) and OPA (pre-deployment guardrails) don't cover: live syscall monitoring on containers/nodes.

```yaml
- rule: Write below binary dir
  desc: An attempt to write to a binary directory
  condition: >
    bin_dir and evt.dir = < and open_write and not proc.name in (known_bin_writers)
  output: "File below a known binary directory opened for writing (user=%user.name cmd=%proc.cmdline)"
  priority: WARNING
  tags: [filesystem, mitre_persistence]
```

## OnPrem mapping (recap table)

| Concern | OnPrem / Generic | AWS | Azure | GCP |
|---|---|---|---|---|
| Detection rule DSL | Sigma → SPL / Lucene | Sigma → CW Insights / Elastic | Sigma → KQL / Sentinel | Sigma → Chronicle / Logging |
| Policy engine | OPA + custom CLI | Cloud Custodian (native) + AWS Config | Azure Policy + Cloud Custodian (Azure provider) | Org Policy + Cloud Custodian (GCP provider) |
| Admission control | OPA Gatekeeper (K8s) | OPA Gatekeeper on EKS | Azure Policy for AKS add-on | OPA Gatekeeper on GKE / Policy Controller |
| Runtime detection | Falco + Auditd | Falco + GuardDuty Runtime Monitoring | Defender for Servers | SCC + Falco |
| Rule conversion | `sigmac -t splunk` | `sigma convert -t logsource -p aws` | `sigma convert -t sentinel-rule -p azure` | `sigma convert -t chronicle -p gcp` |
| Rule testing | Sigma test pipeline (pySigma) | Deploy to test account, trigger benign event | Deploy to test subscription, trigger | Deploy to test project, trigger |

## 🔴 Red Team view

### The false-positive fatigue attack

An attacker who understands the defender's detection rules can trigger low-severity, high-volume rules so often that the SOC ignores them — a technique called detection rule fatigue.

**Narrative:** The attacker knows the defender has a Sigma rule for `ConsoleLogin` with MFA disabled. The attacker creates 50 IAM users (each with Console access, no MFA) over a weekend. Monday morning, the SOC is flooded with 50 `ConsoleLogin` alerts. They mute the rule until the noise is processed. The attacker then logs in as the *real* compromised account with MFA still disabled, and no alert fires.

```bash
# Attacker creates noise accounts (contained example, run in your own sandbox):
for i in $(seq 1 50); do
  aws iam create-user --user-name noise-user-${i}
  aws iam create-login-profile --user-name noise-user-${i} --password "NoisePassword123!" --no-password-reset-required
done

# Then attacker uses the real compromised account:
# (This ConsoleLogin event would normally trigger the alert — but the rule is muted.)
```

**What slips through:** Any high-severity detection that was among the muted rules. If the MFA-disabled rule was co-located in a suppression window that also covered `AttachRolePolicy`, the attacker gets a clean privilege escalation.

**Azure equivalent:** Create 50 guest users in Entra ID (`az ad user create` loop), flooding the "new external user" Sentinel rule.

**GCP equivalent:** Create 50 service accounts with no alerting suppression expected — wait for the SOC to exhaustively triage `google.iam.admin.v1.CreateServiceAccount` alerts, then create the *real* service account carrying `roles/iam.serviceAccountTokenCreator`.

### Artifacts

- The 50 noise accounts are logged individually in CloudTrail as `CreateUser` / `CreateLoginProfile`.
- The *real* attacker's `AttachRolePolicy` is logged — it just wasn't alerted on.
- The SIEM query logs show the defender manually muted the rule (audit trail of suppression).

## 🔵 Blue Team view

### Detection rule coverage matrix with MITRE mappings

Maintain a spreadsheet in git (Markdown table) that maps each MITRE technique to your deployed detection rules:

| MITRE technique | Tactic | Sigma rule ID | Cloud Custodian policy | Sentinel rule | Deployment status | Last tested |
|---|---|---|---|---|---|---|
| T1078.004 — Cloud Accounts | Initial Access | `6a84b985` | — | `Root-Account-Usage` | Deployed | 2026-06-20 |
| T1098 — Account Manipulation | Persistence | `e3c5a2b` | — | — | Deployed | 2026-06-18 |
| T1530 — Data from Cloud Storage | Collection | `b1a2c3d4` | `s3-public-bucket` | — | Deployed | 2026-06-22 |
| T1562.008 — Disable Cloud Logs | Defense Evasion | `a1b2c3d4` | — | `StopLogging` in CW | Deployed | 2026-06-21 |

### Automated rule testing against attack packs

```bash
# Clone and run Red Canary's Atomic Red Team or Stratus Red Team (cloud attack simulator)
stratus run aws.credential-access.iam-backdoor-role
stratus run aws.defense-evasion.cloudtrail-stop
stratus run aws.exfiltration.s3-bucket-sync

# After each run, check if any Sigma rule would have fired:
sigma convert -t logsource -p aws rules/*.yml | \
  while read query; do
    aws logs start-query --log-group-name cloudtrail --query-string "$query" --start-time ...
  done
```

### Detection-as-code CI/CD pipeline

```yaml
# .github/workflows/detection-ci.yml (GitHub Actions)
name: Detection Rule CI
on:
  pull_request:
    paths:
      - 'sigma-rules/**'
      - 'custodian-policies/**'
jobs:
  validate-sigma:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install sigma-cli pysigma
      - run: |
          for rule in sigma-rules/*.yml; do
            sigma convert -t elasticsearch $rule || exit 1
            sigma convert -t splunk $rule || exit 1
          done

  validate-custodian:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install c7n c7n_schema
      - run: custodian validate -c custodian-policies/
```

### Severity-based alert routing

| Severity | Routing | Response SLA |
|---|---|---|
| Critical | PagerDuty + Slack `#soc-critical` | 15 min |
| High | Slack `#soc-alerts` + email | 1 hour |
| Medium | Jira ticket auto-created | 24 hours |
| Low | Dashboard review only (weekly) | 7 days |

## Hands-on lab

1. Write a Sigma rule for "IAM User attached AdministratorAccess":
```bash
cat > /tmp/rule-adminaccess.yml << 'EOF'
title: IAM User Attached AdminAccess
id: lab-rule-001
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AttachUserPolicy
    requestParameters.policyArn|endswith: AdministratorAccess
  condition: selection
level: high
EOF
```

2. Convert to CloudWatch Logs Insights:
```bash
pip install sigma-cli
sigma convert -t logsource -p aws /tmp/rule-adminaccess.yml
```

3. Trigger the event in your sandbox:
```bash
aws iam create-user --user-name lab-test-user
aws iam attach-user-policy --user-name lab-test-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

4. Query CloudTrail Event History for the event:
```bash
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=EventName,AttributeValue=AttachUserPolicy \
  --max-results 5
```

5. **Teardown:**
```bash
aws iam detach-user-policy --user-name lab-test-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user --user-name lab-test-user
rm /tmp/rule-adminaccess.yml
```

## Detection rules & checklists

```
# Checklist
- [ ] All Sigma rules stored in version control with unique UUID
- [ ] Sigma CI validates conversion to all target backends (Splunk, Elastic, Sentinel)
- [ ] Cloud Custodian policies with `mode: cloudtrail` for real-time enforcement
- [ ] OPA Rego policies run in Terraform plan CI and Kubernetes admission webhook
- [ ] Detection rule coverage matrix exists with MITRE ATT&CK mapping
- [ ] False-positive rate reviewed monthly per rule; muted rules documented with expiry
- [ ] Auto-test suite runs Stratus Red Team / Atomic Red Team in sandbox weekly
- [ ] Critical rules route to PagerDuty; low-severity rules are dashboard-only
```

## References
- [Sigma repo on GitHub](https://github.com/SigmaHQ/sigma)
- [Sigma CLI tooling](https://github.com/SigmaHQ/sigma-cli)
- [Cloud Custodian](https://cloudcustodian.io/docs/aws/gettingstarted.html)
- [OPA / Rego policy language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Falco rules](https://falco.org/docs/rules/)
- [Stratus Red Team (cloud attack simulation)](https://github.com/DataDog/stratus-red-team)
- [../Red-Team-Offense/red-team-basics.md](../Red-Team-Offense/red-team-basics.md)
- [../Blue-Team-Defense/blue-team-basics.md](../Blue-Team-Defense/blue-team-basics.md)
