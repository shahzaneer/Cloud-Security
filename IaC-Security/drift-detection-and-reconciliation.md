# 07 — Drift Detection & Reconciliation

> **Level:** Advanced
> **Prereqs:** [08-01 — IaC State & Backend Security](./iac-state-and-backend-security.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Persistence, Defense Evasion, Impact
> **Authorization scope:** Run detection queries against your own cloud accounts; all resource IDs are placeholders.

## What & why

Drift is any change to live infrastructure that wasn't made through IaC. It happens from emergency console fixes, attacker persistence, or an over-eager teammate. Drift detection answers: "Does running `terraform apply` right now change anything?" If the answer is yes, something happened outside the IaC pipeline — and you need to know about it before it becomes an incident.

## The OnPrem reality

CFEngine's promise model was built on drift: the agent checked filesystem checksums, process tables, and package versions every 5 minutes against the policy. Any deviation triggered an automatic repair. In the cloud, drift is harder because resources can be mutated through the API from anywhere, and Terraform has no resident agent — it only checks when you tell it to.

```bash
# CFEngine: continuous drift detection
cf-agent -KI  # runs policy, repairs drift automatically
# Any change made by hand (chmod 777 /etc/shadow) is reverted within 5 minutes
```

## Core concepts

| Concept | Description | Detection method |
|---|---|---|
| Configuration drift | Resource attributes differ from Terraform state | `terraform plan -detailed-exitcode` |
| Unmanaged resources | Resources exist in cloud but not in Terraform | AWS Config / Azure Resource Graph / GCP Asset Inventory |
| Manual changes | Console/CLI changes made outside IaC | CloudTrail with non-Terraform `userAgent` |
| Reconciliation | Auto-revert drift (dangerous) or alert for manual review | Cloud Custodian `remediate`, Config auto-remediation |
| `-detailed-exitcode` | Terraform plan exits 0 (no changes), 1 (error), 2 (drift) | CI automation decision point |

## Cross-cloud drift tooling

| Concern | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Native drift detection | AWS Config (per-resource rules) | Azure Policy `DeployIfNotExists` + Guest Configuration | GCP Config Connector (CRD drift) + Asset Inventory | CFEngine promise compliance |
| IaC drift (Terraform) | `terraform plan -detailed-exitcode` | Same | Same | Same |
| Conformance packs | AWS Config Conformance Packs | Azure Policy Initiatives | GCP Org Policy constraints | OPA bundles |
| Automated remediation | Config auto-remediation (SSM) | `DeployIfNotExists` + `modify` effect | Config Connector reconcile loop | CFEngine auto-repair |
| Alert-only mode | Config rules with `ComplianceResourceTypes` | `AuditIfNotExists` | Constraint `dryrun` | CFEngine `warnonly` |

## AWS

### Drift detection with Terraform

```bash
#!/bin/bash
# Nightly drift check — runs terraform plan against every workspace

WORKSPACES=("prod" "staging" "dev")
for ws in "${WORKSPACES[@]}"; do
  echo "=== Checking workspace: $ws ==="
  terraform workspace select "$ws" 2>/dev/null || terraform workspace new "$ws"

  terraform plan -detailed-exitcode -out=/dev/null
  EXIT_CODE=$?

  case $EXIT_CODE in
    0) echo "✅ $ws: No drift" ;;
    1) echo "❌ $ws: Plan error" ;;
    2) echo "⚠️  $ws: DRIFT DETECTED" ;;
  esac
done
```

### AWS Config — per-resource drift

```bash
# Enable AWS Config with a conformance pack
aws configservice put-conformance-pack \
  --conformance-pack-name terraform-governed-resources \
  --template-s3-uri s3://awsconfigconforms/config-templates/OperationalBestPractices.yaml

# Query compliance status
aws configservice describe-compliance-by-config-rule \
  --query "ComplianceByConfigRules[?Compliance.ComplianceType=='NON_COMPLIANT']"

# List resources NOT managed by CloudFormation/Terraform tag
aws configservice list-discovered-resources \
  --query "resourceIdentifiers[?resourceType=='AWS::EC2::SecurityGroup']" | \
  jq '.[] | select(.resourceId | test("sg-"))' | \
  while read -r sg; do
    tags=$(aws ec2 describe-security-groups --group-ids "$(echo $sg | jq -r .resourceId)" \
      --query "SecurityGroups[0].Tags")
    if echo "$tags" | jq -e 'map(select(.Key == "ManagedBy" and .Value == "Terraform")) | length == 0' > /dev/null; then
      echo "UNMANAGED SG: $sg"
    fi
  done
```

## Azure

```bash
# Azure Policy — check subscription compliance
az policy state list \
  --filter "complianceState eq 'NonCompliant'" \
  --query "[].{resource:resourceId, policy:policyDefinitionName}" \
  -o table

# Azure Resource Graph — find resources without IaC tags
az graph query -q '
  Resources
  | where isnotempty(tags)
  | where tags !has "IaC"
  | project name, type, location, tags
  | limit 50
'
```

```bash
# Scheduled drift check via Azure Automation / CI
terraform plan -detailed-exitcode -out=/dev/null 2>&1 | \
  tee /tmp/drift-report.txt

if [ $? -eq 2 ]; then
  # Post to Slack/Teams
  curl -X POST https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX \
    -H "Content-Type: application/json" \
    -d "{\"text\": \"⚠️ Terraform drift detected in $(terraform workspace show)\n$(cat /tmp/drift-report.txt | head -50)\"}"
fi
```

## GCP

```bash
# GCP Asset Inventory — list resources not tagged as IaC-managed
gcloud asset search-all-resources \
  --scope=projects/000000000000 \
  --query="NOT labels.IaC:*" \
  --asset-types="compute.googleapis.com/Instance,storage.googleapis.com/Bucket" \
  --format="table(name, assetType)"

# Org Policy — check constraint violations
gcloud org-policies list-violations \
  --organization=000000000000 \
  --format="json"
```

### GCP Config Connector — CRD drift detection

```yaml
# Config Connector manages GCP resources as K8s CRDs
# Drift appears as a diff between desired (CRD) and live (GCP API)
apiVersion: storage.cnrm.cloud.google.com/v1beta1
kind: StorageBucket
metadata:
  name: prod-logs-bucket
  annotations:
    cnrm.cloud.google.com/management-conflict-prevention-policy: "resource"
spec:
  location: us-central1
  uniformBucketLevelAccess: true
---
# Check drift: kubectl diff against live
kubectl diff -f bucket.yaml
```

```bash
# Periodic reconcile check
gcloud config-connector nomos status --contexts
```

## OnPrem

```bash
# CFEngine — classic drift detection
cf-agent -KI --dry-run  # show what would be repaired
cf-agent -KI            # actually repair

# Ansible — ad-hoc drift check
ansible-playbook site.yml --check --diff
```

## 🔴 Red Team view

**Persistence via untracked infrastructure.**

An attacker who gains cloud access can create resources that Terraform never knows about — and therefore never reverts. These "ghost resources" provide persistent backdoor access.

**Contained scenario — S3 bucket policy backdoor:**

1. Attacker gets temporary access to an AWS account (phished credential, SSRF, console access).
2. Finds a Terraform-managed S3 bucket `prod-logs-bucket`.
3. Uses the AWS CLI to add a bucket policy granting `s3:GetObject` to an external account:
   ```bash
   aws s3api put-bucket-policy --bucket prod-logs-bucket \
     --policy '{
       "Statement": [{
         "Effect": "Allow",
         "Principal": {"AWS": "111111111111"},
         "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::prod-logs-bucket/*"
       }]
     }'
   ```
4. Terraform's state still says the bucket has no policy (or a different one).
5. `terraform plan` detects drift — but only if someone runs it.
6. If no drift detection runs for 30 days, the backdoor persists undetected.

**Artifacts:**
- CloudTrail: `s3:PutBucketPolicy` with `userAgent` NOT containing `HashiCorp-Terraform` (or `aws-sdk`, or console)
- CloudTrail: `sourceIPAddress` from attacker's IP, not the deployer's known range
- AWS Config (if enabled): `s3-bucket-policy-not-public` rule → NON_COMPLIANT
- Terraform plan: drift on `aws_s3_bucket_policy.prod-logs`

## 🔵 Blue Team view

**Drift detection pipeline — nightly scheduled check:**

```bash
#!/bin/bash
# drift-nightly.sh — scheduled CI/CD job (runs at 3am daily)
set -euo pipefail

REPOS=(
  "github.com/example-org/infra-prod"
  "github.com/example-org/infra-staging"
)

for repo in "${REPOS[@]}"; do
  dir="/tmp/drift-$(basename $repo)"
  git clone --depth 1 "https://${repo}" "$dir"
  cd "$dir"

  terraform init -backend-config="region=us-east-1" > /dev/null 2>&1

  terraform plan -detailed-exitcode -out=/dev/null
  EXIT=$?

  if [ $EXIT -eq 2 ]; then
    # DETAIL: capture the drift and alert
    terraform plan -no-color 2>&1 | tee "/tmp/drift-$(basename $repo).log"

    # Send to SIEM or alerting platform
    curl -X POST "https://alerts.internal.example.com/drift" \
      -H "Content-Type: application/json" \
      -d "{
        \"repo\": \"$repo\",
        \"severity\": \"HIGH\",
        \"summary\": \"Infrastructure drift detected\",
        \"details\": \"$(head -30 /tmp/drift-$(basename $repo).log | jq -Rs .)\"
      }"
  fi

  cd /tmp
done
```

**Layered drift detection:**

| Layer | Tool | Frequency | Catches |
|---|---|---|---|
| Immediate (push) | `terraform plan` in CI | Every merge to main | Drift from concurrent manual changes |
| Nightly | `terraform plan -detailed-exitcode` | Every 24h | Drift from console changes, attacker persistence |
| Continuous | AWS Config / Azure Policy / GCP Config Connector | 5–15 min | Individual resource drift against defined rules |
| Audit | CloudTrail + tag check | Daily | Resources not tagged as IaC-managed |

**Detection rule — Cloud Custodian drift policy:**

```yaml
policies:
  - name: s3-drift-from-terraform
    resource: aws.s3
    filters:
      - type: event
        key: "detail.eventName"
        value: "PutBucketPolicy"
      - type: event
        key: "detail.userAgent"
        value: "HashiCorp-Terraform"
        op: not-regex
      - "tag:ManagedBy": "Terraform"
    actions:
      - type: notify
        to: ["secops@example.com"]

  - name: ec2-drift-unmanaged-instances
    resource: aws.ec2
    filters:
      - type: value
        key: "tag:ManagedBy"
        value: absent
    actions:
      - type: notify
        to: ["secops@example.com"]
```

**Authorized break-glass procedure:**

When emergency console changes are needed (e.g., scaling up a DB during outage):

1. Engineer makes the change via console with a specific tag: `BreakGlass=true`, `BreakGlassReason=SEV-1234`.
2. CloudTrail captures the event with the engineer's identity.
3. Next `terraform plan` shows drift — the team expects it.
4. Within 24 hours, the engineer either `terraform import`s the resource state or reverts the manual change.
5. If `BreakGlass` tag persists > 24h, a Cloud Custodian policy alerts.

**Detection checklist:**
- [ ] Nightly `terraform plan -detailed-exitcode` for every production workspace
- [ ] AWS Config / Azure Policy / GCP Org Policy enabled on all subscriptions/projects
- [ ] CloudTrail / Activity Log alert for resource mutations without `HashiCorp-Terraform` user-agent
- [ ] All IaC-managed resources tagged with `ManagedBy=Terraform` (or equivalent)
- [ ] Unmanaged resources alert fires to Slack/Teams/PagerDuty
- [ ] Break-glass procedure defined and auto-remediated after 24h
- [ ] Drift alert includes `git blame` for the resource's last Terraform change author

## Hands-on lab

1. Create a Terraform-managed resource and induce drift:
   ```bash
   mkdir lab-drift && cd lab-drift
   cat > main.tf <<'EOF'
   resource "aws_s3_bucket" "managed" {
     bucket = "drift-lab-111111111111"
     tags = { ManagedBy = "Terraform" }
   }
   resource "aws_s3_bucket_versioning" "managed" {
     bucket = aws_s3_bucket.managed.id
     versioning_configuration { status = "Disabled" }
   }
   EOF
   terraform init && terraform apply -auto-approve
   ```

2. Induce drift via CLI (simulating manual change):
   ```bash
   aws s3api put-bucket-tagging \
     --bucket drift-lab-111111111111 \
     --tagging '{"TagSet":[{"Key":"Drifted","Value":"true"}]}'
   ```

3. Detect the drift:
   ```bash
   terraform plan -detailed-exitcode -out=/dev/null
   echo "Exit code: $?"  # Expected: 2 (drift)
   ```

4. See the specific change:
   ```bash
   terraform plan -no-color 2>&1 | grep -A 5 "tags"
   # Shows: tags = {} -> {"Drifted": "true"}  (outside Terraform)
   ```

5. Reconcile (revert the drift):
   ```bash
   terraform apply -auto-approve  # reapplies Terraform's desired tags
   ```

6. **Teardown:** `terraform destroy -auto-approve`

## References

- [Terraform — Detecting and Managing Drift](https://developer.hashicorp.com/terraform/tutorials/state/resource-drift)
- [AWS Config — Conformance Packs](https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html)
- [Azure Policy — Compliance Data](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data)
- [GCP Asset Inventory](https://cloud.google.com/asset-inventory/docs/overview)
- [GCP Config Connector](https://cloud.google.com/config-connector/docs/overview)
- See ATT&CK: T1578 (Modify Cloud Compute Infrastructure), T1525 (Implant Internal Image)
- [08-01 — IaC State & Backend Security](./iac-state-and-backend-security.md)
- [detections/drift-alert-detection.md](./detections/drift-alert-detection.md)
