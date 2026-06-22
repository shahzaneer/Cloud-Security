# Lab: Detect and Kill the APT (Blue)

> **Level:** Advanced
> **Prereqs:** Modules 06, 10, 11; 13-02, 13-04
> **Clouds:** AWS · Azure · GCP · OnPrem
> **Duration:** 90–120 minutes
**Authorization scope:** Capstone labs are to be run only against learner-owned sandbox accounts. Placeholder accounts are used throughout. No live attack surfaces.

## Objective

Starting from the same deliberately-vulnerable sandbox as the red lab, deploy detection controls, honey-tokens, and preventive guardrails from Modules 06, 10, and 11. Then re-run the red killchain and measure MTTD/MTTR at every stage. Produce a post-incident report using the template from [13-06](../Capstone-APT-Scenario/post-incident-report-template.md).

## Prerequisites checklist

- [ ] Sandbox deployed (`terraform apply` completed in 13-02)
- [ ] Red lab [build-the-apt-lab.md](./build-the-apt-lab.md) completed once (first run for baseline)
- [ ] `capstone/red-evidence.jsonl` from red lab available
- [ ] SIEM / log ingestion pipeline set up per Module 06 (at minimum: CloudTrail Lake + CloudWatch Logs Insights / Sentinel free-tier / GCP Logs Explorer)
- [ ] `prowler` or equivalent scanner installed

---

## Step 0 — Lab scaffolding

```bash
mkdir -p capstone/blue
mkdir -p capstone/blue/alerts
mkdir -p capstone/blue/timeline
touch capstone/blue/detection-fires.jsonl
```

---

## Step 1 — Deploy detection ingestion (Day 0)

**Module 06 refs:** [06-02](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md), [06-03](../Monitoring-Detection-SIEM/azure-log-analytics-and-sentinel.md), [06-04](../Monitoring-Detection-SIEM/gcp-cloud-audit-logs-and-scc.md)

### AWS — CloudTrail + GuardDuty

```bash
# 1a. Enable CloudTrail on all regions
aws cloudtrail create-trail \
  --name capstone-trail \
  --s3-bucket-name capstone-cloudtrail-logs-111111111111

aws cloudtrail start-logging --name capstone-trail

# 1b. Enable CloudTrail Lake for SQL queries
aws cloudtrail create-event-data-store \
  --name capstone-ed \
  --retention-period 30 \
  --multi-region-enabled

# 1c. Enable GuardDuty
aws guardduty create-detector --enable

# 1d. Enable S3 data events on the capstone bucket
# (Critical — without this, the Collection stage is invisible)
aws cloudtrail put-event-selectors \
  --trail-name capstone-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::capstone-data-111111111111/"]
    }]
  }]'

echo "Detection ingestion deployed. Allow 5 minutes for activation."
```

### Azure — Sentinel + Defender for Cloud

```bash
# 1e. Enable Azure Sentinel on the sandbox Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group sandbox-rg \
  --workspace-name capstone-sentinel-ws

az sentinel workspace connect --workspace-name capstone-sentinel-ws

# 1f. Connect Azure Activity Log to Sentinel
az monitor activity-log alert create \
  --name "capstone-activity-alert" \
  --resource-group sandbox-rg \
  --condition "category=Administrative"

# 1g. Enable Defender for Cloud (free-tier)
az security pricing create --name VirtualMachines --tier Free
az security pricing create --name StorageAccounts --tier Free
```

### GCP — Cloud Audit Logs + SCC

```bash
# 1h. Enable Cloud Audit Logs (Admin Read + Data Read + Data Write)
gcloud services enable logging.googleapis.com --project=example-project

# 1i. Enable Event Threat Detection in SCC
gcloud scc settings describe --project=example-project
# Enable via console: Security Command Center → Settings → Services → Event Threat Detection
```

### OnPrem equivalent

```bash
# WinRM + Windows Event Forwarding → SIEM
# wecutil qc  # Quick config
# wecutil cs subscription.xml  # Subscribe to Security + Sysmon channels
```

---

## Step 2 — Deploy honey-tokens (Day 0)

**Module 10 ref:** [10-04 Deception / Honeytokens](../Blue-Team-Defense/deception-honeytokens.md)

### AWS

```bash
# 2a. Canary IAM user + inactive access key
aws iam create-user --user-name honey-user
CANARY_KEY=$(aws iam create-access-key --user-name honey-user)

# Store the key — it will NEVER be used legitimately
echo "$CANARY_KEY" > capstone/blue/canary-key.json

# 2b. Canary S3 object
echo "HONEYTOKEN — DO NOT TOUCH" | aws s3 cp - s3://capstone-data-111111111111/honey-token.txt

# 2c. Decoy role trust relationship (honey role)
aws iam create-role \
  --role-name HoneyProdRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
      "Action": "sts:AssumeRole"
    }]
  }'
aws iam attach-role-policy \
  --role-name HoneyProdRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

echo "Honey-tokens deployed. Any access = alert."
```

### Azure

```bash
# 2d. Canary SP — created but never assigned a role
az ad sp create-for-rbac --name honey-sp --skip-assignment
az ad sp list --filter "displayName eq 'honey-sp'" > capstone/blue/canary-sp.json

# 2e. Canary blob
az storage blob upload --account-name capstonedataXXXX --container-name public-data \
  --name honey-token.txt --data "HONEYTOKEN"
```

### GCP

```bash
# 2f. Canary SA + key
gcloud iam service-accounts create honey-sa --display-name "Honey Service Account"
gcloud iam service-accounts keys create capstone/blue/canary-sa-key.json \
  --iam-account=honey-sa@example-project.iam.gserviceaccount.com

# 2g. Canary GCS object
echo "HONEYTOKEN" | gsutil cp - gs://capstone-data-example-project/honey-token.txt
```

---

## Step 3 — Apply preventive guardrails (Day 0)

**Module 10 ref:** [10-02 Preventive Guardrails as Code](../Blue-Team-Defense/preventive-guardrails-as-code.md)

### AWS — SCPs

```bash
# 3a. SCP: Deny making S3 public
# (Learner: craft the SCP JSON from 10-02 and attach to sandbox OU)
aws organizations create-policy \
  --name DenyPublicS3 \
  --type SERVICE_CONTROL_POLICY \
  --description "Deny s3:PutBucketPublicAccessBlock with false" \
  --policy file://scp-deny-public-s3.json

aws organizations attach-policy \
  --policy-id <policy-id> \
  --target-id <sandbox-ou-id>

# 3b. SCP: Deny IAM user creation (enforce SSO)
aws organizations create-policy \
  --name DenyIAMUserCreation \
  --type SERVICE_CONTROL_POLICY \
  --policy file://scp-deny-iam-user.json

# 3c. IAM permissions boundary — cap all roles
aws iam create-policy \
  --policy-name PermissionBoundary-Capstone \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": ["iam:CreateUser", "iam:CreateAccessKey", "iam:PassRole", "iam:UpdateAssumeRolePolicy"],
      "Resource": "*",
      "Condition": {"StringNotEquals": {"aws:PrincipalArn": "arn:aws:iam::111111111111:role/BreakGlassRole"}}
    }]
  }'

# Attach to roles
aws iam put-role-permissions-boundary \
  --role-name vulnerable-ec2-role \
  --permissions-boundary arn:aws:iam::111111111111:policy/PermissionBoundary-Capstone
```

### Azure — Deny policies

```bash
# 3d. Azure Policy: Deny public storage account
az policy assignment create \
  --name "deny-public-storage" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/...denyPublicStorage..." \
  --scope "/subscriptions/00000000-0000-0000-0000-000000000000"

# 3e. Azure Policy: Require MFA for admins
az policy assignment create \
  --name "require-mfa-admins" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/...requireMFA..." \
  --scope "/subscriptions/00000000-0000-0000-0000-000000000000"
```

### GCP — Org policies

```bash
# 3f. Disable service account key creation
gcloud org-policies set-policy capstone/blue/disable-sa-key.yaml

# 3g. Enforce uniform bucket-level access (prevents public object ACLs)
gcloud org-policies set-policy capstone/blue/enforce-ubla.yaml
```

---

## Step 4 — Import detection pack rules

**Module 06 ref:** [06-07 Detection-as-Code Sigma & Custodian](../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md)

Deploy the rules from [`detections/capstone-detection-pack.md`](../detections/capstone-detection-pack.md) into your detection pipeline.

### AWS — CloudWatch Logs Insights saved queries + EventBridge

```bash
# 4a. Create saved queries in CloudWatch Logs Insights
aws logs put-query-definition \
  --name "CAP-IA-01-SSRF-IMDS" \
  --query-string 'filter eventName = "GetCallerIdentity" | filter sourceIPAddress not in ("<trusted-cidr>") | fields @timestamp, sourceIPAddress, userIdentity.arn | sort @timestamp desc'

# 4b. EventBridge rule: GuardDuty finding → SNS → SIEM
aws events put-rule \
  --name capstone-guardduty-to-siem \
  --event-pattern '{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}'

aws events put-targets \
  --rule capstone-guardduty-to-siem \
  --targets "Id=1,Arn=arn:aws:sns:us-east-1:111111111111:capstone-alerts"
```

### Azure — Sentinel Analytics rules

```bash
# 4c. The KQL queries from the detection pack are deployed as Sentinel Analytics rules
# (Learner: import via Sentinel console or ARM template)

# Portal path:
# Microsoft Sentinel → Analytics → Create → Scheduled query rule
# Paste each KQL query from detections/capstone-detection-pack.md
```

### GCP — SCC custom findings + Logs-based metrics

```bash
# 4d. Create log-based metric for each detection rule
gcloud logging metrics create capstone-passrole-escalation \
  --description="Count of PassRole+CreateFunction pairs" \
  --log-filter='protoPayload.methodName=("iam.serviceAccounts.getAccessToken" OR "iam.serviceAccountKeys.create")'

# 4e. Create alert policy on the metric
gcloud alpha monitoring policies create \
  --policy-from-file capstone/blue/alert-policy-passrole.yaml
```

---

## Step 5 — Re-run the red lab (with detection watching)

> Before re-running, ensure all detection is active. Wait 5 minutes for CloudTrail/GuardDuty/SCC propagation.

```bash
# Reset sandbox (clean up any red lab resources still present)
cd sandbox-aws && terraform apply -auto-approve && cd ..

# Start detection watch in a separate terminal
# Terminal 1: Watch GuardDuty findings
watch -n 30 'aws guardduty list-findings --detector-id <detector-id> --finding-criteria "{\"Criterion\":{\"service.archived\":{\"Eq\":[\"false\"]}}}"'
```

Now re-run the red lab ([labs/red/build-the-apt-lab.md](./build-the-apt-lab.md)) step-by-step, watching for detection alerts at each stage.

```bash
# As you complete each red stage, check for the corresponding alert in a new terminal:

# Terminal 2 — Check GuardDuty findings
aws guardduty list-findings --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Terminal 3 — Query CloudTrail Lake
aws cloudtrail query --query-statement \
  'SELECT eventTime, eventName, sourceIPAddress FROM "arn:aws:cloudtrail:..." WHERE eventTime > "2025-01-01T00:00:00Z" ORDER BY eventTime DESC LIMIT 50'
```

---

## Step 6 — Verify detection at each stage

For each red stage, record whether the corresponding alert fired and at what timestamp.

```bash
# Record per-stage detection in capstone/blue/detection-fires.jsonl

python3 << 'PYEOF'
import json, time

stages = [
    ("CAP-RECON-01", "recon", None, None),
    ("CAP-IA-01", "initial_access_ssrf", None, None),
    ("CAP-IA-02", "initial_access_leaked_key", None, None),
    ("CAP-PE-01", "privilege_escalation", None, None),
    ("CAP-PER-01", "persistence", None, None),
    ("CAP-LM-01", "lateral_movement", None, None),
    ("CAP-COLL-01", "collection", None, None),
    ("CAP-IMP-01", "impact", None, None),
]

results = []
for rule_id, stage, red_ts, blue_ts in stages:
    results.append({
        "rule_id": rule_id,
        "stage": stage,
        "red_completed_at": red_ts or "<fill-from-red-evidence>",
        "blue_detected_at": blue_ts or "<check-guardduty/sentinel/scc>",
        "fired": blue_ts is not None,
        "gap_minutes": "<calculate>" if blue_ts else "MISSED"
    })

with open("capstone/blue/detection-fires.jsonl", "w") as f:
    for r in results:
        f.write(json.dumps(r) + "\n")

print(f"Results written. Stages detected: {sum(1 for r in results if r['fired'])}/{len(results)}")
PYEOF
```

### Expected results by stage

| Stage | Rule ID | Alert source | Typical MTTD | Notes |
|---|---|---|---|---|
| Recon | CAP-RECON-01 | Honey-token S3 `GetObject` from external IP | 5–15 min | Depends on SIEM ingestion delay |
| Initial Access (SSRF) | CAP-IA-01 | GuardDuty `InstanceCredentialExfiltration` | 2–7 min | GuardDuty finding delivery ~5 min |
| Initial Access (leaked key) | CAP-IA-02 | CloudTrail `GetCallerIdentity` from new IP | 10–15 min | Requires IP allow-list baseline |
| Privilege Escalation | CAP-PE-01 | GuardDuty `PrivilegeEscalation` | 2–10 min | PassRole→CreateFunction pattern |
| Persistence | CAP-PER-01 | CloudTrail `CreateAccessKey` outside CI window | 15–30 min | Daily-batch rule; may miss real-time |
| Lateral Movement | CAP-LM-01 | CloudTrail cross-account `AssumeRole` | 10–15 min | Requires multi-hop correlation |
| Collection | CAP-COLL-01 | S3 data events volume spike | 5–10 min | **Must have S3 data events enabled** |
| Impact | CAP-IMP-01 | CloudTrail `DeleteObject` denied (WORM) | 1–3 min | Low noise, high confidence |

---

## Step 7 — Verify preventive guardrails block escalation

**Module 10 ref:** [10-02 Preventive Guardrails as Code](../Blue-Team-Defense/preventive-guardrails-as-code.md)

Re-run red Step 4 (Privilege Escalation) and Step 5 (Persistence) — this time the SCPs / Azure deny policies / GCP Org Policies should block the actions.

```bash
# Attempt iam:CreateUser — should be denied by SCP
aws iam create-user --user-name monitoring-service-v2
# Expected: An error occurred (AccessDenied) when calling the CreateUser operation:
#   User is not authorized to perform: iam:CreateUser with an explicit deny in a service control policy

# Attempt s3:PutBucketPublicAccessBlock with false — should be denied
aws s3api put-public-access-block \
  --bucket capstone-data-111111111111 \
  --public-access-block-configuration \
    BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
# Expected: AccessDenied by SCP

echo "Guardrails verified — escalation and persistence blocked."
```

### Azure

```bash
# Attempt to create a public storage container — should be denied
az storage container create --name public-test --account-name capstonedataXXXX --public-access blob
# Expected: (403) Disallowed by policy
```

### GCP

```bash
# Attempt to create service account key — should be denied
gcloud iam service-accounts keys create /tmp/test-key.json \
  --iam-account=monitoring-service@example-project.iam.gserviceaccount.com
# Expected: (403) Disallowed by organization policy
```

---

## Step 8 — Execute the IR runbook

**Module 11 refs:** [11-01 IR Runbook Cloud-Aware](../IR-Forensics-Cloud/ir-runbook-cloud-aware.md), [11-05 IAM Revocation & Session Physics](../IR-Forensics-Cloud/iam-revocation-and-session-physics.md)

Now run the full IR cycle on a fresh red attempt — this time actively responding as alerts fire.

### Phase 1: Triage (T+0 to T+5)

```bash
# As the first GuardDuty finding fires, begin triage:
# 1. Record the finding ID and timestamp
aws guardduty get-findings --detector-id <id> --finding-ids <finding-id> > capstone/blue/initial-finding.json

# 2. Query CloudTrail for the last 30 minutes
aws cloudtrail lookup-events --start-time "<T-minus-30>" --end-time "<T-now>" > capstone/blue/initial-query.json

# 3. Determine blast radius: what principal, what IP, what resources touched
cat capstone/blue/initial-query.json | jq '[.Events[] | {eventName, sourceIPAddress, userIdentity}]'
```

### Phase 2: Containment (T+5 to T+10)

```bash
# 4. Deactivate the compromised key IMMEDIATELY
# (Replace with the key ID from your red lab — is it ci-deployer or a stolen instance role?)
aws iam update-access-key \
  --user-name ci-deployer \
  --access-key-id <stolen-key-id> \
  --status Inactive

# 5. Attach quarantine policy
aws iam put-user-policy \
  --user-name ci-deployer \
  --policy-name Quarantine-Deny-All \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
  }'

# 6. Revoke active STS sessions for the compromised role
# (Reduce max session duration to invalidate long-running sessions)
aws iam update-role --role-name vulnerable-ec2-role --max-session-duration 900

# 7. Snapshot evidence
INSTANCE_ID=$(aws ec2 describe-instances --filters "Name=tag:capstone:weakness,Values=imdsv1-ssrf" --query 'Reservations[0].Instances[0].InstanceId' --output text)
aws ec2 create-snapshot --volume-id $(aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' --output text) --description "IR evidence capstone" > capstone/blue/evidence-snap.json

# 8. Record MTTR (T+containment)
echo "MTTR: track timestamp when step 4 completed. Should be < 5 min from alert."
```

### Phase 3: Eradication (T+10 to T+30)

```bash
# 9. Delete attacker-created resources
aws iam list-access-keys --user-name monitoring-service
aws iam delete-access-key --user-name monitoring-service --access-key-id <key-id>
aws iam delete-user --user-name monitoring-service

aws lambda delete-function --function-name capstone-escalate

# 10. Rotate all remaining keys
for KEY_ID in $(aws iam list-access-keys --user-name ci-deployer --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
  aws iam update-access-key --user-name ci-deployer --access-key-id $KEY_ID --status Inactive
done

# 11. Fix the overly broad trust policy
aws iam update-assume-role-policy \
  --role-name CrossAccountRole-SharedServices \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
      "Action": "sts:AssumeRole",
      "Condition": {"StringEquals": {"sts:ExternalId": "capstone-external-id-REPLACE"}}
    }]
  }'
```

### Phase 4: Recovery (T+30 to T+60)

```bash
# 12. Re-apply IaC baseline
cd sandbox-aws
terraform plan   # review drift
terraform apply -auto-approve
cd ..

# 13. Verify compliance posture
prowler aws --region us-east-1 --custom-checks-metadata-file /dev/null | tee capstone/blue/post-ir-scan.json

# 14. Confirm CloudTrail still enabled
aws cloudtrail describe-trails --query 'trailList[?Name==`capstone-trail`].IsLogging'

# 15. Report metrics
MTTD=$(<calculate-from-timestamps>)
MTTR=$(<calculate-from-timestamps>)
echo "MTTD: ${MTTD} min | MTTR: ${MTTR} min | Coverage: <X>/8 stages detected"
```

---

## Step 9 — Write the post-incident report

Using the template from [13-06](../Capstone-APT-Scenario/post-incident-report-template.md), fill in the post-incident report with your actual metrics.

```bash
# Copy the template and fill in your data
cp ../Capstone-APT-Scenario/post-incident-report-template.md capstone/blue/CAP-PIR-001.md

# Fill in the bracketed fields using your detection-fires.jsonl and timeline data
# Use sed or manual editing to replace placeholders
```

---

## Step 10 — Purple-team improvement loop

**Module 13 ref:** [13-05 Pairing Red & Blue Timeline](../Capstone-APT-Scenario/pairing-red-blue-timeline.md)

```bash
# 1. Identify detection gaps (from detection-fires.jsonl)
# 2. Tune rules (lower thresholds, add correlation)
# 3. Update the detection pack (detections/capstone-detection-pack.md)
# 4. Re-run red lab → confirm gaps close
# 5. Update PIR to version 1.1
```

---

## Teardown

```bash
# AWS
cd sandbox-aws && terraform destroy -auto-approve && cd ..

# Azure
cd sandbox-azure && terraform destroy -auto-approve && cd ..

# GCP
cd sandbox-gcp && terraform destroy -auto-approve && cd ..

# Delete CloudTrail Lake event data store
aws cloudtrail delete-event-data-store --event-data-store-arn <arn>

# Keep capstone/blue/ artifacts for portfolio
echo "Blue lab complete. Artifacts preserved in capstone/blue/"
```

---

## Verification checklist

- [ ] CloudTrail/Activity Log/Cloud Audit Log ingestion confirmed active
- [ ] GuardDuty/Defender/SCC enabled with findings flowing
- [ ] Honey-tokens deployed (canary user/SA, canary object, decoy role)
- [ ] SCPs/Azure deny policies/GCP Org Policies attached and blocking
- [ ] At least 6/8 detection rules fired during red lab re-run
- [ ] SCP blocked `iam:CreateUser` (escalation blocked)
- [ ] IR runbook executed: containment (key deactivated) within MTTR SLO
- [ ] Eradication complete: attacker resources deleted, trust policies fixed
- [ ] Recovery complete: IaC baseline re-applied, posture scan compliant
- [ ] Post-incident report written (CAP-PIR-001.md)
- [ ] All resources torn down

## References

- [13-04 — Blue Variant Walkthrough](../Capstone-APT-Scenario/blue-variant-walkthrough.md)
- [13-06 — Post-Incident Report Template](../Capstone-APT-Scenario/post-incident-report-template.md)
- [detections/capstone-detection-pack.md](../detections/capstone-detection-pack.md)
- [Module 06 — Monitoring & Detection](../Monitoring-Detection-SIEM/README.md)
- [Module 10 — Blue Team Defense](../Blue-Team-Defense/README.md)
- [Module 11 — IR & Forensics](../IR-Forensics-Cloud/README.md)
