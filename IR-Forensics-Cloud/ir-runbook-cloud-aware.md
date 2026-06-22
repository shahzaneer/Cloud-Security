# 01 — Cloud-Aware IR Runbook

> **Level:** Intermediate
> **Prereqs:** [06-Monitoring](../Monitoring-Detection-SIEM/), [10-Blue](../Blue-Team-Defense/), [09-Red](../Red-Team-Offense/)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Impact, Defense Evasion
> **Authorization scope:** Run only in your own sandbox account; all example account IDs are placeholders (`111111111111`, `00000000-0000-0000-0000-000000000000`).

## What & why

A cloud-aware IR runbook codifies the decision matrix, roles, and automation triggers *before* the incident. Unlike on-prem playbooks, cloud runbooks must account for autoscaling, ephemeral compute, IAM session physics, and the imperative to snapshot before the scale-set reaps the host.

## The OnPrem reality

On-prem IR relied on a printed runbook in a binder, tape-based imaging of a server that sat in a locked rack, and no risk of the evidence host vanishing under load. Ticketing systems drove escalation; Tier-1 triaged, Tier-2 contained. There was no STS token TTL to race.

## Core concepts

### IR lifecycle — cloud translation

| Phase | OnPrem | Cloud-translated action |
|-------|--------|-------------------------|
| Prepare | Train staff, stock hardware | Pre-deploy Lambda/Logic App runbooks, hardened AMI with forensic tools |
| Detect | SIEM alert | GuardDuty / Azure Defender / SCC → EventBridge/EventGrid → runbook |
| Triage | Analyst opens ticket | SEV-scoring API call, evidence-preservation trigger |
| Contain | Unplug cable, VLAN change | Security Group quarantine, IAM revocation, SCP attachment |
| Eradicate | Re-image disk | Snapshot + terminate, rotate all secrets, audit trail replay |
| Recover | Restore from backup | Launch from golden AMI, re-attach data volume, re-issue least-privilege creds |
| Lessons | Post-mortem meeting | Automated timeline reconstruction, root-cause report from CloudTrail/Sentinel/BQ |

### Runbook skeleton (YAML template)

```yaml
# cloud-ir-runbook.yaml — shared skeleton, per-cloud overrides below
incident:
  declare:
    trigger: "GuardDuty severity >= Medium OR Sentinel high-confidence OR SCC finding"
    escalation: "PagerDuty → IC (Incident Commander)"
  freeze:
    rule: "NO destructive actions until evidence captured"
    exceptions: "containment actions listed in this runbook"
  assign_ic:
    primary: "on-call-security-engineer@example.com"
    backup: "security-manager@example.com"
  preserve:
    order: [snapshot, memory, logs, config]
    tag_marker: "forensic=true,incident-id=${INCIDENT_ID}"
  revoke:
    order: [deactivate_key, attach_boundary, rotate_source_identity]
    note: "in-flight STS sessions live up to TTL; see 05-iam-revocation"
  logs:
    sources: [CloudTrail, VPC-Flow, GuardDuty, Config]
    destination: "s3://forensic-bucket-${ACCOUNT_ID}/incident-${INCIDENT_ID}/"
  notify:
    - "security@example.com"
    - "legal@example.com"
    - "compliance@example.com"
```

## AWS

**Services:** AWS Systems Manager, Lambda, EventBridge, S3 Object Lock, IAM, EC2, GuardDuty.

**Console path:** GuardDuty → Findings → Create EventBridge Rule → Target Lambda.

**CLI automation snippet:**

```bash
# Declare incident and auto-preserve
INCIDENT_ID="inc-$(date +%s)"
INSTANCE_ID="i-0a1b2c3d4e5f67890"

aws ec2 create-snapshots \
    --instance-specification InstanceId=$INSTANCE_ID \
    --tag-specifications 'ResourceType=snapshot,Tags=[{Key=forensic,Value=true},{Key=incident-id,Value='$INCIDENT_ID'}]' \
    --description "Forensic snapshot for $INCIDENT_ID"

aws ec2 create-tags --resources $INSTANCE_ID \
    --tags Key=incident-id,Value=$INCIDENT_ID Key=state,Value=quarantined

aws iam put-role-policy --role-name OverPermittedRole \
    --policy-name DenyAllBoundary \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
```

**Gotcha:** AWS does not support in-flight STS revocation — even after `iam:DeactivateAccessKey`, existing sessions run until the token expires (default 1h). Attach an SCP deny-all to the role to block new assume-role calls.

## Azure

**Services:** Azure Monitor, Logic Apps, Event Grid, Microsoft Sentinel, Azure Resource Graph.

**CLI snippet:**

```bash
INCIDENT_ID="inc-$(date +%s)"
VM_NAME="compromised-vm"
RG="forensics-rg"

az vm show --name $VM_NAME --resource-group $RG --query id -o tsv

az snapshot create \
    --resource-group $RG \
    --name "snap-${INCIDENT_ID}" \
    --source "$(az vm show -g $RG -n $VM_NAME --query storageProfile.osDisk.name -o tsv)"

az vm deallocate --resource-group $RG --name $VM_NAME

az tag update --resource-id $(az vm show -g $RG -n $VM_NAME --query id -o tsv) \
    --operation Merge \
    --tags forensic=true incident-id=$INCIDENT_ID

az ad sp update --id "00000000-0000-0000-0000-000000000000" \
    --set accountEnabled=false
```

**Gotcha:** Azure AD session token revocation via `revokeSignInSession` is not immediate for all apps — up to 15-min propagation. Use Conditional Access `signInFrequency` to cap session lifetime.

## GCP

**Services:** Cloud Logging, Security Command Center, Cloud Functions (2nd gen), Pub/Sub, Compute Engine.

**CLI snippet:**

```bash
INCIDENT_ID="inc-$(date +%s)"
INSTANCE_NAME="compromised-instance"
ZONE="us-central1-a"

gcloud compute disks snapshot $INSTANCE_NAME \
    --zone=$ZONE \
    --snapshot-names="snap-${INCIDENT_ID}" \
    --labels=forensic=true,incident-id=$INCIDENT_ID

gcloud compute instances stop $INSTANCE_NAME --zone=$ZONE

gcloud compute instances add-tags $INSTANCE_NAME \
    --zone=$ZONE \
    --tags=quarantined,incident-${INCIDENT_ID}

gcloud compute instances update $INSTANCE_NAME \
    --zone=$ZONE \
    --update-labels=forensic=true,incident-id=$INCIDENT_ID

gcloud iam service-accounts disable \
    "sa-compromised@${PROJECT_ID}.iam.gserviceaccount.com"
```

**Gotcha:** GCP service account key disable is immediate, but JWT tokens already issued remain valid until expiry. Use `--lifetime=1800s` for all service account keys as a hardening baseline.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Evidence capture | Write-blocked dd image | `ec2 create-snapshots` | `az snapshot create` | `gcloud compute disks snapshot` |
| Host isolation | Unplug NIC / VLAN change | Move to quarantine SG | NSG rule deny-all | Firewall rule deny-all |
| Credential kill | AD account disable | `iam:DeactivateAccessKey` + boundary | `az ad sp update --set accountEnabled=false` | `gcloud iam service-accounts disable` |
| Runbook trigger | SIEM alert → ticket | GuardDuty → EventBridge → Lambda | Sentinel → Logic App | SCC → Pub/Sub → Cloud Function |
| Session lifetime gap | Kerberos TGT (default 10h) | STS token (default 1h, max 12h) | Azure AD token (up to configured lifetime) | GCP JWT (default 3600s, max 12h) |

## 🔴 Red Team view

Attackers monitor for IR activity signals in-cloud to gauge defender speed. Recognizable patterns:

- **VPC Flow Log query spike:** CloudWatch Logs Insights scans or Athena queries against VPC Flow Logs surge in the minutes after detection. Attacker with read access to CloudTrail can see `StartQuery` API calls.
- **Snapshot volume burst:** `ec2:CreateSnapshots` API calls appear in the account trail. An attacker watching CloudTrail in real time sees these and knows a forensic capture is underway.
- **IAM trust-policy removals:** `iam:UpdateAssumeRolePolicy` or `iam:PutRolePolicy` with deny-all policies signal that the defender is cutting attacker's lateral movement paths.
- **Security Group mutations:** Instance moves to a quarantine SG with only an S3/VPC endpoint egress whitelisted — attacker can detect loss of outbound connectivity.

**Attacker adaptation:** Once IR is detected, the attacker's TTL budget shrinks. They will:
- Attempt `kubectl delete pod --force --grace-period=0` to destroy container evidence.
- Call `ec2:TerminateInstances` if they still hold privileges to eliminate disk evidence.
- Exfiltrate remaining accessible data before the session expires.

**Artifacts left:** The attacker's presence-checking API calls (e.g., `DescribeInstances`, `GetCallerIdentity` polls) appear in CloudTrail as a spike in control-plane reads just before the defender's revocation calls.

## 🔵 Blue Team view

### Pre-ship automation

Deploy the snapshot-and-quarantine chain as a Lambda/Cloud Function triggered by high-confidence findings:

```bash
# AWS EventBridge pattern
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{"numeric": [">=", 7]}],
    "type": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]
  }
}
```

### Quarterly tabletop validation

- Run the YAML runbook against a sandbox incident quarterly.
- Measure: time-to-snapshot, time-to-revoke, completeness of artifact set.
- Track via metric: MTTD (Mean Time to Detect), MTTC (Mean Time to Contain), evidence completeness %.

### Runbook versioning

Store the runbook as infrastructure-as-code in the same repo as the detection rules. Every runbook revision triggers a CI pipeline that validates IAM permissions for the Lambda execution role.

```python
# Example: Lambda handler for auto-snapshot on GuardDuty finding
def lambda_handler(event, context):
    finding = event['detail']
    resource = finding['resource']['instanceDetails']['instanceId']
    incident_id = f"inc-{context.aws_request_id}"
    ec2 = boto3.client('ec2')
    ec2.create_snapshots(
        InstanceSpecification={'InstanceId': resource},
        TagSpecifications=[{
            'ResourceType': 'snapshot',
            'Tags': [{'Key': 'incident-id', 'Value': incident_id}]
        }]
    )
    return {'incident_id': incident_id, 'status': 'preserved'}
```

## Hands-on lab

1. In your sandbox account, create an EC2 instance with an over-permissive IAM role.
2. Simulate a GuardDuty finding by posting a test finding via `aws guardduty create-sample-findings`.
3. Run the preservation script above. Verify snapshot creation and tags.
4. Validate that the instance was moved to a quarantine SG.
5. Teardown: delete snapshots, terminate instance, detach the quarantine SG.

## Detection rules & checklists

```yaml
# Sigma-style: IR snapshot was NOT taken within N seconds of GuardDuty finding
title: IR Snapshot Missed After GuardDuty Finding
logsource:
  product: aws
  service: cloudtrail
detection:
  guardduty_finding:
    eventSource: guardduty.amazonaws.com
    eventName: CreateFindings
  no_snapshot_after:
    condition: not (ec2:CreateSnapshots within 300s of guardduty_finding)
  condition: guardduty_finding and no_snapshot_after
  timeframe: 5m
severity: high
```

## References

- [AWS Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [Azure Security Incident Response](https://learn.microsoft.com/en-us/azure/security/fundamentals/incident-response)
- [GCP Incident Response](https://cloud.google.com/docs/security/incident-response)
- [NIST SP 800-61 Rev 2 Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- See ATT&CK Cloud matrix for Impact, Defense Evasion
