# 03 — Evidence Preservation in Ephemeral Infrastructure

> **Level:** Advanced
> **Prereqs:** [11-01](./ir-runbook-cloud-aware.md), [04-Snapshot-and-Memory](./snapshot-and-memory-acquisition.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Impact
> **Authorization scope:** Run only in your own sandbox account; all example account IDs are placeholders (`111111111111`, `00000000-0000-0000-0000-000000000000`).

## What & why

Container instances, Lambda functions, and spot instances can disappear within 60 seconds of alert — terminated by autoscaler, spot reclamation, or an attacker calling `TerminateInstances`. The cloud IR maxim: **preserve first, ask questions later.** Disk snapshot → memory capture → log export → THEN containment/termination.

## The OnPrem reality

On-prem evidence preservation meant walking to the data center, attaching a write-blocker to the suspect drive, and imaging bit-by-bit with `dd` or a hardware duplicator. The server stayed in the rack, powered on, until the imaging completed — hours or days. No cloud ephemerality risk existed.

## Core concepts

### Preservation order (immutable)

```
1. DISK SNAPSHOT   — always succeeds; no root needed
2. MEMORY CAPTURE  — requires root / kernel module; may fail
3. LOG EXPORT      — CloudTrail / Sentinel / Cloud Audit Logs
4. CONFIG CAPTURE  — Security Groups, IAM policies, NSGs, firewall rules
5. CONTAIN         — quarantine SG / NSG / firewall rule
6. TERMINATE       — only after 1-5 confirmed complete
```

### The "DO NOT Terminate" rule

| Action | Safe? | Rationale |
|--------|-------|-----------|
| `ec2:StopInstances` | Yes | EBS-backed volumes persist; instance-store volumes are lost |
| `ec2:TerminateInstances` | No (until snapshot) | EBS root `DeleteOnTermination=true` by default — disk gone |
| `az vm deallocate` | Yes | OS disk and data disks persist |
| `az vm delete` | No (until snapshot) | Disk may be deleted depending on delete option |
| `gcloud compute instances stop` | Yes | Persistent disks survive |
| `gcloud compute instances delete` | No (until snapshot) | Disks deleted unless `--keep-disks=all` specified |
| `kubectl delete pod --force` | No (until dump) | Ephemeral storage destroyed immediately |

### Spot instance warning

Spot instances can be terminated with a 2-minute warning. For spot-based workloads, deploy a CloudWatch Event / Event Grid / Pub/Sub listener on the spot interruption signal that triggers an emergency snapshot before the instance is forcibly terminated.

## AWS

**Preservation script:**

```bash
#!/bin/bash
INCIDENT_ID="inc-$(date +%s)"
INSTANCE_ID="i-0a1b2c3d4e5f67890"
REGION="us-east-1"
FORENSIC_BUCKET="s3://forensic-bucket-111111111111"

echo "=== Phase 1: Snapshot ==="
SNAP_ID=$(aws ec2 create-snapshots \
    --instance-specification InstanceId=$INSTANCE_ID \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=incident-id,Value=$INCIDENT_ID},{Key=forensic,Value=true}]" \
    --copy-tags-from-source volume \
    --query 'Snapshots[0].SnapshotId' --output text)
echo "Snapshot: $SNAP_ID"

echo "=== Phase 2: Memory (ensure AVML is available in environment) ==="
aws ssm send-command \
    --document-name "AWS-RunShellScript" \
    --targets "Key=instanceids,Values=$INSTANCE_ID" \
    --parameters 'commands=["curl -sL https://github.com/microsoft/avml/releases/download/v0.11.0/avml -o /tmp/avml && chmod +x /tmp/avml && /tmp/avml /tmp/memory.lime && aws s3 cp /tmp/memory.lime '$FORENSIC_BUCKET/$INCIDENT_ID/memory.lime'"]'

echo "=== Phase 3: Log export ==="
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=ResourceName,AttributeValue=$INSTANCE_ID \
    --start-time "$(date -u -d '6 hours ago' +%s)" \
    --output json > /tmp/cloudtrail_${INCIDENT_ID}.json

echo "=== Phase 4: Config capture ==="
aws ec2 describe-instances --instance-ids $INSTANCE_ID > /tmp/instance_config_${INCIDENT_ID}.json
aws ec2 describe-security-groups --group-ids sg-0a1b2c3d4e5f67890 > /tmp/sg_config_${INCIDENT_ID}.json

echo "=== Phase 5: Quarantine ==="
aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID --groups sg-quarantine

echo "=== Phase 6: Revoke instance profile ==="
ASSOC_ID=$(aws ec2 describe-iam-instance-profile-associations \
    --filters Name=instance-id,Values=$INSTANCE_ID \
    --query 'IamInstanceProfileAssociations[0].AssociationId' --output text)
aws ec2 disassociate-iam-instance-profile --association-id $ASSOC_ID

echo "=== Phase 7: Deallocate (DO NOT Terminate) ==="
aws ec2 stop-instances --instance-ids $INSTANCE_ID
```

**Gotcha:** EC2 instance-store volumes (ephemeral) cannot be snapshotted. If the root volume is instance-store, only memory capture and log export are possible — the disk disappears on stop/terminate.

## Azure

```bash
#!/bin/bash
INCIDENT_ID="inc-$(date +%s)"
VM_NAME="compromised-vm"
RG="forensics-rg"
STORAGE_ACCT="forensicsacct"
CONTAINER="evidence"

echo "=== Phase 1: Disk Snapshot ==="
OS_DISK=$(az vm show -g $RG -n $VM_NAME --query 'storageProfile.osDisk.name' -o tsv)
az snapshot create -g $RG -n "snap-os-${INCIDENT_ID}" --source $OS_DISK
for DISK in $(az vm show -g $RG -n $VM_NAME --query 'storageProfile.dataDisks[].name' -o tsv); do
    az snapshot create -g $RG -n "snap-data-${INCIDENT_ID}-${DISK}" --source $DISK
done

echo "=== Phase 2: Memory (AVML via Run Command) ==="
az vm run-command invoke -g $RG -n $VM_NAME \
    --command-id RunShellScript \
    --scripts "curl -sL https://github.com/microsoft/avml/releases/download/v0.11.0/avml -o /tmp/avml && chmod +x /tmp/avml && /tmp/avml /tmp/memory.lime"

echo "=== Phase 3: NSG quarantine ==="
az network nic update -g $RG -n "${VM_NAME}VMNic" \
    --network-security-group quarantine-nsg

echo "=== Phase 4: Revoke managed identity ==="
IDENTITY_ID=$(az vm identity show -g $RG -n $VM_NAME --query 'principalId' -o tsv)
# Remove role assignments for this identity (requires AzAD module or REST call)
az role assignment delete --assignee $IDENTITY_ID --scope "/subscriptions/00000000-0000-0000-0000-000000000000"

echo "=== Phase 5: Deallocate (DO NOT DELETE) ==="
az vm deallocate -g $RG -n $VM_NAME
```

## GCP

```bash
#!/bin/bash
INCIDENT_ID="inc-$(date +%s)"
INSTANCE_NAME="compromised-instance"
ZONE="us-central1-a"
BUCKET="gs://forensic-bucket"

echo "=== Phase 1: Disk Snapshot ==="
gcloud compute instances describe $INSTANCE_NAME --zone=$ZONE \
    --format='value(disks[].deviceName)' | while read DISK; do
    gcloud compute disks snapshot $DISK \
        --zone=$ZONE \
        --snapshot-names="snap-${INCIDENT_ID}-${DISK}" \
        --labels=incident-id=$INCIDENT_ID,forensic=true
done

echo "=== Phase 2: Memory (AVML via SSH) ==="
gcloud compute ssh $INSTANCE_NAME --zone=$ZONE \
    --command="sudo curl -sL https://github.com/microsoft/avml/releases/download/v0.11.0/avml -o /tmp/avml && sudo chmod +x /tmp/avml && sudo /tmp/avml /tmp/memory.lime && gsutil cp /tmp/memory.lime $BUCKET/$INCIDENT_ID/memory.lime"

echo "=== Phase 3: Firewall quarantine ==="
gcloud compute firewall-rules create quarantine-${INCIDENT_ID} \
    --network=default \
    --priority=0 \
    --direction=INGRESS \
    --action=DENY \
    --rules=all \
    --source-ranges=0.0.0.0/0 \
    --target-tags=quarantined

gcloud compute instances add-tags $INSTANCE_NAME --zone=$ZONE --tags=quarantined

echo "=== Phase 4: Revoke service account ==="
SA_EMAIL="sa-compromised@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud iam service-accounts disable $SA_EMAIL

echo "=== Phase 5: Stop (DO NOT DELETE) ==="
gcloud compute instances stop $INSTANCE_NAME --zone=$ZONE
```

## OnPrem mapping (recap table)

| Preservation step | OnPrem | AWS | Azure | GCP |
|-------------------|--------|-----|-------|-----|
| Disk image | Write-blocker + `dd` + hash | `ec2 create-snapshots` (EBS only) | `az snapshot create` | `gcloud compute disks snapshot` |
| Memory dump | LiME / WinPmem via KVM console | SSM + AVML (LKM) | Run Command + AVML | SSH + AVML |
| Log export | Rsyslog forwarder | `aws cloudtrail lookup-events` | Sentinel export API | `gcloud logging read` |
| Network isolate | VLAN change / unplug NIC | Move to quarantine SG | Attach quarantine NSG | Attach deny-all firewall rule |
| Terminate safety | Power off (no OS shutdown) | Stop (not Terminate) | Deallocate (not Delete) | Stop (not Delete) |
| Spot/lifecycle hook | N/A | ASG lifecycle hook → Lambda snapshot | VMSS scale-in hook | MIG standby + snapshot hook |

## 🔴 Red Team view

The attacker knows the defender's preservation window is narrow. The goal: force destruction before evidence is captured.

**"Rapid-destroy" adversary pattern:**
1. Attacker gains access to EC2 instance via SSRF against metadata.
2. Immediately after credential exfiltration, attacker calls `ec2:TerminateInstances` on the compromised host to destroy the disk.
3. If the instance is in an ASG, the autoscaler launches a replacement — the forensic window closes in under 90 seconds from detection to termination.

**Cryptolocking shortcut:** The attacker drops a cryptominer that consumes 100% CPU. The defender can't install a kernel module for memory capture under CPU contention; the system may be unresponsive to SSM Run Command. Attacker buys time.

**Spot instance timing attack:** If the attacker recognizes spot instance interruption notices (2-min warning), they call `shutdown -h now` before the defender's snapshot completes — corrupting filesystem state.

**Artifacts:**
- CloudTrail shows `TerminateInstances` from the same compromised identity, seconds after credential exfiltration.
- Missing CloudTrail entries during the attacker's session (if they used `cloudtrail:StopLogging`).
- System logs show abnormal shutdown requests or `poweroff` commands.

**Attacker detection of IR:** The attacker polls `DescribeInstances` and observes the instance state change from `running` → `stopping` → `stopped`. If the stop was initiated by the defender, the attacker knows IR is active and may initiate counter-actions on other compromised resources.

## 🔵 Blue Team view

### Pre-deploy forensic AMI / VM image

Bake forensic tooling into the base AMI to eliminate the "download tool" step:
- AVML binary at `/opt/forensics/avml`
- Pre-configured SSM Agent with `SessionManagerRunShell` enabled
- `auditd` rules for kernel module loads and `poweroff` / `shutdown` commands

### Auto-preservation trigger (EventBridge pattern)

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": {"numeric": [">=", 7]},
    "resource": {"instanceDetails": {"instanceId": [{"exists": true}]}}
  }
}
// Target: Lambda that runs the preservation script within 5 seconds of trigger
```

### "Deallocate, never Terminate" policy

Enforce via SCP (AWS) / Azure Policy / GCP org policy:

```json
// AWS SCP: Deny ec2:TerminateInstances unless tagged forensic=complete
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "ec2:TerminateInstances",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {"ec2:ResourceTag/forensic": "complete"}
    }
  }]
}
```

### Spot instance hook

For ASGs using spot instances:

```bash
# ASG lifecycle hook → Lambda
aws autoscaling put-lifecycle-hook \
    --auto-scaling-group-name prod-asg \
    --lifecycle-hook-name forensic-snapshot-on-terminate \
    --lifecycle-transition "autoscaling:EC2_INSTANCE_TERMINATING" \
    --heartbeat-timeout 900 \
    --default-result ABANDON
```

The Lambda receives the lifecycle event, snapshots the instance, then calls `complete-lifecycle-action`.

## Hands-on lab

1. Launch EC2 with IMDSv1 enabled and an over-permissive role. 
2. Trigger a simulated GuardDuty Medium+ finding via `create-sample-findings`.
3. Run the preservation script above. Verify: snapshot exists in EC2 console, instance has quarantine SG, instance state is `stopped`, IAM profile is disassociated.
4. Verify CloudTrail timeline shows preservation actions in correct order.
5. Teardown: delete snapshots, terminate instance.

## Detection rules & checklists

```yaml
title: Instance Terminated Without Forensic Snapshot
logsource:
  product: aws
  service: cloudtrail
detection:
  terminated:
    eventSource: ec2.amazonaws.com
    eventName: TerminateInstances
  no_snapshot_before:
    timeframe: 24h
    condition: not (eventName: CreateSnapshots AND resource.instanceId = terminated.resource.instanceId)
  condition: terminated and no_snapshot_before
severity: critical
```

- [ ] Forensic AMI with pre-installed AVML maintained in every region.
- [ ] SCP preventing TerminateInstances without `forensic=complete` tag deployed org-wide.
- [ ] Lifecycle hook for spot ASGs tested monthly.
- [ ] Runbook printed and laminated — includes the words "DO NOT TERMINATE" in red.

## References

- [AWS EC2 instance recovery](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-recover.html)
- [Azure VM snapshot documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk)
- [GCP disk snapshots](https://cloud.google.com/compute/docs/disks/create-snapshots)
- [AWS spot instance interruption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-interruptions.html)
- See ATT&CK Cloud matrix for Defense Evasion, Impact
