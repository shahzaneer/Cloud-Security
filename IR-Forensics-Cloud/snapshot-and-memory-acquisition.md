# 04 — Snapshot and Memory Acquisition

> **Level:** Advanced
> **Prereqs:** [11-03](./evidence-preservation-in-ephemeral-infra.md), [03-IAM](../IAM/)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Credential Access
> **Authorization scope:** Run only in your own sandbox account; all example account IDs are placeholders (`111111111111`, `00000000-0000-0000-0000-000000000000`).

## What & why

Before destroying a compromised host, capture its disk and (where feasible) its memory for chain-of-custody analysis. Cloud hypervisors do not expose raw memory snapshots by default; disk snapshots are the minimum viable forensic artifact — memory requires in-guest tooling and root access.

## The OnPrem reality

On-prem forensics used the Volatility framework against a raw memory image captured via LiME (Linux Memory Extractor) kernel module or WinPmem on Windows. Disk imaging required a write-blocker on a SCSI enclosure, with `dd` piping through `sha256sum`. Both artifacts were stored on a forensically-wiped drive and sealed in an evidence bag with a chain-of-custody form.

## Core concepts

### Snapshot vs. live disk

| Artifact | OnPrem | AWS | Azure | GCP |
|----------|--------|-----|-------|-----|
| EBS/persistent disk snapshot | N/A (physical) | `ec2 create-snapshots` — block-level, crash-consistent | `az snapshot create` — incremental point-in-time | `gcloud compute disks snapshot` — crash-consistent |
| Instance-store / ephemeral disk | Boot from SAN | Not snapshottable — lost on stop/terminate | Temp disks (D: drive) — lost on deallocate | Local SSD — lost on stop/terminate |
| Memory | LiME LKM → file | AVML via SSM Run Command | AVML via Run Command | AVML via SSH |
| Swap / page file | Part of disk image | Included in EBS snapshot if swap on EBS | Included in OS disk snapshot | Included in persistent disk snapshot |

### Memory acquisition feasibility matrix

| Cloud | Root required? | Kernel module load allowed? | Vendor-built tool | Notes |
|-------|---------------|---------------------------|-------------------|-------|
| AWS EC2 | Yes (for LiME/AVML) | Yes (unless locked-down kernel) | None; use AVML or LiME | SSM Run Command needs `AmazonSSMManagedInstanceCore` policy |
| Azure VM | Yes (for AVML) | Yes (Linux); Windows uses `Microsoft.Diagnostic` extension (does not capture RAM; use WinPmem or Belkasoft on Windows) | None; use AVML or `gcore` | Run Command `RunShellScript` requires VM Agent |
| GCP Compute Engine | Yes (for AVML) | Yes (if not Container-Optimized OS) | None; use AVML or `gcore` | OSLogin or SSH key required; COS has no package manager |
| OnPrem (Linux) | Yes | Yes | LiME, AVML | Direct KVM/IPMI console if SSH unavailable |

> (as of June 2026, no cloud provider offers a first-party, hypervisor-level memory snapshot to tenants. Microsoft's Azure VM `Diagnostic` extension does NOT capture RAM. AWS Nitro hypervisor does not expose guest memory. GCP likewise provides no hypervisor-level memory capture. All memory acquisition relies on in-guest kernel modules — AVML (cross-platform, maintained by Microsoft) and LiME (Linux Memory Extractor) are the primary tools.)

## AWS

**Full acquisition chain (via Systems Manager):**

```bash
INCIDENT_ID="inc-$(date +%s)"
INSTANCE_ID="i-0a1b2c3d4e5f67890"
EVIDENCE_BUCKET="forensic-bucket-111111111111"
EVIDENCE_PREFIX="s3://${EVIDENCE_BUCKET}/${INCIDENT_ID}"

aws ec2 create-snapshots \
    --instance-specification InstanceId=$INSTANCE_ID \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=incident-id,Value=$INCIDENT_ID},{Key=forensic,Value=true}]" \
    --description "Forensic snapshot for $INCIDENT_ID"

SNAP_IDS=$(aws ec2 describe-snapshots \
    --filters Name=tag:incident-id,Values=$INCIDENT_ID \
    --query 'Snapshots[*].SnapshotId' --output text)

for SNAP in $SNAP_IDS; do
    echo "Waiting for snapshot $SNAP to complete..."
    aws ec2 wait snapshot-completed --snapshot-ids $SNAP
done

COMMAND_ID=$(aws ssm send-command \
    --document-name "AWS-RunShellScript" \
    --targets "Key=instanceids,Values=$INSTANCE_ID" \
    --parameters '{
        "commands": [
            "curl -sL https://github.com/microsoft/avml/releases/download/v0.11.0/avml -o /tmp/avml",
            "chmod +x /tmp/avml",
            "/tmp/avml /tmp/memory-'"$INCIDENT_ID"'.lime",
            "sha256sum /tmp/memory-'"$INCIDENT_ID"'.lime > /tmp/memory-'"$INCIDENT_ID"'.sha256",
            "aws s3 cp /tmp/memory-'"$INCIDENT_ID"'.lime '"$EVIDENCE_PREFIX"'/memory.lime",
            "aws s3 cp /tmp/memory-'"$INCIDENT_ID"'.sha256 '"$EVIDENCE_PREFIX"'/memory.sha256"
        ]
    }' \
    --query 'Command.CommandId' --output text)

echo "Command ID: $COMMAND_ID — check /var/lib/amazon/ssm/... for output"

aws s3api put-object-lock-configuration \
    --bucket $EVIDENCE_BUCKET \
    --object-lock-configuration '{
        "ObjectLockEnabled": "Enabled",
        "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Years": 7}}
    }'
```

**Instance-store limitation:**

```bash
aws ec2 describe-instances --instance-ids $INSTANCE_ID \
    --query 'Reservations[0].Instances[0].BlockDeviceMappings[?contains(DeviceName, `ephemeral`)]'
# If non-empty, these volumes CANNOT be snapshotted
# Data loss is inevitable; prioritize memory and log capture
```

## Azure

```bash
INCIDENT_ID="inc-$(date +%s)"
VM_NAME="compromised-vm"
RG="forensics-rg"
STORAGE_ACCT="forensicsacct"
CONTAINER="evidence"

az snapshot create -g $RG -n "os-snap-${INCIDENT_ID}" \
    --source "$(az vm show -g $RG -n $VM_NAME --query 'storageProfile.osDisk.name' -o tsv)" \
    --tags incident-id=$INCIDENT_ID forensic=true

az storage container create --name $CONTAINER \
    --account-name $STORAGE_ACCT \
    --auth-mode login

COMMAND_OUTPUT=$(az vm run-command invoke -g $RG -n $VM_NAME \
    --command-id RunShellScript \
    --scripts "
        curl -sL https://github.com/microsoft/avml/releases/download/v0.11.0/avml -o /tmp/avml
        chmod +x /tmp/avml
        /tmp/avml /tmp/memory.lime
        sha256sum /tmp/memory.lime > /tmp/memory.sha256
    ")

az storage blob upload \
    --account-name $STORAGE_ACCT \
    --container-name $CONTAINER \
    --name "${INCIDENT_ID}/memory.lime" \
    --file /tmp/memory.lime

az storage blob immutability-policy set \
    --account-name $STORAGE_ACCT \
    --container-name $CONTAINER \
    --blob-name "${INCIDENT_ID}/memory.lime" \
    --period 2555 \
    --policy-mode Unlocked
```

## GCP

```bash
INCIDENT_ID="inc-$(date +%s)"
INSTANCE_NAME="compromised-instance"
ZONE="us-central1-a"
BUCKET="gs://forensic-bucket"

gcloud compute disks snapshot $INSTANCE_NAME \
    --zone=$ZONE \
    --snapshot-names="snap-${INCIDENT_ID}" \
    --labels=incident-id=$INCIDENT_ID,forensic=true

gcloud compute ssh $INSTANCE_NAME --zone=$ZONE --command="
    sudo mkdir -p /mnt/forensics
    sudo curl -sL https://github.com/microsoft/avml/releases/download/v0.11.0/avml -o /mnt/forensics/avml
    sudo chmod +x /mnt/forensics/avml
    sudo /mnt/forensics/avml /mnt/forensics/memory.lime
    sha256sum /mnt/forensics/memory.lime | sudo tee /mnt/forensics/memory.sha256
    gsutil cp /mnt/forensics/memory.lime $BUCKET/$INCIDENT_ID/memory.lime
    gsutil cp /mnt/forensics/memory.sha256 $BUCKET/$INCIDENT_ID/memory.sha256
"

gcloud storage buckets update $BUCKET \
    --retention-period=7y \
    --no-lock
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Disk acquisition tool | `dd` via write-blocker | `ec2 create-snapshots` | `az snapshot create` | `gcloud compute disks snapshot` |
| Memory acquisition tool | Volatility + LiME | AVML via SSM | AVML via Run Command | AVML via SSH |
| Memory without root | `gcore` (userland, partial) | Not possible; root required for LKM | Not possible | Not possible |
| Hash manifest | `sha256sum` on imaging workstation | `sha256sum` on instance + S3 upload | `sha256sum` + blob upload | `sha256sum` + GCS upload |
| Evidence storage lock | Physical safe | S3 Object Lock | Immutable blob storage | Bucket retention policy |
| Ephemeral risk | None (physical disk persists) | Instance-store lost; spot instance 2-min warning | Temp disk lost; low-priority VM preemption | Local SSD lost; preemptible VM 30-sec warning |

## 🔴 Red Team view

The attacker with root on the compromised host can interfere with memory acquisition:

**Block kernel module load.** If the attacker controls `modprobe` or `insmod` paths, they can prevent LiME/AVML from loading. Signs: `dmesg` shows `avml: module verification failed` or audit logs show `syscall=init_module` being denied.

**Corrupt `/proc/kcore`.** The attacker can remount `/proc` with `hidepid=2` or unload required drivers, making `/proc/kcore` unreadable.

**Tamper with `auditd`.** If `auditd` is stopped (`service auditd stop`), kernel-level events like module insertion and memory access are not recorded. The defender cannot prove what happened during the acquisition.

**Tamper with SSM/Run Command agent.** The attacker can stop the SSM agent (`systemctl stop amazon-ssm-agent`) or block the Run Command extension on Azure. The defender's acquisition command never executes. The instance appears "unmanaged."

**Memory-race timing.** If the attacker knows the defender's mean time to acquisition (via repeated tabletop metrics — say 90 seconds), they script a `cryptsetup luksErase` of the data volume at 85 seconds post-credential-exfil. The defender captures an encrypted blob with no key.

**Artifacts:**
- `auditd` stop events in `/var/log/messages`
- SSM agent service stop in systemd journal
- Missing SSM command invocations in CloudTrail (the `SendCommand` API call succeeded but the agent never polled)
- Kernel logs showing `avml` load attempt and failure

## 🔵 Blue Team view

### Pre-install forensic tooling on hardened AMI

```bash
# Packer / Image Builder snippet
sudo mkdir -p /opt/forensics
sudo curl -sL -o /opt/forensics/avml \
    https://github.com/microsoft/avml/releases/download/v0.11.0/avml
sudo chmod 755 /opt/forensics/avml
echo "avml $(sha256sum /opt/forensics/avml)" >> /opt/forensics/manifest.txt
```

This eliminates the download-from-GitHub step, which can be blocked, delayed, or tampered with.

### Harden SSM agent

```bash
# Prevent SSM agent stop by non-root
sudo systemctl mask amazon-ssm-agent
# Monitor SSM agent health via CloudWatch agent
# Alert if agent heartbeat stops for > 60s
```

### `auditd` monitoring rule

```bash
# Monitor kernel module loads
-a always,exit -F arch=b64 -S init_module -F key=forensic-tamper
# Monitor auditd service stop
-w /usr/sbin/auditd -p x -k auditd-exec
```

### Hypertap / hypervisor-level limitation documentation

| Cloud | Hypervisor memory snapshot available? | Workaround |
|-------|--------------------------------------|------------|
| AWS Nitro | No — hypervisor does not expose guest RAM | In-guest AVML only |
| AWS Xen (legacy) | No | In-guest LiME |
| Azure Hyper-V | Not exposed to tenant (as of June 2026, no tenant-accessible hypervisor memory APIs exist) | In-guest AVML |
| GCP KVM | Not exposed to tenant (as of June 2026, no tenant-accessible hypervisor memory APIs exist) | In-guest AVML |

The blue team must document this limitation in the evidence report: "Memory acquisition relied on in-guest tooling; no hypervisor-level verification is available." This keeps chain-of-custody defensible.

### Verification checklist after acquisition

```bash
# Validate snapshot hash (AWS example)
aws ec2 describe-snapshots --snapshot-ids snap-xxxx \
    --query 'Snapshots[0].{State:State,VolumeSize:VolumeSize,Progress:Progress}'

# Validate memory dumped correctly
file memory.lime   # Expect: "LiME compressed memory image..."
volatility3 -f memory.lime linux.pslist  # Quick sanity check
```

## Hands-on lab

1. Launch EC2 with a hardened AMI that includes AVML at `/opt/forensics/avml`.
2. Generate some dummy process state: `dd if=/dev/urandom of=/tmp/secret bs=1M count=50`.
3. Execute the full acquisition chain: snapshot → AVML memory capture → S3 upload → hash manifest.
4. Download memory image to local machine; run `volatility3 -f memory.lime linux.pslist` and confirm the `dd` process is visible.
5. Teardown: delete S3 objects, delete snapshots, terminate instance.

## Detection rules & checklists

```yaml
title: SSM Agent Stopped on Production Instance
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: ssm.amazonaws.com
    eventName: UpdateInstanceInformation
    requestParameters.agentStatus: Inactive
  condition: selection
  severity: high
  description: "SSM agent stopped — forensic acquisition capability lost"
```

```yaml
title: Kernel Module Loaded Without Authorization
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: SYSCALL
    syscall: init_module
  filter:
    comm: "avml"  # Authorized forensic tool
  condition: selection and not filter
  severity: medium
```

- [ ] AVML binary baked into base AMI / VM image.
- [ ] `auditd` rules for `init_module` syscall deployed on all production instances.
- [ ] SSM agent health CloudWatch alarm enabled.
- [ ] Chain-of-custody gap for hypervisor-level memory snapshot documented in evidence cover sheet.

## References

- [AVML — Microsoft Acquire Volatile Memory for Linux](https://github.com/microsoft/avml)
- [LiME — Linux Memory Extractor](https://github.com/504ensicsLabs/LiME)
- [Volatility 3 Framework](https://github.com/volatilityfoundation/volatility3)
- [AWS SSM Run Command](https://docs.aws.amazon.com/systems-manager/latest/userguide/execute-remote-commands.html)
- [Azure Run Command](https://learn.microsoft.com/en-us/azure/virtual-machines/run-command-overview)
- See ATT&CK Cloud matrix for Defense Evasion
