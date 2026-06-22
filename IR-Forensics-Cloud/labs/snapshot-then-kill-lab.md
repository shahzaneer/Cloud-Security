# Lab — Snapshot-Then-Kill

> **Level:** Intermediate (hands-on)
> **Prereqs:** [11-01](./ir-runbook-cloud-aware.md), [11-03](./evidence-preservation-in-ephemeral-infra.md), [11-04](./snapshot-and-memory-acquisition.md)
> **Clouds:** AWS (primary; Azure/GCP analogues noted)
> **Estimated time:** 30 min
> **Cost risk:** EC2 t3.micro (~$0.01/hr), EBS snapshot (~$0.05/GB-month). Delete all resources when done.
> **Authorization scope:** Run only in your own sandbox AWS account. Uses `LocalStack` for metadata simulation. All account IDs are placeholders (`111111111111`).

## Objective

Simulate an EC2 instance compromise via SSRF, then execute the full IR preservation chain: snapshot, tag forensic, quarantine security group, revoke IAM role, capture memory (if root available), and reconstruct the CloudTrail timeline.

## Lab architecture

```
┌──────────────────────────────────────────────┐
│  Your Sandbox VPC                             │
│  ┌──────────────┐    ┌──────────────────────┐ │
│  │ EC2 Instance  │    │  S3 Evidence Bucket  │ │
│  │ - IMDSv1      │    │  (Object Lock)       │ │
│  │ - Over-       │    └──────────────────────┘ │
│  │   permissive  │                              │
│  │   IAM role    │    ┌──────────────────────┐ │
│  │ - SSM Agent   │    │  Quarantine SG       │ │
│  └──────────────┘    │  (no inbound/outbound)│ │
│                       └──────────────────────┘ │
└──────────────────────────────────────────────┘
```

## Step 1 — Provision infrastructure

### 1a. Create the evidence bucket

```bash
EVIDENCE_BUCKET="forensic-lab-$(aws sts get-caller-identity --query Account --output text)"

aws s3api create-bucket \
    --bucket $EVIDENCE_BUCKET \
    --region us-east-1 \
    --object-lock-enabled-for-bucket

aws s3api put-object-lock-configuration \
    --bucket $EVIDENCE_BUCKET \
    --object-lock-configuration '{
        "ObjectLockEnabled": "Enabled",
        "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}}
    }'

echo "Evidence bucket: $EVIDENCE_BUCKET"
```

### 1b. Create quarantine security group

```bash
QUARANTINE_SG=$(aws ec2 create-security-group \
    --group-name "Quarantine-Lab" \
    --description "Quarantine SG — blocks all traffic" \
    --vpc-id $(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text) \
    --query 'GroupId' --output text)

aws ec2 revoke-security-group-egress \
    --group-id $QUARANTINE_SG \
    --protocol -1 --port -1 --cidr 0.0.0.0/0 2>/dev/null || true

echo "Quarantine SG: $QUARANTINE_SG"
```

### 1c. Create over-permissive IAM role with IMDSv1 instance

```bash
aws iam create-role \
    --role-name LabOverPermittedRole \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }'

aws iam attach-role-policy \
    --role-name LabOverPermittedRole \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws iam create-instance-profile --instance-profile-name LabOverPermittedProfile

aws iam add-role-to-instance-profile \
    --instance-profile-name LabOverPermittedProfile \
    --role-name LabOverPermittedRole

sleep 10
```

### 1d. Launch EC2 instance with IMDSv1 and SSM agent

```bash
AMI_ID=$(aws ssm get-parameters \
    --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
    --query 'Parameters[0].Value' --output text)

INSTANCE_ID=$(aws ec2 run-instances \
    --image-id $AMI_ID \
    --instance-type t3.micro \
    --iam-instance-profile Name=LabOverPermittedProfile \
    --metadata-options HttpTokens=optional,HttpEndpoint=enabled \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ForensicLabTarget}]' \
    --query 'Instances[0].InstanceId' --output text)

echo "Instance ID: $INSTANCE_ID"

aws ec2 wait instance-running --instance-ids $INSTANCE_ID
aws ec2 wait instance-status-ok --instance-ids $INSTANCE_ID
echo "Instance running — SSM agent may need 2-3 min to register"
sleep 120
```

**Expected output:**

```
Instance ID: i-0a1b2c3d4e5f67890
Instance running — SSM agent may need 2-3 min to register
```

## Step 2 — Simulate SSRF credential exfiltration

This is a **contained simulation** — we curl the EC2 metadata endpoint from localhost on the instance itself. This mirrors what an SSRF vulnerability would do.

```bash
# SSM Run Command: simulate SSRF against IMDSv1
COMMAND_ID=$(aws ssm send-command \
    --document-name "AWS-RunShellScript" \
    --targets "Key=instanceids,Values=$INSTANCE_ID" \
    --parameters '{
        "commands": [
            "ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)",
            "echo \"Role name: $ROLE_NAME\"",
            "CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME)",
            "echo \"$CREDS\" | tee /tmp/exfiltrated_creds.json",
            "ACCESS_KEY=$(echo $CREDS | jq -r .AccessKeyId)",
            "SECRET_KEY=$(echo $CREDS | jq -r .SecretAccessKey)",
            "SESSION_TOKEN=$(echo $CREDS | jq -r .Token)",
            "export AWS_ACCESS_KEY_ID=$ACCESS_KEY",
            "export AWS_SECRET_ACCESS_KEY=$SECRET_KEY",
            "export AWS_SESSION_TOKEN=$SESSION_TOKEN",
            "aws sts get-caller-identity",
            "aws s3 ls 2>/dev/null || echo \"S3 listing attempted (simulated recon)\"",
            "echo \"CREDENTIAL_EXFIL_MARKER: $(date -u +%Y-%m-%dT%H:%M:%SZ)\""
        ]
    }' \
    --query 'Command.CommandId' --output text)

echo "SSM Command ID: $COMMAND_ID"
```

**Expected output (after `aws ssm get-command-invocation --command-id $COMMAND_ID --instance-id $INSTANCE_ID`):**

```
Role name: LabOverPermittedRole
{
  "Code": "Success",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2026-06-22T15:23:00Z"
}
arn:aws:sts::111111111111:assumed-role/LabOverPermittedRole/i-0a1b2c3d4e5f67890
CREDENTIAL_EXFIL_MARKER: 2026-06-22T14:23:00Z
```

The `CREDENTIAL_EXFIL_MARKER` timestamp is your ground-zero for timeline reconstruction.

## Step 3 — Execute IR preservation chain

```bash
INCIDENT_ID="lab-inc-$(date +%s)"
echo "Incident ID: $INCIDENT_ID"

echo "=== Phase 1: Snapshot EBS volumes ==="
SNAP_RESPONSE=$(aws ec2 create-snapshots \
    --instance-specification InstanceId=$INSTANCE_ID \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=forensic,Value=true},{Key=incident-id,Value=$INCIDENT_ID}]" \
    --description "Forensic snapshot for $INCIDENT_ID" \
    --copy-tags-from-source volume)

SNAP_IDS=$(echo $SNAP_RESPONSE | jq -r '.Snapshots[].SnapshotId')
echo "Snapshot IDs: $SNAP_IDS"

for SNAP in $SNAP_IDS; do
    echo "Waiting for $SNAP..."
    aws ec2 wait snapshot-completed --snapshot-ids $SNAP
done
echo "All snapshots completed"

echo "=== Phase 2: Tag instance as forensic ==="
aws ec2 create-tags --resources $INSTANCE_ID \
    --tags Key=incident-id,Value=$INCIDENT_ID Key=forensic,Value=true

echo "=== Phase 3: Move to quarantine SG ==="
aws ec2 modify-instance-attribute \
    --instance-id $INSTANCE_ID \
    --groups $QUARANTINE_SG

echo "=== Phase 4: Disassociate IAM instance profile ==="
ASSOC_ID=$(aws ec2 describe-iam-instance-profile-associations \
    --filters Name=instance-id,Values=$INSTANCE_ID \
    --query 'IamInstanceProfileAssociations[0].AssociationId' --output text)

aws ec2 disassociate-iam-instance-profile --association-id $ASSOC_ID
echo "IAM profile disassociated: $ASSOC_ID"

echo "=== Phase 5: Attach deny-all to role ==="
aws iam put-role-policy \
    --role-name LabOverPermittedRole \
    --policy-name "IR-${INCIDENT_ID}-DenyAll" \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }]
    }'

echo "=== Phase 6: Memory acquisition (if root/AVML available) ==="
aws ssm send-command \
    --document-name "AWS-RunShellScript" \
    --targets "Key=instanceids,Values=$INSTANCE_ID" \
    --parameters '{
        "commands": [
            "curl -sL https://github.com/microsoft/avml/releases/download/v0.11.0/avml -o /tmp/avml 2>&1 || echo 'AVML download failed'",
            "chmod +x /tmp/avml 2>/dev/null",
            "/tmp/avml /tmp/memory.lime 2>&1 || echo 'AVML execution failed — likely no root or kernel module blocked'",
            "aws s3 cp /tmp/memory.lime s3://'$EVIDENCE_BUCKET'/'$INCIDENT_ID'/memory.lime 2>&1 || echo 'Memory upload skipped'",
            "sha256sum /tmp/memory.lime 2>/dev/null | tee /tmp/memory.sha256"
        ]
    }' \
    --query 'Command.CommandId' --output text

echo "=== Phase 7: Stop instance (DO NOT Terminate) ==="
aws ec2 stop-instances --instance-ids $INSTANCE_ID
echo "Instance stopping — snapshot in place"
```

**Expected output:**

```
Incident ID: lab-inc-1719000000
Snapshot IDs: snap-0a1b2c3d4e5f67890
...
Instance stopping — snapshot in place
```

## Step 4 — Verify preservation

```bash
echo "=== Verification ==="

echo "Snapshots:"
aws ec2 describe-snapshots \
    --filters Name=tag:incident-id,Values=$INCIDENT_ID \
    --query 'Snapshots[*].{ID:SnapshotId,State:State,Size:VolumeSize,Progress:Progress}' \
    --output table

echo "Instance state:"
aws ec2 describe-instances --instance-ids $INSTANCE_ID \
    --query 'Reservations[0].Instances[0].{State:State.Name,SecurityGroups:SecurityGroups[*].GroupId,IamProfile:!IamInstanceProfile}' \
    --output json

echo "S3 evidence:"
aws s3 ls "s3://${EVIDENCE_BUCKET}/${INCIDENT_ID}/"
```

**Expected output:**

```
Snapshots:
|     ID       |  State     |  Size |  Progress |
|--------------|------------|-------|-----------|
| snap-abc...  | completed  |  8    |  100%     |

Instance state:
{
  "State": "stopped",
  "SecurityGroups": ["sg-quarantine-id"],
  "IamProfile": null
}

S3 evidence:
memory.lime (if AVML succeeded)
```

## Step 5 — Reconstruct CloudTrail timeline (1h post-alert)

```bash
START_TIME=$(date -u -d '2 hours ago' +%s)

echo "=== CloudTrail events for the instance ==="
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=ResourceName,AttributeValue=$INSTANCE_ID \
    --start-time $START_TIME \
    --output json | jq '.Events[] | {time: .EventTime, event: .EventName, user: .Username, sourceIP: .CloudTrailEvent | fromjson | .sourceIPAddress}' \
    > timeline_${INCIDENT_ID}.json

echo "Timeline events: $(jq -s 'length' timeline_${INCIDENT_ID}.json)"

echo "=== Key events in timeline ==="
jq -r '[.time, .event, .sourceIP] | @tsv' timeline_${INCIDENT_ID}.json
```

**Expected output (approx):**

```
2026-06-22T14:20:00Z  RunInstances      10.0.0.1
2026-06-22T14:23:00Z  SendCommand       203.0.113.1  (SSM Run Command source)
2026-06-22T14:23:05Z  GetCallerIdentity  (via IMDS role on instance)
2026-06-22T14:24:00Z  CreateSnapshots    203.0.113.1  (IR action)
2026-06-22T14:24:15Z  ModifyInstanceAttribute  203.0.113.1  (quarantine SG)
2026-06-22T14:24:20Z  DisassociateIamInstanceProfile  203.0.113.1
2026-06-22T14:24:30Z  StopInstances      203.0.113.1
```

## Step 6 — Teardown

```bash
echo "=== Deleting evidence objects ==="
aws s3 rm "s3://${EVIDENCE_BUCKET}/${INCIDENT_ID}/" --recursive

echo "=== Deleting snapshots ==="
for SNAP in $SNAP_IDS; do
    aws ec2 delete-snapshot --snapshot-id $SNAP
done

echo "=== Terminating instance ==="
aws ec2 terminate-instances --instance-ids $INSTANCE_ID

echo "=== Cleaning up IAM ==="
aws iam remove-role-from-instance-profile \
    --instance-profile-name LabOverPermittedProfile \
    --role-name LabOverPermittedRole

aws iam delete-instance-profile --instance-profile-name LabOverPermittedProfile

aws iam detach-role-policy \
    --role-name LabOverPermittedRole \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws iam delete-role-policy \
    --role-name LabOverPermittedRole \
    --policy-name "IR-${INCIDENT_ID}-DenyAll"

aws iam delete-role --role-name LabOverPermittedRole

echo "=== Deleting security group ==="
aws ec2 delete-security-group --group-id $QUARANTINE_SG

echo "=== Deleting S3 evidence bucket ==="
aws s3 rm "s3://${EVIDENCE_BUCKET}" --recursive
aws s3api delete-bucket --bucket $EVIDENCE_BUCKET --region us-east-1

echo "=== Lab teardown complete ==="
```

## Azure equivalent (summary)

| Step | AWS | Azure |
|------|-----|-------|
| Simulate SSRF | IMDSv1 `curl http://169.254.169.254/...` | Azure Instance Metadata Service `curl -H "Metadata:true" http://169.254.169.254/metadata/identity/oauth2/token` |
| Snapshot | `aws ec2 create-snapshots` | `az snapshot create --source <osdisk>` |
| Quarantine | Move to quarantine SG | Attach NSG with deny-all rule |
| Revoke IAM | `disassociate-iam-instance-profile` + deny-all policy | `az vm identity remove` + disable SP |
| Stop | `aws ec2 stop-instances` | `az vm deallocate` |

## GCP equivalent (summary)

| Step | AWS | GCP |
|------|-----|-----|
| Simulate SSRF | IMDSv1 `curl http://169.254.169.254/...` | GCE metadata `curl -H "Metadata-Flavor:Google" http://metadata.google.internal/...` |
| Snapshot | `aws ec2 create-snapshots` | `gcloud compute disks snapshot` |
| Quarantine | Move to quarantine SG | Attach deny-all firewall rule + target tags |
| Revoke IAM | `disassociate-iam-instance-profile` | `gcloud compute instances remove-service-account` |
| Stop | `aws ec2 stop-instances` | `gcloud compute instances stop` |

## Validation checklist

- [ ] `aws ec2 describe-snapshots` shows snapshots with `forensic=true` tag
- [ ] `aws ec2 describe-instances` shows instance state `stopped`
- [ ] Instance SecurityGroups includes only the quarantine SG
- [ ] `aws ec2 describe-iam-instance-profile-associations` returns empty for instance
- [ ] CloudTrail timeline shows the SSRF credential access *before* preservation actions
- [ ] S3 evidence bucket contains the memory dump or note that memory capture was skipped
