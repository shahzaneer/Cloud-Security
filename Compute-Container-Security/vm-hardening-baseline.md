# 01 — VM Hardening Baseline

> **Level:** Fundamental
> **Prereqs:** [Shared Responsibility](../Fundamentals/shared-responsibility.md) (Cloud Fundamentals)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Privilege Escalation, Lateral Movement
**Authorization scope:** Run only in your own sandbox cloud account. All commands are read-only or hardening-only; no offensive payloads.

## What & why

VM hardening is the set of configuration controls that shrink the attack surface of a running compute instance — disabling unnecessary services, enforcing kernel protections, locking down the OS userland, and restricting metadata access. A hardened VM collapses an attacker's post-exploitation run-loop by removing common pivot points like credential caches, writable service binaries, and exposed instance metadata.

## The OnPrem reality

Before cloud, hardening meant applying CIS Benchmarks via configuration management (Puppet, Chef, Ansible) to bare-metal servers or vSphere VMs. Each OS image was baked with a golden kickstart/PXE profile that enabled SELinux, set file permissions, removed compiler toolchains, and disabled unused kernel modules. Audit was manual via Lynis/OpenSCAP reports.

## Core concepts

| Control Family | What It Enforces | Zero-Cost Option |
|---|---|---|
| OS user accounts | No default passwords, limited sudoers | cloud-init user provisioning |
| File-system permissions | `/etc/shadow` 000, no world-writable cron | baked into base AMI |
| Kernel hardening | `kernel.randomize_va_space=2`, `kernel.kptr_restrict=2` | sysctl via cloud-init |
| Network exposure | No `sshd` on 0.0.0.0, restrict security groups | cloud firewall (SG/NSG) |
| Metadata service | IMDSv2 required (AWS), no metadata from containers | free on all clouds |
| Logging & auditing | auditd rules, syslog shipping | cloud-native agent |
| Package hygiene | Remove compilers, netcat, tcpdump from prod | image build pipeline |

## AWS

**Primary services:** EC2, Systems Manager Patch Manager, Inspector, CloudWatch agent

**CLI baseline check (CIS Level 1):**
```bash
# AWS
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].[InstanceId,MetadataOptions.HttpTokens]' \
  --output table
```

**Terraform snippet — hardened EC2 with IMDSv2:**
```hcl
# AWS
resource "aws_instance" "hardened" {
  ami           = data.aws_ami.cis_hardened.id
  instance_type = "t3.micro"
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
  user_data = <<-EOF
    #!/bin/bash
    # CIS Level 1 — boot-time hardening
    # Disable unused filesystems
    echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf
    echo "install freevxfs /bin/true" >> /etc/modprobe.d/freevxfs.conf
    # Ensure SELinux enforcing
    setenforce 1
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
    # Kernel hardening
    sysctl -w kernel.randomize_va_space=2
    sysctl -w kernel.kptr_restrict=2
    sysctl -w net.ipv4.conf.all.log_martians=1
    # Remove dev tools
    yum remove -y gcc make perl
    # Ensure auditd enabled
    systemctl enable auditd && systemctl start auditd
    EOF
}
```

**Patch Manager (free):**
```bash
# AWS
aws ssm send-command \
  --document-name "AWS-RunPatchBaseline" \
  --targets "Key=InstanceIds,Values=i-11111111111111111" \
  --parameters "Operation=Scan"
```

## Azure

**Primary services:** Azure Automanage, Azure Policy (guest configuration), Update Management

**CLI baseline check:**
```bash
# Azure
az vm show --name vm-hardened --resource-group rg-sec \
  --query "diagnosticsProfile.bootDiagnostics" -o tsv
```

**Terraform snippet — hardened Azure VM:**
```hcl
# Azure
resource "azurerm_linux_virtual_machine" "hardened" {
  name                = "vm-hardened"
  resource_group_name = azurerm_resource_group.rg.name
  size                = "Standard_B1s"
  admin_username      = "azureadmin"
  admin_ssh_key {
    username   = "azureadmin"
    public_key = file("~/.ssh/id_rsa.pub")
  }
  custom_data = base64encode(<<-EOF
    #!/bin/bash
    # CIS Level 1 hardening
    apt-get update && apt-get upgrade -y
    apt-get remove -y gcc make
    sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
    sysctl -w kernel.randomize_va_space=2
    systemctl enable auditd && systemctl start auditd
    EOF
  )
}
```

**Azure Policy for guest configuration (no-cost audit):**
```json
// Azure
{
  "properties": {
    "policyRule": {
      "if": {
        "field": "type",
        "equals": "Microsoft.Compute/virtualMachines"
      },
      "then": {
        "effect": "auditIfNotExists",
        "details": {
          "type": "Microsoft.GuestConfiguration/guestConfigurationAssignments",
          "existenceCondition": {
            "field": "Microsoft.GuestConfiguration/guestConfigurationAssignments/complianceStatus",
            "equals": "Compliant"
          }
        }
      }
    }
  }
}
```

## GCP

**Primary services:** VM Manager (OS Config), Security Command Center, OS Login

**CLI baseline check:**
```bash
# GCP
gcloud compute instances describe instance-hardened \
  --zone=us-central1-a \
  --format="json(metadata.items[].key,metadata.items[].value)"
```

**Terraform snippet — hardened GCE instance with shielded VM:**
```hcl
# GCP
resource "google_compute_instance" "hardened" {
  name         = "instance-hardened"
  machine_type = "e2-micro"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params {
      image = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2204-lts"
    }
  }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
  metadata = {
    enable-oslogin     = "TRUE"
    serial-port-enable = "FALSE"
  }
  metadata_startup_script = <<-EOF
    #!/bin/bash
    sysctl -w kernel.randomize_va_space=2
    sysctl -w kernel.kptr_restrict=2
    apt-get remove -y gcc make
    systemctl enable auditd && systemctl start auditd
    EOF
}
```

**VM Manager OS Config compliance (free):**
```bash
# GCP
gcloud compute os-config os-policy-assignments list \
  --location=us-central1-a
```

## OnPrem

**Primary tooling:** Ansible + CIS playbooks, OpenSCAP, Lynis

**Ansible snippet applying CIS Level 1:**
```yaml
# OnPrem
- name: Apply CIS L1 hardening
  hosts: all
  become: yes
  tasks:
    - name: Remove legacy packages
      package:
        name: "{{ item }}"
        state: absent
      loop:
        - xinetd
        - telnet-server
        - rsh-server
    - name: Set kernel randomization
      sysctl:
        name: kernel.randomize_va_space
        value: '2'
        state: present
        reload: yes
    - name: Ensure auditd is active
      service:
        name: auditd
        state: started
        enabled: yes
    - name: Set restrictive UMASK
      lineinfile:
        path: /etc/login.defs
        regexp: '^UMASK'
        line: 'UMASK 027'
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| OS baseline scan | OpenSCAP / Lynis | Inspector | Azure Policy guest config | VM Manager OS Config |
| Patch management | Ansible + yum-cron | Systems Manager Patch Manager | Update Management | VM Manager patch |
| Boot integrity | TPM measured boot | Nitro Enclaves | vTPM | Shielded VM |
| Metadata protection | N/A | IMDSv2 | Azure Instance Metadata Service | Metadata server (v1) |
| Remote access hardening | SSH key-only | Session Manager (no SSH) | Azure Bastion | OS Login (IAP) |
| File integrity | AIDE / Tripwire | Inspector CIS | Azure Change Tracking | N/A (COOS read-only root) |

## 🔴 Red Team view

Attackers probe unhardened VMs for four primary vectors:

**1. Open SSH with password auth**

An attacker who gets an internal IP probes for SSH on 22:
```bash
ssh -o PreferredAuthentications=password ec2-user@10.0.1.5
```
If the AMI was launched with `PasswordAuthentication yes`, a brute-force or credential-stuffing attack succeeds against `ec2-user`. Once inside, the attacker has a shell on a VM in the VPC.

**2. Kernel exploit via unpatched CVE chain**

A VM that hasn't been patched in 90 days may be vulnerable to a local privilege escalation. Without referencing specific CVEs, attackers chain a kernel module vulnerability (e.g. in netfilter or eBPF) to escalate from an unprivileged user to root. The prerequisite is shell access (from vector 1 or a compromised application).

**3. IMDSv1 credential theft**

On AWS with IMDSv1 enabled:
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/s3-readonly-role
```
This returns temporary AWS credentials without any session token validation — usable from any process on the box. The attacker exfiltrates these and uses them from outside the VM.

**4. Writable cron/service binary**

If `/etc/crontab` or `/etc/systemd/system/` is world-writable (umask too permissive), the attacker drops a persistence unit:
```bash
echo "* * * * * root /tmp/beacon.sh" >> /etc/crontab
```
This survives reboot and calls back to a C2 endpoint.

**Artifacts left:** CloudTrail `GetCallerIdentity` from the instance profile (`i-*`), SSH auth logs in `/var/log/secure`, crontab modification timestamps, unusual outbound connections in VPC Flow Logs.

## 🔵 Blue Team view

**Detection signals:**

| Signal | Log Source | Query |
|---|---|---|
| First `sudo` from new source IP | CloudTrail + SSM RunCommand | Filter `eventName=SendCommand` with `sourceIPAddress != known_range` |
| IMDSv1 access | VPC Flow Logs + instance metadata logs | Look for `destinationPort=80` to `169.254.169.254` via IMDSv1 (no `X-aws-ec2-metadata-token` header) |
| SSH brute-force | `/var/log/secure` → CloudWatch | `grep "Failed password" /var/log/secure \| wc -l > 10` over 5 min window |
| Crontab modification | auditd rule | `-w /etc/crontab -p wa -k crontab_change` |
| Package install (gcc, netcat) | CloudTrail `RunCommand` or osquery | `SELECT name, version FROM deb_packages WHERE name IN ('gcc','netcat');` |

**Preventive controls:**

- **AWS:** Enforce IMDSv2 via SCP or account-wide setting; use Session Manager instead of SSH; patch with Automation runbook on schedule.
- **Azure:** Enable Azure Policy guest configuration audit `[Preview]: Audit Linux VMs that do not have the specified applications installed`; force key-only SSH.
- **GCP:** Enable OS Login across the org; enforce Shielded VM by Org Policy constraint `compute.requireShieldedVm`.
- **OnPrem:** Enforce CIS via Ansible Tower/AWX scheduled jobs; FIM (AIDE) baseline alerts on config drift.

**Response steps:**
1. Isolate the instance (remove from target group / apply `deny-all` SG).
2. Snapshot the EBS disk for forensics.
3. Rotate all credentials that touched the instance (IAM role, SSH keys).
4. Investigate CloudTrail for the source IP's activity across all services.
5. Rebuild from known-good AMI.

## Hands-on lab

**Goal:** Scan a VM for CIS compliance and apply hardening via cloud-native tooling (free tier).

**Steps:**
1. Launch a t3.micro / B1s / e2-micro instance with default Ubuntu 22.04.
2. Run `lynis audit system --quick` to see baseline score.
3. Apply the cloud-init hardening script from the cloud-specific section above.
4. Re-run `lynis audit system --quick` — score should increase.
5. Verify IMDSv2 is required (AWS): `TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")` then `curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/`.
6. Teardown: terminate the instance.

## Detection rules & checklists

**Sigma rule — SSH brute-force on cloud VM:**
```yaml
title: SSH Brute Force on Cloud VM
logsource:
  product: linux
  service: auth
detection:
  selection:
    type: 'USER_LOGIN'
    message|contains: 'Failed password'
  timeframe: 5m
  condition: selection | count() > 10
  level: medium
```

**Cloud Custodian — enforce IMDSv2:**
```yaml
policies:
  - name: require-imdsv2
    resource: aws.ec2
    filters:
      - type: metadata-options
        key: HttpTokens
        value: optional
    actions:
      - type: notify
        template: default
```

**CLI audit one-liners:**
```bash
# AWS: find instances with password auth in user-data
aws ec2 describe-instance-attribute --instance-id i-11111111111111111 \
  --attribute userData --query 'UserData.Value' --output text | base64 -d | grep -i password

# Azure: audit NSG rules allowing SSH from 0.0.0.0/0
az network nsg rule list --nsg-name nsg-web --resource-group rg-sec \
  --query "[?destinationPortRange=='22' && sourceAddressPrefix=='*'].name"

# GCP: find instances without shielded VM
gcloud compute instances list --filter="shieldedInstanceConfig.enableSecureBoot!=true"

# OnPrem: lynis audit quick
lynis audit system --quick 2>&1 | grep -E "Warning|Suggestion"
```

## References
- CIS Distribution Independent Linux Benchmark: https://www.cisecurity.org/benchmark/distribution_independent_linux
- AWS IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Azure Automanage: https://learn.microsoft.com/en-us/azure/automanage/automanage-virtual-machines
- GCP Shielded VM: https://cloud.google.com/compute/shielded-vm/docs/shielded-vm
- MITRE ATT&CK: see Cloud matrix for "Defense Evasion" and "Privilege Escalation"
- Cross-links: [`../IAM/assume-role-chains.md`](../IAM/assume-role-chains.md), [`../01-Network-Security`](../Network-Security/)
