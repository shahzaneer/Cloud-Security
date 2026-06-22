# 02 — Security Groups, NACLs, NSGs & Firewall Rules

> **Level:** Fundamental
> **Prereqs:** [Vpc Segmentation Design](vpc-segmentation-design.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** see ATT&CK Cloud matrix for Initial Access, Defense Evasion
**Authorization scope:** Run only in your own sandbox account / lab VPC.

## What & why
Stateful firewalls track connections and auto-allow return traffic; stateless filters evaluate every packet independently. In cloud, you layer both: stateful security groups (AWS SG, Azure NSG, GCP Firewall Rules) on the instance/interface, and stateless NACLs (AWS only) or equivalent at the subnet boundary. Misconfiguration — especially `0.0.0.0/0` on management ports — is the #1 cause of cloud breaches.

## The OnPrem reality
Pre-cloud, iptables/nftables provided stateful per-host filtering (analogous to SGs), while router ACLs provided stateless subnet-level control. The critical difference: on-prem firewall changes required physical or remote console access through a jump host; cloud firewall changes are one API call away and can be automated — for better or worse.

## Core concepts

### Stateful vs stateless

| Property | Stateful | Stateless |
|----------|----------|-----------|
| Tracks connections | Yes (SYN → SYN-ACK → ACK) | No — evaluates every packet |
| Return traffic | Auto-allowed | Must have explicit inbound AND outbound rules |
| Rule ordering | First match wins OR all rules evaluated | Rule number ordering (AWS NACL) |
| Common use | Instance-level security | Subnet boundary filter |
| Performance | Slightly more overhead | Faster, simpler |

### Cross-cloud comparison

| Concept | AWS | Azure | GCP | OnPrem |
|---------|-----|-------|-----|--------|
| Stateful instance/interface | Security Group | Network Security Group | Firewall Rule (priority, allow/deny) | iptables |
| Stateless subnet | Network ACL | — (use NSG or Azure Firewall) | VPC Firewall Policy (stateless tier) | Router ACL |
| Scope | ENI / instance | NIC / subnet | VPC-wide, target by tag/service account | Per-host / VLAN |
| Default behavior | Deny all inbound, allow all outbound | Deny all inbound, allow all outbound (NSG on NIC) | `default-allow-internal` allow | Deny all |
| Rule direction | Inbound + outbound (separate) | Inbound + outbound (separate) | Ingress + egress (direction on rule) | Chain-based (INPUT/OUTPUT/FORWARD) |
| Priority / ordering | All rules evaluated; most permissive wins | Priority number (100-4096, lower = higher) | Priority number (0-65535, lower = higher) | Chain order (first match) |

## AWS

Security Groups are stateful, attached to ENIs. NACLs are stateless, attached to subnets.

```hcl
# AWS default-deny SG with explicit allow
resource "aws_security_group" "web" {
  name   = "web-tier"
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "web_https" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "10.0.0.0/8"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "web_out" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_network_acl" "db_subnet" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.db.id]
}

resource "aws_network_acl_rule" "db_deny_all" {
  network_acl_id = aws_network_acl.db_subnet.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
}
```

CLI audit one-liner:

```
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[*].GroupId'
```

## Azure

NSGs can be applied to NICs (instance-level) or subnets. Azure Firewall provides additional stateless/stateful filtering at the VNet edge.

```hcl
# Azure NSG on subnet, default-deny inbound
resource "azurerm_network_security_group" "web" {
  name                = "web-nsg"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
}

resource "azurerm_network_security_rule" "allow_https_in" {
  name                        = "AllowHttpsInbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "10.0.0.0/8"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.web.name
}

resource "azurerm_network_security_rule" "deny_all_in" {
  name                        = "DenyAllInbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.web.name
}

resource "azurerm_subnet_network_security_group_association" "web" {
  subnet_id                 = azurerm_subnet.public.id
  network_security_group_id = azurerm_network_security_group.web.id
}
```

CLI audit one-liner:

```
az network nsg rule list --nsg-name web-nsg -g mygroup \
  --query "[?sourceAddressPrefix=='*' && (destinationPortRange==22 || destinationPortRange==3389)]"
```

## GCP

Firewall rules are VPC-wide, stateful, and can target instances by tag or service account — no per-subnet firewall binding.

```hcl
# GCP firewall rule — allow HTTPS from internal only
resource "google_compute_firewall" "web_allow_https" {
  name    = "allow-https-internal"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["10.0.0.0/8"]
  direction     = "INGRESS"
  priority      = 1000
}

resource "google_compute_firewall" "default_deny_ingress" {
  name      = "deny-all-ingress"
  network   = google_compute_network.main.name
  direction = "INGRESS"
  priority  = 65535

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}
```

CLI audit one-liner:

```
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=(0.0.0.0/0) AND allowed[].ports=(22,3389)" \
  --format="table(name, sourceRanges, allowed)"
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Instance firewall | iptables / nftables | Security Group | NSG (on NIC) | Firewall Rule (by tag/SA) |
| Subnet firewall | Router ACL / VLAN ACL | Network ACL | NSG (on subnet) | — (use VPC fw priority) |
| Default-deny inbound | iptables policy DROP | Implicit (SG defaults deny) | Implicit (NSG defaults deny) | Add explicit deny rule |
| Change audit | syslog / auditd | CloudTrail + Config | Azure Activity Log + Policy | Cloud Audit Logs + Org Policy |
| Rule drift detection | Config mgmt (Ansible) | AWS Config | Azure Policy | GCP Organization Policy |

## 🔴 Red Team view

Two common patterns: (1) overly permissive `0.0.0.0/0` rules accidentally granting SSH/RDP from anywhere; (2) "temporary debug" rules left behind permanently.

Contained drift detection example — terraform state shows actual vs expected:

```bash
terraform state show aws_security_group.web
# Look for: ingress { cidr_blocks = ["0.0.0.0/0"], from_port = 22 ... }
# If found, a debug rule slipped in and was never cleaned up
```

Equivalent across clouds:

```
# Azure NSG rule drift
az network nsg rule list --nsg-name web-nsg -g mygroup -o table

# GCP firewall drift
gcloud compute firewall-rules list --filter="network=main-vpc" --format=json
```

Detection pairing: All providers log security group / NSG / firewall rule changes in their audit trail (CloudTrail `AuthorizeSecurityGroupIngress`, Azure Activity Log `Microsoft.Network/networkSecurityGroups/securityRules/write`, GCP `firewalls.patch`). Alert on any rule that opens a port wider than `/24` to the internet.

Artifacts:
- CloudTrail: `AuthorizeSecurityGroupIngress` / `RevokeSecurityGroupIngress` events
- Azure Activity Log: `Microsoft.Network/networkSecurityGroups/securityRules/write`
- GCP Cloud Audit Logs: `v1.compute.firewalls.patch`

## 🔵 Blue Team view

### Preventive controls

- **AWS:** SCP to deny `ec2:AuthorizeSecurityGroupIngress` with `0.0.0.0/0` condition; AWS Config rule `restricted-ssh` and `restricted-common-ports`
- **Azure:** Azure Policy `Network security groups should not allow all inbound traffic from the internet`
- **GCP:** Organization Policy `compute.restrictProtocolForwarding`; custom constraint on firewall rules
- **OnPrem:** Configuration management (Ansible/Puppet) validation of iptables state drift

### Detection queries

```
# AWS CloudTrail — new 0.0.0.0/0 ingress rule
fields @timestamp, userIdentity.arn, requestParameters.groupId
| filter eventName = "AuthorizeSecurityGroupIngress"
| filter requestParameters.ipPermissions.cidrIp = "0.0.0.0/0"

# Azure Activity Log — NSG rule creation
AzureActivity
| where OperationNameValue contains "networkSecurityGroups/securityRules/write"
| where Properties contains "0.0.0.0/0"
| project TimeGenerated, Caller, ResourceId

# GCP Cloud Logging — firewall rule insert
resource.type="gce_firewall_rule"
protoPayload.methodName="v1.compute.firewalls.insert"
protoPayload.request.sourceRanges="0.0.0.0/0"
```

## Hands-on lab

1. Create a security group/NSG/firewall rule that allows SSH from `0.0.0.0/0`
2. Verify it works — `terraform state show` or CLI describe
3. Use the provider's audit tool to detect the open rule (Config, Policy, Org Policy)
4. Restrict SSH to your current IP only (`curl ifconfig.co` then use `/32`)
5. Re-run the audit to confirm the finding is resolved
6. Teardown

## Detection rules & checklists

```
# Cloud Custodian — detect open SSH
policies:
  - name: sg-open-ssh
    resource: security-group
    filters:
      - type: ingress
        Ports: [22]
        Cidr: { value: "0.0.0.0/0" }

# OPA — deny SG with 0.0.0.0/0 on management ports
deny[msg] {
  rule := input.sg_ingress_rules[_]
  rule.cidr == "0.0.0.0/0"
  rule.port == 22
  msg = sprintf("SG %s exposes SSH to internet", [input.sg_id])
}
```

```
# Checklist
- [ ] No SG/NSG/firewall rule has 0.0.0.0/0 on ports 22, 3389, 5432, 3306, 6379, 27017
- [ ] NACL default rule (rule 32767 in AWS) is deny-all
- [ ] SG egress default is restricted, not 0.0.0.0/0 all ports
- [ ] Config rule / Azure Policy / Org Policy detects drift automatically
```

## References

- [AWS Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html)
- [Azure NSG](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
- [GCP Firewall Rules](https://cloud.google.com/firewall/docs/firewalls)
- see ATT&CK Cloud matrix for Initial Access
