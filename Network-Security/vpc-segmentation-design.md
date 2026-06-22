# 01 — VPC Segmentation Design

> **Level:** Fundamental
> **Prereqs:** [Shared Responsibility](../Fundamentals/shared-responsibility.md), [The Four Example Lenses](../Fundamentals/the-four-example-lenses.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** see ATT&CK Cloud matrix for Discovery, Lateral Movement, Collection
**Authorization scope:** Run only in your own sandbox account / lab VPC.

## What & why
Segmentation is blast-radius isolation: confine a breach to one tier or one app. In cloud, VPC/VNet/VPC networks are the segmentation primitive — every subnet, route table, NACL, and security group is a policy decision. Poor segmentation means one leaked web-tier host hands an attacker every database and metadata endpoint on the network.

## The OnPrem reality
Pre-cloud segmentation relied on L2 broadcast domains separated by VLANs, with inter-VLAN traffic forced through a firewall zone. Every new application meant a new VLAN ID, a new subnet on the core switch, and a firewall rule. Lateral movement from one VLAN to another required crossing the firewall, which logged the attempt. Cloud removes L2 entirely (per-VPC L3 isolation) but introduces a much larger and more dynamic IP space — often a single `/16` with no internal firewalling by default.

## Core concepts

### Tier separation model

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Public     │───▶│   Private    │───▶│  Database    │
│  (web/ALB)   │    │  (app/API)   │    │  (RDS/NoSQL) │
│ 10.0.1.0/24  │    │ 10.0.2.0/24  │    │ 10.0.3.0/24  │
└─────────────┘    └─────────────┘    └─────────────┘
        │                 │                  │
   Internet GW        NAT GW            No egress
   inbound: web      outbound: API       no IGW/NAT
```

### CIDR planning principles

| Principle | Rule |
|-----------|------|
| Over-allocate | Use /16 per VPC/VNet, /20 per region if multi-region |
| Leave gaps | Never put subnets back-to-back; leave room for peering |
| Tag everything | `env=prod`, `tier=app`, `app=checkout` — feeds flow log queries |
| RFC 1918 only | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 unless you own the prefix |

### Naming across providers

| Concept | AWS | Azure | GCP | OnPrem |
|---------|-----|-------|-----|--------|
| Isolated network | VPC | VNet | VPC network | VLAN + firewall zone |
| Subnet | Subnet (AZ-scoped) | Subnet (VNet-scoped) | Subnet (region-scoped) | Subnet (switch-scoped) |
| Region selector | Region | Region | Region | Datacenter |
| Availability Zone | AZ | Availability Zone | Zone | Rack/row |
| Route table | Route Table | Route Table | Route (on subnet) | Core route / VRF |
| Stateful firewall | Security Group | Network Security Group | Firewall Rule | iptables / stateful FW |
| Stateless filter | Network ACL | — (use ASG/NSG) | Firewall policy (stateless) | Router ACL |
| Internet egress | Internet Gateway | Internet Gateway default | Internet Gateway via route | Default route to FW |

## AWS

VPC is a region-scoped, software-defined network. Subnets are AZ-scoped. Route tables control subnet-to-subnet and subnet-to-gateway traffic.

```hcl
# AWS Terraform: three-tier VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "db" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}
```

Gotcha: AWS default VPC comes with `0.0.0.0/0 → IGW` route on all subnets. Delete it and build your own.

## Azure

VNet is region-scoped; subnets are VNet-scoped (not AZ-scoped). All subnets within a VNet can route to each other by default.

```hcl
# Azure Terraform: three-tier VNet
resource "azurerm_virtual_network" "main" {
  name                = "main-vnet"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "public" {
  name                 = "public-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "private" {
  name                 = "private-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_subnet" "db" {
  name                 = "db-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.3.0/24"]
  delegation {
    # Azure Database for PostgreSQL delegation
  }
}
```

Gotcha: Azure subnets reserve the first 3 and last 1 IPs (`x.x.x.0` through `x.x.x.3`, and broadcast), so a `/24` has 251 usable addresses, not 256.

## GCP

VPC networks are global (not region-scoped). Subnets are region-scoped. Firewall rules apply at the VPC level, not subnet level.

```hcl
# GCP Terraform: three-tier VPC
resource "google_compute_network" "main" {
  name                    = "main-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "public" {
  name          = "public-subnet"
  network       = google_compute_network.main.id
  region        = "us-central1"
  ip_cidr_range = "10.0.1.0/24"
}

resource "google_compute_subnetwork" "private" {
  name          = "private-subnet"
  network       = google_compute_network.main.id
  region        = "us-central1"
  ip_cidr_range = "10.0.2.0/24"

  # No external IPs by default
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "db" {
  name          = "db-subnet"
  network       = google_compute_network.main.id
  region        = "us-central1"
  ip_cidr_range = "10.0.3.0/24"
}
```

Gotcha: GCP `default` network is auto-mode with a subnet in every region. Delete it. Also, GCP firewall rules are implicitly allowed between instances in the same VPC — you must add explicit deny rules.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Tier isolation | VLANs + FW rules | Subnets + NACL/SG | Subnets + NSG | Subnets + fw rules |
| Internet edge | Perimeter firewall + DMZ | IGW + public subnet | Azure Firewall / default SNAT | Cloud NAT + fw rules |
| Intra-VPC routing | Core switch L3 | Implicit (route table) | Implicit (system routes) | Implicit + custom routes |
| IP space planning | IPAM tool / spreadsheet | VPC CIDR + subnets | VNet address space + subnets | Network + subnet CIDRs |
| DNS | Internal DNS servers | Route 53 Resolver (+ .2) | Azure DNS (168.63.129.16) | Cloud DNS / metadata server |

## 🔴 Red Team view

A single foothold in a flat VPC (one `/16`, no NACL segmentation) lets an attacker scan the entire CIDR for metadata endpoints, database DNS names, and open management ports.

Contained example — local nmap against `localhost` simulating a flat-VPC scan:

```
nmap -p 80,443,3306,5432,6379,27017,3389,22 localhost --open
```

Detection pairing: Any intra-VPC scan targeting ports 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB) from a web-tier IP should never occur in a properly segmented network. See [sg-nacl-nsg-firewall-rules.md](./sg-nacl-nsg-firewall-rules.md) for flow log queries that catch this.

Artifacts left:
- AWS: VPC Flow Logs show a single source IP hitting many destination IPs/ports rapidly
- Azure: NSG Flow Logs record `A` (allowed) or `D` (denied) per 5-tuple
- GCP: VPC Flow Logs record `src_ip`, `dest_ip`, `dest_port` tuples
- OnPrem: NetFlow / sFlow records from switch/router

## 🔵 Blue Team view

### Prevention checklist

- [ ] No VPC/VNet uses the provider default (`172.31.0.0/16` in AWS, auto-mode in GCP)
- [ ] Every tier has its own subnet or set of subnets
- [ ] Route tables differ per tier: public subnets only have `0.0.0.0/0 → IGW`
- [ ] Private subnets route `0.0.0.0/0` through NAT GW/NAT instance only if egress is approved
- [ ] DB subnets have no `0.0.0.0/0` route at all
- [ ] VPC Flow Logs / NSG Flow Logs / GCP VPC Flow Logs enabled to S3/Storage/Cloud Storage
- [ ] Intra-tier traffic is restricted: web subnet cannot reach DB subnet directly

### Detection queries

```
# AWS CloudWatch Logs Insights — detect port scans
fields @timestamp, srcAddr, dstAddr, dstPort
| filter action = "ACCEPT"
| stats count(*) as hits by srcAddr, dstAddr
| filter hits > 50
| sort hits desc

# Azure Log Analytics — intra-subnet lateral movement
AzureDiagnostics
| where Category == "NetworkSecurityGroupFlowEvents"
| summarize Count = count() by SrcIP = PrimaryIPv4Address_s, DstPort_d
| where Count > 100

# GCP Logging — port scan detection
resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.src_ip=SRC_IP
jsonPayload.connection.dest_port!=80
jsonPayload.connection.dest_port!=443
```

## Hands-on lab

1. Create a two-tier VPC: public (web) + private (app) using any provider's free tier
2. Deploy t2.micro / B1s / e2-micro instances in each tier
3. From the public instance, `nmap` scan the private tier's subnet
4. Verify Flow Logs captured the scan
5. Add a NACL/NSG/firewall rule denying all traffic from public to private tier
6. Retry the scan — confirm it's blocked
7. Teardown: `terraform destroy` or delete resources via console

## Detection rules & checklists

```
# Cloud Custodian — detect VPCs with only one route table for all subnets
policies:
  - name: vpc-single-route-table
    resource: vpc
    filters:
      - type: flow-logs
        enabled: false

# OPA/Rego — require subnet tier tags
deny[msg] {
  subnet := input.subnets[_]
  not subnet.tags.tier
  msg = sprintf("Subnet %s missing tier tag", [subnet.id])
}
```

```
# CLI audit one-liners
aws ec2 describe-vpcs --query 'Vpcs[?CidrBlock==`172.31.0.0/16`]'
az network vnet list --query '[?addressSpace.addressPrefixes[0]==`10.0.0.0/16`]'
gcloud compute networks describe default --format='value(subnetworks)'
```

## References

- [AWS VPC docs](https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html)
- [Azure VNet docs](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview)
- [GCP VPC docs](https://cloud.google.com/vpc/docs/vpc)
- see ATT&CK Cloud matrix for Discovery (T1526)
