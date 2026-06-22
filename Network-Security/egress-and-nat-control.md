# 03 — Egress and NAT Control

> **Level:** Intermediate
> **Prereqs:** [Vpc Segmentation Design](vpc-segmentation-design.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** see ATT&CK Cloud matrix for Exfiltration, Command and Control
**Authorization scope:** Run only in your own sandbox account / lab VPC.

## What & why
Egress matters more than ingress in cloud compromise. Once an attacker has code execution inside your VPC, their next move is outbound — exfiltration, C2 beaconing, or calling attacker-controlled infrastructure. A strict default-deny egress posture with explicit allowlisting is the single most impactful control after proper IAM. Every cloud provides NAT Gateways for outbound-only connectivity and firewall primitives to restrict destination IPs/FQDNs.

## The OnPrem reality
Pre-cloud, egress went through one chokepoint: a forward proxy (Squid, Blue Coat) that authenticated users and allowlisted domains. No machine could reach the internet without passing through that proxy. Cloud breaks this model: every subnet can have its own route to the internet via NAT Gateway or IGW. You must deliberately architect egress control — it does not happen by default.

## Core concepts

### Egress primitives

| Primitive | AWS | Azure | GCP | OnPrem |
|-----------|-----|-------|-----|--------|
| NAT (outbound-only) | NAT Gateway / NAT Instance | NAT Gateway / Azure Firewall SNAT | Cloud NAT | NAT device / proxy |
| Egress firewall | Network Firewall / 3P NVA | Azure Firewall | Cloud NGFW / Firewall Policy | Forward proxy / NGFW |
| FQDN filtering | Network Firewall (Suricata) | Azure Firewall FQDN rules | Cloud NGFW FQDN objects | Proxy allowlist |
| Private service access | VPC Endpoints / PrivateLink | Private Endpoints / Service Endpoints | Private Google Access / PSC | Internal API gateway |

### Default-deny egress pattern

```
┌──────────────┐
│  Private     │──── NAT GW ────▶ Internet
│  Subnet      │──── VPC Endpoint ──▶ S3 / Blob / GCS (no internet)
│  10.0.2.0/24 │──── (deny everything else)
└──────────────┘
```

## AWS

3-tier egress: NAT Gateway provides outbound-only IPv4, VPC Endpoints keep service traffic off the internet, Network Firewall enforces allowlist policies.

```hcl
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
}

resource "aws_route" "private_egress" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.us-east-1.s3"
}

resource "aws_networkfirewall_rule_group" "egress_allow" {
  type    = "STATEFUL"
  capacity = 100
  name    = "egress-allowlist"

  rule_group {
    rules_source {
      stateful_rule {
        action = "PASS"
        header {
          destination      = "logs.us-east-1.amazonaws.com"
          destination_port = "443"
          protocol         = "TCP"
          direction        = "FORWARD"
          source           = "10.0.0.0/16"
          source_port      = "ANY"
        }
        rule_option {
          keyword = "sid:1"
        }
      }
    }
  }
}
```

CLI egress audit:

```
aws ec2 describe-route-tables \
  --filters Name=route.destination-cidr-block,Values=0.0.0.0/0 \
  --query 'RouteTables[].Routes[?GatewayId!=`local`]'
```

## Azure

Azure Firewall provides stateful egress filtering with FQDN allowlisting. Virtual Network NAT Gateway provides outbound SNAT.

```hcl
resource "azurerm_firewall" "egress" {
  name                = "egress-fw"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"

  ip_configuration {
    name                 = "fw-ipconfig"
    subnet_id            = azurerm_subnet.firewall.id
    public_ip_address_id = azurerm_public_ip.fw.id
  }
}

resource "azurerm_firewall_application_rule_collection" "egress_allow" {
  name                = "egress-allowlist"
  azure_firewall_name = azurerm_firewall.egress.name
  resource_group_name = azurerm_resource_group.rg.name
  priority            = 100
  action              = "Allow"

  rule {
    name = "allow-logging"
    source_addresses = ["10.0.0.0/16"]
    target_fqdns     = ["*.azure-monitor.com"]
    protocol {
      type = "Https"
      port = 443
    }
  }
}

resource "azurerm_route" "egress_via_fw" {
  name                = "egress-via-fw"
  resource_group_name = azurerm_resource_group.rg.name
  route_table_name    = azurerm_route_table.private.name
  address_prefix      = "0.0.0.0/0"
  next_hop_type       = "VirtualAppliance"
  next_hop_in_ip_address = azurerm_firewall.egress.ip_configuration[0].private_ip_address
}
```

CLI egress audit:

```
az network route-table route list --route-table-name private-rt -g mygroup \
  --query "[?addressPrefix=='0.0.0.0/0']"
```

## GCP

Cloud NAT provides outbound connectivity; VPC Firewall Rules with `destinationRanges` enforce egress filtering.

```hcl
resource "google_compute_router" "nat_router" {
  name    = "nat-router"
  network = google_compute_network.main.name
  region  = "us-central1"
}

resource "google_compute_router_nat" "main" {
  name   = "cloud-nat"
  router = google_compute_router.nat_router.name
  region = "us-central1"

  nat_ip_allocate_option = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

resource "google_compute_firewall" "egress_deny_default" {
  name      = "deny-all-egress"
  network   = google_compute_network.main.name
  direction = "EGRESS"
  priority  = 65534

  deny {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "egress_allow_logging" {
  name      = "allow-logging-egress"
  network   = google_compute_network.main.name
  direction = "EGRESS"
  priority  = 1000

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  destination_ranges = ["199.36.153.0/24"]
}
```

CLI egress audit:

```
gcloud compute firewall-rules list --filter="direction=EGRESS AND disabled!=True" --format=json
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Outbound NAT | NAT device / PAT | NAT Gateway / Instance | NAT Gateway / Azure FW | Cloud NAT |
| Egress filtering | Forward proxy / NGFW | Network Firewall / SG egress | Azure Firewall | VPC Firewall Rules |
| FQDN allowlist | Proxy PAC files | Network Firewall domain list | Azure FW FQDN rules | Cloud NGFW |
| Service egress w/o internet | DMZ to internal API | VPC Endpoints / PrivateLink | Private Endpoints | PSC / Private Google Access |
| Flow logs | NetFlow / IPFIX | VPC Flow Logs | NSG Flow Logs | VPC Flow Logs |

## 🔴 Red Team view

When egress is unrestricted, attackers exfiltrate data over any outbound channel. DNS tunneling and HTTPS requests to attacker-controlled domains are the most common vectors.

Contained example — simulating a data exfiltration over an allowed HTTPS channel:

```bash
python3 -c "
import http.server, socketserver
import urllib.parse

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/exfil':
            print(f'[exfil] received: {parsed.query}')
        self.send_response(200)
        self.end_headers()

with socketserver.TCPServer(('127.0.0.1', 8080), Handler) as httpd:
    print('Listening on localhost:8080')
    httpd.handle_request()
"
```

Detection pairing: Outbound connections to unknown hosts or on unusual ports are visible in VPC Flow Logs. Any connection to an IP outside the known allowlist constitutes an incident. See [dns-routing-and-exfil-channels.md](./dns-routing-and-exfil-channels.md) for DNS exfil detection.

Artifacts:
- VPC Flow Logs: `src_ip:any → dst_ip:443, TCP, ACCEPT` with previously unseen `dst_ip`
- DNS query logs: unusual query volume, long subdomains, TXT record lookups
- CloudTrail/Activity Log: no direct artifact (network-layer only)

## 🔵 Blue Team view

### Preventive controls

- [ ] Private subnets route `0.0.0.0/0` only through NAT Gateway / Azure Firewall / Cloud NAT
- [ ] SG egress rules / NSG outbound rules / VPC firewall rules restrict destination CIDRs
- [ ] VPC Endpoints / PrivateLink / Private Google Access used for service API calls
- [ ] AWS Network Firewall / Azure Firewall / Cloud NGFW enforces FQDN allowlisting
- [ ] No public IPs on instances in private subnets (break-glass exception requires ticket)

### Detection queries

```
# AWS CloudWatch Insights — detect connections to unknown IPs
fields @timestamp, srcAddr, dstAddr, dstPort, action
| filter action = "ACCEPT" and dstPort = 443
| filter dstAddr not in ["s3.amazonaws.com"]   # extend with known CIDRs
| stats count() by srcAddr, dstAddr, dstPort

# Azure Log Analytics — unusual outbound destinations
AzureDiagnostics
| where Category == "NetworkSecurityGroupFlowEvents"
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| extend DestIP = split(Flows_s, ",")
| summarize Count = count() by DestIP

# GCP Logging — egress to known-bad IP
resource.type="gce_subnetwork"
jsonPayload.connection.dest_ip != ""
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
```

### Policy enforcement

```
# Cloud Custodian — enforce egress restrictions on SGs
policies:
  - name: sg-restrict-egress
    resource: security-group
    filters:
      - type: egress
        Cidr: { value: "0.0.0.0/0" }

# OPA — require VPC endpoints for S3
deny[msg] {
  route := input.routes[_]
  route.destination == "0.0.0.0/0"
  not route.via_nat_gateway
  msg = sprintf("Subnet %s has unrestricted IGW egress", [route.subnet_id])
}
```

## Hands-on lab

See [`labs/egress-owner-lab.md`](./labs/egress-owner-lab.md) for a full Terraform-based lab building a 3-tier network with restricted egress.

Quick exercise:
1. Launch an instance in a private subnet with no NAT Gateway
2. `curl https://example.com` — fails (no egress)
3. Add a VPC Endpoint for S3 (or equivalent service endpoint)
4. `aws s3 ls` (or equivalent) — succeeds without internet
5. Teardown

## Detection rules & checklists

```
# Checklist
- [ ] All private subnets route 0.0.0.0/0 through NAT GW or not at all
- [ ] Egress SG/NSG/firewall rules use specific destination CIDRs, not 0.0.0.0/0
- [ ] VPC Endpoints / PrivateLink / PSC deployed for all managed services in use
- [ ] Flow logs enabled on all VPCs/VNets with 14+ day retention
- [ ] DNS query logging enabled (Route 53 Resolver, Azure DNS, Cloud DNS)
```

## References

- [AWS egress-only internet gateway](https://docs.aws.amazon.com/vpc/latest/userguide/egress-only-internet-gateway.html)
- [Azure Firewall FQDN filtering](https://learn.microsoft.com/en-us/azure/firewall/fqdn-filtering-network-rules)
- [GCP Cloud NAT](https://cloud.google.com/nat/docs/overview)
- see ATT&CK Cloud matrix for Exfiltration (TA0010)
