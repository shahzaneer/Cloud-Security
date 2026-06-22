# 08 — Peering, Transit, and Private Endpoints

> **Level:** Intermediate–Advanced
> **Prereqs:** [Vpc Segmentation Design](vpc-segmentation-design.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** see ATT&CK Cloud matrix for Lateral Movement, Discovery
**Authorization scope:** Run only in your own sandbox account / lab VPC.

## What & why
Connecting VPCs/VNets privately — through peering, transit gateways, or private endpoints — extends your network boundary and audit surface. Every peering is a potential lateral movement path if misconfigured. Managed services (S3, Blob, GCS, RDS) should be accessed via private endpoints that keep traffic on the provider backbone, not through the public internet. Over-permissive peering and missing endpoint usage are two of the most common cloud network audit findings.

## The OnPrem reality
Pre-cloud, inter-network connectivity meant dark fiber, MPLS circuits, or L2 stretched VLANs between data centers. Each link was a physical contract with a telecom provider — expensive, slow to provision, but also inherently audited (circuit ID, port mapping, monthly bill). Cloud peering is an API call that takes seconds and creates an invisible data path that is easy to forget but hard to audit at scale.

### OnPrem inter-site connectivity

```
DC-1 ── MPLS (10.1.0.0/16) ── DC-2 (10.2.0.0/16)
         │
         ├── Leased line / dark fiber
         └── IPsec VPN over internet (backup)
```

## Core concepts

### Connectivity patterns

| Pattern | Description | Risk level |
|---------|-------------|------------|
| VPC Peering | 1:1 direct connection between two VPCs | Medium — non-transitive, but multiplies quickly |
| Transit Gateway | Hub-spoke: central TGW connects many VPCs | High — one TGW, one route table misconfig exposes all |
| Private Endpoint | Interface to managed service over provider backbone | Low — targeted, single service, no peering needed |
| VPN / Direct Connect | On-prem to cloud private link | High — extends corporate network into cloud |
| Cross-account peering | Peering between different AWS accounts / Azure tenants / GCP projects | High — shared responsibility, hard to audit |

### Hub-spoke transit architecture

```
                ┌──────────────┐
                │   Transit     │
                │   Gateway     │
                │   / Hub VNet  │
                └───┬──┬──┬─────┘
          ┌────────┘  │  └────────┐
    ┌─────▼────┐ ┌────▼────┐ ┌────▼────┐
    │  Prod    │ │  Staging│ │  Shared │
    │  VPC     │ │  VPC    │ │  Svcs   │
    │10.1.0.0  │ │10.2.0.0 │ │10.99.0.0│
    └──────────┘ └─────────┘ └─────────┘
```

## Cross-cloud comparison

| Concern | AWS | Azure | GCP | OnPrem |
|---------|-----|-------|-----|--------|
| 1:1 peering | VPC Peering | VNet Peering | VPC Network Peering | Site-to-site VPN |
| Hub-spoke transit | Transit Gateway (TGW) | Virtual WAN (vWAN) / Hub VNet | Network Connectivity Center (NCC) | MPLS / SD-WAN |
| Private service access | VPC Endpoint (Gateway/Interface) | Private Endpoint / Service Endpoint | Private Service Connect (PSC) / Private Google Access | Internal API gateway |
| Cross-account | TGW + RAM / Peering | VNet Peering across tenants | Shared VPC / VPC Peering across projects | BGP peering |
| Transit routing | TGW route tables | Hub VNet + Azure Firewall | NCC spokes + VPC routes | BGP route redistribution |

## AWS

Transit Gateway provides hub-spoke with centralized route tables. VPC Endpoints provide private access to S3, DynamoDB, and 200+ AWS services.

```hcl
resource "aws_ec2_transit_gateway" "main" {
  description = "hub-tgw"
}

resource "aws_ec2_transit_gateway_vpc_attachment" "prod" {
  subnet_ids         = aws_subnet.tgw[*].id
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.prod.id
}

resource "aws_ec2_transit_gateway_vpc_attachment" "staging" {
  subnet_ids         = aws_subnet.tgw[*].id
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.staging.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.prod.id
  service_name = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = "*"
      Condition = {
        StringNotEquals = {
          "aws:SourceVpc" = aws_vpc.prod.id
        }
      }
    }]
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_peered" {
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = "10.99.0.0/16"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
```

Gotcha: VPC peering is non-transitive. A → B peering and B → C peering does NOT give A → C connectivity. TGW is required for transitive routing.

CLI audit — list all peerings:

```
aws ec2 describe-vpc-peering-connections \
  --filter Name=status-code,Values=active \
  --query 'VpcPeeringConnections[*].{Accepter:AccepterVpcInfo.VpcId,Requester:RequesterVpcInfo.VpcId}'
```

## Azure

VNet peering connects VNets; Virtual WAN / hub VNet with Azure Firewall provides transit routing. Private Endpoints connect to PaaS services.

```hcl
resource "azurerm_virtual_network_peering" "hub_to_prod" {
  name                      = "hub-to-prod"
  resource_group_name       = azurerm_resource_group.rg.name
  virtual_network_name      = azurerm_virtual_network.hub.name
  remote_virtual_network_id = azurerm_virtual_network.prod.id
  allow_forwarded_traffic   = true
  allow_gateway_transit     = true
}

resource "azurerm_private_endpoint" "blob" {
  name                = "blob-endpoint"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  subnet_id           = azurerm_subnet.private.id

  private_service_connection {
    name                           = "blob-connection"
    private_connection_resource_id = azurerm_storage_account.app.id
    is_manual_connection           = false
    subresource_names              = ["blob"]
  }
}
```

CLI audit — list all VNet peerings:

```
az network vnet peering list --resource-group mygroup --vnet-name hub-vnet -o table
```

> (as of June 2026, Azure Global VNet Peering (cross-region) incurs data transfer charges that differ from intra-region peering; check current Azure VNet Peering pricing.)

## GCP

VPC Network Peering connects VPC networks. Network Connectivity Center (NCC) provides hub-spoke transit. Private Service Connect (PSC) enables private service access.

```hcl
resource "google_compute_network_peering" "hub_to_prod" {
  name         = "hub-to-prod"
  network      = google_compute_network.hub.id
  peer_network = google_compute_network.prod.id

  export_custom_routes = true
  import_custom_routes = true
}

resource "google_compute_global_address" "psc" {
  name         = "psc-address"
  purpose      = "PRIVATE_SERVICE_CONNECT"
  address_type = "INTERNAL"
  network      = google_compute_network.prod.id
}

resource "google_compute_forwarding_rule" "psc" {
  name                  = "psc-endpoint"
  region                = "us-central1"
  network               = google_compute_network.prod.id
  ip_address            = google_compute_global_address.psc.id
  target                = "all-apis"
  load_balancing_scheme = ""
}
```

CLI audit — list all VPC peerings:

```
gcloud compute networks peerings list --format=json
```

Gotcha for GCP: VPC peering is also non-transitive. Unlike AWS, GCP Shared VPC allows multiple projects to share a single VPC — this is often a better pattern than peering for hub-spoke designs.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Inter-network | MPLS / dark fiber / IPsec VPN | VPC Peering / TGW | VNet Peering / vWAN | VPC Peering / NCC |
| Hub-spoke | MPLS hub router | Transit Gateway | Hub VNet + vWAN | NCC hub |
| Private service | Internal API gateway / VIP | VPC Endpoint / PrivateLink | Private Endpoint | PSC / Private Google Access |
| Cross-account/org | BGP peering across AS | TGW + RAM | Cross-tenant peering | Shared VPC / cross-project peering |
| Transit routing | BGP route redistribution | TGW route tables | Hub VNet UDRs / Azure FW | NCC + VPC routes |

## 🔴 Red Team view

Over-permissive peering defaults create lateral movement paths between environments that are supposed to be isolated.

**Scenario:** A staging VPC is peered with the production VPC "for data migration" — but the peering was configured with `allow_ingress_from_peered_vpc` SG rules that open all ports. An attacker who compromises a staging instance can now reach production database servers without crossing any monitoring boundary.

Contained example — audit script that identifies permissive peerings:

```bash
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values=10.0.0.0/8 \
  --query 'SecurityGroups[*].{GroupId:GroupId,IpPermissions:IpPermissions[?contains(IpRanges[*].CidrIp, `10.0.0.0/8`)]}'
```

This reveals any security group that allows inbound traffic from the entire RFC 1918 `10.0.0.0/8` range — which typically includes peered VPCs. An attacker in any peered VPC can reach this resource.

Detection pairing: Review all peering connections and their associated route tables. Verify that:
1. Every peering has a documented business justification
2. SG/NSG/firewall rules on the *accepter* side restrict source to specific subnets, not entire CIDRs
3. Flow logs between peered networks are actively monitored

Artifacts:
- AWS CloudTrail: `CreateVpcPeeringConnection`, `AcceptVpcPeeringConnection`
- Azure Activity Log: `Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write`
- GCP: `compute.networks.addPeering`

## 🔵 Blue Team view

### Peering audit & detection

```
# AWS CloudTrail — new peering creation
fields @timestamp, userIdentity.arn, requestParameters.vpcId, requestParameters.peerVpcId
| filter eventName in ["CreateVpcPeeringConnection", "AcceptVpcPeeringConnection"]
| sort @timestamp desc

# Azure Activity Log — new VNet peering
AzureActivity
| where OperationNameValue contains "virtualNetworkPeerings/write"
| project TimeGenerated, Caller, ResourceId

# GCP Cloud Logging — new VPC peering
resource.type="gce_network"
protoPayload.methodName="compute.networks.addPeering"
```

### Auditing peering map (scheduled runbook)

```bash
#!/bin/bash
echo "=== AWS Peerings ==="
aws ec2 describe-vpc-peering-connections \
  --query 'VpcPeeringConnections[*].{Requester:RequesterVpcInfo.CidrBlock,Accepter:AccepterVpcInfo.CidrBlock,Status:Status.Code}' \
  --output table

echo "=== Azure Peerings ==="
az network vnet peering list --vnet-name hub-vnet -g mygroup --query '[].{Name:name,Remote:remoteVirtualNetwork.id,State:peeringState}' -o table

echo "=== GCP Peerings ==="
gcloud compute networks peerings list --format="table(name, network, peerNetwork, state)"
```

### Preventive controls

- **SCP/Azure Policy/GCP Org Policy:** Deny VPC peering creation except by approved roles/networking team
- **AWS TGW route table:** Use dedicated TGW route tables per environment; never use `0.0.0.0/0` route to all attachments
- **Private endpoints for services:** Require VPC Endpoint / Private Endpoint / PSC for S3, Blob, GCS access — deny public access with bucket policies / storage firewall
- **Flow log alerts:** Alert on any traffic crossing production ↔ non-production peering

## Hands-on lab

1. Create two VPCs: `app-a` (10.1.0.0/16) and `app-b` (10.2.0.0/16)
2. Deploy an instance in each, same security group with no cross-CIDR ingress
3. `ping` from app-a to app-b — fails (no connectivity)
4. Create VPC peering between them (accept both sides for AWS/GCP)
5. Add route table entries: `10.2.0.0/16 → peering` in app-a, vice versa in app-b
6. Update SG to allow ICMP from `10.2.0.0/16`
7. `ping` from app-a to app-b — succeeds
8. Audit: find the active peering via CLI
9. Teardown: delete peering first, then VPCs

## Detection rules & checklists

```
# Cloud Custodian — detect VPC Endpoint not present for S3
policies:
  - name: require-s3-endpoint
    resource: vpc
    filters:
      - type: vpc-endpoint
        key: ServiceName
        value: "com.amazonaws.*.s3"
        op: regex
      - type: value
        key: "length(vpc-endpoints)"
        value: 0
        op: eq

# OPA — require peering justification tag
deny[msg] {
  peering := input.peerings[_]
  not peering.tags.justification
  msg = sprintf("Peering %s missing justification tag", [peering.id])
}
```

```
# Checklist
- [ ] All VPC peerings have documented business justification (tag or CMDB)
- [ ] Private endpoints enabled for all managed services in use (S3, RDS, Blob, GCS)
- [ ] SGs allow cross-VPC traffic only from specific subnets, not 0.0.0.0/0 or 10.0.0.0/8
- [ ] Transit Gateway / vWAN / NCC route tables are environment-segregated
- [ ] Flow logs enabled on all peered VPCs
- [ ] Peering creation alert active (CloudTrail / Activity Log / Cloud Audit Logs)
```

## References

- [AWS Transit Gateway](https://docs.aws.amazon.com/vpc/latest/tgw/what-is-transit-gateway.html)
- [Azure Virtual WAN](https://learn.microsoft.com/en-us/azure/virtual-wan/virtual-wan-about)
- [GCP Network Connectivity Center](https://cloud.google.com/network-connectivity/docs/network-connectivity-center/concepts/overview)
- [AWS PrivateLink](https://docs.aws.amazon.com/vpc/latest/privatelink/what-is-privatelink.html)
- see ATT&CK Cloud matrix for Lateral Movement
