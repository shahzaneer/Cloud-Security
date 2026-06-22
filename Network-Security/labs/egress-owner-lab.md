# Lab 01 — Egress Owner Lab: Build a 3-Tier Network with Restricted Egress

> **Level:** Intermediate
> **Prereqs:** 01-01, 01-03
> **Clouds:** AWS · Azure · GCP (choose one for lab execution)
**Authorization scope:** Run only in your own sandbox account. This lab creates resources that may incur cost. Estimate ~$0.50–$2.00 for ~1 hour usage on free-tier-eligible resources.

## Objective

Build a 3-tier application network (public web → private app → isolated database) with egress restricted to only your cloud provider's API endpoints. Verify that outbound requests to unapproved destinations are blocked, flow logs capture the denied traffic, and modifying the allowlist restores connectivity.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Public Web  │────▶│ Private App  │────▶│   Database   │
│  10.0.1.0/24 │     │  10.0.2.0/24│     │  10.0.3.0/24 │
│  IGW egress  │     │  NAT egress  │     │  NO egress   │
│  open:443    │     │  allowlist   │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
```

## Prerequisites

- Terraform ≥ 1.0 installed
- Cloud CLI authenticated (`aws configure`, `az login`, `gcloud auth login`)
- A sandbox account/subscription/project with admin access
- Python 3 (for the test HTTP server)

## Pick your cloud

Choose one section below to run the lab. All three achieve the same outcome with cloud-specific primitives.

---

## Option A: AWS

### Step A1: Apply Terraform

```hcl
provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "db" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.lab.id
}

resource "aws_eip" "nat" {
  vpc = true
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table" "db" {
  vpc_id = aws_vpc.lab.id
}

resource "aws_route_table_association" "db" {
  subnet_id      = aws_subnet.db.id
  route_table_id = aws_route_table.db.id
}

resource "aws_flow_log" "vpc" {
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  log_destination_type = "cloud-watch-logs"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.lab.id
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/vpc/flow-logs/lab"
  retention_in_days = 7
}

resource "aws_security_group" "app" {
  name   = "private-app"
  vpc_id = aws_vpc.lab.id
}

resource "aws_vpc_security_group_egress_rule" "allow_aws_api" {
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"

  tags = {
    purpose = "allow-deny-test"
  }
}

resource "aws_security_group" "web" {
  name   = "public-web"
  vpc_id = aws_vpc.lab.id
}

resource "aws_vpc_security_group_ingress_rule" "web_https" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_instance" "app" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.app.id]

  tags = { Name = "lab-app-server" }
}
```

Save as `lab.tf` and apply:

```bash
terraform init
terraform apply -auto-approve
```

### Step A2: Test unrestricted egress

SSH to the web instance, then SSH to the private app instance (or use SSM Session Manager if configured).

From the app instance:

```bash
curl -s -o /dev/null -w "%{http_code}" https://aws.amazon.com
```

Should return `200` — egress is open to the internet via NAT Gateway.

### Step A3: Restrict egress to AWS APIs only

Update the SG egress rule to restrict to AWS API CIDRs:

```hcl
resource "aws_vpc_security_group_egress_rule" "allow_aws_api_restricted" {
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = "99.84.0.0/16"   # CloudFront API subset, for testing
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "deny_all" {
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  # Security groups are allow-only; removing 0.0.0.0/0 effectively denies
}
```

Actually, since SGs are allow-only stateful, remove the broad rule and add only specific CIDRs:

```bash
# Remove the open egress rule (via console or CLI)
aws ec2 revoke-security-group-egress \
  --group-id sg-11111111111111111 \
  --ip-permissions '[{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'

# Add specific CIDR
aws ec2 authorize-security-group-egress \
  --group-id sg-11111111111111111 \
  --ip-permissions '[{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"203.0.113.0/24"}]}]'
```

### Step A4: Verify blocked egress

```bash
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://example.com
```

Should hang/timeout — the request is blocked because `example.com` resolves to an IP outside the allowed CIDR.

### Step A5: Verify flow logs capture blocked traffic

```bash
# Query CloudWatch Insights
aws logs start-query \
  --log-group-name /vpc/flow-logs/lab \
  --start-time $(date -v-1H +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, srcAddr, dstAddr, dstPort, action | filter action = "REJECT" | limit 10'

# Wait, then get results
aws logs get-query-results --query-id QUERY_ID
```

Expected output: REJECT rows showing the app instance IP attempting to reach the IP of `example.com`.

### Step A6: Update allowlist and retry

Add the CloudFront IP range back:

```bash
aws ec2 authorize-security-group-egress \
  --group-id sg-11111111111111111 \
  --ip-permissions '[{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"3.5.140.0/22"}]}]'
```

```bash
curl -s https://aws.amazon.com | head -c 100
```

Should now return HTML — connectivity restored to the allowed CIDR.

### Step A7: Teardown

```bash
terraform destroy -auto-approve
```

---

## Option B: Azure

### Step B1: Apply Terraform

```hcl
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "lab" {
  name     = "lab-egress-rg"
  location = "eastus"
}

resource "azurerm_virtual_network" "lab" {
  name                = "lab-vnet"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "public" {
  name                 = "public-subnet"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "private" {
  name                 = "private-subnet"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_subnet" "db" {
  name                 = "db-subnet"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.0.3.0/24"]
}

resource "azurerm_public_ip" "nat" {
  name                = "nat-pip"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_nat_gateway" "main" {
  name                = "lab-nat"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  sku_name            = "Standard"
}

resource "azurerm_nat_gateway_public_ip_association" "main" {
  nat_gateway_id       = azurerm_nat_gateway.main.id
  public_ip_address_id = azurerm_public_ip.nat.id
}

resource "azurerm_subnet_nat_gateway_association" "private" {
  subnet_id      = azurerm_subnet.private.id
  nat_gateway_id = azurerm_nat_gateway.main.id
}

resource "azurerm_network_security_group" "private" {
  name                = "private-nsg"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
}

resource "azurerm_network_security_rule" "allow_azure_api" {
  name                        = "AllowAzureAPI"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "AzureCloud.eastus"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.private.name
}

resource "azurerm_network_security_rule" "deny_internet_out" {
  name                        = "DenyInternetOutbound"
  priority                    = 4096
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.private.name
}

resource "azurerm_subnet_network_security_group_association" "private" {
  subnet_id                 = azurerm_subnet.private.id
  network_security_group_id = azurerm_network_security_group.private.id
}

resource "azurerm_network_watcher_flow_log" "lab" {
  name                 = "lab-flowlog"
  network_watcher_name = "NetworkWatcher_eastus"
  resource_group_name  = "NetworkWatcherRG"

  target_resource_id = azurerm_network_security_group.private.id
  storage_account_id  = azurerm_storage_account.flowlog.id

  enabled = true
}

resource "azurerm_storage_account" "flowlog" {
  name                     = "labflowlogs001"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_linux_virtual_machine" "app" {
  name                = "lab-app-vm"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  size                = "Standard_B1s"
  admin_username      = "azureuser"

  network_interface_ids = [azurerm_network_interface.app.id]

  admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}
```

```bash
terraform init
terraform apply -auto-approve
```

### Step B2: Test egress

SSH into the private VM (via public jump or Azure Bastion):

```bash
curl -s -o /dev/null -w "%{http_code}" https://management.azure.com
```

Should return `200` — the `AzureCloud.eastus` service tag allows Azure API access.

### Step B3: Test blocked egress

```bash
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://example.com
```

Should timeout — `example.com` is not in `AzureCloud` service tag.

### Step B4: Check flow logs

In Azure Portal → Network Watcher → NSG Flow Logs → select the private NSG → view logs. Alternatively:

```
# Azure Log Analytics
AzureDiagnostics
| where Category == "NetworkSecurityGroupFlowEvents"
| where FlowStatus_s == "D"
| project TimeGenerated, SrcIP = PrimaryIPv4Address_s, DestIP = Destinations_s, DestPort, Rule
| take 20
```

### Step B5: Teardown

```bash
terraform destroy -auto-approve
```

---

## Option C: GCP

### Step C1: Apply Terraform

```hcl
provider "google" {
  project = var.project_id
  region  = "us-central1"
}

resource "google_compute_network" "lab" {
  name                    = "lab-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "public" {
  name          = "public-subnet"
  network       = google_compute_network.lab.id
  region        = "us-central1"
  ip_cidr_range = "10.0.1.0/24"
}

resource "google_compute_subnetwork" "private" {
  name                     = "private-subnet"
  network                  = google_compute_network.lab.id
  region                   = "us-central1"
  ip_cidr_range            = "10.0.2.0/24"
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "db" {
  name          = "db-subnet"
  network       = google_compute_network.lab.id
  region        = "us-central1"
  ip_cidr_range = "10.0.3.0/24"
}

resource "google_compute_router" "nat_router" {
  name    = "nat-router"
  network = google_compute_network.lab.id
  region  = "us-central1"
}

resource "google_compute_router_nat" "main" {
  name   = "cloud-nat"
  router = google_compute_router.nat_router.name
  region = "us-central1"
  nat_ip_allocate_option = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.private.id
    source_ip_ranges_to_nat = ["PRIMARY_IP_RANGE"]
  }
}

resource "google_compute_firewall" "allow_private_egress_cloud_api" {
  name      = "allow-cloud-api-egress"
  network   = google_compute_network.lab.id
  direction = "EGRESS"
  priority  = 1000

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  destination_ranges = ["199.36.153.0/24"]   # GCP API IP range (partial)

  target_tags = ["app-server"]
}

resource "google_compute_firewall" "deny_all_egress" {
  name      = "deny-all-egress"
  network   = google_compute_network.lab.id
  direction = "EGRESS"
  priority  = 65534

  deny {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["app-server"]
}

resource "google_compute_instance" "app" {
  name         = "lab-app-vm"
  machine_type = "e2-micro"
  zone         = "us-central1-a"
  tags         = ["app-server"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.lab.id
    subnetwork = google_compute_subnetwork.private.id
  }
}
```

```bash
terraform init
terraform apply -auto-approve
```

### Step C2: Test egress

SSH to the private instance (via IAP or public jump):

```bash
curl -s -o /dev/null -w "%{http_code}" https://storage.googleapis.com
```

If the destination IP resolves within the allowed CIDR, should return `200`.

### Step C3: Test blocked egress

```bash
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://example.com
```

Should timeout — egress is denied.

### Step C4: Check flow logs

GCP VPC Flow Logs are enabled per subnet:

```
gcloud logging read 'resource.type="gce_subnetwork" AND jsonPayload.connection.dest_ip!=""' \
  --project=PROJECT_ID --limit=20
```

### Step C5: Teardown

```bash
terraform destroy -auto-approve
```

---

## Expected outputs

| Step | Expected result |
|------|----------------|
| Initial curl to allowed API | HTTP 200 |
| curl to blocked destination | Timeout or connection refused |
| Flow log query | REJECT/DENY entries showing app IP → blocked IP |
| Updated allowlist curl | HTTP 200 restored |

## Lessons learned

1. Egress restriction is additive — you start with default-allow and must configure deny/block rules
2. Cloud egress filtering is IP/CIDR/FQDN-based — service tags help but aren't universal
3. Flow logs are your primary evidence that egress is actually blocked vs. just misconfigured
4. `0.0.0.0/0` in an SG/NSG/firewall egress rule means "the entire internet" — every private subnet should replace this with a specific allowlist
5. Egress policy is only as good as your CIDR/FQDN list — stay current with provider IP ranges

## References

- [AWS VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [Azure NSG Flow Logs](https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview)
- [GCP VPC Flow Logs](https://cloud.google.com/vpc/docs/flow-logs)
- [AWS IP ranges](https://ip-ranges.amazonaws.com/ip-ranges.json)
- [Azure service tags](https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview)
- [GCP IP ranges](https://www.gstatic.com/ipranges/cloud.json)
