# 07 — DDoS and Edge Protection

> **Level:** Intermediate
> **Prereqs:** [Load Balancers & WAF](load-balancers-and-waf.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** see ATT&CK Cloud matrix for Impact
**Authorization scope:** Run only in your own sandbox account / lab VPC.

## What & why
Cloud providers absorb volumetric DDoS attacks at the edge using massive global anycast networks and scrubbing infrastructure. L3/4 attacks (SYN floods, UDP reflection) are mitigated automatically by most providers. L7 attacks (HTTP floods, Slowloris) require explicit WAF configuration — the provider won't protect your application layer automatically. Engineers must configure rate limiting, IP reputation rules, and autoscaling to survive L7 attacks.

## The OnPrem reality
Pre-cloud DDoS defense meant purchasing a scrubbing service (Prolexic, Arbor), provisioning GRE tunnels from your perimeter routers to scrubbing centers, and hoping your WAN link didn't saturate before traffic was redirected. A 10 Gbps SYN flood would saturate most enterprise data center links long before reaching any mitigation appliance. Cloud's fundamental advantage: providers have 100+ Tbps of edge capacity, so the flood never reaches your VPC's bandwidth limits.

### OnPrem scrubbing center topology

```
Internet ──▶ GRE tunnel ──▶ Scrubbing Center ──▶ (clean traffic) ──▶ Your DC
   │              (BGP announcement redirects traffic)
   └── (pre-mitigation: direct path, immediate saturation)
```

## Core concepts

### DDoS attack taxonomy

| Layer | Attack type | Protocol/Vector | Cloud mitigates automatically? |
|-------|------------|-----------------|-------------------------------|
| L3 | SYN flood, ICMP flood | TCP SYN, ICMP echo | Yes (AWS Shield Standard, Azure, GCP) |
| L3 | UDP reflection (DNS, NTP, SSDP, Memcached) | UDP with spoofed source | Yes (ingress filtering, anycast distribution) |
| L4 | Connection exhaustion | TCP connection table full | Partially — need WAF for L7 |
| L7 | HTTP GET/POST flood | Valid HTTP requests, high volume | No — must configure WAF rate-limit rules |
| L7 | Slowloris / Slow read | Partial HTTP requests, keep-alive | No — must configure WAF request timeout |
| L7 | API abuse | Valid API calls, stolen tokens | No — must configure API Gateway rate limits |

### Edge protection architecture

```
┌──────────┐    ┌────────────┐    ┌───────────┐    ┌──────────┐
│ Internet │───▶│ CDN / Edge │───▶│   WAF     │───▶│  Origin  │
│          │    │ (anycast)  │    │ (L7 rules)│    │ (ALB/LB) │
└──────────┘    └────────────┘    └───────────┘    └──────────┘
     │               │                  │                │
  attack     absorbed at edge     rate-limited      autoscaling
  traffic    (Tbps capacity)      / ACL blocked     handles surge
```

## Cross-cloud comparison

| Concern | AWS | Azure | GCP | OnPrem |
|---------|-----|-------|-----|--------|
| L3/4 auto-mitigation | Shield Standard (included) | Azure DDoS Protection Basic (included) | Cloud Armor Managed Protection (included) | Scrubbing center (3P) |
| L7 DDoS protection | Shield Advanced (paid) | Azure DDoS Protection Standard (paid) | Cloud Armor Adaptive Protection (paid) | WAF + rate-limit (manual) |
| CDN / edge caching | CloudFront | Azure Front Door / CDN | Cloud CDN | 3P CDN (Akamai, Cloudflare) |
| Rate limiting | AWS WAF rate-based rule | Azure WAF custom rate-limit | Cloud Armor rate-limit rules | HAProxy / Nginx limit_req |
| IP reputation | AWS WAF IP set (manual) | Azure WAF IP match (manual) | Cloud Armor named IP lists | Firewall reputation feed |
| DDoS cost protection | Shield Advanced covers scaling cost | DDoS Protection Standard covers scaling | Cloud Armor — included scaling | No — you pay for burst |

## AWS

Shield Standard is always-on and included. Shield Advanced adds cost protection, DDoS Response Team (DRT) access, and L7 visibility.

```hcl
resource "aws_wafv2_web_acl" "ddos" {
  name  = "ddos-rules"
  scope = "CLOUDFRONT"

  default_action {
    block {}
  }

  rule {
    name     = "rate-limit-per-ip"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitPerIP"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "DDoSProtection"
    sampled_requests_enabled   = true
  }
}

resource "aws_shield_protection" "alb" {
  name         = "alb-protection"
  resource_arn = aws_lb.app.arn
}

resource "aws_shield_protection" "cloudfront" {
  name         = "cloudfront-protection"
  resource_arn = aws_cloudfront_distribution.app.arn
}
```

CLI audit:

```
aws shield list-protections
aws shield describe-drt-access
aws cloudfront list-distributions --query 'DistributionList.Items[*].DomainName'
```

## Azure

Azure DDoS Protection Standard covers virtual network public IPs. WAF policies add L7 rate limiting.

```hcl
resource "azurerm_network_ddos_protection_plan" "main" {
  name                = "ddos-plan"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
}

resource "azurerm_virtual_network" "main" {
  name                = "main-vnet"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  address_space       = ["10.0.0.0/16"]

  ddos_protection_plan {
    id     = azurerm_network_ddos_protection_plan.main.id
    enable = true
  }
}

resource "azurerm_web_application_firewall_policy" "ddos" {
  name                = "ddos-waf-policy"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location

  policy_settings {
    enabled                     = true
    mode                        = "Prevention"
    request_body_check          = true
    file_upload_limit_in_mb     = 100
    max_request_body_size_in_kb = 128
  }

  custom_rules {
    name      = "RateLimit"
    priority  = 1
    rule_type = "RateLimitRule"
    rate_limit_duration_in_min = 1
    rate_limit_threshold       = 1000

    action = "Block"

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator           = "IPMatch"
      negation_condition = false
      match_values       = ["*"]
    }
  }
}
```

CLI audit:

```
az network ddos-protection list -o table
```

> (as of June 2026, Azure DDoS Protection Standard is priced per protected public IP per month with a monthly flat rate per VNet; check the current Azure DDoS Protection pricing page for exact numbers.)

## GCP

Cloud Armor Managed Protection provides always-on L3/4 defense. Adaptive Protection (paid add-on) applies ML-based L7 detection. Rate limiting is configured in Cloud Armor security policies.

```hcl
resource "google_compute_security_policy" "ddos" {
  name        = "ddos-protection"
  type        = "CLOUD_ARMOR"
  description = "DDoS protection policy"

  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
    }
  }

  rule {
    action   = "deny(429)"
    priority = 1000

    match {
      expr {
        expression = "request.path.matches('/api/') && origin.ip in ['198.51.100.0/24']"
      }
    }

    description = "block known scanner IP range"
  }

  rule {
    action   = "rate_based_ban"
    priority = 2000

    match {
      expr {
        expression = "true"
      }
    }

    rate_limit_options {
      ban_duration_sec = 300
      rate_limit_threshold {
        count        = 500
        interval_sec = 60
      }
      conform_action = "allow"
      exceed_action  = "deny(429)"
    }

    description = "global rate limit"
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}
```

CLI audit:

```
gcloud compute security-policies list --format=json
gcloud compute security-policies describe ddos-protection
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| L3/4 auto-mitigation | — (buy scrubbing) | Shield Standard | DDoS Protection Basic | Managed Protection |
| L7 rate-limit | HAProxy / Nginx config | WAF rate-based rule | WAF RateLimitRule | Cloud Armor rate-limit |
| CDN | 3P (Akamai, Cloudflare) | CloudFront | Front Door / CDN | Cloud CDN |
| DRT / support | — (retainer) | Shield Advanced DRT | Azure DDoS Rapid Response | — (support tier) |
| Cost protection | — (you pay burst) | Shield Advanced | DDoS Protection Standard | — (included scaling) |

## 🔴 Red Team view

L7 DDoS attacks (HTTP floods, Slowloris) exploit the fact that most cloud deployments lack L7 rate limiting. An attacker discovers this by sending sustained traffic and observing whether the application degrades or costs spike.

**HTTP flood:** Thousands of valid-looking HTTP GET/POST requests from a botnet or cloud IPs. Without rate limiting, the backend autoscales up, increasing the victim's cloud bill dramatically ("economic DDoS"). WAFs don't block these by default because the requests are syntactically valid.

**Slowloris:** Opens many connections and sends partial HTTP headers slowly, holding sockets open on the server until the connection pool is exhausted. Cloud LBs have connection timeouts by default, but a large enough botnet can still exhaust backend resources.

Contained detection test — not an actual attack, but validation your WAF rules trigger:

```bash
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/ &
done
wait
```

If all 50 requests return 200, your local endpoint has no rate limiting — but this is expected for a local test. In production, the WAF should trigger at your configured threshold.

Detection pairing: WAF metrics (CloudWatch/Log Analytics/Cloud Monitoring) spike dramatically during attacks. Set alerts on `BlockedRequests` exceeding baseline and on `AllowedRequests` growth rate anomaly. See [load-balancers-and-waf.md](./load-balancers-and-waf.md) for WAF configuration.

Artifacts:
- AWS: CloudWatch `AWS/WAFV2 → BlockedRequests` metric surge; Shield Advanced events
- Azure: Azure Monitor `WebApplicationFirewall → Blocked Hits`; DDoS Protection telemetry
- GCP: Cloud Monitoring `security_policy/blocked_requests_count`

## 🔵 Blue Team view

### Detection of volumetric events

```
# AWS CloudWatch Insights — request volume anomaly per IP
fields @timestamp, httpRequest.clientIp
| stats count() as reqs by bin(1m), httpRequest.clientIp
| filter reqs > 500
| sort reqs desc

# Azure Log Analytics — volumetric detection
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| summarize RequestCount = count() by bin(TimeGenerated, 1m), clientIp_s
| where RequestCount > 500

# GCP Cloud Logging — high request rate per IP
resource.type="http_load_balancer"
jsonPayload.statusDetails!=""
severity>=WARNING
```

### Autoscale-as-defense math

The defensive value of autoscaling during an attack:

- **Without autoscaling:** Backend crashes at max capacity → outage
- **With naive autoscaling:** Backend scales to absorb attack → your AWS/Azure/GCP bill spikes; attacker achieves "economic denial of wallet"
- **With WAF rate-limit + autoscaling:** WAF blocks >90% of attack traffic; autoscaling handles legitimate surge + residual attack traffic

Configure:
1. **WAF rate-limit** at 200-500 requests/second per IP (tune to your baseline)
2. **ALB/LB/Azure LB/Cloud LB** connection draining at 60 seconds
3. **Autoscaling** with max instance cap (e.g., 5x baseline) to prevent bill shock
4. **CloudFront/Front Door/Cloud CDN** with caching enabled — edge absorbs static content requests

### Response steps during L7 attack

1. Verify attack via WAF/LB metrics dashboard — confirm surge in blocked + allowed traffic
2. Update WAF IP block list with attacker source IPs (identified from logs)
3. If attack is geographic, add geo-restriction rule (CloudFront geo-block, WAF custom rule)
4. If attack persists, engage provider DDoS support (Shield Advanced DRT / Azure DDoS Rapid Response)
5. Post-incident: add attack signatures to WAF custom rules

## Hands-on lab

1. Deploy an ALB/App Gateway/Cloud LB with a simple web backend
2. Attach WAF with a rate-limit rule (100 requests/5 min per IP)
3. From your local machine, send 150 requests rapidly: `for i in $(seq 1 150); do curl -s http://<LB-DNS>/ & done; wait`
4. Check the responses — some should return 403 (rate limited)
5. Check WAF logs to confirm the rate-limit rule was triggered
6. Increase rate limit to 1000 and verify all requests succeed
7. Teardown

## Detection rules & checklists

```
# Cloud Custodian — verify Shield Advanced protection on ALBs
policies:
  - name: shield-advanced-check
    resource: elb
    filters:
      - type: shield-enabled
        key: ProtectionStatus
        value: "DISABLED"

# OPA — require WAF rate-limit rule
deny[msg] {
  waf := input.waf_policies[_]
  not waf.rate_limit_rule
  msg = sprintf("WAF %s missing rate-limit rule", [waf.name])
}
```

```
# Checklist
- [ ] Shield Standard / DDoS Protection Basic / Managed Protection enabled on all public resources
- [ ] WAF rate-limit configured (typically 200-2000 req/s per IP, depending on app)
- [ ] CloudFront / Front Door / Cloud CDN in front of origin for static content caching
- [ ] Autoscaling configured with max cap (cost control)
- [ ] DDoS-specific alert on BlockedRequests > threshold
```

## References

- [AWS Shield](https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html)
- [Azure DDoS Protection](https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview)
- [GCP Cloud Armor Adaptive Protection](https://cloud.google.com/armor/docs/cloud-armor-adaptive-protection-overview)
- see ATT&CK Cloud matrix for Impact — Endpoint Denial of Service (T1499)
