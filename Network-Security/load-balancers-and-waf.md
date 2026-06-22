# 05 — Load Balancers and WAF

> **Level:** Intermediate–Advanced
> **Prereqs:** [SG NACL NSG Firewall Rules](sg-nacl-nsg-firewall-rules.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** see ATT&CK Cloud matrix for Initial Access, Defense Evasion
**Authorization scope:** Run only in your own sandbox account / lab VPC.

## What & why
L7 load balancers and Web Application Firewalls (WAFs) form the primary L3/4/7 attack surface shield. They terminate TLS, inspect HTTP payloads against rule sets, and absorb application-layer attacks before they reach backend instances. In cloud, these are managed services — the provider runs the OWASP Core Rule Set (CRS) and handles scaling, but you must configure detection thresholds and custom rules.

## The OnPrem reality
Pre-cloud, F5 BIG-IP or HAProxy handled load balancing; ModSecurity (Apache/NGINX module) provided WAF capabilities. Engineers maintained CRS rule versions manually, tuned false-positives per application, and managed hardware capacity planning. Cloud managed WAF removes the hardware burden but requires the same tuning rigor.

### OnPrem ModSecurity WAF example

```
# ModSecurity rule — block SQL injection via query string
SecRule ARGS "@rx (?i)(select|union|insert|drop|delete).*from" \
  "id:1001,phase:2,deny,status:403,log,msg:'SQL injection attempt detected'"
```

## Core concepts

### LB and WAF placement

```
┌──────────┐    ┌──────────┐    ┌─────────────┐
│  Client  │───▶│   WAF    │───▶│   LB (L7)   │───▶ Backend pool
│          │    │ (inspect) │    │ (route/tls) │
└──────────┘    └──────────┘    └─────────────┘
```

### Cross-cloud comparison

| Concern | AWS | Azure | GCP | OnPrem |
|---------|-----|-------|-----|--------|
| L7 LB | ALB / NLB (L4) | App Gateway / Front Door (L7), Azure LB (L4) | Cloud Load Balancing (global L7) | HAProxy / F5 BIG-IP |
| WAF product | AWS WAF (on ALB/CloudFront/API GW) | Azure WAF (on App GW / Front Door) | Cloud Armor (on LB) | ModSecurity |
| Rule set | AWS Managed Rules (CRS 3.x) | OWASP CRS 3.x managed rules | OWASP CRS 3.x pre-configured rules | Custom CRS |
| Rate limiting | AWS WAF rate-based rule | Azure WAF custom rate-limit rule | Cloud Armor rate-limit rule | HAProxy stick-table |
| Custom rules | Conditions + action | Custom rules + managed | Security policy + pre-configured | ModSecurity rule file |
| Bot protection | AWS WAF Bot Control | Azure WAF Bot Protection (add-on) | reCAPTCHA Enterprise + Cloud Armor | 3P (Akamai, Cloudflare) |

## AWS

AWS WAF sits on ALB, CloudFront, API Gateway, or AppSync.

```hcl
resource "aws_wafv2_web_acl" "main" {
  name        = "app-waf"
  scope       = "REGIONAL"
  description = "OWASP CRS + custom rate-limit"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit"
    priority = 2

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
      metric_name                = "RateLimit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "AppWAF"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.app.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}
```

CLI check WAF association:

```
aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[*].{Name:Name,ARN:ARN}'
aws wafv2 list-resources-for-web-acl --web-acl-arn ARN --resource-type APPLICATION_LOAD_BALANCER
```

## Azure

Azure WAF runs on Application Gateway (regional) or Front Door (global).

```hcl
resource "azurerm_web_application_firewall_policy" "app" {
  name                = "waf-policy"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location

  policy_settings {
    enabled = true
    mode    = "Prevention"
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
  }

  custom_rules {
    name      = "ContentTypeBlock"
    priority  = 1
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RequestHeaders.Content-Type"
      }
      operator           = "Contains"
      negation_condition = false
      match_values       = ["application/x-www-form-urlencoded"]
    }
  }
}

resource "azurerm_application_gateway" "app" {
  name                = "app-gateway"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location

  firewall_policy_id = azurerm_web_application_firewall_policy.app.id

  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2
  }
}
```

CLI check WAF:

```
az network application-gateway waf-policy list -g mygroup -o table
```

## GCP

Cloud Armor attaches to global external HTTP(S) load balancers.

```hcl
resource "google_compute_security_policy" "app" {
  name = "app-waf-policy"

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default allow"
  }

  rule {
    action   = "deny(403)"
    priority = 1000
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 2})"
      }
    }
    description = "SQL injection detection"
  }

  rule {
    action   = "throttle"
    priority = 2000

    match {
      expr {
        expression = "request.path.matches('/api/login')"
      }
    }

    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
    }
  }
}
```

CLI check Cloud Armor:

```
gcloud compute security-policies describe app-waf-policy --format=json
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| L7 LB | HAProxy / F5 | ALB | App Gateway / Front Door | Cloud LB (global) |
| WAF | ModSecurity | AWS WAF (regional/global) | Azure WAF (regional/global) | Cloud Armor |
| Rule engine | ModSecurity SecRules | AWS Managed / custom rules | OWASP CRS managed / custom | Pre-configured / custom CEL |
| TLS termination | On LB hardware | On ALB/NLB | On App GW / Front Door | On LB |
| Bot mitigation | 3P (Cloudflare, Akamai) | AWS WAF Bot Control | Azure WAF Bot Protection | reCAPTCHA Enterprise |

## 🔴 Red Team view

WAF bypasses leverage the fact that WAF engines parse HTTP differently than backend applications. Common techniques: header splitting, encoding tricks, parameter pollution.

Contained example — testing a WAF with header variation (against `localhost`):

```bash
echo -e "GET /?id=1' OR '1'='1 HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/html;\r\n\tcharset=utf-8\r\n\r\n" | nc localhost 8080
```

The extra tab before `charset` can cause some WAF engines to skip inspection of the request body or treat the Content-Type differently than the backend.

Additional bypass vectors:
- **HTTP Parameter Pollution (HPP):** `?id=1&id=1' OR 1=1--`
- **Unicode normalization:** `%uff0e` for `.`, `%u2215` for `/`
- **Method override:** `X-HTTP-Method-Override: PUT` to bypass GET-only rules
- **Chunked encoding:** Splitting payloads across chunks

Detection pairing: WAF logs record blocked requests with rule IDs. A spike in `BLOCK` actions on the SQL injection rule group can indicate a probing phase. Configure CloudWatch/Log Analytics/Cloud Monitoring alerts on WAF `BlockedRequests` metric crossing threshold.

Artifacts:
- AWS WAF: CloudWatch metric `BlockedRequests` per WebACL + `AWSWAFLogs` in S3
- Azure WAF: `AzureDiagnostics` log category `ApplicationGatewayFirewallLog`
- GCP Cloud Armor: Cloud Logging `resource.type="http_load_balancer"` with `jsonPayload.enforcedSecurityPolicy`

## 🔵 Blue Team view

### WAF visibility and detection

```
# AWS CloudWatch Insights — top blocked request patterns
fields @timestamp, httpRequest.uri, terminatingRuleId, httpRequest.clientIp
| filter action = "BLOCK"
| stats count() by terminatingRuleMatchDetails, httpRequest.uri
| sort count desc

# Azure Log Analytics — WAF blocked requests
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where action_s == "Blocked"
| project TimeGenerated, clientIp_s, requestUri_s, ruleId_s, message_s
| summarize Count = count() by ruleId_s, requestUri_s

# GCP Cloud Logging — Cloud Armor denies
resource.type="http_load_balancer"
jsonPayload.enforcedSecurityPolicy.name!=""
jsonPayload.statusDetails="denied_by_security_policy"
```

### Response steps for WAF bypass detection

1. Enable WAF logging with full request body capture (cost-sensitive — sample or rotate)
2. Create a dashboard tracking `BlockedRequests` vs `AllowedRequests` ratio
3. Set alert when `AllowedRequests` spike correlates with `BlockedRequests` — might indicate bypass
4. Tune managed rule exclusions per app, not globally
5. Run regular penetration tests against staging WAF instance with the same rule set

## Hands-on lab

1. Deploy a simple ALB/App Gateway/Cloud LB with default backend (e.g., a "Hello World" HTTP server)
2. Attach WAF with OWASP CRS managed rules in `Prevention` mode
3. Send a benign request: `curl http://<LB-DNS>/`
4. Send a SQLi probe: `curl "http://<LB-DNS>/?id=1' OR '1'='1"`
5. Verify WAF triggered — 403 response
6. Check WAF logs for the blocked request and rule ID
7. Add a custom rule blocking requests with `Content-Type: application/x-www-form-urlencoded` (simulate a custom check)
8. Test the custom rule
9. Teardown: delete WAF policy + LB (free tier eligible)

## Detection rules & checklists

```
# AWS WAF logging checklist
- [ ] WAF logs enabled → S3 or CloudWatch Logs
- [ ] CloudWatch metric alarm on BlockedRequests < expected baseline
- [ ] WAF rules in "Count" mode for new apps before "Block"
```

```
# CLI audit — list WAFs not in prevention mode
aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[?DefaultAction.Allow!=null].Name'
az network application-gateway waf-policy list -g mygroup --query "[?policySettings.mode!=`Prevention`].name"
gcloud compute security-policies list --format="table(name, rules[0].action)"
```

## References

- [AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)
- [Azure WAF](https://learn.microsoft.com/en-us/azure/web-application-firewall/overview)
- [GCP Cloud Armor](https://cloud.google.com/armor/docs/cloud-armor-overview)
- [OWASP ModSecurity CRS](https://coreruleset.org/)
- see ATT&CK Cloud matrix for Initial Access — T1190 (Exploit Public-Facing Application)
