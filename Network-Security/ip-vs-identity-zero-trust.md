# 04 — IP vs Identity: Zero Trust Networking

> **Level:** Intermediate
> **Prereqs:** [Authn Authz Accountability](../Fundamentals/authn-authz-accountability.md), [Vpc Segmentation Design](vpc-segmentation-design.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** see ATT&CK Cloud matrix for Initial Access, Persistence, Defense Evasion
**Authorization scope:** Run only in your own sandbox account / lab VPC.

## What & why
Zero trust replaces "trust the network" with "verify every request." Identity and device posture become the perimeter; IP addresses become insufficient signals for access decisions. In cloud, this means moving from IP allowlists in security groups to identity-aware proxies (IAP), device certificates, and conditional access policies. Every major cloud now offers a Zero Trust Network Access (ZTNA) product.

## The OnPrem reality
Pre-cloud "trust" was simple: if your laptop was on the corporate VLAN or connected via VPN, you were inside the perimeter and implicitly trusted. Active Directory membership plus an IP on the right subnet granted access to internal apps and databases. Attackers who stole a VPN credential or found an open RDP port inherited that full implicit trust.

## Core concepts

### Perimeter model vs Zero Trust

| Dimension | Perimeter model | Zero Trust |
|-----------|----------------|------------|
| Perimeter | Corporate network / VPN | None — every request authenticated |
| Access decision | Source IP + subnet | Identity + device posture + context |
| Protocol | Any (implicit trust) | HTTPS + mTLS + short-lived tokens |
| Revocation | Remove from AD / disable VPN | Revoke token / session |
| Audit | NetFlow + firewall logs | Per-request identity logs |
| Lateral movement | Easy after foothold | Hard — every hop re-authenticated |

### ZTNA architectural components

1. **Identity provider (IdP):** Authenticates user/device, issues tokens
2. **Policy engine:** Evaluates whether this identity + device + context should access this resource
3. **Enforcement point/proxy:** Sits in front of every resource, validates tokens, denies if insufficient
4. **Device posture:** OS version, patch level, disk encryption, corporate enrollment

## AWS

AWS Verified Access (ZTNA for corporate apps) and IAM conditions for `aws:SourceIp` replacement.

```hcl
resource "aws_verifiedaccess_instance" "main" {
  description = "corp-zta"
}

resource "aws_verifiedaccess_trust_provider" "okta" {
  description        = "okta-idp"
  policy_reference_name = "okta"
  trust_provider_type = "user"

  oidc_options {
    client_secret = var.okta_client_secret
    issuer        = "https://example.okta.com"
    # > (as of June 2026, AWS Verified Access is a GA feature; check current AWS pricing for per-endpoint and per-GB charges)
  }
}

resource "aws_verifiedaccess_group" "app" {
  verifiedaccess_instance_id = aws_verifiedaccess_instance.main.id
}

resource "aws_verifiedaccess_endpoint" "app_https" {
  verified_access_group_id = aws_verifiedaccess_group.app.id
  endpoint_type            = "network-interface"
  domain_certificate_arn   = aws_acm_certificate.app.arn
  endpoint_domain_prefix   = "myapp"
  security_group_ids       = [aws_security_group.verified.id]

  network_interface_options {
    network_interface_id = aws_network_interface.app.id
    port                 = 443
    protocol             = "https"
  }
}
```

Identity-based SG alternative — reference another SG rather than an IP:

```hcl
resource "aws_security_group_rule" "allow_from_jenkins_sg" {
  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.jenkins.id
  security_group_id        = aws_security_group.app.id
}
```

## Azure

Entra Private Access (preview) and Entra Global Secure Access provide ZTNA. Conditional Access policies evaluate identity + device.

```json
{
  "displayName": "require-compliant-device",
  "state": "enabled",
  "conditions": {
    "applications": {
      "includeApplications": ["all"]
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["compliantDevice", "domainJoinedDevice"]
  }
}
```

App Gateway + Entra ID for identity-aware access:

```hcl
resource "azurerm_application_gateway" "app" {
  name                = "zta-appgateway"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location

  frontend_port {
    name = "https"
    port = 443
  }

  backend_http_settings {
    name                  = "app-backend"
    cookie_based_affinity = "Disabled"
    port                  = 443
    protocol              = "Https"
    request_timeout       = 30
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }
}
```

> (as of June 2026, Microsoft Entra Private Access is GA as part of the Microsoft Entra Suite; check current Entra licensing and pricing for tier requirements.)

## GCP

BeyondCorp Enterprise / Identity-Aware Proxy (IAP) is the canonical ZTNA offering.

```hcl
resource "google_iap_client" "app" {
  display_name = "corp-app"
  brand        = "projects/${var.project_id}/brands/${var.project_number}"
}

resource "google_iap_web_iam_binding" "allow_group" {
  project = var.project_id
  role    = "roles/iap.httpsResourceAccessor"

  members = [
    "group:engineering@example.com",
  ]
}

resource "google_compute_backend_service" "app" {
  name    = "app-backend"
  project = var.project_id

  iap {
    oauth2_client_id     = google_iap_client.app.client_id
    oauth2_client_secret = google_iap_client.app.secret
  }
}
```

GCP CLI for IAP-secured SSH (no public IP needed):

```
gcloud compute ssh instance-name --tunnel-through-iap --zone us-central1-a
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| ZTNA product | 3P (Zscaler, Cloudflare) | Verified Access | Entra Private/Global Access | BeyondCorp / IAP |
| Identity proxy | Reverse proxy + IdP | Verified Access endpoint | App Gateway + Entra ID | IAP |
| Device posture | MDM / NAC | — (via IdP) | Conditional Access + Intune | Endpoint Verification |
| IP→Identity migration | Remove IP allowlists | SG source SG / Verified Access | NSG → App Gateway with Entra | Firewall → IAP |
| Token enforcement | OAuth2 proxy | Verified Access | Entra ID tokens | IAP OAuth2 |

## 🔴 Red Team view

IP allowlists are brittle. Two classic abuse scenarios:

**Scenario 1 — Stale IP persist.** An employee's home static IP `203.0.113.5/32` is allowlisted in a security group for SSH access. The employee leaves the company, but the SG rule is never removed. The employee's ISP recycles the IP to a new customer months later — that random person can now reach port 22.

**Scenario 2 — Shared NAT egress.** A cloud-hosted CI/CD pipeline (GitHub Actions, GitLab CI) has a static outbound IP range. That range is allowlisted in production security groups. Any other GitHub Actions user sharing the same IP range can now reach the production backend.

Contained example — audit stale IP allowlist entries:

```bash
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values=203.0.113.5/32 \
  --query 'SecurityGroups[*].{GroupId:GroupId,Description:Description}' \
  --output table
```

Detection pairing: Every SG/NSG/firewall rule with a `/32` should be tracked in an asset inventory with a documented owner and expiration date. See [sg-nacl-nsg-firewall-rules.md](./sg-nacl-nsg-firewall-rules.md) for drift detection patterns.

Artifacts:
- CloudTrail: `AuthorizeSecurityGroupIngress` with a `/32` CIDR
- Azure Activity Log: NSG rule creation with `/32` source
- GCP: firewall rule insert with single-IP `sourceRanges`

## 🔵 Blue Team view

### Migration: IP allowlist → Identity

Step-by-step replacement strategy:

1. **Inventory** all IP-based rules across SG/NSG/firewall
2. **Classify** each: is this a corporate egress IP, a partner IP, a home IP?
3. **Replace corporate IPs** with identity: deploy IAP/Verified Access/App Gateway + Entra ID
4. **Replace service-to-service** with VPC Endpoints / PrivateLink / PSC (private IP, not public IP allowlist)
5. **Remove** the IP-based rule
6. **Monitor** for breakage; add identity-based access first, then remove IP

### Detection queries

```
# AWS CloudTrail — new /32 SG rule
fields @timestamp, userIdentity.arn, requestParameters.groupId
| filter eventName = "AuthorizeSecurityGroupIngress"
| filter ispresent(requestParameters.ipPermissions.items[0].ipRanges.items[0].cidrIp)
| filter requestParameters.ipPermissions.items[0].ipRanges.items[0].cidrIp like /\/32$/

# Azure — NSG rule with /32 source
AzureActivity
| where OperationNameValue contains "securityRules/write"
| where Properties contains "/32"
| project TimeGenerated, Caller, ResourceId

# GCP — firewall rule with single IP
resource.type="gce_firewall_rule"
protoPayload.methodName:"firewalls"
protoPayload.request.sourceRanges =~ "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/32$"
```

### ZTNA readiness checklist

- [ ] All admin/SSH access goes through an identity-aware proxy, not raw TCP
- [ ] No `/32` IP rules without a documented owner + annual review
- [ ] CI/CD pipeline outbound IPs are NOT in production allowlists (use OIDC + short-lived credentials)
- [ ] SGs reference other SGs (AWS) or service tags (Azure), not CIDRs, for internal traffic
- [ ] Device posture is evaluated before granting access (conditional access, endpoint verification)

## Hands-on lab

1. Deploy a simple web app on an instance with a public IP and SG allowing `0.0.0.0/0:443`
2. Set up IAP (GCP free tier) or App Gateway with Entra ID (Azure) in front
3. Remove the public IP from the instance — service now reachable only through identity proxy
4. Test: `curl` to the proxy URL without token → 403; with token → 200
5. Teardown

## Detection rules & checklists

```
# OPA — require identity-based access for SSH
deny[msg] {
  rule := input.sg_ingress_rules[_]
  rule.port == 22
  not rule.cidr
  msg = "SSH access must use identity-aware proxy, not IP allowlist"
}
```

## References

- [AWS Verified Access](https://docs.aws.amazon.com/verified-access/latest/ug/what-is-verified-access.html)
- [Azure Global Secure Access](https://learn.microsoft.com/en-us/entra/global-secure-access/overview-what-is-global-secure-access)
- [GCP IAP](https://cloud.google.com/iap/docs/concepts-overview)
- [NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- see ATT&CK Cloud matrix for Initial Access
