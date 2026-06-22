# 10 — Admin Takeover via Identity Provider

> **Level:** Advanced
> **Prereqs:** [Federation SSO & External Providers](federation-sso-and-external-providers.md) (Federation, SSO & External Providers)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Persistence, Privilege Escalation
> **Authorization scope:** Identity attacks only in your own sandbox accounts / sanctioned targets.

## What & why

The cloud admin role is not really in the cloud — it sits in the identity provider and DNS. If an attacker controls the email domain that your cloud tenant trusts, they can reclaim tenant admin access without knowing a single password. Domain verification is the cloud's root-of-trust, and abandoned/expired domains are the skeleton key.

## The OnPrem reality

DNS hijacking for email: if an attacker hijacks DNS for `example.com`, they can redirect MX records, receive password-reset emails for domain admins, and take over the AD domain controller's remote access. ADFS token-signing certificate theft achieved the same result — mint valid SAML assertions without any user password. The cloud equivalent is domain verification reuse: the attacker proves ownership of a DNS domain that was previously verified against the cloud tenant, and the cloud trusts the proof as "original admin."

## Cross-cloud domain verification comparison

| Provider | Domain verification method | Risk of stale domain | Tenant recovery path | Email routing dependency |
|---|---|---|---|---|
| AWS | `TXT` record in DNS at `_amazonses.example.com` format | If domain expires, attacker re-registers and adds TXT record | Root user email = domain admin; if domain lost, open support case | Root user email (password reset) |
| Azure / Entra ID | `TXT` record `MS=msXXXXXXXX` in DNS | (as of June 2026, Microsoft has substantially addressed the historical unverified domain takeover; domain re-verification in a different tenant requires additional validation. However, stale verified domains from deleted tenants remain a risk if not properly cleaned up.) | Global Admin can remove domain; if the ONLY admin domain is lost, call Microsoft support | Entra ID password reset (email) |
| GCP Cloud Identity | `TXT` record `google-site-verification=...` | If domain expires, attacker can re-verify the domain in their own Cloud Identity tenant | Super Admin via recovery email; support ticket if all admins lost | Recovery email for Super Admin |
| OnPrem | DNS MX record / SPF record control | DNS hijack → email intercept → password reset | Physical access to DC / DSRM password | Email reset for DA accounts |

## AWS

AWS root user email is the ultimate identity. If the domain hosting that email is lost, the attacker gains password-reset capability.

**Domain verification — AWS SES identity (analogous to email domain control):**

```bash
# Verify domain ownership (SES)
aws ses verify-domain-identity --domain example.com
# AWS returns a TXT record to add to DNS

# Check verification status
aws ses get-identity-verification-attributes --identities example.com

# If the domain expires and an attacker re-registers it, they add the TXT record
# and the domain becomes verified in THEIR AWS account — but not in the original.
# The original root user is at risk if the email domain is the same.
```

**Root user email domain risk (conceptual):**

The AWS root user is `admin@example.com`. If `example.com` expires and an attacker re-registers it, they create `admin@example.com` as a catch-all mailbox. They then go to `aws.amazon.com/console/forgot-password`, enter `admin@example.com`, receive the reset link, and change the root password.

**Mitigation — use a non-email-based root alias:**

```bash
# Root user email should be a dedicated, never-expires domain
# example: aws-root-111111111111@corp-owned-domain.example
# Include the AWS account ID itself in the email for uniqueness
```

## Azure / Entra ID

Azure's domain verification is the most sensitive because Entra ID is the IdP for Azure itself. A verified domain in Entra ID means the tenant "owns" it, and users with that domain suffix are implicitly trusted.

**Situation — unverified domain takeover:**

> (as of June 2026, Microsoft has substantially mitigated the historical AAD "unverified domain takeover" vulnerability. Entra ID now requires additional validation before accepting domain verification in a new tenant, and recently-removed domains have a cooldown period. However, domains verified in deleted tenants that were never explicitly removed still pose a residual risk. The distinction between "managed" and "federated" domains remains relevant — federated domains can be taken over via the federation metadata URL if the original IdP is no longer controlled.)

**Check domain verification status:**

```bash
# List verified domains
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/domains" \
  --query "value[?isVerified == true].{id:id, isDefault:isDefault}" -o table

# Check for unverified domains (risk)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/domains" \
  --query "value[?isVerified == false].id" -o table
```

**Conceptual attack — expired domain re-registration:**

1. `example.net` is verified in `example-tenant.onmicrosoft.com`.
2. `example.net` domain registration expires. Attacker registers it.
3. Attacker configures email for `admin@example.net`.
4. Attacker goes to `login.microsoftonline.com`, enters `admin@example.net`, requests password reset.
5. If the tenant has self-service password reset enabled and allows email-based reset, the attacker receives the reset link and gains `admin@example.net` access.
6. If `admin@example.net` is a Global Admin (or can be escalated), the tenant is compromised.

**Defense — domain takeover protection:**

```bash
# Entra ID — domain verification check
# Azure Portal: Entra ID → Custom domain names → check all verified domains

# Transfer prohibited notification setup
# Registrars offer "Domain Lock" / "TransferProhibited"
# Ensure all verified domains have registrar lock + auto-renew + multi-year registration
```

## GCP

GCP Cloud Identity domain verification works similarly. A domain is verified once, and the verification token is a static TXT record.

**Domain verification check:**

```bash
# List domains in Cloud Identity
gcloud identity domains list --customer <customer-id>

# Verify domain status
gcloud identity domains get-verification --domain example.com
```

**GCP domain takeover risk — deleted/expired domain re-claim:**

If an attacker registers a domain previously verified in a Cloud Identity tenant, they add the verification TXT record. The domain is now verified in the *existing* tenant (not the attacker's). But the attacker also controls email at that domain, enabling password resets for Cloud Identity users.

**GCP Super Admin recovery:**

The Cloud Identity Super Admin is linked to a recovery email. If the recovery email's domain is also controlled by the attacker (because they own the DNS), they initiate recovery and take over the Super Admin account.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Domain verification method | DNS TXT/SPF + AD domain join | `TXT` record (SES) or email for root user | `TXT` record `MS=msXXXXXXXX` | `TXT` record `google-site-verification` |
| Admin recovery path | Physical DC access + DSRM password | Root user email → forgot password | Global Admin password reset | Super Admin recovery email |
| Attacker entry point | Expired domain + catch-all email | Expired domain + catch-all email | Unverified domain + SSPR | Expired domain + email recovery |
| Registration protection | Registrar lock + auto-renew | Registrar lock + auto-renew | Registrar lock + auto-renew | Registrar lock + auto-renew |
| Detection signal | SPF/DMARC monitoring + DNS change alerts | CloudTrail `PasswordRecoveryRequested` + DNS zone changes | Entra ID audit log `Reset password` + domain TXT record change | Cloud Audit Log `ResetSuperAdminPassword` + DNS changes |
| Hardening | Pin recovery email to separate, locked domain | Use dedicated non-email alias for root | SSPR requires MFA not just email | Recovery email on separate, ultra-locked domain |

## 🔴 Red Team view

**Tenant takeover with zero stolen passwords (contained narrative, `example.net` only):**

The attacker monitors domain expiration databases (or simply `whois`) for domains used in cloud tenant verification. They find `example.net` approaching expiry. The domain is verified in `example-tenant.onmicrosoft.com` and is the default domain for user `admin@example.net`.

Attack flow:
1. **Domain registration:** `example.net` expires. Legitimate owner doesn't notice. Attacker registers `example.net` at any registrar.
2. **Email setup:** Attacker configures a catch-all or specific `admin@example.net` mailbox with a cheap email provider.
3. **Verification re-assertion:** The attacker adds the Entra ID verification TXT record (`MS=msXXXXXXXX`) to `example.net`'s DNS zone. Entra ID does *not* automatically un-verify a domain when its DNS record disappears — the verification persists until an admin manually removes it. The domain remains verified in the existing tenant.
4. **Password reset:** Attacker goes to `login.microsoftonline.com`, enters `admin@example.net`, clicks "Forgot password." Self-Service Password Reset (SSPR) sends an email to `admin@example.net`. The attacker receives it, sets a new password.
5. **MFA enrollment (if applicable):** If MFA is not pre-enrolled or the tenant allows self-service MFA registration after password reset, the attacker enrolls their own MFA device.
6. **Admin role:** If `admin@example.net` was already a Global Admin (common for the initial tenant creator), the attacker is now Global Admin. If not, the attacker enumerates tenant configuration and attempts role escalation.

**Artifacts in directory audit logs:**
- `Add unverified domain` or `Verify domain` event in Entra ID Audit Logs (though domain was already verified — DNS TXT record change is *not* logged by Entra ID, only by the DNS provider).
- `Reset password (self-service)` event for `admin@example.net`.
- `User registered security info` (MFA enrollment) event.
- `Add member to role` if the attacker escalates.
- DNS TXT record change in the domain's DNS history (requires DNS provider audit logs).

**AWS root takeover variant:**

If `root@example.net` is the AWS root user email, and `example.net` expires, the attacker captures password-reset emails via catch-all. The `Forgot password` flow on `signin.aws.amazon.com/console` sends an email to the root user address.

**Artifacts (AWS):**
- CloudTrail management event: `PasswordRecoveryRequested` (root user).
- Successful sign-in from a new, untrusted IP.
- Root user activity after long dormancy.

**Defensive pairing:** Lock root user email to a domain with registrar lock + auto-renew + multi-year prepay. Use an email alias that includes the AWS account ID so it's never guessable (`aws-root-111111111111@long-lived-domain.com`). Require hardware MFA for root.

## 🔵 Blue Team view

**Domain governance — protect verified domains:**

```bash
# 1. Inventory all verified domains in Entra ID
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/domains" \
  --query "value[?isVerified == true].{Domain:id, Default:isDefault, Capabilities:supportedServices}" -o table

# 2. For each domain, verify registrar lock
whois example.com | grep -E "Domain Status|Registrar Expiration"

# 3. Ensure auto-renew is enabled at the registrar
# (This is a registrar-specific operation — not CLI-automatable)
```

**Deferred deletion / TransferProhibited for critical domains:**

At the DNS registrar level, ensure:
- `Domain Lock` (TransferProhibited) is enabled.
- Auto-renew is enabled with multiple payment methods.
- Registration is multi-year (5+ years) to reduce expiry risk.
- Recovery email for the registrar account is on a *different* domain (not self-referencing).

**Monitoring for domain-verification-associated admin role grants:**

```
-- Entra ID: detect admin role assignments following domain-related events
AuditLogs
| where ActivityDisplayName in ("Add verified domain", "Verify domain", "Reset password (self-service)")
| project ActivityDateTime, InitiatedBy.user.userPrincipalName, ActivityDisplayName, TargetResources

-- Entra ID: detect MFA enrollment after password reset
AuditLogs
| where ActivityDisplayName in ("User registered security info", "User registered all required security info")
| join kind=inner (
    AuditLogs
    | where ActivityDisplayName == "Reset password (self-service)"
    | project TargetUser = tostring(TargetResources[0].userPrincipalName), ResetTime = ActivityDateTime
) on $left.TargetResources[0].userPrincipalName == $right.TargetUser
| where ActivityDateTime between (ResetTime .. (ResetTime + 10m))
```

**Break-glass notification on root/reset events:**

```bash
# AWS EventBridge — root password recovery attempted
aws events put-rule --name RootPasswordRecoveryAlert --event-pattern '{
  "source": ["aws.signin"],
  "detail-type": ["AWS Console Sign-in via CloudTrail"],
  "detail": {
    "userIdentity": {"type": ["Root"]},
    "eventName": ["ConsoleLogin", "PasswordRecoveryRequested"]
  }
}'

aws events put-targets --rule RootPasswordRecoveryAlert \
  --targets "Id=1,Arn=arn:aws:sns:us-east-1:111111111111:SecurityTeam"
```

**Checklist — domain governance:**
- [ ] All verified domains have registrar lock + auto-renew + multi-year registration.
- [ ] AWS root user email uses a dedicated, long-lived domain (not a free email provider).
- [ ] Entra ID SSPR requires MFA, not just email verification.
- [ ] Cloud Identity Super Admin recovery email is on a separate domain.
- [ ] No unverified domains remain in Entra ID (remove them after verification attempts).
- [ ] DNS TXT verification record changes are monitored (via DNS provider audit logs or a zone-monitoring service).

**Response playbook — suspected domain-based takeover:**
1. Immediately contact the DNS registrar and verify domain ownership.
2. Lock the tenant admin accounts (Entra: revoke sessions + block sign-in; AWS: deny all via SCP on root; GCP: suspend Super Admin).
3. Review directory audit logs for the artifact sequence: `Add verified domain` → `Reset password` → `User registered MFA` → `Add member to role`.
4. If confirmed, initiate full tenant compromise investigation — the attacker had admin access.
5. Remove the compromised domain from the tenant and re-verify with a fresh, securely-registered domain.

## Hands-on lab

**Verify domain ownership and check SSPR settings (Entra ID):**

> **Prereq:** An Entra ID tenant with admin access (free tier sufficient).

```bash
# 1. List all domains
az rest --method GET --uri "https://graph.microsoft.com/v1.0/domains" \
  --query "value[].{Domain:id, Verified:isVerified, Default:isDefault}" -o table

# 2. Check SSPR configuration
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" \
  --query "{authenticationMethodConfigurations: authenticationMethodConfigurations[?id == 'email'].state}"

# 3. Check if any user has SSPR with email-only (no MFA)
az rest --method GET \
  --uri "https://graph.microsoft.com/beta/users?$select=userPrincipalName,authenticationRequirement" \
  --query "value[?authenticationRequirement == 'multiFactorAuthentication'].userPrincipalName" -o table
```

**Check AWS root user email domain (requires root login):**

```bash
# From an admin session (not root — root API calls are blocked by most SCPs)
aws iam get-account-summary --query "SummaryMap"
# Note: root user email is not exposed via API — check the AWS Console for the actual email.
# If using Organizations, check:
aws organizations describe-organization --query "Organization.MasterAccountEmail"
```

**Teardown:** No resources to destroy — this lab is read-only inspection.

## Detection rules & checklists

**Sigma rule — Entra ID domain verification + password reset chain:**

```yaml
title: Entra ID Domain Verified Followed by Admin Password Reset
status: experimental
logsource:
  product: azure
  service: auditlogs
detection:
  selection_domain:
    ActivityDisplayName: "Verify domain"
  selection_reset:
    ActivityDisplayName: "Reset password (self-service)"
  timeframe: 1h
  condition: selection_domain and selection_reset
falsepositives:
  - Legitimate domain migration or admin password reset after domain re-verification
```

**WHOIS monitoring one-liner:**

```bash
# Check domain expiry for a list of domains
while read domain; do
  expiry=$(whois "$domain" | grep -i "Expir" | head -1)
  echo "$domain: $expiry"
done < /tmp/domains.txt
```

## References
- [Azure AD Domain Takeover (secureworks research)](https://www.secureworks.com/research/azure-ad-domain-takeover)
- [Entra ID Self-Service Password Reset](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-howitworks)
- [GCP Cloud Identity domain verification](https://cloud.google.com/identity/docs/verify-domains)
- [AWS root user best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html)
- [MITRE ATT&CK — Create Account: Cloud Account (T1136.003)](https://attack.mitre.org/techniques/T1136/003/)
