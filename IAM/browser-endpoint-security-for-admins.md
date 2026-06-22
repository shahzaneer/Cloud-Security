# 11 — Browser & Endpoint Security for Cloud Admins

> **Level:** Intermediate
> **Prereqs:** [Identity Primitives per Cloud](identity-primitives-per-cloud.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Credential Access, Persistence
> **Authorization scope:** Run only in your own sandbox accounts. All phishing/session-hijack examples use placeholder credentials and isolated lab environments.

## What & why

Cloud console phishing and session hijacking bypass MFA entirely by stealing post-authentication tokens. Admins who manage infrastructure through a browser on an unmanaged device are one stolen session cookie away from a full account takeover, regardless of how strong their password or MFA is.

## The OnPrem reality

On-prem admins used jump hosts (RDP/SSH boxes) behind VPNs. The attack was network-based: steal a domain credential, pivot via RDP. In cloud, the attack is browser-based: steal a session cookie or OAuth token, replay it from anywhere on earth. No VPN, no network segmentation, no jump host stops a stolen cookie from granting console access.

| Attack vector | OnPrem | Cloud |
|---|---|---|
| Credential theft | Password hash from LSASS | Session cookie from browser storage |
| MFA bypass | N/A (MFA rarely deployed) | Token replay, push fatigue, SIM swap |
| Privileged access path | RDP to jump host → domain admin | Browser → cloud console → IAM role |
| Device trust | Domain-joined machine | Conditional Access / device compliance |

## Core concepts

### Session token types and their attack surface

| Token type | Storage location | Replay window | Theft method |
|---|---|---|---|
| AWS console session cookie | Browser cookie jar (`aws-creds*`) | Session duration (max 12h) | Malware, XSS, phishing proxy |
| Azure Entra ID PRT (Primary Refresh Token) | OS token cache (Windows) | Up to 90 days | Malware extraction (Mimikatz, ROADtools) |
| GCP OAuth2 refresh token | Browser local storage | Until revoked | Browser extension, malware |
| SAML assertion (response) | Browser memory/network trace | Minutes | IdP-initiated flow replay |

### Browser isolation models

| Model | How it works | Protection level | Performance impact |
|---|---|---|---|
| Local browser (unmanaged) | Admin uses any device | None | None |
| Remote browser isolation (RBI) | Browser runs on cloud VM, pixels streamed | High — cookie stays on remote | Latency ~50–100ms |
| Enterprise browser (Island, Talon) | Custom Chromium with DLP, watermarking | High | Minimal |
| Managed browser (SCCA policies) | Chrome/Edge with GPO-enforced extensions | Medium | Minimal |
| PIM/PAM-gated browser session | Browser only works after PIM activation | Medium-high (time-bound) | Workflow friction |

## AWS

```bash
# Check if an IAM user has console access
aws iam get-login-profile --user-name admin-user

# Force MFA for all console users via policy condition
aws iam create-policy --policy-name enforce-console-mfa \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
      }
    }]
  }'
```

**Gotcha:** AWS console sessions default to 12 hours. Attackers with a stolen cookie have a half-day window. Consider SCPs that limit `aws:PrincipalTag/sessionDuration` for human users.

## Azure

```bash
# Conditional Access policy (conceptual — configured via Portal/Graph API)
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/policies/conditionalAccessPolicies" \
  --body '{
    "displayName":"Require compliant device for admins",
    "state":"enabled",
    "conditions":{
      "clientAppTypes":["browser"],
      "users":{"includeRoles":["62e90394-69f5-4237-9190-012177145e10"]}
    },
    "grantControls":{"operator":"AND","builtInControls":["compliantDevice","mfa"]}
  }'
```

**Gotcha:** The Entra ID Primary Refresh Token (PRT) can be extracted from a compromised device and used for 90 days. Enforce compliant-device + sign-in frequency (1 hour for admins) to limit the replay window.

## GCP

```bash
# Context-aware access for GCP console
gcloud access-context-manager levels create browser_restriction \
  --title "Restrict to corporate devices" \
  --basic-level-spec '{
    "conditions": [{
      "devicePolicy": {
        "requireCorpOwned": true,
        "osConstraints": [{"osType": "DESKTOP_CHROME_OS"}]
      }
    }]
  }'
```

**Gotcha:** GCP BeyondCorp Enterprise allows context-aware access but requires the paid tier (as of June 2026, ~$6/user/month). Many organizations skip it, leaving console access wide open from any device.

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Console access | Domain-joined jump host | AWS console + IAM | Azure Portal + Entra ID | GCP Console + Cloud Identity |
| MFA enforcement | Radius/AD FS | IAM condition `MultiFactorAuthPresent` | Conditional Access MFA grant | Cloud Identity 2-Step Verification |
| Device trust | AD computer object | N/A (requires IdP layer) | Intune compliant device | BeyondCorp context-aware |
| Session limit | GPO session timeout | `aws:SessionDuration` | Sign-in frequency CA policy | Session length via Cloud Identity |
| Browser isolation | Jump host (network-based) | AWS Verified Access (preview) | Defender for Cloud Apps session proxy | BeyondCorp Enterprise |
| Token replay protection | Kerberos PAC validation | None native (needs IdP) | Continuous Access Evaluation (CAE) | None native |

## 🔴 Red Team view

Attackers target cloud admin sessions because a stolen session cookie gives immediate, MFA-bypassed access.

### Technique 1 — Phishing proxy (EvilGinx-style)

```
Attacker's flow:
1. Set up reverse proxy (evilginx3) between victim and legit IdP
2. Victim enters credentials + performs MFA on the proxy
3. The legit IdP returns a session cookie to the proxy
4. Proxy captures the session cookie — attacker replays it
```

**Contained example — AWS console session hijack:**
```bash
# Attacker (on own sandbox host) captures cookies from browser dev tools
# Chrome DevTools → Application → Cookies → extract aws-creds* cookies

# Replay on attacker's host:
# Install EditThisCookie extension → import the JSON cookie blob
# Navigate to console.aws.amazon.com → immediate admin access, no MFA prompt
```

**Why this works:** AWS console session cookies are bearer tokens. AWS does not bind them to the originating IP or User-Agent by default. No additional authentication challenge is presented on a new device.

### Technique 2 — Device code phishing (consent grant)

```bash
# Attacker initiates a device code flow (commonly used for CLI auth):
aws sso login --profile victim-profile
# The CLI displays: "Open https://device.sso.us-east-1.amazonaws.com/ and enter code: ABCD-EFGH"
# Attacker sends a phishing email: "Your cloud access has expired. Please verify at https://device.sso.us-east-1.amazonaws.com/ and enter your verification code."
# Victim enters the real code on the real AWS page → completes MFA
# Attacker's CLI session is now authenticated as the victim
```

### Technique 3 — Malicious browser extension

A seemingly useful extension ("Cloud Resource Tagger") requests broad browser permissions. It reads and exfiltrates every cookie set by `*.aws.amazon.com`, `*.azure.com`, and `*.google.com` — including authenticated session tokens.

**Artifacts left:** CloudTrail `ConsoleLogin` with `sourceIPAddress` matching the attacker's location (different from normal admin IPs). Entra ID sign-in logs show `deviceDetail.isCompliant=false` if device policies are in place. Browser extension installation is visible in Chrome/Edge admin policy logs if managed.

## 🔵 Blue Team view

### Preventive controls

1. **FIDO2/WebAuthn for cloud admins:**
   - Disable SMS/voice/email OTP MFA methods for privileged users.
   - Enroll FIDO2 security keys (YubiKey, Titan) as the only MFA method.
   - WebAuthn is phishing-resistant because the key validates the origin domain before signing.

2. **Conditional Access — device compliance:**
```json
{
  "displayName": "Require compliant device for Global Admin",
  "conditions": {
    "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
    "users": { "includeRoles": ["Global Administrator"] }
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": ["compliantDevice", "mfa"]
  }
}
```

This prevents session replay from an unmanaged attacker device even if the cookie is stolen.

3. **Sign-in frequency enforcement:**
   - AWS: Use IAM role chaining max session duration of 1 hour for human users.
   - Azure: Conditional Access sign-in frequency at 1 hour for privileged roles.
   - GCP: Cloud Identity session length at 1 hour.

4. **Browser isolation for privileged ops:**
   - Force all Global Admin / root-account-equivalent logins through a remote browser isolation (RBI) platform.
   - The session cookie never touches the local endpoint — it lives only on the RBI server.

### Detection signals

| Signal | Source | What to query |
|---|---|---|
| ConsoleLogin from unusual IP | CloudTrail | `eventName="ConsoleLogin" AND sourceIPAddress NOT IN (corporate_ips)` |
| Session created without MFA | CloudTrail | `eventName="ConsoleLogin" AND additionalEventData.MFAUsed="No"` |
| Token replay (geographic impossibility) | Azure Sign-in Logs | Two sign-ins from same user, different countries, <5 minutes apart |
| Browser extension installation surge | Endpoint EDR logs | Chrome extension install event on admin machines |
| Device code auth from unusual device | Entra ID logs | `authenticationProtocol="deviceCode" AND deviceDetail.deviceId=""` |

### Response steps

1. Immediately revoke the compromised session:
```bash
# AWS: delete login profile, invalidate console session
aws iam delete-login-profile --user-name compromised-admin
# Azure: revoke user sessions
az ad user revoke-sign-in-sessions --id compromised@example.com
# GCP: revoke OAuth tokens
gcloud auth revoke compromised@example.com
```

2. Force MFA re-registration on a known-clean device.
3. Investigate CloudTrail/Activity Log for all actions during the session window.
4. Rotate all access keys the compromised principal could have created.

## Hands-on lab

1. In your sandbox AWS account, create a test IAM user with console access and no MFA:
```bash
aws iam create-user --user-name lab-nomfa-admin
aws iam create-login-profile --user-name lab-nomfa-admin \
  --password 'TempP@ssw0rd123!' --no-password-reset-required
aws iam attach-user-policy --user-name lab-nomfa-admin \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

2. Log in to the console with this user. Use browser DevTools to inspect the `aws-creds*` cookies.

3. Copy the cookie values and attempt to replay them:
   - Open an incognito window
   - Use browser DevTools → Application → Cookies → manually create the same cookies
   - Refresh the console — observe you're authenticated without a password

4. Enable MFA and a Deny-without-MFA policy:
```bash
aws iam create-virtual-mfa-device --virtual-mfa-device-name lab-nomfa-admin-mfa
# Enroll the MFA device (use Google Authenticator / Authy)
aws iam enable-mfa-device --user-name lab-nomfa-admin \
  --serial-number arn:aws:iam::111111111111:mfa/lab-nomfa-admin-mfa \
  --authentication-code-1 123456 --authentication-code-2 654321
```

**Teardown:**
```bash
aws iam delete-login-profile --user-name lab-nomfa-admin
aws iam deactivate-mfa-device --user-name lab-nomfa-admin \
  --serial-number arn:aws:iam::111111111111:mfa/lab-nomfa-admin-mfa
aws iam delete-virtual-mfa-device \
  --serial-number arn:aws:iam::111111111111:mfa/lab-nomfa-admin-mfa
aws iam delete-user --user-name lab-nomfa-admin
```

## Detection rules & checklists

**CloudTrail query — ConsoleLogin without MFA:**
```sql
SELECT eventTime, userIdentity.arn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
  AND responseElements.ConsoleLogin = 'Success'
  AND additionalEventData.MFAUsed = 'No'
  AND userIdentity.type = 'IAMUser'
```

**Checklist:**
- [ ] All privileged users enrolled with FIDO2/WebAuthn (no SMS/TOTP phone-based MFA).
- [ ] Conditional Access / SCP denies console access without MFA.
- [ ] Sign-in frequency enforced at 1 hour for all admin roles.
- [ ] Browser isolation or managed device required for Global Admin / root-equivalent access.
- [ ] Device code flow blocked or restricted to managed devices only.
- [ ] ConsoleLogin events shipped to SIEM with alert on new IP / no-MFA.
- [ ] Break-glass accounts excluded from session-limit policies but monitored with high-fidelity alerts.

## References
- [AWS — Enabling MFA for IAM Users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html)
- [Azure — Conditional Access for Privileged Roles](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-common)
- [GCP — BeyondCorp Enterprise](https://cloud.google.com/beyondcorp-enterprise)
- [MITRE ATT&CK — Steal Web Session Cookie (T1539)](https://attack.mitre.org/techniques/T1539/)
- [OWASP — Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [FIDO2 / WebAuthn Specification](https://fidoalliance.org/fido2/)
