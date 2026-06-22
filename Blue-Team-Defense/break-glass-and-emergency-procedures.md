# 06 — Break-Glass and Emergency Procedures

> **Level:** Intermediate
> **Prereqs:** [Just In Time & Break Glass](../IAM/just-in-time-and-break-glass.md), [Break Glass & Emergency Procedures](break-glass-and-emergency-procedures.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Credential Access
> **Authorization scope:** Provision and test break-glass mechanisms only in your own sandbox accounts.

## What & why

Break-glass is the emergency administrative access procedure — the "in case of emergency, break glass" identity that bypasses normal guardrails when JIT is unavailable, identity infrastructure is compromised, or a critical production incident demands immediate privileged action. Its unused state is itself the strongest integrity signal. When the glass breaks, pages must fire.

## The OnPrem reality

On-prem break-glass literally involved a sealed envelope in a safe containing the domain administrator password, with two-person rule (two separate key fragments or safes). Usage meant: physical access to the safe, breaking the tamper-evident seal, logging in, fixing the issue, resetting the password, resealing in a new envelope. The physical seal provided non-repudiation — you couldn't "accidentally" use break-glass.

## Cross-cloud comparison

| Provider | Break-glass primitive | Activation method | Dual-control mechanism | Alerting mechanism |
|---|---|---|---|---|
| AWS | Break-glass IAM Role (non-SSO, MFA-enforced) | `aws sts assume-role --serial-number --token-code` | MFA device held by separate person + CloudTrail alert | EventBridge `AssumeRole` → SNS → PagerDuty |
| AWS | Root user (last resort) | Root email + password + MFA | MFA-HW token in physical safe | Config rule `root-account-mfa-enabled` + alert |
| Azure | Emergency access account (Global Admin) | `user@example-tenant.onmicrosoft.com` password + MFA | Password in vault + MFA app on dedicated phone | PIM audit log + Sentinel alert rule |
| Azure | PIM eligible Global Admin (time-bound) | PIM activation + approver required | Approver = security-team group (not same team) | PIM audit log → Sentinel |
| GCP | Break-glass Service Account (Org-level) | SA key in physical HSM / sealed envelope + gcloud auth | Key held by CISO + security architect | Cloud Audit Log `SetIamPolicy` / `GenerateAccessToken` |
| GCP | Super admin Cloud Identity user | `superadmin@example.com` + MFA | Password split across two vaults + MFA on separate devices | Cloud Identity audit log + SCC alert |
| OnPrem | Sealed envelope DA password | Physical envelope + AD logon | Two safe fragments, two physical locations | Event ID 4624 + SIEM correlation |

## AWS

**Break-glass role — with MFA enforcement and full alerting:**

```hcl
resource "aws_iam_role" "break_glass" {
  name = "BreakGlassRole"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::111111111111:user/break-glass-user"
      }
      Action = "sts:AssumeRole"
      Condition = {
        Bool = { "aws:MultiFactorAuthPresent": "true" }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "break_glass_admin" {
  role       = aws_iam_role.break_glass.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
```

**EventBridge rule — alert on ANY break-glass role usage:**

```bash
aws events put-rule --name BreakGlassAssumeRole \
  --event-pattern '{
    "source": ["aws.sts"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["AssumeRole"],
      "requestParameters": {
        "roleArn": [{"suffix": ":role/BreakGlassRole"}]
      }
    }
  }'

aws events put-targets --rule BreakGlassAssumeRole \
  --targets "Id=1,Arn=arn:aws:sns:us-east-1:111111111111:BreakGlassAlert"

aws lambda create-function \
  --function-name BreakGlassNotifier \
  --runtime python3.12 \
  --role arn:aws:iam::111111111111:role/LambdaExecutionRole \
  --handler index.handler \
  --code S3Bucket=lambda-code-bucket,S3Key=break-glass-notifier.zip
```

**Lambda notifier — pages on-call:**

The Lambda function posts to PagerDuty and Slack with the `userIdentity.arn`, `sourceIPAddress`, `userAgent`, and timestamp. It also writes to a dedicated "break-glass-usage" S3 bucket for immutable audit trail.

**Response procedure:**

1. Break-glass user (one half of MFA) and MFA device holder (second half) coordinate via out-of-band channel.
2. User initiates `aws sts assume-role --role-arn arn:aws:iam::111111111111:role/BreakGlassRole --role-session-name "incident-INC-001234-$(date +%s)" --serial-number arn:aws:iam::111111111111:mfa/break-glass --token-code 123456 --duration-seconds 3600`
3. EventBridge fires. SOC acknowledges within 60 seconds.
4. If the SOC does not acknowledge within 60 seconds, PagerDuty escalates to security director.
5. Post-incident: break-glass role credentials rotated; MFA device re-verified; incident report logged.

**Break-glass user should:**
- Have NO permissions outside of `sts:AssumeRole` to the break-glass role.
- NOT be used for daily admin tasks.
- Have its own credentials stored separately from the MFA device.

## Azure

**Emergency access account ("break-glass" Global Admin):**

```bash
az ad user create \
  --display-name "Emergency Access - Break Glass" \
  --user-principal-name breakglass@example-tenant.onmicrosoft.com \
  --password "COMPLEX_PASSWORD_STORED_IN_VAULT_123!" \
  --force-change-password-next-sign-in false

az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members/\$ref" \
  --body '{"@odata.id": "https://graph.microsoft.com/v1.0/users/00000000-0000-0000-0000-000000000000"}'
```

**Conditional Access exclusion — emergency account bypasses MFA requirements (by design, with compensating controls):**

Emergency accounts should be excluded from Conditional Access policies that would lock them out (e.g., "require MFA" if MFA infrastructure is the thing that's broken). Compensating control: every sign-in is alerted.

**Sentinel alert rule — emergency account sign-in:**

```kusto
SigninLogs
| where UserPrincipalName == "breakglass@example-tenant.onmicrosoft.com"
| project TimeGenerated, IPAddress, UserAgent, DeviceDetail, Location, RiskLevelDuringSignIn
```

**Quarterly fire-drill test:**

```bash
az ad user show --id breakglass@example-tenant.onmicrosoft.com \
  --query "{enabled: accountEnabled, lastSignIn: signInActivity.lastSignInDateTime}"

az ad user revoke-sign-in-session \
  --id breakglass@example-tenant.onmicrosoft.com

az ad user update \
  --id breakglass@example-tenant.onmicrosoft.com \
  --password "NEW_COMPLEX_PASSWORD_AFTER_DRILL_456!" \
  --force-change-password-next-sign-in false
```

## GCP

**Org-level break-glass Service Account:**

```bash
gcloud iam service-accounts create break-glass \
  --display-name "Break Glass Emergency Account" \
  --project org-admin-111111

gcloud organizations add-iam-policy-binding 000000000000 \
  --member "serviceAccount:break-glass@org-admin-111111.iam.gserviceaccount.com" \
  --role roles/resourcemanager.organizationAdmin

gcloud iam service-accounts keys create break-glass-key.json \
  --iam-account break-glass@org-admin-111111.iam.gserviceaccount.com
```

**Store the key securely:**

```bash
gcloud kms encrypt \
  --key break-glass-seal \
  --keyring emergency-keys \
  --location global \
  --plaintext-file break-glass-key.json \
  --ciphertext-file break-glass-key.json.enc

shred -u break-glass-key.json
```

**Cloud Audit Log alert — any break-glass SA activity:**

```bash
gcloud logging sinks create break-glass-alert \
  pubsub.googleapis.com/projects/org-admin-111111/topics/break-glass \
  --log-filter='protoPayload.authenticationInfo.principalEmail:"break-glass@org-admin-111111.iam.gserviceaccount.com"' \
  --organization=000000000000
```

**Quarterly fire-drill:**

```bash
gcloud kms decrypt \
  --key break-glass-seal \
  --keyring emergency-keys \
  --location global \
  --ciphertext-file break-glass-key.json.enc \
  --plaintext-file /tmp/break-glass-key.json

gcloud auth activate-service-account \
  break-glass@org-admin-111111.iam.gserviceaccount.com \
  --key-file /tmp/break-glass-key.json

gcloud organizations get-iam-policy 000000000000

gcloud iam service-accounts keys delete \
  $(cat /tmp/break-glass-key.json | jq -r .private_key_id) \
  --iam-account break-glass@org-admin-111111.iam.gserviceaccount.com

gcloud iam service-accounts keys create break-glass-key-new.json \
  --iam-account break-glass@org-admin-111111.iam.gserviceaccount.com

shred -u /tmp/break-glass-key.json
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Emergency identity | Sealed envelope DA password | Break-glass IAM Role (MFA enforced) | Emergency access account (Global Admin) | Break-glass Service Account (Org Admin) |
| Activation gate | Physical safe + two-person rule | MFA device + AssumeRole | Password + MFA (exempt from CA) | Decrypt key with KMS + gcloud auth |
| Alert mechanism | Event ID 4624 + SIEM | EventBridge + Lambda → PagerDuty | Sentinel alert rule | Log sink → Pub/Sub → PagerDuty |
| Compensating controls | Tamper-evident seal | MFA on separate physical device, no daily use | Excluded from CA, monitored per sign-in | Key encrypted at rest, decrypt event audited |
| Post-use procedure | Password reset, new envelope | Rotate role, delete MFA session, verify | Password change, session revoke, audit | Key deletion, new key creation, re-encrypt |
| Drill cadence | Quarterly | Quarterly | Quarterly | Quarterly |

## 🔴 Red Team view

**Why attackers don't use break-glass — and what they use instead.**

**Narrative (contained):**

A sophisticated attacker knows that using `BreakGlassRole` triggers an immediate PagerDuty escalation. The attacker avoids the break-glass role entirely and instead looks for **adjacent non-break-glass roles with similar permissions**.

During reconnaissance, the attacker discovers:
```
BreakGlassRole: arn:aws:iam::111111111111:role/BreakGlassRole
  - Attached: AdministratorAccess
  - MFA-enforced: Yes
  - Alert on use: Yes

PlatformAdminRole: arn:aws:iam::111111111111:role/PlatformAdmin
  - Attached: AdministratorAccess (same permissions!)
  - MFA-enforced: No (overlooked during audit)
  - Alert on use: No (not classified as break-glass)
```

The attacker compromises `PlatformAdminRole` instead — same effective permissions, zero alerts, no PagerDuty call. The break-glass role sat unused.

**The detection gap:** Organizations focus heavily on securing the break-glass role but underinvest in auditing roles that share its permission scope. If `AdministratorAccess` is attached to 5 roles, all 5 need the same alerting, session duration controls, and MFA enforcement — not just the one labeled "break-glass."

**Artifacts:**
- CloudTrail: `PlatformAdminRole` performing admin actions (CreateUser, AttachRolePolicy) during non-business hours.
- No `BreakGlassRole` activity in the same window.
- `PlatformAdminRole` trust policy had no MFA condition and no source IP restriction.

## 🔵 Blue Team view

**Break-glass must be: dual-control, alerted, tested quarterly.**

**Ensure all AdministratorAccess roles share break-glass controls:**

```
SELECT roleName, attachedPolicies
FROM iam_roles_111111111111
WHERE attachedPolicies CONTAINS 'AdministratorAccess'
  OR attachedPolicies CONTAINS 'arn:aws:iam::aws:policy/AdministratorAccess'
```

For each result, verify:
- [ ] MFA enforced on trust policy.
- [ ] Alert on any usage via EventBridge/Sentinel/Log sink.
- [ ] Session duration <= 1 hour.
- [ ] No standing IAM Users with AdministratorAccess.

**Audit one-liner — find roles with AdministratorAccess without MFA:**

```bash
aws iam list-roles --query "Roles[*].{Name:RoleName,ARN:Arn}" --output json | \
  jq -r '.[].Name' | while read role; do
    attached=$(aws iam list-attached-role-policies --role-name "$role" \
      --query "AttachedPolicies[?PolicyArn=='arn:aws:iam::aws:policy/AdministratorAccess']" --output text)
    if [ -n "$attached" ]; then
      trust=$(aws iam get-role --role-name "$role" --query "Role.AssumeRolePolicyDocument" --output json)
      mfa=$(echo "$trust" | jq '.Statement[] | select(.Condition.Bool."aws:MultiFactorAuthPresent")')
      if [ -z "$mfa" ]; then
        echo "NO MFA ON ADMIN ROLE: $role"
      fi
    fi
  done
```

**Break-glass drill procedure (quarterly):**

1. Schedule drill: notify security director 24h in advance (exact time withheld).
2. SOC on-call receives PagerDuty alert for break-glass usage.
3. SOC must acknowledge within 60 seconds and verify: "Is this a drill or real?"
4. If SOC cannot reach security director within 5 minutes → treat as real incident.
5. Drill user performs a read-only audit action (`DescribeInstances`, `ListSubscriptions`, `getIamPolicy`).
6. Drill user immediately exits session.
7. Post-drill: rotate break-glass credentials, verify MFA device, file drill report.
8. If SOC failed to acknowledge within time: incident post-mortem.

**Slack integration — immediate channel notification:**

```bash
curl -X POST https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX \
  -H "Content-Type: application/json" \
  -d '{
    "channel": "#sec-alerts-critical",
    "username": "BreakGlassMonitor",
    "text": "BREAK GLASS USED: Role BreakGlassRole assumed by user@example.com from IP 203.0.113.50 at 2026-06-22T04:15:00Z",
    "icon_emoji": ":rotating_light:"
  }'
```

**Checklist:**
- [ ] Break-glass role(s) exist in all orgs/subscriptions/projects.
- [ ] Break-glass usage triggers PagerDuty within 60 seconds.
- [ ] No more than 2 individuals possess break-glass credentials at any time.
- [ ] MFA device for break-glass is stored separately from the credential.
- [ ] Quarterly fire-drill completed with report filed.
- [ ] All roles with AdministratorAccess / Global Admin / Owner share break-glass alerting.

Cross-link: [02-07 Just-in-Time & Break-Glass](../IAM/just-in-time-and-break-glass.md), [10-05 Auto-Response Isolate](auto-response-isolate-and-quarantine.md), [06-07 Detection-as-Code](../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md).

## Hands-on lab

Create a break-glass role with MFA enforcement and EventBridge alerting — see the lab within [02-07 Just-in-Time & Break-Glass](../IAM/just-in-time-and-break-glass.md).

## Detection rules & checklists

**Sigma rule — break-glass usage detection:**

```yaml
title: Break Glass Role Usage
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AssumeRole
    requestParameters.roleArn|endswith: ':role/BreakGlassRole'
  condition: selection
level: critical
```

## References
- [AWS — Break-glass best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html)
- [Azure — Emergency access accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- [GCP — Emergency access strategies](https://cloud.google.com/iam/docs/emergency-access)
- [MITRE ATT&CK — Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
