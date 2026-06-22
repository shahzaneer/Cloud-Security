# 07 — Just-in-Time & Break-Glass

> **Level:** Advanced
> **Prereqs:** [Assume Role Chains & Trust Graphs](assume-role-chains-and-trust-graphs.md) (Assume-Role Chains), [Federation SSO & External Providers](federation-sso-and-external-providers.md) (Federation), [Permission Boundaries & Quarantine](permission-boundaries-and-quarantine.md) (Permission Boundaries)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Privilege Escalation, Persistence, Defense Evasion
> **Authorization scope:** Identity attacks only in your own sandbox accounts / sanctioned targets.

## What & why

Standing administrative access is a ticking clock — every second an admin session exists is a second an attacker can steal it. Just-in-Time (JIT) means elevated privileges are minted *only when needed*, for a bounded time, with approval. Break-glass is the emergency override when JIT is unavailable.

## The OnPrem reality

On-prem JIT was manual: a ticket in ServiceNow/JIRA, an email approval from a manager, a temporary addition to the Domain Admins group, then removal after the task. The "two-person rule" (two admins present for critical actions) was enforced by physical presence or split-key vaults. Break-glass meant a sealed envelope with the domain admin password, stored in a safe, with usage triggering immediate audit notification. The weakness: manual processes meant admins stayed in `Domain Admins` for hours after the window closed, or the JIRA approval was rubber-stamped.

## Cross-cloud JIT comparison

| Provider | JIT mechanism | Activation method | Time-bound | Approval workflow |
|---|---|---|---|---|
| AWS | IAM Identity Center Permission Sets (scheduled) | User requests elevation via Identity Center portal | Session duration on permission set | > (as of June 2026, IAM Identity Center does not include a native approval workflow; third-party integration such as Okta Access Requests or ServiceNow is required for approval gating.) |
| AWS | IAM Roles (manual activation via sts:AssumeRole) | `aws sts assume-role` with `--duration-seconds` | Session duration (15 min – 12 h) | Manual; pair with SCIM/IdP approval |
| Azure | Entra ID PIM (Privileged Identity Management) | User activates eligible role assignment via portal/API | 15 min – 24 h (configurable) | Approver required (optional); MFA enforced |
| Azure | JIT VM Access (Azure Security Center) | Request JIT access to NSG rule | Temporary port open (1 h) | Security Center workflow |
| GCP | IAM Conditions (time-bounded access) | Policy binding with `request.time` condition | Configurable duration via condition expr | Manual; pair with custom approval pipeline |
| GCP | IAM Recommender + Policy Troubleshooter | Analyze excess permissions; generate recommendations | N/A (advisory only) | Automatic recommendation generation |
| OnPrem | AD Privileged Access Management (PAM) | MIM PAM shadow principal activation | TTL on PAM group membership | Approver + MFA in MIM portal |

## AWS

AWS JIT is primarily achieved through IAM Identity Center Permission Sets with session duration controls, or through general IAM role assumption with short `MaxSessionDuration`.

**IAM Identity Center — time-bound permission set:**

```bash
aws sso-admin create-permission-set \
  --instance-arn <instance-arn> \
  --name JIT-Admin \
  --session-duration PT1H  # 1 hour

aws sso-admin attach-managed-policy-to-permission-set \
  --instance-arn <instance-arn> \
  --permission-set-arn <ps-arn> \
  --managed-policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Users get a one-hour session for admin tasks via the Identity Center portal. After expiry, they redirect back to SSO for a new session.

**Generic IAM role — short session + manual activation:**

```bash
# The user does NOT have this role attached permanently.
# They assume it only when needed.
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/JITAdminRole \
  --role-session-name "jit-session-$(date +%s)" \
  --duration-seconds 900  # 15 minutes
```

> (as of June 2026, IAM Identity Center does not include a native JIT approval workflow. Organizations typically integrate a third-party IdP's approval mechanism such as Okta Access Requests, SailPoint, or a custom ServiceNow workflow to gate permission set activation.)

## Azure

**Entra ID PIM — activate eligible role:**

```bash
# List roles the current user is eligible for
az rest --method GET \
  --uri "https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleRequests?api-version=2022-04-01-preview" \
  --query "value[?properties.status=='Provisioned']"

# View eligible assignments via Graph API
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" \
  --query "value[?principalId=='$(az ad signed-in-user show --query id -o tsv)']"
```

**PIM activation flow (portal-driven):**

The user navigates to `portal.azure.com → Privileged Identity Management → My roles → Activate`. They choose a duration (e.g., 1 hour), provide a justification, and if approval is required, a designated approver receives a notification. Once approved, the role assignment transitions from `Eligible` to `Active`.

**PIM settings — enforce MFA and approval:**

```bash
# PIM role settings (Azure Portal / Graph API)
# Key settings:
# - Activation maximum duration: 1 hour
# - Require MFA on activation: Yes
# - Require approval: Yes (approver = security-team-group)
# - Require justification: Yes
# - Notification: Email approver
```

> (as of June 2026, Graph API endpoints for PIM role settings change across API versions (`beta` vs `v1.0`). Check the current [Microsoft Graph REST API reference](https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagement-root) for the latest endpoints for `roleManagementPolicies` and `roleEligibilityScheduleRequests`.)

## GCP

GCP uses IAM Conditions to create time-bounded access grants. There is no native "PIM" equivalent — JIT is expressed through conditional IAM bindings.

**Time-bounded IAM binding via condition:**

```bash
# Grant 2-hour admin access starting from a future time
gcloud projects add-iam-policy-binding project-id-111111 \
  --member "user:eng@example.com" \
  --role roles/editor \
  --condition-from-file condition.yaml
```

```yaml
# condition.yaml — grants access only for a 2h window
expression: |
  request.time >= timestamp("2026-06-22T10:00:00Z") &&
  request.time < timestamp("2026-06-22T12:00:00Z")
title: "jit_window_june22"
description: "JIT access for migration task"
```

After the window expires, the binding remains in the IAM policy but is ineffective — permissions evaluate to `false`. The binding should be cleaned up for hygiene.

**GCP break-glass — emergency access via Org-level SA:**

```bash
# Emergency service account — exists at org level, rarely used
gcloud organizations add-iam-policy-binding 000000000000 \
  --member "serviceAccount:break-glass@org-000000000000.iam.gserviceaccount.com" \
  --role roles/resourcemanager.organizationAdmin

# Access is monitored:
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="break-glass@org-000000000000.iam.gserviceaccount.com"'
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Activation mechanism | MIM PAM / temporary group add | `sts:AssumeRole` / Identity Center session | PIM role activation (Eligible → Active) | IAM condition with `request.time` |
| Approval gateway | MIM PAM approval workflow | IdP integration (Okta Access Requests) | PIM approver group (MFA required) | Custom Cloud Function / IaC pipeline |
| Session duration | PAM TTL (configurable, e.g., 1 h) | `MaxSessionDuration` / `DurationSeconds` | PIM activation duration (15 min – 24 h) | Condition expression time range |
| Break-glass identity | Sealed envelope DA password | Break-glass IAM role (alert on use) | Emergency access account (Global Admin) | Org-level emergency SA |
| Audit trail | Windows Security Event 4728/4729 | CloudTrail `AssumeRole` | PIM audit log (`RoleAssignmentActivated`) | Cloud Audit Log `SetIamPolicy` |
| Automated removal | MIM scheduled cleanup job | Session expiry (STS token dies) | PIM automatic deactivation on expiry | Condition evaluates to false after window | PAM TTL (configurable, e.g., 1 h) |

## 🔴 Red Team view

**Self-approving JIT ticket rules.** When JIT is "fake JIT" — a ticket rule that auto-approves requests from the requester's own team, or where the approval queue is unmonitored — the attacker activates and pivots without human scrutiny.

**Narrative (contained):**

A platform engineer has permanent `eligible` status for `Contributor` in PIM. The PIM role settings require "approval" — but the designated approver group is `platform-engineering@example.com`, the same team the engineer belongs to. The attacker (a compromised engineer) activates PIM, selects themselves as the justification, and a colleague auto-approves the Slack notification without reviewing because "it's just Bob doing his job."

**Self-approving via automation:**

```python
# Hypothetical: an attacker scripts the PIM activation + approval
# when the "approver" is a shared mailbox with auto-responder rules.
# Run only in sandbox environments.

import requests

# Step 1: Activate role
resp = requests.post(
    "https://management.azure.com/.../roleAssignmentScheduleRequests/activate?api-version=2022-04-01-preview",
    headers={"Authorization": f"Bearer {compromised_token}"},
    json={"properties": {"principalId": "...", "duration": "PT1H", "justification": "Prod deployment"}}
)

# Step 2: If the approval rule is misconfigured to "any approver from IT group"
#          and the attacker controls ANY IT account, they approve their own request.
```

**Artifacts:**
- PIM audit logs show `RoleAssignmentActivated` with `justification: "Prod deployment"` and `approver: platform-engineering-group`.
- No incident ticket in the ITSM system matching the time window.
- CloudTrail/Activity Log shows admin actions (VM delete, IAM change) immediately after an `Active` transition from a user who rarely performs admin actions.

## 🔵 Blue Team view

**Enforced dual-control approvals:**

```bash
# Azure PIM — restrict approver to security team only (not the requester's team)
# This is set via the PIM role settings in the portal:
#   Approvers: <security-team-group-object-id>
#   Require Azure MFA: Yes
#   Require justification: Yes 
#   Require ticket info: Yes (ticket number OR link)
```

**Slack integration alert on privilege activation:**

```bash
# Example webhook that triggers on PIM activation (via Logic App / Event Grid)
curl -X POST https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX \
  -H "Content-Type: application/json" \
  -d '{
    "text": "🔵 PIM activation: user@example.com activated Contributor for 1h at subscription 00000000-0000-0000-0000-000000000000. Justification: Prod deploy. Approver: sec-team."
  }'
```

**Detect privilege *use* — not just activation:**

```
-- AWS CloudTrail: detect write actions immediately after AssumeRole
SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress
FROM cloudtrail_111111111111
WHERE userIdentity.type = 'AssumedRole'
  AND userIdentity.arn LIKE '%:role/JITAdminRole'
  AND eventName NOT LIKE 'Get%'
  AND eventName NOT LIKE 'List%'
  AND eventName NOT LIKE 'Describe%'
ORDER BY eventTime DESC

-- Azure: detect write operations during PIM active window
AzureActivity
| where Caller contains "jit"
| where OperationNameValue !contains "read"
| project TimeGenerated, Caller, OperationNameValue, ResourceId
```

**Break-glass monitoring:**

```
-- Detect ANY break-glass usage (should be near-zero outside drills)
SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress
FROM cloudtrail_111111111111
WHERE userIdentity.arn LIKE '%:role/BreakGlassRole'
  OR userIdentity.arn LIKE '%break-glass%'
```

**Automated break-glass notification:**

```bash
# AWS EventBridge rule → SNS → PagerDuty
aws events put-rule --name BreakGlassAlert \
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

aws events put-targets --rule BreakGlassAlert \
  --targets "Id=1,Arn=arn:aws:sns:us-east-1:111111111111:PagerDutyTopic"
```

**Checklist:**
- [ ] No standing admin IAM User — all admin access via JIT role assumption or PIM.
- [ ] PIM approvers are NOT in the same team as requester (separation of duty).
- [ ] PIM activation requires MFA.
- [ ] Break-glass role triggers PagerDuty/on-call alert within 60 seconds.
- [ ] Break-glass credentials rotated after each use (even drills).

## Hands-on lab

**Simulate a time-bounded role assumption and verify expiry:**

```bash
# 1. Create a JIT role with short session duration
aws iam create-role --role-name LabJITRole --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::'$(aws sts get-caller-identity --query Account --output text)':user/lab-admin"},
    "Action": "sts:AssumeRole"
  }]
}'

aws iam update-role --role-name LabJITRole --max-session-duration 900
aws iam attach-role-policy --role-name LabJITRole \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# 2. Assume the role for 15 minutes
CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/LabJITRole \
  --role-session-name "jit-test-$(date +%s)" \
  --duration-seconds 900)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .Credentials.AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .Credentials.SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .Credentials.SessionToken)

EXPIRY=$(echo $CREDS | jq -r .Credentials.Expiration)
echo "Session expires at: $EXPIRY"
aws sts get-caller-identity

# 3. Wait for expiry, re-test (or simulate by checking the token's expiration)
# In real usage: after 15 min, retry — gets ExpiredToken error.
```

**Expected output:** `GetCallerIdentity` succeeds immediately. After 15 minutes, the STS credentials expire and any API call returns `ExpiredTokenException`.

**Teardown:**
```bash
aws iam detach-role-policy --role-name LabJITRole \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam delete-role --role-name LabJITRole
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

## Detection rules & checklists

**AWS Config rule — roles with excessive `MaxSessionDuration`:**
```json
{
  "ConfigRuleName": "iam-role-max-session-duration",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "IAM_ROLE_MANAGED_POLICY_CHECK"
  },
  "InputParameters": "{\"maxSessionDuration\": \"3600\"}"
}
```

**GCP — detect permanent IAM bindings without conditions:**
```bash
gcloud projects get-iam-policy project-id-111111 --format json | \
  jq '.bindings[] | select(.condition == null and .role != "roles/viewer") | {role, members}'
```

## References
- [AWS IAM — Temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
- [Azure Entra ID PIM](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- [GCP IAM Conditions](https://cloud.google.com/iam/docs/conditions-overview)
- [Microsoft Identity Manager PAM](https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services)
- [MITRE ATT&CK — Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
