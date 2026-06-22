# 05 — IAM Revocation and Session Physics

> **Level:** Advanced
> **Prereqs:** [02-IAM](../IAM/assume-role-chains.md), [09-Red](../Red-Team-Offense/assume-role-chains.md), [10-Blue](../Blue-Team-Defense/)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Persistence, Defense Evasion
> **Authorization scope:** Run only in your own sandbox account; all example account IDs are placeholders (`111111111111`, `00000000-0000-0000-0000-000000000000`).

## What & why

IAM revocation in cloud is not a magic kill switch. Disabling a key stops *new* API calls, but in-flight STS / JWT / Azure AD sessions live until their TTL expires. Defenders must understand session physics to choose the correct revocation level: deactivate key → attach deny boundary → rotate source identity → poison trust policy — each with different latency and coverage.

## The OnPrem reality

Active Directory account disablement was the canonical revocation: set `userAccountControl` to `ACCOUNTDISABLE`, wait for Kerberos TGT to expire (default 10 hours), or forcibly purge tickets via `klist purge` on each domain controller. The gap between disable and effective kill was the TGT lifetime — similar to STS TTL, but localized to the domain.

## Core concepts

### Revocation levels (in order of strength)

| Level | Action | Latency | Covers in-flight sessions? | Risk |
|-------|--------|---------|---------------------------|------|
| L1: Deactivate key | `iam:UpdateAccessKey` status=Inactive | ~1s | No — STS tokens from this key live until TTL | Attacker keeps existing session |
| L2: Deny-all boundary | Attach `DenyAll` permission boundary or inline policy to role | ~5s | No — already-assumed role sessions persist | New AssumeRole calls blocked |
| L3: Rotate source identity | Delete IAM user's access keys, rotate password | ~1s | No — existing sessions persist | Attacker loses key material for new calls |
| L4: Poison trust policy | Remove `Principal` from role trust policy | ~5s | No — but blocks new `AssumeRole` | Attacker can't get new session tokens |
| L5: SCP deny-all on role | Attach SCP `Deny *` to the OU containing the role | Minutes (propagation) | Partially — existing STS sessions may start returning AccessDenied | Org-wide blast radius risk |
| L6: Revoke refresh tokens | OAuth token revocation endpoint | ~1s | Yes — refresh tokens are server-side invalidated | Only if attacker uses OAuth flow |

### STS session lifecycle (AWS)

```
AssumeRole call → STS issues:
├── AccessKeyId (temporary, valid for TTL duration, max 12h)
├── SecretAccessKey
└── SessionToken
    ↓
API calls signed with these credentials → IAM evaluates:
    1. Identity-based policy
    2. Resource-based policy
    3. Permission boundaries
    4. SCPs
    ↓
Session expires at TTL → credentials stop working
```

**Critical physics:** Once STS issues the temporary credentials, neither `iam:DeactivateAccessKey` on the *source* IAM user nor `iam:UpdateAssumeRolePolicy` on the *target* role terminates the in-flight session. The session is a bearer token — the holder can use it until expiry. (as of June 2026, AWS has no `RevokeSession` API; active STS sessions cannot be revoked before their TTL expires. Only an SCP deny or attaching a deny policy to the role — which may not immediately propagate — can block new API calls.)

## AWS

### Revocation playbook

```bash
#!/bin/bash
COMPROMISED_USER="operator-user"
COMPROMISED_ROLE="ProdAppRole"
INCIDENT_ID="inc-$(date +%s)"

echo "=== L1: Deactivate access keys ==="
for KEY in $(aws iam list-access-keys --user-name $COMPROMISED_USER \
    --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name $COMPROMISED_USER \
        --access-key-id $KEY --status Inactive
    echo "Deactivated: $KEY"
done

echo "=== L2: Attach deny-all inline policy to compromised role ==="
aws iam put-role-policy --role-name $COMPROMISED_ROLE \
    --policy-name "IR-${INCIDENT_ID}-DenyAll" \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }]
    }'

echo "=== L3: Diagnose active STS sessions ==="
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time "$(date -u -d '12 hours ago' +%s)" \
    --query "Events[?CloudTrailEvent.contains('$COMPROMISED_ROLE')]" \
    --output json | jq '[.[] | {time: .EventTime, principal: .Username, sourceIP: .CloudTrailEvent | fromjson | .sourceIPAddress}]'

echo "=== L4: Poison trust policy — remove all principals ==="
aws iam update-assume-role-policy --role-name $COMPROMISED_ROLE \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "sts:AssumeRole",
            "Principal": {"AWS": "*"}
        }]
    }'

echo "=== L5: Org-wide SCP (if P1) ==="
aws organizations attach-policy \
    --policy-id p-scpdenyall \
    --target-id ou-abcd-12345678

echo "=== ⚠️ IN-FLIGHT STS SESSIONS STILL LIVE ==="
echo "Max remaining TTL: check CloudTrail AssumeRole timestamps"
echo "Wait period: up to 12h (default TTL cap)"
```

**Gotcha:** AWS STS default session duration is 3600s (1h). If the role's `MaxSessionDuration` was raised to 12h, the defender must wait up to 12 hours before all attacker sessions expire. The SCP `Deny *` may be the only way to force terminations — attach it to the OU, not the account, to scope blast radius.

### SCP to cap session duration org-wide

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "CapSTSSessionDuration",
    "Effect": "Deny",
    "Action": "sts:AssumeRole",
    "Resource": "*",
    "Condition": {
      "NumericGreaterThan": {"sts:DurationSeconds": "3600"}
    }
  }]
}
```

## Azure

### Revocation playbook

```bash
#!/bin/bash
COMPROMISED_SP="00000000-0000-0000-0000-000000000000"
COMPROMISED_USER="operator@example.com"

echo "=== L1: Disable Service Principal ==="
az ad sp update --id $COMPROMISED_SP --set accountEnabled=false

echo "=== L2: Revoke sign-in sessions ==="
az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/users/${COMPROMISED_USER}/revokeSignInSessions"
#    (status as of June 2026: revokeSignInSessions invalidates refresh tokens;
#     existing access tokens remain valid until their 1-hour expiry; propagation
#     may take up to 15 minutes per Microsoft documentation)

echo "=== L3: Remove SP credentials ==="
for KEY_ID in $(az ad sp credential list --id $COMPROMISED_SP \
    --query '[].keyId' -o tsv); do
    az ad sp credential delete --id $COMPROMISED_SP --key-id $KEY_ID
done

echo "=== L4: Conditional Access — block by location/IP ==="
az ad conditional-access policy create \
    --display-name "IR-${INCIDENT_ID}-BlockSuspiciousIP" \
    --state enabled \
    --conditions '{
        "applications": {"includeApplications": ["All"]},
        "locations": {"includeLocations": ["blocked-ips-ir"]}
    }' \
    --grant-controls '{"operator": "OR", "builtInControls": ["block"]}'

echo "=== Azure AD sessions: control via signInFrequency ==="
# Pre-configure conditional access for 1h max session
az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/policies/conditionalAccessPolicies/${POLICY_ID}" \
    --body '{
        "sessionControls": {
            "signInFrequency": {"value": 1, "type": "hours", "authenticationType": "primaryAndSecondaryAuthentication"}
        }
    }'
```

**Gotcha:** Azure AD `revokeSignInSessions` revokes refresh tokens but not necessarily all access tokens already issued to apps. Access tokens remain valid until their configured lifetime (default 60-90 min depending on client). Conditional Access policies are evaluated at token refresh time, not mid-session.

## GCP

### Revocation playbook

```bash
#!/bin/bash
COMPROMISED_SA="sa-compromised@${PROJECT_ID}.iam.gserviceaccount.com"
INCIDENT_ID="inc-$(date +%s)"

echo "=== L1: Disable service account ==="
gcloud iam service-accounts disable $COMPROMISED_SA

echo "=== L2: Delete all service account keys ==="
for KEY_ID in $(gcloud iam service-accounts keys list \
    --iam-account="$COMPROMISED_SA" \
    --format='value(name.basename())' \
    --managed-by=user); do
    gcloud iam service-accounts keys delete $KEY_ID \
        --iam-account="$COMPROMISED_SA" --quiet
done

echo "=== L3: Revoke OAuth tokens ==="
curl -s -X POST \
    "https://oauth2.googleapis.com/revoke?token=${OAUTH_TOKEN}"

echo "=== L4: Remove IAM policy bindings ==="
gcloud projects remove-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$COMPROMISED_SA" \
    --role="roles/editor" --condition=None

echo "=== (status as of June 2026: JWT tokens issued to this SA remain valid until their `exp` claim; GCP does not maintain a server-side revocation list for JWTs) ==="
echo "Preventive: cap key lifetime at creation"
gcloud iam service-accounts keys create /dev/null \
    --iam-account="$COMPROMISED_SA" \
    --key-file-type=json \
    --valid-duration=3600s  # 1h max for new keys
```

**Gotcha:** GCP `serviceAccounts.disable` blocks new token issuance but does not invalidate existing JWTs. JWTs are stateless bearer tokens — the GCP auth infrastructure does not check a revocation list on every API call. The token's `exp` claim controls validity. Service account keys have no default expiry; always create with `--valid-duration`.

## OnPrem mapping (recap table)

| Revocation primitive | OnPrem | AWS | Azure | GCP |
|---------------------|--------|-----|-------|-----|
| Disable principal | AD `userAccountControl` = 0x2 | `iam:UpdateAccessKey` status=Inactive | `az ad sp update --set accountEnabled=false` | `gcloud iam service-accounts disable` |
| Remove credential material | Delete user's password | Delete access key | Delete SP secret/cert | Delete SA key JSON |
| Terminate in-flight sessions | `klist purge` on DC (TGT) | No direct API — wait TTL or SCP deny | `revokeSignInSession` (refresh tokens only; access tokens remain valid until expiry) | OAuth token revoke endpoint |
| Block new authentications | Add user to "Denied RODC Password Replication" | Poison trust policy | Conditional Access block policy | Remove IAM binding |
| Org-wide session cap | GPO: `MaxTicketAge` = 1h | SCP: `sts:DurationSeconds` ≤ 3600 | Conditional Access: `signInFrequency` = 1h | `--valid-duration=3600s` for all keys |
| In-flight TTL gap | Up to `MaxTicketAge` (default 10h) | Up to `MaxSessionDuration` (default 1h, max 12h) | Up to token lifetime (default ~60 min) | Up to JWT `exp` claim (user-specified) |

## 🔴 Red Team view

Mid-session revocation leaves the attacker TTL-bound. If the attacker fetched an STS token with a 12-hour `MaxSessionDuration`, the defender's key-disable has no effect for 12 hours.

**Attacker pre-revocation strategy:**
1. On initial access, immediately call `sts:AssumeRole` with `--duration-seconds 43200` to get the longest possible session.
2. Create additional access keys on any IAM user they compromise — backup persistence.
3. Call `sts:GetCallerIdentity` in a 60-second loop to detect when the session stops working (revocation happened).

**Attacker mid-session behavior (after defender revokes source key):**
- STS session still works. Attacker accelerates lateral movement and data exfiltration.
- If the role trust policy changes (L4), new `AssumeRole` calls fail — but the current session continues.
- If an SCP deny is applied (L5), API calls from the in-flight session may start returning `AccessDenied` as SCPs propagate to the AWS control plane boundary.

**Maximizing TTL window (contained narrative):**
```
T+0m:  Attacker assumes role, requests 43200s TTL
T+2m:  GuardDuty fires InstanceCredentialExfiltration finding
T+5m:  Defender deactivates source IAM user's access keys (L1)
T+6m:  Attacker detects key deactivation (GetCallerIdentity still works)
T+7m:  Attacker runs: aws s3 sync s3://prod-data ./loot/
T+60m: STS session still valid. Attacker runs: aws ec2 describe-instances --region us-east-1 (recon for lateral targets)
T+180m: Defender attaches SCP DenyAll to OU (L5)
T+195m: Attacker's next API call returns AccessDenied
T+43200s (12h): STS session expires regardless
```

**Artifacts:**
- CloudTrail `AssumeRole` with `durationSeconds: 43200` (long-duration request).
- Multiple successful API calls after `UpdateAccessKey` (status=Inactive) — proves TTL bypass.
- `GetCallerIdentity` polling pattern (1 call every 60 seconds) — heartbeat check.

## 🔵 Blue Team view

### Hardening: cap TTL org-wide

**AWS SCP:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "LimitSTSDuration",
    "Effect": "Deny",
    "Action": "sts:AssumeRole",
    "Resource": "*",
    "Condition": {
      "NumericGreaterThan": {"sts:DurationSeconds": "3600"}
    }
  }]
}
```

**Azure Conditional Access session control:**
```bash
az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/policies/conditionalAccessPolicies" \
    --body '{
        "displayName": "Max1HourSession",
        "state": "enabled",
        "sessionControls": {
            "signInFrequency": {"value": 1, "type": "hours", "isEnabled": true}
        }
    }'
```
> (as of June 2026, `signInFrequency` enforcement applies at token refresh time, not at exact boundary; a token obtained at 09:00 with a 1-hour policy may still be valid until the next refresh event, which can be up to 1 hour after the boundary.)

**GCP org policy:**
```bash
gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
    --member="domain:example.com" \
    --role="roles/iam.serviceAccountKeyAdmin" \
    --condition='expression=resource.name.endsWith("invalid")'
```
GCP service account key lifetime is not org-policy-controllable at creation time. Enforce via Cloud Asset Inventory periodic sweep: delete any key older than 7 days or with no `validAfterTime`.

### Alert: STS TTL > 1h

```sql
-- AWS CloudTrail Lake query
SELECT eventTime, userIdentity.arn, requestParameters.durationSeconds
FROM cloudtrail_events
WHERE eventName = 'AssumeRole'
  AND requestParameters.durationSeconds > 3600
  AND eventTime > now() - interval '1' day
```

### Post-revocation validation script

```bash
#!/bin/bash
ROLE_ARN="arn:aws:iam::111111111111:role/CompromisedRole"

echo "Attempting AssumeRole (should FAIL)"
aws sts assume-role --role-arn $ROLE_ARN \
    --role-session-name "revocation-test-$(date +%s)" 2>&1
if [ $? -ne 0 ]; then
    echo "✅ Trust policy poisoned successfully"
else
    echo "❌ AssumeRole still possible — revocation incomplete"
fi

echo "Checking existing sessions via CloudTrail"
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time "$(date -u -d '1 hour ago' +%s)" \
    --query "Events[?CloudTrailEvent.contains('$ROLE_ARN')]" | \
    jq -r '.[] | "\(.EventTime) \(.Username) — session may still be live"'
```

### Runbook note

> STS sessions cannot be revoked mid-flight by the AWS IAM API. If the attacker has an active session, you must either (a) wait out the TTL, (b) attach an SCP deny-all to the OU (propagation ~minutes), or (c) rotate the underlying resource's encryption keys to force AccessDenied on data-plane calls (S3/KMS/DynamoDB). Document the TTL gap in the incident timeline as a known limitation.

## Hands-on lab

1. Create an IAM role with `MaxSessionDuration=43200` (12h).
2. Assume the role: `aws sts assume-role --role-arn <arn> --role-session-name test --duration-seconds 43200`.
3. Export the returned credentials.
4. From another terminal, deactivate the source user's access keys and attach deny-all policy to the role.
5. Verify: new `AssumeRole` calls fail, but the exported session credentials still work.
6. Wait or forcibly revoke via SCP. Document the delta.
7. Teardown: delete role, user, SCP.

## Detection rules & checklists

```yaml
title: STS AssumeRole Duration Exceeds 1 Hour
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AssumeRole
    requestParameters.durationSeconds|gt: 3600
  condition: selection
  severity: medium
```

- [ ] SCP capping `sts:DurationSeconds` ≤ 3600 deployed org-wide.
- [ ] CloudTrail alert on `AssumeRole` with `durationSeconds > 3600`.
- [ ] Revocation runbook includes TTL-gap documentation and wait-period checklist.
- [ ] Quarterly test: assume a role, revoke source key, measure effective kill time.

## References

- [AWS STS temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
- [AWS SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [Azure AD revoke user access](https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/users-revoke-access)
- [GCP service account keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys)
- See ATT&CK Cloud matrix for Credential Access, Persistence
