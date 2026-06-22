# 05 — Auto-Response: Isolate and Quarantine

> **Level:** Advanced
> **Prereqs:** [Alert To Action SOC Tiers](../Monitoring-Detection-SIEM/alert-to-action-soc-tiers.md), [Blast Radius Reduction Patterns](blast-radius-reduction-patterns.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Persistence, Lateral Movement
> **Authorization scope:** Run auto-response playbooks only in your own sandbox accounts against resources you own.

## What & why

When a threat detection alert fires, automation must isolate before a human reads the ticket. Compute isolation (detach/terminate instance), identity isolation (invalidate tokens, deny policies), network isolation (swap to quarantine security group) — all executed within seconds of detection. Manual response means the attacker has the full MTTR window to persist and exfiltrate.

> ⚠️ **Critical caveat — AWS STS sessions cannot be revoked mid-TTL.** Active temporary credentials remain valid until their natural expiry. Isolation must therefore rotate or deny the *source of trust* (the IAM User key or IAM Role trust policy that issued the session), not just the session itself.

## The OnPrem reality

On-prem auto-response was coarse: a SOC analyst's SIEM alert fires, they SSH into the switch and shut the VLAN (`interface GigabitEthernet0/1; shutdown`) or disable the AD account (`Disable-ADAccount -Identity victim_user`). This took minutes, gave false positives that nuked business traffic, and required the analyst to be awake. Cloud auto-response can be surgical — isolate one instance, one role, one security group — without taking down a subnet.

## Cross-cloud comparison

| Provider | Compute isolate | Identity isolate | Network isolate | Playbook engine |
|---|---|---|---|---|
| AWS | SSM Automation `AWS-StopEC2Instance` / `AWS-DetachIAMRole` | SCP Deny * + rotate source key / update trust policy | Swap to quarantine SG via `ec2:ModifyInstanceAttribute` | EventBridge → Lambda / Step Functions |
| AWS | GuardDuty → Lambda → `ec2:TerminateInstances` | Revoke IAM role sessions (`PutRolePolicy` with `DateLessThan`) | `ec2:ReplaceRouteTableAssociation` | GuardDuty → EventBridge → Lambda |
| Azure | Azure Automation `Stop-AzVM` / Sentinel Playbook | Conditional Access block + `Revoke-AzureADUserAllRefreshToken` | `Set-AzNetworkSecurityGroup` on VM NIC | Sentinel Playbook (Logic App) |
| Azure | Defender for Cloud → Logic App | Disable Service Principal (`az ad sp update --account-enabled false`) | NSG rule change (`DenyAllInbound`) | Defender → Logic Apps connector |
| GCP | `gcloud compute instances stop` via Cloud Function | Remove IAM bindings + disable SA key | Firewall rule insert (`DENY_ALL` priority 0) | Eventarc → Cloud Function / Workflows |
| GCP | OS Config patch to disable SSH | `gcloud iam service-accounts keys delete` | VPC firewall rule update | SCC finding → Pub/Sub → Cloud Function |

## AWS

**Compute quarantine — detach IAM role + stop instance:**

```bash
aws ssm start-automation-execution \
  --document-name "AWS-DetachIamRoleFromInstance" \
  --parameters '{"InstanceId":["i-0abcd1234efgh5678"]}'

aws ec2 stop-instances --instance-ids i-0abcd1234efgh5678
```

**Identity quarantine — deny all future API calls for a compromised role:**

```bash
aws iam put-role-policy --role-name CompromisedRole --policy-name QuarantineDenyAll --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "Quarantine",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "DateGreaterThan": {"aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}
    }
  }]
}'
```

This inline deny policy applies only to new STS sessions — existing sessions are not affected. To close the window for existing sessions, you must rotate the source-of-trust.

**Source-of-trust rotation (closes the STS session window):**

```bash
aws iam update-role --role-name CompromisedRole \
  --max-session-duration 900

aws iam update-assume-role-policy --role-name CompromisedRole \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole"
    }]
  }'
```

> (as of June 2026, changing an `AssumeRole` trust policy does NOT invalidate already-issued STS tokens. It only prevents new `AssumeRole` calls. Active sessions remain valid until their TTL expires. No AWS API exists to revoke in-flight STS sessions.)

**Network quarantine — swap to quarantine security group:**

```bash
aws ec2 modify-instance-attribute \
  --instance-id i-0abcd1234efgh5678 \
  --groups sg-0quarantinexxxxxxxx

aws ec2 revoke-security-group-ingress \
  --group-id sg-0compromisedxxxxxx \
  --protocol all --port all --cidr 0.0.0.0/0
```

**Full automation — EventBridge → Step Functions playbook:**

```json
{
  "detail-type": ["GuardDuty Finding"],
  "source": ["aws.guardduty"],
  "detail": {
    "type": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"],
    "severity": [{"numeric": [">=", 7]}]
  }
}
```

Step Functions workflow:
1. `DetachIamRoleFromInstance` (SSM)
2. `ModifyInstanceAttribute` → swap SG to quarantine
3. `StopEC2Instance` (optional, severity-dependent)
4. `CreateSnapshot` (forensic snapshot of EBS volumes)
5. `PublishSNS` → SOC + PagerDuty
6. `PutRolePolicy` → deny new sessions on compromised role

## Azure

**Compute quarantine — Sentinel Playbook (Logic App):**

```json
{
  "type": "Microsoft.Compute/virtualMachines/stop",
  "apiVersion": "2023-03-01",
  "parameters": {
    "resourceGroupName": "rg-prod",
    "vmName": "vm-compromised-01"
  }
}
```

**Identity quarantine — block user + revoke tokens:**

```bash
az ad user update --id compromised@example-tenant.onmicrosoft.com \
  --account-enabled false

az ad user revoke-sign-in-session \
  --id compromised@example-tenant.onmicrosoft.com

az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/users/00000000-0000-0000-0000-000000000000/revokeSignInSessions"
```

**Network quarantine — attach deny-all NSG:**

```bash
az network nic update \
  --resource-group rg-prod \
  --name vm-compromised-01-nic \
  --network-security-group nsg-quarantine

az network nsg rule create \
  --resource-group rg-prod \
  --nsg-name nsg-quarantine \
  --name DenyAllInbound \
  --priority 100 \
  --direction Inbound \
  --access Deny \
  --protocol '*' \
  --source-address-prefixes '*' \
  --destination-port-ranges '*'
```

## GCP

**Compute quarantine:**

```bash
gcloud compute instances stop vm-compromised-01 \
  --zone us-east1-b \
  --project project-id-111111

gcloud compute instances remove-iam-policy-binding vm-compromised-01 \
  --zone us-east1-b \
  --member "serviceAccount:vm-compromised-sa@project-id-111111.iam.gserviceaccount.com" \
  --role roles/iam.serviceAccountUser
```

**Identity quarantine:**

```bash
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account compromised-sa@project-id-111111.iam.gserviceaccount.com

gcloud projects remove-iam-policy-binding project-id-111111 \
  --member "serviceAccount:compromised-sa@project-id-111111.iam.gserviceaccount.com" \
  --role roles/editor
```

**Network quarantine — insert deny-all firewall rule:**

```bash
gcloud compute firewall-rules create quarantine-deny-all \
  --priority 0 \
  --direction INGRESS \
  --action DENY \
  --rules all \
  --source-ranges 0.0.0.0/0 \
  --target-tags quarantine \
  --project project-id-111111

gcloud compute instances add-tags vm-compromised-01 \
  --tags quarantine \
  --zone us-east1-b
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Compute stop | `shutdown /s` via SCCM / Ansible | `ec2:StopInstances` / SSM Automation | `Stop-AzVM` / Automation Account | `compute instances stop` |
| Identity disable | `Disable-ADAccount` + revoke Kerberos tickets | SCP Deny * + rotate trust policy | `--account-enabled false` + revoke sessions | Remove IAM bindings + delete SA keys |
| Network quarantine | Switch port shutdown / VLAN change | SG swap to quarantine + revoke ingress | NSG attach deny-all rule | Firewall rule insert priority 0 |
| STS session revoke | Kerberos TGT purge (`klist purge`) | Cannot revoke active STS; must rotate source | Revoke refresh tokens + sign-in sessions | OAuth token revocation endpoint |
| Forensic snapshot | dd / FTK Imager | EBS snapshot before terminate | VM disk snapshot | Persistent disk snapshot |
| Automation engine | SOAR (Splunk Phantom / XSOAR) | EventBridge + Step Functions | Sentinel Playbook (Logic App) | Eventarc + Workflows + Cloud Functions |

## 🔴 Red Team view

**Active STS sessions survive quarantine — the attacker's window.**

**Narrative (contained):**

A GuardDuty finding detects `InstanceCredentialExfiltration.OutsideAWS` at `T+0`. The auto-response playbook fires at `T+30s`:

1. Detaches the IAM role from the compromised EC2 instance. (New API calls from the instance now fail.)
2. Attaches SCP `Deny *` to the account. (New API calls from anywhere in the account now fail.)
3. Publishes SNS → SOC ticket at `T+45s`.

But the attacker's STS session (stolen from the metadata endpoint at `T-180s`) is valid for **1 hour** from issue time. The attacker's credentials:

```
AWS_ACCESS_KEY_ID=ASIA...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=...
Expiration: T+3540s
```

The attacker uses the remaining 58 minutes of session to:
1. Assume a role in a non-quarantined account that trusts the compromised account.
2. Create a backdoor IAM User in the trusted account.
3. Exfiltrate data from S3 buckets the compromised role could access.

**Why the window exists:**
STS tokens are bearer tokens — they are validated against the credential's expiry, not against the principal's current state. The trust policy was valid at issue time; the token remains valid until expiry regardless of trust policy changes.

**Artifacts:**
- CloudTrail: `AssumeRole` from the compromised account to a healthy account *after* the quarantine playbook executed.
- The `AssumedRole` events show `sessionContext.attributes.creationDate` predating the quarantine but the events timestamps postdate it.

## 🔵 Blue Team view

**Mitigate the STS token window:**

| Strategy | Implementation | Trade-off |
|---|---|---|
| Reduce session TTL | Set `MaxSessionDuration` to 900s (15 min) for all roles | More frequent credential refreshes; some long-running jobs break |
| Rotate source of trust | Deny assume-role trust policy — blocks new AssumeRole calls | Existing sessions survive; not a full revocation |
| SCP deny with `aws:TokenIssueTime` | Deny actions from tokens issued before a timestamp | SCP propagation has delay; attacker actions after SCP lands are blocked |
| Funnel to honey account | Replace target trust policy to redirect AssumeRole to a zero-perm honey role | Complex to orchestrate; risk of misconfigured redirect |
| Accept window, detect fast | Tighten detection + reduce MTTR SLO to < 5 minutes | Window still exists but shrinks with detection speed |

**Reduced session TTL — SCP enforcement:**

```json
{
  "Sid": "DenyLongSessions",
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "*",
  "Condition": {
    "NumericGreaterThan": {"sts:DurationSeconds": "3600"}
  }
}
```

**Quarantine playbook — full sequence with STS window mitigation:**

```bash
#!/usr/bin/env bash

COMPROMISED_ROLE_ARN="$1"
QUARANTINE_SG="$2"

echo "=== T+0: Quarantine initiated ==="

aws iam put-role-policy --role-name CompromisedRole \
  --policy-name QuarantineDeny --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny", "Action": "*", "Resource": "*",
      "Condition": {
        "DateGreaterThan": {"aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}
      }
    }]
  }'

aws iam update-assume-role-policy --role-name CompromisedRole \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny", "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole"
    }]
  }'

sleep 5

aws ec2 modify-instance-attribute \
  --instance-id i-0compromisedxxx \
  --groups "$QUARANTINE_SG"

echo "=== T+30s: Quarantine applied. Active STS session window: check creation time ==="

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '60 minutes ago' +%s) \
  --query 'Events[?Username==`CompromisedRole`]'
```

**Detect post-quarantine activity (attacker using surviving STS session):**

```
SELECT eventTime, eventName, sourceIPAddress, userIdentity.sessionContext.creationDate
FROM cloudtrail_111111111111
WHERE userIdentity.arn LIKE '%CompromisedRole%'
  AND eventTime > '2026-06-22T01:00:00Z'
  AND eventName NOT IN ('GetCallerIdentity', 'LookupEvents')
ORDER BY eventTime DESC
```

Cross-link: [02-06 Permission Boundaries & Quarantine](../IAM/permission-boundaries-and-quarantine.md), [06-08 Alert-to-Action SOC Tiers](../Monitoring-Detection-SIEM/alert-to-action-soc-tiers.md), [09-08 Evasion](../Red-Team-Offense/evasion-and-trail-free-actions.md).

## Hands-on lab

Not a standalone lab. Quarantine mechanics are exercised in [labs/honey-token-lab.md](labs/honey-token-lab.md).

## Detection rules & checklists

**Detect quarantine execution — for audit:**

See [`detections/quarantine-action-detection.md`](detections/quarantine-action-detection.md).

**Checklist:**
- [ ] Auto-response playbook fires within 60 seconds of GuardDuty/Defender/SCC finding.
- [ ] Playbook cannot be stopped by deleting the Lambda/Logic App — use SCP to deny `lambda:DeleteFunction` on the playbook function.
- [ ] STS session TTL set to maximum 15 minutes for all workload roles.
- [ ] Quarantine playbook tested quarterly with red-team simulation.
- [ ] Post-quarantine CloudTrail query runs automatically for 1 hour after isolation.

## References
- [AWS SSM Automation — runbooks](https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-documents.html)
- [Azure Sentinel Playbooks](https://learn.microsoft.com/en-us/azure/sentinel/automate-responses-with-playbooks)
- [GCP Eventarc + Workflows](https://cloud.google.com/eventarc/docs)
- [AWS STS Temporary Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
- [MITRE ATT&CK — Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
