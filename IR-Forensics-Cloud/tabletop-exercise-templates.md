# 09 — Tabletop Exercise Templates

> **Level:** Intermediate
> **Prereqs:** All modules 01–11
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** All (scenario-dependent)
> **Authorization scope:** Tabletop exercises are discussion-based; no production changes. All inject messages use placeholder accounts (`example.com`, `111111111111`, `00000000-0000-0000-0000-000000000000`).

## What & why

Tabletop exercises are the most cost-effective incident response rehearsal. A structured scenario, inject messages, and decision cards force the team to navigate the IR lifecycle under time pressure — surfaced gaps in runbooks, tooling, and cross-team communication cost nothing to fix before a real incident.

## The OnPrem reality

On-prem tabletops were fire-drill analogues: "A fire breaks out in the server room — who calls facilities?" Facilitators read from printed scripts. Cloud tabletops add the dimensions of IAM session physics, ephemeral resource loss, multi-account blast radius, and managed-service dependencies.

## Core concepts

### Tabletop anatomy

```
Pre-brief (15 min)  →  Rules of engagement, scope, SLOs
Inject 1 (10 min)   →  Initial signal: alert, finding, or user report
Inject 2 (15 min)   →  Escalation: additional telemetry, logs available
Inject 3 (20 min)   →  Twist: something unexpected (attacker changes TTPs, legal hold)
Inject 4 (15 min)   →  Containment decisions: who does what, in what order
Hot wash (20 min)   →  What worked, what didn't, action items
Post-mortem (1 wk)  →  Written report, tracked improvements
```

### Scenario template structure

```yaml
scenario:
  id: TT-001
  title: "Leaked CI Runner Token in Public Repo"
  difficulty: Intermediate
  duration: 90 min
  roles: [IC, Scribe, IR-Responder, Legal-Liaison, Engineering-Liaison]
  clouds: [AWS, Azure, GCP]  # pick one per exercise
  prereqs: [Module-02, Module-06, Module-09, Module-10, Module-11]
```

## Scenario: "Leaked CI Runner Token" — detailed walkthrough

### Background (read to participants)

Your organization runs CI/CD on GitHub Actions with OIDC federation to AWS / workload identity to Azure / Workload Identity Federation to GCP. A developer accidentally committed a `.env` file containing a long-lived IAM access key to a public repo 2 hours ago. The key has `AdministratorAccess` on the production account.

**Current state:** GuardDuty just fired `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom`. Three EC2 instances in `us-east-1` are showing 100% CPU (cryptomining). The compromised key was used 47 minutes ago to create a new IAM user `backdoor_admin` with full admin privileges.

### Inject 1 — Initial alert (T+0:00)

> **Inject message:** "Security On-Call, this is your automated monitoring system. GuardDuty finding `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` fired at 14:23 UTC for IAM user `ci-deployer`. The source IP `198.51.100.77` is geolocated to a country we have no operations in. Additionally, `iam:CreateUser` was called creating user `backdoor_admin` at 14:25 UTC. What are your first three actions?"

**Decision card — AWS:**
1. Freeze: no `TerminateInstances`, no `DeleteUser` — preserve evidence first.
2. Deactivate the `ci-deployer` access key immediately: `aws iam update-access-key --user-name ci-deployer --access-key-id AKIA... --status Inactive`.
3. Attach deny-all inline policy to `ci-deployer` and the newly created `backdoor_admin`.

**Decision card — Azure:**
1. Same freeze principle. Disable the leaked service principal: `az ad sp update --id <sp-id> --set accountEnabled=false`.
2. Remove role assignments for the SP.
3. Revoke sign-in sessions: `az rest --method POST --uri "https://graph.microsoft.com/v1.0/users/<sp-id>/revokeSignInSessions"`.

**Decision card — GCP:**
1. Disable the leaked service account: `gcloud iam service-accounts disable sa-ci-deployer@project.iam.gserviceaccount.com`.
2. Delete the leaked key: `gcloud iam service-accounts keys delete <key-id> --iam-account=sa-ci-deployer@...`.
3. Check for any new service accounts created: `gcloud iam service-accounts list --filter="createTime>-PT2H"`.

### Inject 2 — Expanded telemetry (T+0:10)

> **Inject message:** "CloudTrail analysis shows the following activity from the leaked key between 13:30 and 14:23 UTC:
> - `ec2:RunInstances` — launched 3 `c5.xlarge` instances in `us-east-1` (now at 100% CPU)
> - `iam:CreateAccessKey` — created a backup key on user `ci-deployer` (key ID `AKIA...BACKUP`)
> - `iam:CreateUser` — created `backdoor_admin`
> - `iam:AttachUserPolicy` — attached `AdministratorAccess` to `backdoor_admin`
> - `s3:ListBuckets` — called against all buckets; `s3:GetObject` against `prod-customer-data` bucket (7 objects, total 3.2 GB downloaded)
>
> The `backdoor_admin` user has not made any further API calls after creation. The STS session TTL for the compromised `ci-deployer` key is 1 hour from initial use (expires ~14:30 UTC). What is your containment strategy?"

**Decision card:**
1. Snapshot the three EC2 instances (evidence) → quarantine SG → stop.
2. Deactivate the backup key on `ci-deployer`.
3. DO NOT delete `backdoor_admin` — leave as-is for forensic analysis; instead attach deny-all.
4. Rotate the OIDC trust (GitHub → AWS IAM) to invalidate future federation.
5. Alert legal: 3.2 GB customer data exfiltration = mandatory breach notification threshold.

**Table discussion points:**
- Did we catch this within the STS TTL window? (Yes — 1h TTL, detection at ~50 min.)
- What if the attacker used `sts:AssumeRole` with `--duration-seconds 43200`? (Then the window is 12h — our playbook must cover that gap.)
- Are S3 Data Events enabled on `prod-customer-data`? If not, we cannot confirm the 3.2 GB exfiltration — we only know `GetObject` was called.

### Inject 3 — Twist: attacker adaptation (T+0:20)

> **Inject message:** "At 14:31 UTC, CloudTrail shows `backdoor_admin` user called `ec2:DescribeInstances` from a new IP `203.0.113.42` — but you disabled `ci-deployer` and attached deny-all to `backdoor_admin` at 14:27. How is this possible? Additionally, one of the three cryptomining instances just terminated itself via `ec2:TerminateInstances` — evidence is potentially lost."

**Discussion points:**
- The `backdoor_admin` still has an active session from before the deny-all was attached (STS TTL physics — see [05-iam-revocation](./iam-revocation-and-session-physics.md)).
- The attacker detected IR activity (key deactivation, policy attachment) and is destroying evidence (`TerminateInstances`).
- Do we have an SCP that prevents `TerminateInstances` without `forensic=complete` tag? (If yes, it would have blocked this.)
- The instance was likely terminated by the attacker using the still-valid `backdoor_admin` session — session revocation didn't propagate in time.

**Decision card:**
1. Attach org-level SCP `Deny ec2:TerminateInstances` to the production OU (propagation may take minutes).
2. Snapshot remaining two instances immediately.
3. Check if the terminated instance was in an ASG — if so, the replacement instance may contain the same cryptominer image (AMIs aren't tampered with, but launch config may be).

### Inject 4 — Containment execution (T+0:30)

> **Inject message:** "The SCP has propagated. The two remaining cryptomining instances have been snapshotted and stopped. `backdoor_admin` sessions appear to have stopped making API calls — likely SCP took effect. Legal asks: 'Can we prove the 3.2 GB was actually exfiltrated? The customer needs a breach notification within 72 hours.' Engineering asks: 'Can we rotate the CI/CD OIDC trust and resume deployments by EOD?'"

**Decision card — AWS:**
1. Confirm S3 Data Events were enabled. If yes, export the object list and share with legal.
2. If S3 Data Events were NOT enabled, you have: the `s3:GetObject` CloudTrail event (proves access was attempted) and VPC Flow Logs showing outbound bytes from the NAT Gateway (proves data volume left the VPC). These together are sufficient for regulatory reporting.
3. Rotate OIDC trust: remove the GitHub Actions role trust policy entry for the old repo, add for a new, cleaned repo.
4. Rotate all IAM keys in the account — the attacker had `AdministratorAccess` and could have created more backdoors we haven't found yet.

**Decision card — Azure:**
1. Confirm Storage diagnostic logs for the exfiltrated blob container.
2. Rotate federated identity credential for the GitHub Actions workload identity.
3. Force password reset for all users in the tenant (attacker could have created backdoor accounts in Azure AD).

**Decision card — GCP:**
1. Confirm Data Access audit logs for GCS bucket.
2. Rotate Workload Identity Federation pool and provider.
3. Full IAM policy audit: `gcloud asset search-all-iam-policies --scope=projects/PROJECT_ID`.

### Hot wash questions

1. MTTD: How long between key leak and GuardDuty alert? (Should be measured.)
2. MTTC: How long between alert and effective containment? (Includes SCP propagation time.)
3. Scope completeness: Did we identify all resources the attacker touched?
4. Artifacts captured: Did we preserve snapshots + memory + logs before destroying evidence?
5. STS TTL gap: Did our revocation work, or did sessions outlive our controls?
6. Runbook: Was the runbook followed? Were there gaps?

## Scenario template catalog

| Scenario ID | Title | Difficulty | Duration | Key cloud concepts |
|-------------|-------|-----------|----------|-------------------|
| TT-001 | Leaked CI Runner Token | Intermediate | 90 min | IAM revocation, STS TTL, S3 data exfil |
| TT-002 | SSRF to Metadata → Credential Exfil | Intermediate | 60 min | IMDSv1/v2, instance profiles, credential lifespan |
| TT-003 | Compromised Third-Party SaaS OAuth Token | Advanced | 120 min | OAuth scope, cross-account access, session revocation |
| TT-004 | Cryptominer on Auto-Scaling Spot Fleet | Advanced | 90 min | Spot instance forensics, lifecycle hooks, container escape |
| TT-005 | Ransomware on RDS / Managed DB | Advanced | 120 min | DB snapshot recovery, KMS key deletion, point-in-time restore |
| TT-006 | Insider Threat: DevOps Admin Exfiltrating Code | Intermediate | 60 min | CodeCommit/GitHub Enterprise audit, S3 bucket policy bypass |
| TT-007 | Supply Chain: Malicious Terraform Module | Advanced | 90 min | IaC drift detection, state file forensics, provider audit |
| TT-008 | Defense Evasion: Logging Disabled + Trail Deleted | Intermediate | 60 min | Org trail, cross-account logging, log gap detection |

## 🔴 Red Team view

The tabletop facilitator playing the "attacker" role must vary TTPs to keep the blue team from memorizing responses:

**Variant 1: Sessions NOT disabled.** In TT-001, have the attacker use `AssumeRole` with 12h TTL instead of a long-lived access key. The defender's key-disable play has zero effect — the tabletop must expose this gap.

**Variant 2: The decoy deployment.** The attacker creates `backdoor_admin` but never uses it. Instead, they created a third user `auditor_2026` that was missed in triage. The defender declares "all backdoors closed" but `auditor_2026` persists.

**Variant 3: The log gap.** The attacker calls `cloudtrail:StopLogging` for 15 minutes before the exfiltration. The defender's timeline has a gap and must explain to legal why they can't prove what happened during those 15 minutes.

**Artifacts for the facilitator to plant (inject 0):**
- A CloudTrail event showing `AssumeRole` with `durationSeconds: 43200`
- A GitHub commit time matching the compromise window
- S3 Data Events showing `GetObject` on `prod-customer-data/*`

## 🔵 Blue Team view

### Metrics to track per tabletop

```
MTTD (Mean Time to Detect):     _____ minutes (target: < 15 min for P1)
MTTC (Mean Time to Contain):    _____ minutes (target: < 60 min for P1)
MTTR (Mean Time to Recover):    _____ hours
Scope completeness:             _____ % of compromised resources identified
Artifacts captured:             _____ % of forensic artifacts preserved
Runbook deviations:             _____ steps not followed or missing
```

### Quarterly cadence checklist

```
[ ] Select one scenario from the catalog (rotate)
[ ] Assign facilitator (ideally external to the IR team)
[ ] Notify participants 2 weeks in advance
[ ] Book 2-hour block in a conference room (or video call)
[ ] Prepare inject messages + decision cards (printed)
[ ] Run exercise
[ ] Record all decisions, timestamps, and gaps
[ ] Hot wash: collect 3 action items maximum
[ ] Post-mortem report: due 1 week after exercise
[ ] Track action items to closure in the next sprint
```

### Post-tabletop improvements register template

```markdown
| ID | Finding | Severity | Owner | Due Date | Status |
|----|---------|----------|-------|----------|--------|
| TT-001-1 | Runbook missing "Deactivate backup keys" step | High | @security-lead | 2026-07-15 | Open |
| TT-001-2 | S3 Data Events not enabled on prod-customer-data | Critical | @platform-team | 2026-07-01 | Open |
| TT-001-3 | No SCP capping STS TTL to 1h | High | @cloud-admin | 2026-07-08 | Open |
```

### Custom inject builder (per-cloud)

```bash
# AWS: generate GuardDuty sample findings for any attack pattern
aws guardduty create-sample-findings \
    --detector-id <detector-id> \
    --finding-types "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"

# Azure: Sentinel test alert
az sentinel alert-rule create \
    --resource-group security-rg \
    --workspace-name sentinel-ws \
    --rule-name "Test-TT001-LeakedKey" \
    --query '...'

# GCP: SCC test finding (requires Security Command Center Premium)
# Simulate via gcloud logging write:
gcloud logging write test-log-entry \
    '{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","authenticationInfo":{"principalEmail":"ci-deployer@project.iam.gserviceaccount.com"},"methodName":"iam.serviceAccounts.create"}}' \
    --payload-type=json
```

## Hands-on lab

1. Pick one scenario (TT-001 recommended for first run).
2. Identify 3-4 colleagues. Assign roles: Incident Commander, Scribe, Responder, Legal Liaison.
3. Facilitator: pre-brief with rules (no blaming, no production changes, time-boxed).
4. Run Inject 1 → discuss → Inject 2 → discuss → Inject 3 → discuss → Inject 4 → discuss.
5. Hot wash: record top 3 action items.
6. Write post-mortem report within 1 week.
7. Track action items in your team's issue tracker.

## Detection rules & checklists

```yaml
# Not a detection rule, but a readiness check
title: Tabletop Exercise Readiness
checklist:
  - Quarter: Q3 2026
  - Scenario: TT-001 Leaked CI Runner Token
  - Facilitator: @external-consultant
  - Participants confirmed: [IC, Scribe, Responder, Legal]
  - Runbook version: v2.3 (reviewed and printed)
  - Previous TT action items closed: 7/7
  - Exercise date: 2026-08-15
severity: informational
```

- [ ] Tabletop catalog maintained with ≥ 4 scenarios.
- [ ] One tabletop exercise run per quarter.
- [ ] Post-tabletop action items tracked in sprint board.
- [ ] Runbook updated within 2 weeks of each tabletop to incorporate findings.
- [ ] Scenario injects updated annually to reflect new threat intelligence.

## References

- [CISA Tabletop Exercise Package (CTEP)](https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages)
- [NIST SP 800-84 — Guide to Test, Training, and Exercise Programs](https://csrc.nist.gov/publications/detail/sp/800-84/final)
- [AWS Incident Response Playbook](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-incident-response-playbook.html)
- [Azure incident response exercises](https://learn.microsoft.com/en-us/azure/security/fundamentals/incident-response)
- [GCP incident response planning](https://cloud.google.com/docs/security/incident-response)
