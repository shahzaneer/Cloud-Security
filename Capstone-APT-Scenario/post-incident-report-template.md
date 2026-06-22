# 06 — Post-Incident Report Template

> **Level:** Intermediate
> **Prereqs:** [Triage & Severity per Cloud](../IR-Forensics-Cloud/triage-and-severity-per-cloud.md), [Pairing Red Blue Timeline](pairing-red-blue-timeline.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** All (reporting)
**Authorization scope:** Capstone labs are to be run only against learner-owned sandbox accounts. Placeholder accounts are used throughout. No live attack surfaces.

## What & why

After completing the red lab ([13-03](./red-variant-walkthrough.md)) and blue lab ([13-04](./blue-variant-walkthrough.md)), the learner produces a formal post-incident report. This documents the full lifecycle — what happened, what worked, what failed, what was learned, and what must change. The report format follows the SANS/ITIL post-incident structure adapted for cloud.

## The OnPrem reality

Traditional ITIL post-incident reports (PIRs) followed a 5-section format: Incident Summary, Timeline, Root Cause Analysis (RCA), Actions Taken, Lessons Learned. Cloud PIRs add: cross-cloud attribution (which account/project/subscription was touched), IAM session-chain reconstruction, and compliance posture Delta (pre- vs post-incident scans).

## Core concepts

### Report sections

```
1. Executive Summary (½ page) — CISO-readable; what happened, impact, containment status
2. Timeline (see 13-05) — red events + blue detections + gaps
3. Root Cause Analysis — the deliberate misconfigurations
4. Detection Performance — MTTD, MTTR, detection coverage
5. Actions Taken — containment, eradication, recovery steps
6. Lessons Learned — what must change (detection gaps, process, tooling)
7. Compliance Delta — pre- vs post-incident posture scan diff
8. Costs — estimated/placeholder cost of incident (compute, data egress, human hours)
9. Appendices — raw logs, evidence chain, IAM session diagram
```

---

## Post-Incident Report Template

```markdown
# Post-Incident Report — Capstone APT Exercise

**Report ID:** CAP-PIR-001
**Date:** <YYYY-MM-DD>
**Author:** <learner-name>
**Classification:** Internal — Purple-Team Exercise
**Cloud(s):** AWS / Azure / GCP (circle one or more)
**Accounts affected:** 111111111111, 222222222222, 333333333333

---

## 1. Executive Summary

On <YYYY-MM-DD>, during a scheduled purple-team exercise (Capstone Module 13), a red team
simulated an APT killchain against the deliberately-vulnerable sandbox organisation. The attacker
achieved initial access via <SSRF→IMDS / leaked CI key> at T+00:03, escalated privileges via
<PassRole→Lambda / role elevation / token impersonation> at T+00:05, persisted through
<new IAM user / new service principal / new service account> at T+00:08, moved laterally
across 3 accounts/projects at T+00:13, and collected <N> objects from the data bucket at T+00:18.
A destruction attempt against WORM-protected data was denied. The blue team detected the
intrusion at T+<XX:XX> (MTTD = <X> min) and completed containment at T+<XX:XX> (MTTR = <X> min).
No production data was exfiltrated; all operations were scoped to the sandbox.

**Conclusion:** <brief assessment — e.g., "Detection pipeline caught 6 of 7 stages within SLO.">

---

## 2. Timeline

| T+ | Actor | Event | Log source | Detection rule | Fired? |
|---|---|---|---|---|---|
| 00:00 | Red | Public bucket enumeration | CloudTrail `s3:ListObjects` | CAP-RECON-01 | <Y/N> |
| 00:02 | Red | SSRF→IMDS `GetCallerIdentity` | CloudTrail `sts:GetCallerIdentity` | CAP-IA-01 | <Y/N> |
| 00:05 | Red | `iam:PassRole` + `lambda:CreateFunction` | CloudTrail `iam:PassRole` | CAP-PE-01 | <Y/N> |
| 00:08 | Red | `iam:CreateAccessKey` / `CreateUser` | CloudTrail `iam:CreateAccessKey` | CAP-PER-01 | <Y/N> |
| 00:13 | Red | `sts:AssumeRole` chain (3 accounts) | CloudTrail `sts:AssumeRole` | CAP-LM-01 | <Y/N> |
| 00:17 | Red | `s3:GetObject` storm | CloudTrail S3 data event | CAP-COLL-01 | <Y/N> |
| 00:20 | Red | `s3:DeleteObject` denied (WORM) | CloudTrail `s3:DeleteObject` (AccessDenied) | CAP-IMP-01 | <Y/N> |
| <T+X> | Blue | First detection fires | GuardDuty / Sentinel / SCC | — | ✓ |
| <T+X> | Blue | Containment: key deactivated | CloudTrail `iam:UpdateAccessKey` | — | ✓ |
| <T+X> | Blue | Eradication: backdoor user deleted | CloudTrail `iam:DeleteUser` | — | ✓ |
| <T+X> | Blue | Recovery: IaC baseline re-applied | CloudTrail (multiple) | — | ✓ |

> Full timeline with detection gaps in [13-05: Pairing Red & Blue Timeline](./pairing-red-blue-timeline.md).

---

## 3. Root Cause Analysis

### 3.1 Deliberate misconfigurations (placed for exercise)

| # | Weakness | Resource | Cloud | Module ref for fix |
|---|---|---|---|---|
| 1 | BlockPublicAccess OFF, ACL `public-read` | S3 bucket `capstone-data-111111111111` / blob container / GCS bucket | AWS/Azure/GCP | [04-02](../Storage-Data-Security/public-exposure-and-block-public.md) |
| 2 | CI runner with `AdministratorAccess`/Owner/`roles/owner` | IAM user `ci-deployer` / SP / SA | AWS/Azure/GCP | [08-06](../IaC-Security/cicd-runner-as-cloud-principal.md) |
| 3 | IMDSv1 allowed on web tier instance | EC2 / VMSS / GCE | AWS/Azure/GCP | [03-XX](../Compute-Container-Security/) |
| 4 | `iam:PassRole` to `*` on Lambda execution role | IAM role `ProdLambdaExecRole` / Function App managed identity / SA | AWS/Azure/GCP | [02-06](../IAM/permission-boundaries-and-quarantine.md) |
| 5 | AssumeRole trust policy with `"Principal": "*"` | IAM role `CrossAccountRole-SharedServices` | AWS | [02-03](../IAM/assume-role-chains-and-trust-graphs.md) |
| 6 | No MFA on IAM user, long-lived key | `ci-deployer` | AWS | [02-04](../IAM/long-lived-keys-vs-workload-identity.md) |

### 3.2 Detection gaps (identified during exercise)

| # | Gap | Impact | Recommendation |
|---|---|---|---|
| 1 | <e.g., No S3 data events enabled on the capstone trail> | <Collection stage went undetected> | <Enable S3 data events on all trails> |
| 2 | | | |
| 3 | | | |

---

## 4. Detection Performance

| Metric | SLO | Actual | Met? | Notes |
|---|---|---|---|---|
| MTTD (first red action → first alert) | ≤ 15 min | <X> min | <Y/N> | |
| MTTR (first alert → containment) | ≤ 30 min | <X> min | <Y/N> | |
| Detection coverage (stages with ≥1 alert) | ≥ 6/7 | <X>/7 | <Y/N> | |
| False positives | 0 | <X> | <Y/N> | |
| Recovery (containment → posture restored) | ≤ 60 min | <X> min | <Y/N> | |

---

## 5. Actions Taken

### 5.1 Containment

| Timestamp | Action | Executor | CloudTrail/Log entry |
|---|---|---|---|
| <T+X> | Deactivated compromised access key `AKIAIOSFODNN7EXAMPLE` | SOC Analyst | `iam:UpdateAccessKey` (status=Inactive) |
| <T+X> | Attached deny-all inline policy to `ci-deployer` | SOC Analyst | `iam:PutUserPolicy` (Quarantine) |
| <T+X> | Revoked active sessions (reduced max session duration) | SOC Analyst | `iam:UpdateRole` (MaxSessionDuration=900) |
| <T+X> | Created EBS snapshot of compromised instance(s) | SOC Analyst | `ec2:CreateSnapshot` (evidence preservation) |
| <T+X> | Revoked inbound security group rules | SOC Analyst | `ec2:RevokeSecurityGroupIngress` (quarantine) |

### 5.2 Eradication

| Timestamp | Action | Executor | CloudTrail/Log entry |
|---|---|---|---|
| <T+X> | Deleted attacker-created IAM user `monitoring-service` | SOC Analyst | `iam:DeleteUser` |
| <T+X> | Deleted attacker-created access keys (all backups) | SOC Analyst | `iam:DeleteAccessKey` (×3) |
| <T+X> | Deleted attacker-created Lambda `capstone-escalate` | SOC Analyst | `lambda:DeleteFunction` |
| <T+X> | Rotated all legitimate ci-deployer keys | DevOps | `iam:CreateAccessKey` → `iam:UpdateAccessKey` |
| <T+X> | Fixed trust policy on `CrossAccountRole-SharedServices` (added ExternalId condition) | DevOps | `iam:UpdateAssumeRolePolicy` |

### 5.3 Recovery

| Timestamp | Action | Executor | Result |
|---|---|---|---|
| <T+X> | Applied Terraform baseline (`terraform apply`) | DevOps | All drifted resources reconciled |
| <T+X> | Ran prowler posture scan → all criticals resolved | SOC Analyst | Posture: compliant |
| <T+X> | Verified CloudTrail enabled on all regions | SOC Analyst | Logging: operational |

---

## 6. Lessons Learned

### 6.1 What worked well

1. <e.g., GuardDuty caught SSRF→IMDS within 5 min with zero false positives.>
2. <e.g., The IR runbook from Module 11-01 provided exact CLI commands for every containment step.>
3.

### 6.2 What needs improvement

1. <e.g., S3 data events were not enabled — the Collection stage had 11+ min detection gap.>
2. <e.g., The CreateAccessKey rule used a daily-batch pipeline — switched to real-time.>
3. <e.g., Cross-account AssumeRole detection fired on single hop but not on chain — add 3-hop correlation.>

### 6.3 Action items

| # | Owner | Action | Due date | Module ref |
|---|---|---|---|---|
| 1 | SOC Engineering | Enable S3 data events on all prod trails | <YYYY-MM-DD> | [06-02](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md) |
| 2 | SOC Engineering | Add `CAP-LM-01b`: 3-hop AssumeRole correlation rule | <YYYY-MM-DD> | [06-07](../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md) |
| 3 | Platform Team | Add SCP denying `iam:PassRole` on `*` | <YYYY-MM-DD> | [10-02](../Blue-Team-Defense/preventive-guardrails-as-code.md) |
| 4 | IR Team | Automate key deactivation via Lambda/Playbook/GCF | <YYYY-MM-DD> | [10-05](../Blue-Team-Defense/auto-response-isolate-and-quarantine.md) |
| 5 | CISO | Schedule quarterly purple-team re-run | <YYYY-MM-DD> | [13-05](./pairing-red-blue-timeline.md) |

---

## 7. Compliance Delta

### Pre-incident posture (from Day 0 scan)

```
AWS:
  prowler check3: FAIL (5 critical, 7 high, 3 medium)

Azure:
  Policy compliance: 67% compliant (expected: deliberately weak)

GCP:
  SCC active findings: 8 (HIGH: 3, MEDIUM: 5)
```

### Post-incident posture (after recovery)

```
AWS:
  prowler check3: PASS (0 critical, 0 high, 1 medium [acceptable])

Azure:
  Policy compliance: 100%

GCP:
  SCC active findings: 0
```

### Attestation

```
I attest that the above compliance comparison reflects the true state of the sandbox
organisation before and after the incident response exercise.

Signed: <learner-name>
Date: <YYYY-MM-DD>
```

---

## 8. Costs (placeholder — sandbox exercise)

| Cost category | AWS estimated | Azure estimated | GCP estimated | Notes |
|---|---|---|---|---|
| Compromised compute (cryptomining equivalent) | $0.00 (simulated) | $0.00 (simulated) | $0.00 (simulated) | Capstone uses free-tier; no cryptomining |
| Data egress (exfil staged) | $0.00 (local-only) | $0.00 (local-only) | $0.00 (local-only) | Data written to `localhost:9000` |
| Human hours — SOC response | <N> person-hours | — | — | Estimate: 2 analysts × 1 hour |
| Human hours — DevOps remediation | <N> person-hours | — | — | Estimate: 1 engineer × 1 hour |
| Sandbox infrastructure | Free-tier / $0 estimate | Free-tier / $0 estimate | Free-tier / $0 estimate | (Reminder: learner should check their cloud usage and billing to confirm no unexpected charges) |

---

## 9. Appendices

### Appendix A — Raw log excerpts

```
<Insert CloudTrail / Activity Log / Cloud Audit Log JSON snippets for key events>
```

### Appendix B — Evidence chain of custody

```
Item 1: EBS snapshot snap-0abcdef1234567890 — created T+X from instance i-0abcdef1234567890
Item 2: IAM credential report — downloaded T+X
Item 3: S3 access logs — capstone-data-access-logs — period T+00:00 to T+00:30
Hashes: <SHA-256 if applicable>
```

### Appendix C — IAM session diagram

```
ci-deployer (user, AKIAIOSFODNN7EXAMPLE)
  └─ AssumeRole → vulnerable-ec2-role (T+00:02)
      └─ lambda:CreateFunction → capstone-escalate (T+00:05)
          └─ runs as ProdLambdaExecRole (AdministratorAccess)
              └─ Creates monitoring-service user (T+00:08)
              └─ Creates backup key on ci-deployer (T+00:08)
  └─ AssumeRole → CrossAccountRole-SharedServices (333...) (T+00:13)
      └─ AssumeRole → StagingDeployRole (222...) (T+00:14)
          └─ AssumeRole → ProdSupportRole (111...) (T+00:15)
              └─ s3:GetObject storm (T+00:17)
              └─ s3:DeleteObject denied (T+00:20)
```

---
**END OF REPORT**
```

## 🔴 Red Team view — what red wants preserved in the report

From the attacker's perspective, the post-incident report preserves:

1. **Topology map** — what the attacker mapped during recon. The blue team should keep this as an "attacker's-eye view" of the organisation's attack surface for continuous improvement.
2. **`mass_accessed` list** — every resource the attacker enumerated/touched. This becomes the scope-of-compromise for legal/regulatory disclosure.
3. **Exfiltration paths** — which network egress points the data traversed. Used to tune DLP/network monitoring.
4. **TTL analysis** — how long credentials/roles remained usable after each action. Used to set `MaxSessionDuration` correctly.

Without these in the report, the blue team loses the attacker's actual map — they only have their own detection map, which is incomplete by definition.

## 🔵 Blue Team view — build the KPI matrix

### Versioned retro

```
v1.0 (first exercise): MTTD = <X> min, MTTR = <Y> min
v1.1 (after rule tuning): MTTD = <X'> min, MTTR = <Y'> min
```

Store each version in the capstone repo:
```
capstone/reports/
  CAP-PIR-001.md
  CAP-PIR-001-v1.1.md
  ...
```

### Track closure of action items

```
capstone/action-items/
  enable-s3-data-events.md (CLOSED: 2025-01-15)
  assume-role-chain-correlation.md (CLOSED: 2025-01-22)
  deny-passrole-scp.md (CLOSED: 2025-01-29)
  auto-key-deactivation.md (IN PROGRESS)
```

### "Show your work" backup refs

Every assertion in the report should be traceable to a log entry:

```
Claim: "GuardDuty fired at T+00:07."
Evidence: capstone/guardduty-findings.json, finding ID: arn:aws:guardduty:us-east-1:111111111111:detector/.../finding/abc123

Claim: "ci-deployer key deactivated at T+00:27."
Evidence: capstone/cloudtrail-timeline.jsonl, eventId: 00000000-0000-0000-0000-000000000000
```

## Hands-on conversion

This template is markdown. To produce a PDF:

```bash
pandoc CAP-PIR-001.md -o CAP-PIR-001.pdf \
  --pdf-engine=xelatex \
  --template=eisvogel \
  --metadata title="Post-Incident Report — Capstone APT"
```

## References

- [11-09 — Tabletop Exercise Templates](../IR-Forensics-Cloud/tabletop-exercise-templates.md)
- [13-05 — Pairing Red & Blue Timeline](./pairing-red-blue-timeline.md)
- [06-02 — CloudTrail Activity & Data Events](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md)
- SANS "A Guide to Cyber Incident Response Reporting"
- ITIL v4 Problem Management — Post-Incident Review
