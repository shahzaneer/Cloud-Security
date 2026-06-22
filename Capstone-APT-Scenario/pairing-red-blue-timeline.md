# 05 — Pairing Red & Blue Timeline

> **Level:** Advanced
> **Prereqs:** [Red Variant Walkthrough](red-variant-walkthrough.md), [Blue Variant Walkthrough](blue-variant-walkthrough.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** All (synthesis)
**Authorization scope:** Capstone labs are to be run only against learner-owned sandbox accounts. Placeholder accounts are used throughout. No live attack surfaces.

## What & why

The timeline file pairs each red-team action with its intended blue detection, records whether the detection actually fired in the learner's run, and identifies gaps where red outpaced blue. This is the primary purple-team artifact — a single axis that joins the [red walkthrough](./red-variant-walkthrough.md) and [blue walkthrough](./blue-variant-walkthrough.md).

## The OnPrem reality

On-prem purple teams used a shared spreadsheet: column A = timestamp from SIEM, column B = Windows Event ID, column C = detection rule, column D = action taken. The cloud timeline adds the dimension of cross-cloud log source diversity (CloudTrail, Activity Log, Cloud Audit Logs).

## Core concepts

### Timeline structure

```
T+00:00 ─┬─ [RED] Recon action starts
         ├─ [BLUE DETECT] Alert should fire within 15 min
         ├─ [ACTUAL] Gap (N minutes) if detection missed/delayed
         └─ [PURPLE] Follow-up ticket, detection rule tuning

T+00:05 ─┬─ [RED] Initial Access achieved
         ├─ [BLUE DETECT] GuardDuty/Defender/SCC fires
         ├─ [ACTUAL] Fired at T+00:07 (MTTD = 7 min)
         └─ [PURPLE] MTTD met SLO ✓
```

### Master timeline (cross-cloud)

| T+ (est.) | Red event | TTP | Log source | MITRE tactic | Blue detection rule | Expected MTTD | Fired? (Y/N) | Gap (min) | Action |
|---|---|---|---|---|---|---|---|---|---|
| 00:00 | Public bucket `ListObjects` from external IP | Recon via public enumeration | CloudTrail `s3:ListObjects` | Reconnaissance | `CAP-RECON-01` (honey-token hit) | 15 min | | | Tune IP allow-list |
| 00:02 | SSRF→IMDS `GetCallerIdentity` | Credential Access via instance metadata | CloudTrail `sts:GetCallerIdentity` | Credential Access | `CAP-IA-01` (GuardDuty InstanceCredentialExfiltration) | 5 min | | | Verify GD enabled |
| 00:03 | `iam:SimulatePrincipalPolicy` | Permission discovery | CloudTrail `iam:Simulate*` | Discovery | `CAP-IA-01b` (anomalous Simulate* from non-admin) | 15 min | | | |
| 00:05 | `iam:PassRole` → `lambda:CreateFunction` | PassRole abuse | CloudTrail `iam:PassRole`, `lambda:CreateFunction` | Privilege Escalation | `CAP-PE-01` (GuardDuty PrivilegeEscalation) | 10 min | | | |
| 00:06 | `lambda:InvokeFunction` (escalation payload) | Execution via serverless | CloudTrail `lambda:InvokeFunction` | Execution | `CAP-PE-01b` (Lambda invoke from new role) | 10 min | | | Correlate with PE-01 |
| 00:08 | `iam:CreateAccessKey` on `ci-deployer` | Account manipulation for persistence | CloudTrail `iam:CreateAccessKey` | Persistence | `CAP-PER-01` (CreateAccessKey outside CI window) | 15 min | | | |
| 00:09 | `iam:CreateUser` (`monitoring-service`) | Create account for persistence | CloudTrail `iam:CreateUser` | Persistence | `CAP-PER-02` (new user + AdministratorAccess) | 15 min | | | |
| 00:11 | `iam:AttachUserPolicy` Admin to `monitoring-service` | Account manipulation | CloudTrail `iam:AttachUserPolicy` | Persistence | `CAP-PER-02` (same rule) | — | | | |
| 00:13 | `sts:AssumeRole` → SharedServices (3333...) | Cross-account assume role | CloudTrail `sts:AssumeRole` | Lateral Movement | `CAP-LM-01` (cross-account chain) | 10 min | | | |
| 00:14 | `sts:AssumeRole` → Staging (2222...) | Second hop | CloudTrail `sts:AssumeRole` | Lateral Movement | `CAP-LM-01` (3-hop chain) | 10 min | | | |
| 00:15 | `sts:AssumeRole` → Prod (1111...) via different role | Return to Prod via new role | CloudTrail `sts:AssumeRole` | Lateral Movement | `CAP-LM-01` (chain closure) | 10 min | | | |
| 00:17 | `s3:ListObjects` mass enumeration | Data staging | CloudTrail S3 data event | Collection | `CAP-COLL-01` (List/Get ratio) | 5 min | | | |
| 00:18 | `s3:GetObject` storm (500+ objects) | Data collection | CloudTrail S3 data event | Collection | `CAP-COLL-01` (volume spike) | 5 min | | | Adjust threshold |
| 00:20 | `s3:DeleteObject` on WORM prefix → `AccessDenied` | Data destruction (blocked) | CloudTrail S3 data event (denied) | Impact | `CAP-IMP-01` (Delete denied by WORM) | 2 min | | | |
| 00:22 | [BLUE] GuardDuty finding fires | SOC notification | GuardDuty → EventBridge → SIEM | — | — | — | | | Record MTTD |
| 00:27 | [BLUE] `iam:UpdateAccessKey` → Inactive | Containment: Key deactivated | CloudTrail `iam:UpdateAccessKey` | Containment | Auto-response from Runbook | — | | | Record MTTR |
| 00:30 | [BLUE] Deny-all inline policy attached | Containment: Quarantine | CloudTrail `iam:PutUserPolicy` | Containment | Auto-response | — | | | |
| 00:35 | [BLUE] `iam:DeleteUser` `monitoring-service` | Eradication: Backdoor removed | CloudTrail `iam:DeleteUser` | Eradication | Manual runbook step | — | | | |
| 00:45 | [BLUE] `iam:DeleteAccessKey` all backup keys | Eradication: Keys rotated | CloudTrail `iam:DeleteAccessKey` | Eradication | Manual runbook step | — | | | |
| 00:55 | [BLUE] `terraform apply` baseline | Recovery: IaC reconciliation | CloudTrail `ec2:*`, `s3:*` (many) | Recovery | Compliance scan passes | — | | | |

## Section per cloud + OnPrem

### AWS — join queries for timeline reconstruction

```bash
# Join CloudTrail entries along a single timestamp axis.
# This script queries CloudTrail Lake for all capstone-relevant events
# and joins them into a single JSONL timeline.

aws cloudtrail query --query-statement '
  SELECT
    eventTime,
    eventName,
    userIdentity.arn,
    sourceIPAddress,
    errorCode
  FROM "arn:aws:cloudtrail:us-east-1:111111111111:eventdatastore/capstone-ed"
  WHERE eventTime > "2025-01-01T00:00:00Z"
    AND eventName IN (
      "ListObjects", "GetObject", "DeleteObject",
      "GetCallerIdentity",
      "PassRole", "CreateFunction", "InvokeFunction",
      "CreateAccessKey", "CreateUser", "AttachUserPolicy",
      "AssumeRole", "SimulatePrincipalPolicy",
      "UpdateAccessKey", "DeleteAccessKey", "DeleteUser",
      "PutUserPolicy"
    )
  ORDER BY eventTime ASC
' --output json > capstone/red-blue-timeline.jsonl
```

### Azure — join Activity Log + Sign-in Logs

```kusto
// Sentinel / Log Analytics: join red events + blue detection alerts
let redEvents = AzureActivity
| where TimeGenerated between (datetime(2025-01-01) .. datetime(2025-01-02))
| where OperationName in (
    "Microsoft.Storage/storageAccounts/listKeys/action",
    "Microsoft.Compute/virtualMachines/retrieveMetadata/action",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Web/sites/functions/action",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
  )
| project TimeGenerated, RedEvent = OperationName, Caller, CallerIpAddress;
let blueAlerts = SecurityAlert
| where TimeGenerated between (datetime(2025-01-01) .. datetime(2025-01-02))
| where DisplayName contains "capstone"
| project TimeGenerated, BlueAlert = DisplayName, Severity;
redEvents
| union blueAlerts
| order by TimeGenerated asc
| project TimeGenerated, Event = coalesce(RedEvent, BlueAlert), Caller
```

### GCP — join Cloud Audit Logs

```bash
gcloud logging read '
  logName:"cloudaudit.googleapis.com"
  timestamp >= "2025-01-01T00:00:00Z"
  protoPayload.methodName:("storage.objects.list" OR "storage.objects.get" OR
    "storage.objects.delete" OR "iam.serviceAccounts.getAccessToken" OR
    "iam.serviceAccountKeys.create" OR "iam.serviceAccounts.create" OR
    "google.iam.admin.v1.SetIamPolicy" OR "compute.instances.get")
' --project=example-project --format='json(timestamp,protoPayload.methodName,
    protoPayload.authenticationInfo.principalEmail,protoPayload.requestMetadata.callerIp)'
  > capstone/gcp-timeline.jsonl
```

### OnPrem — Windows Event Log + SIEM join

```powershell
# PowerShell: join Security (4624/4625), Sysmon (EventID 1), and Application logs
Get-WinEvent -FilterHashtable @{
  LogName='Security','Microsoft-Windows-Sysmon/Operational'
  StartTime=(Get-Date).AddHours(-24)
  ID=4624,4625,4672,4768,4688,1,11
} | Select-Object TimeCreated,Id,Message |
  Export-Csv capstone/onprem-timeline.csv
```

## 🔴 Red Team view — metric-edges where red outpaced blue

Identify gaps where the red action completed before the blue detection fired:

```
Gap analysis (fill in from your run):

1. Recon → CAP-RECON-01:
   Red completed at T+00:02. Detection fired at T+_ _ : _ _ . Gap: _ _ min.
   Root cause: (e.g., honey-token not deployed / SIEM ingestion delay / threshold too high)

2. SSRF IMDS → CAP-IA-01:
   Red completed at T+00:03. GuardDuty fired at T+_ _ : _ _ . Gap: _ _ min.
   Root cause: (e.g., GuardDuty finding delivery delay ~5 min per AWS docs)

3. PassRole → CAP-PE-01:
   Red completed at T+00:06. Alert fired at T+_ _ : _ _ . Gap: _ _ min.
   Root cause: (e.g., CloudTrail delivery delay + SIEM index latency)

4. CreateAccessKey → CAP-PER-01:
   Red completed at T+00:09. Alert fired at T+_ _ : _ _ . Gap: _ _ min.
   Root cause: (e.g., needed daily-batch diff; real-time rule missing)

5. AssumeRole chain → CAP-LM-01:
   Red completed at T+00:16. Alert fired at T+_ _ : _ _ . Gap: _ _ min.
   Root cause: (e.g., single AssumeRole didn't fire; 3-hop correlation not implemented)

6. GetObject storm → CAP-COLL-01:
   Red completed at T+00:20. Alert fired at T+_ _ : _ _ . Gap: _ _ min.
   Root cause: (e.g., S3 data events not enabled on the capstone trail)
```

The largest gap is the priority for detection-rule tuning in the next purple-team iteration.

## 🔵 Blue Team view — purple-team loop

### Per-gap follow-up ticket template

```
Title: [CAPSTONE-PURPLE] Detection gap: <red-stage> outpaced <detection-rule>
Severity: High
Detected: <detection-rule-ID>
Red completed: T+XX:XX
Blue fired: T+YY:YY
Gap: Z min
Root cause: <analysis>
Recommendation: <rule tuning, new correlation, log source enablement>
Assignee: <SOC engineering>
Due: Before next quarterly purple-team exercise
```

### Re-test after remediation

```
1. Tune detection rule per root cause.
2. Re-run red lab step (or full lab).
3. Confirm detection fires within SLO.
4. Update gap to 0 min in timeline.
5. Close ticket.
```

### Purple-team KPI matrix

| KPI | SLO | Baseline (first run) | Target (next run) | Module ref |
|---|---|---|---|---|
| MTTD (any red action → first alert) | ≤ 15 min | | ≤ 10 min | [11-01](../IR-Forensics-Cloud/ir-runbook-cloud-aware.md) |
| MTTR (alert → containment) | ≤ 30 min | | ≤ 15 min | [11-01](../IR-Forensics-Cloud/ir-runbook-cloud-aware.md) |
| Detection coverage (red stages with at least 1 alert) | ≥ 6/7 stages | | 7/7 stages | [06-07](../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md) |
| False positives (alerts not from red lab) | 0 | | 0 | [06-08](../Monitoring-Detection-SIEM/alert-to-action-soc-tiers.md) |
| Recovery time (containment → posture restored) | ≤ 60 min | | ≤ 45 min | [10-08](../Blue-Team-Defense/remediation-automation.md) |

## References

- [13-03 — Red Variant Walkthrough](./red-variant-walkthrough.md)
- [13-04 — Blue Variant Walkthrough](./blue-variant-walkthrough.md)
- [06-07 — Detection-as-Code Sigma & Custodian](../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md)
- [11-01 — IR Runbook Cloud-Aware](../IR-Forensics-Cloud/ir-runbook-cloud-aware.md)
- [11-07 — Log Timeline & Attack Reconstruction](../IR-Forensics-Cloud/log-timeline-and-attack-reconstruction.md)
- [13-06 — Post-Incident Report Template](./post-incident-report-template.md)
