# Post-Incident Report — INC-YYYY-NNNN

> **Status:** DRAFT | REVIEW | FINAL
> **Date of report:** TODO: <YYYY-MM-DD>
> **Author:** TODO: <name / role>
> **Classification:** TODO: <Internal | Confidential | Restricted>

---

## 1. Executive Summary

TODO: Summarize the incident in 3–5 sentences — what happened, impact, root cause, and whether it is contained.

- **Incident declared:** TODO: <ISO-8601>
- **Contained:** TODO: <ISO-8601> (or "ongoing")
- **Remediated:** TODO: <ISO-8601> (or "ongoing")
- **Affected accounts/tenants/projects:** TODO: <list>
- **Data exposure confirmed?** TODO: Yes / No / Under investigation
- **Regulatory notification required?** TODO: Yes / No, <rationale>

---

## 2. Timeline

| Timestamp (UTC) | Actor / System | Event | Evidence ref |
|---|---|---|---|
| TODO | TODO | TODO | TODO |
| TODO | TODO | TODO | TODO |
| TODO | TODO | TODO | TODO |

> Add or remove rows; keep events chronological. Link each event to the evidence bucket path.

---

## 3. Root Cause Analysis

TODO: Describe the technical root cause. Include:
- Vulnerable configuration, software defect, or human error that enabled the incident.
- Why existing controls did not prevent or detect it sooner.
- How the root cause was validated (reproduction steps, log correlation).

**Root cause category:** TODO: Configuration drift | Credential leak | Software CVE | Insider action | Supply-chain compromise | Other

---

## 4. Detection Performance

| ATT&CK stage | First artifact (UTC) | Detected (UTC) | MTTD (min) | Detection source | Alert that fired |
|---|---|---|---|---|---|
| TODO: Initial Access | TODO | TODO | TODO | TODO | TODO |
| TODO: Execution | TODO | TODO | TODO | TODO | TODO |
| TODO: Persistence | TODO | TODO | TODO | TODO | TODO |
| TODO: Privilege Escalation | TODO | TODO | TODO | TODO | TODO |
| TODO: Defense Evasion | TODO | TODO | TODO | TODO | TODO |
| TODO: Credential Access | TODO | TODO | TODO | TODO | TODO |
| TODO: Discovery | TODO | TODO | TODO | TODO | TODO |
| TODO: Lateral Movement | TODO | TODO | TODO | TODO | TODO |
| TODO: Collection | TODO | TODO | TODO | TODO | TODO |
| TODO: Exfiltration | TODO | TODO | TODO | TODO | TODO |
| TODO: Impact | TODO | TODO | TODO | TODO | TODO |

**Overall MTTD:** TODO: <N> minutes
**Overall MTTR:** TODO: <N> minutes (containment) / <N> minutes (full remediation)

---

## 5. Actions Taken

### 5.1 Immediate Containment

TODO: List containment steps with timestamps and who executed them.

| Action | When (UTC) | By | Outcome |
|---|---|---|---|
| TODO | TODO | TODO | TODO |

### 5.2 Investigation

TODO: Describe forensic steps, snapshot acquisitions, log pulls, memory captures.

### 5.3 Eradication

TODO: Steps taken to remove attacker persistence and restore known-good state.

### 5.4 Recovery

TODO: Steps to restore services, rotate credentials, rebuild resources.

---

## 6. Lessons Learned

### 6.1 What Went Well

TODO: <list>

### 6.2 What Went Wrong

TODO: <list>

### 6.3 Action Items

| AI # | Owner | Description | Due date | Status |
|---|---|---|---|---|
| AI-1 | TODO | TODO | TODO | TODO |
| AI-2 | TODO | TODO | TODO | TODO |

### 6.4 Runbook / Detection Updates

TODO: List specific runbook sections or detection rules that will be created or revised.

---

## 7. Costs

TODO: Estimate total incident cost — engineering hours, cloud resource re-provisioning, third-party IR retainers, regulatory fines (if any), and reputational impact.

| Category | Amount | Notes |
|---|---|---|
| TODO | TODO | TODO |
| **Total** | TODO | TODO |

---

## 8. Appendices

### 8.1 Evidence Index

TODO: Full listing of evidence artifacts with chain-of-custody pointers.

- **AWS evidence:** TODO: `s3://<bucket>/INC-YYYY-NNNN/`
- **Azure evidence:** TODO: `https://<storage>.blob.core.windows.net/evidence/INC-YYYY-NNNN/`
- **GCP evidence:** TODO: `gs://<bucket>/INC-YYYY-NNNN/`
- **OnPrem evidence:** TODO: `/mnt/evidence/INC-YYYY-NNNN/`

### 8.2 Runbook Used

TODO: Link to the IR runbook followed (e.g., `resources/templates/ir-runbook.template.yaml`).

### 8.3 Communication Log

TODO: Reference the #incident channel export, stakeholder emails, regulator filings.

### 8.4 IOCs

TODO: List indicators of compromise (IPs, domains, hashes, user-agent strings, toolmarks).

---

> Template derived from `resources/templates/post-incident-report.template.md`.
> This report cross-references `../Capstone-APT-Scenario/post-incident-report-template.md` (learner-facing version).
