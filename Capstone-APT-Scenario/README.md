# Module 13 — Capstone: Build & Defeat an APT (Synthesis)

The integrating module. Walks one end-to-end scenario across the entire curriculum: misconfigured multi-cloud organisation → credential theft → pivot → exfil → detection → containment → IR → lessons published. No new concepts; everything is cross-links to Modules 00–12. Includes two mutually-opposed labs: one for the "red" persona and one for the "blue," built on the *same* deliberately-vulnerable reference sandbox.

## Learning objectives

- Synthesize modules 00–12 into a single attack+defense narrative.
- Stand up the canonical vulnerable multi-cloud sandbox safely.
- Execute each red-team step from `labs/red` and confirm each blue-team control from the matching `labs/blue` fires.
- Measure MTTD/MTTR with the SLOs defined in Module 11.
- Produce a written post-incident report + tabletop package.

## Reference scenario narrative

| Stage | Red action (Module 09) | Blue signal (Modules 06/10/11) |
|-------|------------------------|-------------------------------|
| Recon | Passive tenant + bucket enumeration (`cloudfox`, `AADInternals`, `gcloud`) | List-storm detection from new IP, honey-token hit |
| Initial Access | SSRF→IMDS retrieving instance credentials; leaked CI token in repo | CloudTrail `GetCallerIdentity` spike; gitleaks action failure |
| Privilege Escalation | `iam:PassRole`+`lambda:CreateFunction` (or Azure equivalent; GCP `iam.serviceAccountTokenCreator`) | GuardDuty/Defender/SCC PrivilegeEscalation finding |
| Persistence | New IAM user access key, patched Lambda event source mapping | Honey-token webhook; daily diff alert on `CreateAccessKey` outside CI |
| Lateral Movement | Assume-role chain through 3 accounts | Cross-account AssumeRole detection; trust-graph alert |
| Collection / Exfil | List-then-Get storm against object store, compressed to log-bucket | List/Get ratio anomaly; SIEM alert on outbound traffic split |
| Impact | Attempt `DeleteObject` on Object-Locked bucket → fail | CloudTrail Denied event + immutable evidence snap |
| Containment | (auto-response) snapshot + revoke + quarantine SG | Detected runbook execution event |
| Eradication | Org/tenant-wide key rotation; perimeter SCPs attached | Detected global guardrail change |
| Recovery | Apply IaC baseline; restore object from WORM | Compliance-green restored posture |

## Lessons

- [x] `capstone-architecture-overview.md`
- [x] `deploying-the-reference-sandbox.md`
- [x] `red-variant-walkthrough.md`
- [x] `blue-variant-walkthrough.md`
- [x] `pairing-red-blue-timeline.md`
- [x] `post-incident-report-template.md`
- [x] `labs/red/build-the-apt-lab.md`
- [x] `labs/blue/detect-and-kill-the-apt-lab.md`
- [x] `detections/capstone-detection-pack.md`

