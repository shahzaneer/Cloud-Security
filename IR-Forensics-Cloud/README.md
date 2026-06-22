# Module 11 — Incident Response & Cloud Forensics

When the red chain succeeds, what does the blue chain *do*? Cloud IR flips the on-prem playbook because infra is ephemeral — you must collect evidence before autoscaler reaps the box. Covers triage, evidence preservation in VMs/containers/IAM, memory and disk acquisition, chain-of-custody, role revocation, attack replay, and tabletop templates.

## Learning objectives

- Execute a cloud IR runbook end-to-end across VM/serverless/K8s and IAM.
- Preserve ephemeral evidence (snapshot + memory + logs) before scale-set replaces the host.
- Distinguish forensic artefacts per cloud and chain-of-custody.
- Revoke compromised identity tokens (and understand their TTL physics).
- Run a tabletop exercise mapped to the curriculum's threat catalogue.

## Lessons

- [x] `ir-runbook-cloud-aware.md`
- [x] `triage-and-severity-per-cloud.md`
- [x] `evidence-preservation-in-ephemeral-infra.md`
- [x] `snapshot-and-memory-acquisition.md`
- [x] `iam-revocation-and-session-physics.md`
- [x] `container-k8s-forensics.md`
- [x] `log-timeline-and-attack-reconstruction.md`
- [x] `chain-of-custody-and-legal-handoff.md`
- [x] `tabletop-exercise-templates.md`
- [x] `labs/snapshot-then-kill-lab.md`
- [x] `detections/ir-snapshot-evidence-trigger.md`

