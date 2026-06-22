# Module 00 — Fundamentals

The mental-model layer. Before dividing things offensive/defensive or per-cloud, build the shared vocabulary: what “security” means in cloud vs on-prem, who is responsible for what, what an attack actually *is* in cloud, and how defenders model it. Every later module assumes the terminology laid out here.

## Learning objectives

By the end of this module a learner can:

- Explain the **Shared Responsibility Model** for AWS, Azure, GCP and where the line shifts by service type (IaaS/PaaS/SaaS).
- Map a cloud compromise onto a **kill chain / MITRE ATT&CK Cloud** kill chain in plain language.
- State the **CIA triad** in cloud-specific terms (e.g. “availability = no one can `PutBucketPolicy` you out of your own bucket”).
- Distinguish **authentication / authorization / accountability** and where each lives in each cloud.
- Sketch the **blast radius** concept and why it dominates cloud defense.
- Name the four example lenses used everywhere else: OnPrem / AWS / Azure / GCP.

## Lessons

- [x] `shared-responsibility.md` — who owns what, by service layer
- [x] `cia-triad-in-cloud.md` — confidentiality/integrity/availability reframed for cloud
- [x] `kill-chain-attack-mapping.md` — Cyber Kill Chain vs MITRE ATT&CK Cloud matrix
- [x] `authn-authz-accountability.md` — the identity tripod and where logs come from
- [x] `blast-radius-and-fail-secure.md` — blast radius, least privilege, fail-secure defaults
- [x] `the-four-example-lenses.md` — OnPrem/AWS/Azure/GCP comparison convention used repo-wide
- [x] `labs/mindmap-lab.md` — build your own threat-model mind map for a sample 3-tier app

