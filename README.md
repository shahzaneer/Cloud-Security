# Cloud Security — Fundamentals to Advanced (Blue + Red, Multi-Cloud)

> A curated, hands-on learning repository for engineers (DevOps/SRE/Platform) who want to move into the **Cyber Security** domain — specifically **Cloud, Infrastructure, Network, and Application-layer** security — covering **both Defense (Blue Team)** and **Offense (Red Team)** perspectives.

This repo follows a **phased curriculum**: each top-level directory is a **module**, increasing in difficulty. Each module contains lesson `.md` files, labs, and detection packs — all ready to read and work through.

---

## Target audience

- **Profile:** Mid-level DevOps / Platform / SRE engineer.
- **Has:** Solid grasp of Linux, networking basics, CI/CD, IaC, and at least one cloud. Basic security awareness (TLS, firewalls, IAM).
- **Wants:** Move from "build & operate" into **defend** and **attack** roles — Cloud Security Engineering, Cloud SOC, Detection Engineering, Cloud Penetration Testing, Offensive Cloud Security Research.
- **Scope:** Cloud + Infra + App/Network layer. Not endpoint, not malware reversing, not physical — except where they touch cloud.

---

## Pedagogical model

Every lesson follows the same shape so the curriculum is predictable and navigable:

1. **Concept** — what it is, why it matters, threat/defense framing.
2. **OnPrem reality** — how this problem existed pre-cloud (anchors intuition).
3. **AWS** — service + config + code/IaC example.
4. **Azure** — service + config + code/IaC example.
5. **GCP** — service + config + code/IaC example.
6. 🔴 **Red Team view** — how an attacker abuses this, with a concrete, contained, *educational* example (the "simple APT" idea repeated at small scale). Always paired with consent/legal notes.
7. 🔵 **Blue Team view** — how to detect, prevent, contain, and respond.
8. **Hands-on lab** — reproducible in a free/low-cost sandbox.
9. **Checklist / Detection rules** — copy-pasteable.
10. **References** — docs, MITRE ATT&CK techniques, CWE, CVE of note.

Cloud-native code examples always show **all three clouds + OnPrem** side-by-side so cross-cloud mental mapping is automatic.

---

## Curriculum map

| # | Module | Theme | Team focus |
|---|--------|-------|-----------|
| 1 | [Fundamentals](./Fundamentals) | Cloud security mental models, shared responsibility, CIA, kill chain, ATT&CK for Cloud | Both |
| 2 | [Network Security](./Network-Security) | VPCs, segmentation, egress, DDoS, DNS, zero trust | Both |
| 3 | [IAM](./IAM) | Identities, authn, authz, federation, privilege arms race | Red heavy |
| 4 | [Compute & Container Security](./Compute-Container-Security) | VMs, Lambda/Functions, Kubernetes, container escape, supply chain | Both |
| 5 | [Storage & Data Security](./Storage-Data-Security) | Buckets, blobs, disks, encryption, public exposure | Both |
| 6 | [Secrets & KMS](./Secrets-KMS) | Key vaults, HSM, rotation, leakage paths | Red heavy |
| 7 | [Monitoring, Detection & SIEM](./Monitoring-Detection-SIEM) | Logs, metrics, GuardDuty/Sentinel/SCC, Sigma rules | Blue heavy |
| 8 | [Cloud-Native App Security](./Cloud-Native-App-Security) | API gateways, serverless, OAuth, OWASP in cloud context | Both |
| 9 | [IaC & Pipeline Security](./IaC-Security) | Terraform, policy-as-code, CI poisoning | Both |
| 10 | [Red Team — Cloud Offense](./Red-Team-Offense) | Assume-role chains, credential theft, pivoting, C2 in cloud, "build-your-APT" labs | Red |
| 11 | [Blue Team — Cloud Defense](./Blue-Team-Defense) | Hardening baselines, guardrails, blast-radius reduction, deception | Blue |
| 12 | [Incident Response & Cloud Forensics](./IR-Forensics-Cloud) | Triage, evidence in ephemeral infra, memory/disk, chain of custody | Blue heavy |
| 13 | [Compliance, Audit & Governance](./Compliance-Audit-Gov) | CIS, NIST, PCI/ISO, evidence automation, guardrails-as-code | Blue |
| 14 | [Capstone — Build & Defeat an APT](./Capstone-APT-Scenario) | End-to-end scenario: attackers compromise creds → pivot → exfil; defenders detect → contain → evict | Both (synthesis) |
| 15 | [AI Security](./AI-Security) | Agentic AI threat model, prompt injection, AI agent hardening & guardrails | Both |

Plus: [`resources/`](./resources) — labs (LocalStack, Terraform bootstrap), templates (Sigma, OPA, runbook), tool index.

---

## How to use this repo

Work modules in order — each builds on the prior. Every module's `README.md` lists the lessons and learning objectives. Read the lessons, run the labs, and study the detection packs alongside. Red and Blue sections are paired so you learn both attack *and* defense for every topic.

---

## Legal & ethics

Offensive content here is **for authorized learning only** (your own lab accounts, CTFs, sanctioned engagements). Never run techniques against clouds you don't own or aren't explicitly authorized to test. Most modules include a one-line "scope of authorization" reminder. Misuse is on you.