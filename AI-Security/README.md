# AI-Security — Agentic AI Threat Model & Hardening

Agentic AI (LLM-based agents that provision cloud resources, modify IAM, execute API calls, and respond to incidents) is the fastest-growing new attack surface in cloud. This module covers the threat model and hardening patterns: ensuring an AI agent can *only* do what it's intended to do, and nothing else.

## Why this matters for a cloud security engineer

- AWS (Amazon Q Developer, Bedrock Agents), Azure (Copilot, AI Agent Service), and GCP (Vertex AI Agent Builder, Gemini Code Assist) are shipping agents capable of reading/writing production infrastructure.
- A prompt injection on an agent with `AdministratorAccess` is equivalent to an unauthenticated RCE with cloud-admin privileges.
- The same principles that protect cloud infra — least privilege, blast-radius reduction, audit logging — apply to AI agents but with *new failure modes* (indirect prompt injection, tool-confusion, multi-turn jailbreaking).

## Learning objectives

- Model the AI agent attack surface: prompt injection, tool misuse, data exfiltration via agent, multi-hop confused deputy.
- Enumerate the permission model of each cloud provider's AI agent platform.
- Implement least-privilege agent roles, human-in-the-loop checkpoints, and prompt guardrails.
- Detect anomalous agent behavior from audit logs.

## Lessons

- [x] `agentic-ai-threat-model.md` — Attack surface taxonomy, OWASP LLM Top 10, prompt injection classes, tool-confusion attacks.
- [x] `ai-agent-hardening-guardrails.md` — Least-privilege IAM for agents, human-in-the-loop, input validation, output filtering, runtime guardrails, monitoring.

## Labs & Detections

- [x] `labs/ai-agent-sandbox-lab.md` — Deploy a minimal AI agent (LangChain + LocalStack / Bedrock Agent simulator) and attempt prompt injection; observe denial.
- [x] `detections/ai-agent-anomaly-detection.md` — Sigma-style rules for anomalous agent actions across clouds.