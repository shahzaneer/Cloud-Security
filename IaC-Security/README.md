# Module 08 — Infrastructure-as-Code & Pipeline Security

Terraform / Pulumi / CloudFormation / Bicep / Config Connector security, plus the CI/CD pipeline as a privileged agent that modifies production infra. Covers state file leakage, drift attack, plan-cache poisoning, and policy-as-code in the pull request loop.

## Learning objectives

- Identify exposure paths in IaC state files and lock backends.
- Use policy-as-code (OPA, Sentinel, Checkov, tfsec, Cloud Custodian) as PR-time guardrails.
- Recognize CI runner as cloud principal — and protect/protect-from it.
- Implement drift detection and forbidden-provider-hardening.
- Automate preventive guardrails with terraform `import` checks and `terraform plan -out` review.

## Lessons

- [x] `iac-state-and-backend-security.md`
- [x] `terraform-secrets-in-state.md`
- [x] `plan-poisoning-and-plan-cache.md`
- [x] `policy-as-code-rego-sentinel.md`
- [x] `static-analysis-checkov-tfsec.md`
- [x] `cicd-runner-as-cloud-principal.md`
- [x] `drift-detection-and-reconciliation.md`
- [x] `iac-supply-chain-and-provider-trust.md`
- [x] `bicep-arm-and-config-connector-tail.md`
- [x] `labs/statefile-leak-lab.md`
- [x] `detections/drift-alert-detection.md`

