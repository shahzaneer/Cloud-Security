# Module 05 — Secrets & Key Management

Covers KMS, HSM, secret stores, and the *leakage paths* between engineering and secrets. The deepest offense module pair: how secrets get cached on disk/env-var/blob/git, how attackers extract them, how defenders detect and rotate. Ties tightly into [IAM](../IAM) and [Storage](../Storage-Data-Security).

## Learning objectives

- Model the secret lifecycle: creation → distribution → use → rotation → revocation.
- Choose KMS vs HSM vs Vault per-cloud for your compliance tier.
- Detect secret leakage paths in CI/CD, env vars, logs, crashes.
- Build automatic rotation and break-glass revocation.
- Identify leakage incidents with `gitleaks`/`truffleHog` + log analysis.

## Lessons

- [x] `kms-hsm-and-vaults.md`
- [x] `key-policies-and-grants.md`
- [x] `secret-stores-per-cloud.md`
- [x] `rotation-and-automatic-providers.md`
- [x] `env-vars-vs-mounted-secrets.md`
- [x] `git-and-cicd-leakage-paths.md`
- [x] `log-redaction-and-leakage-detection.md`
- [x] `revocation-and-break-glass-keys.md`
- [x] `cmk-vs-byok-and-external-keys.md`
- [x] `quantum-safe-cryptography-readiness.md`
- [x] `labs/secret-blind-leak-lab.md`
- [x] `detections/ci-leaked-token-detection.md`

