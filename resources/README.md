# resources

Supporting material for the curriculum.

## Layout

- `labs/` — re-usable mini-lab templates invoked across modules (mostly modules that share a sandbox scenario): global tf helper snippets, sandbox-account bootstraps, LocalStack compose stack.
- `templates/` — copy-paste scaffolds: Sigma YAML templates per cloud backend, Cloud Custodian policy skeleton, OPA Rego starter, IR runbook YAML honey-token provisioning script, post-incident-report template.
- `tool-index.md` — cross-cloud tool cheat sheet (CLI commands, IDE plugins, FOSS scanners) used by multiple modules.

## Tool index proposed entries

| Concern | Tool | Cloud(s) | Installed by |
|---------|------|----------|--------------|
| Posture / audit | Prowler | AWS | `labs/02-*` |
| Posture / audit | ScoutSuite | All | `labs/00-*` |
| IaC scanning | Checkov / tfsec / KICS | All | `labs/05-*` |
| IAM review | cloudfox | AWS | `09-02` |
| IAM review | AADInternals | Azure | `09-02` |
| K8s auditkube-bunter | kube-bench | All | `03-*` |
| K8s runtime detect | Falco | All | `03-08` |
| Secret scanning | gitleaks / truffleHog | n/a | `05-06`, `08-lab` |
| Detection-as-code | Sigma+`sigmac` | n/a | `06-07` |
| Policy-as-code | Cloud Custodian / OPA / Kyverno | All | `02-08` |
| Honey tokens | canarytokens.org | All | `10-04` |
| Memory forensics | AVML / LiME / Volatility | Linux | `11-04` |

See `tool-index.md` for the full tool reference.