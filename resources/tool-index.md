# Tool Index — Cloud Security Curriculum

A curated, cross-cloud cheat sheet mapping security concerns to tools used throughout this curriculum. Every tool listed is free / open-source or offers a free tier sufficient for labs. Paid upgrades are noted explicitly.

**How to read this index:** Each row links a tool to its primary concern, cloud coverage, the modules and lessons where it is introduced or exercised, and a minimal install snippet. Cross-cloud tools (e.g. ScoutSuite) appear once; cloud-specific tools (e.g. Prowler) appear under their native cloud with a note about multi-cloud where applicable.

---

## 1. Posture & Audit Scanners

| Tool | Cloud(s) | Modules (lessons) | Install |
|---|---|---|---|
| **Prowler** | AWS, Azure (preview), GCP (preview) | `Blue-Team-Defense/preventive-guardrails-as-code.md`, `Blue-Team-Defense/continuous-hardening-baselines.md`, `Compliance-Audit-Gov/` | `brew install prowler` or `pip install prowler` |
| **ScoutSuite** | AWS, Azure, GCP | `Fundamentals/`, `Red-Team-Offense/recon-osint-and-fingerprint.md`, `Blue-Team-Defense/landing-zone-as-defense.md` | `pip install scoutsuite` |
| **CloudSploit** | AWS, Azure, GCP, OCI | `Blue-Team-Defense/preventive-guardrails-as-code.md` | `git clone https://github.com/aquasecurity/cloudsploit.git && cd cloudsploit && npm install` |
| **AWS Audit Manager** | AWS | `Compliance-Audit-Gov/` | AWS Console (no CLI install; access via `aws auditmanager`) |
| **Azure Defender for Cloud regulatory compliance** | Azure | `Compliance-Audit-Gov/`, `Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md` | Azure Portal built-in |
| **GCP Security Command Center Premium** | GCP | `Compliance-Audit-Gov/`, `Monitoring-Detection-SIEM/gcp-cloud-audit-logs-and-scc.md` | GCP Console built-in |

---

## 2. IaC Scanners

| Tool | Cloud(s) | Modules (lessons) | Install |
|---|---|---|---|
| **Checkov** | AWS, Azure, GCP, K8s, Terraform, CloudFormation, Bicep, ARM, Docker | `IaC-Security/static-analysis-checkov-tfsec.md` | `brew install checkov` or `pip install checkov` |
| **tfsec / Trivy** | AWS, Azure, GCP (Trivy supersedes tfsec; both usable) | `IaC-Security/static-analysis-checkov-tfsec.md`, `Compute-Container-Security/` | `brew install aquasecurity/trivy/trivy` or `brew install tfsec` |
| **KICS** | AWS, Azure, GCP, K8s, Terraform, CloudFormation, Ansible, Docker | `IaC-Security/static-analysis-checkov-tfsec.md` | `brew install checkmarx/kics/kics` or `docker run checkmarx/kics` |
| **Terrascan** | AWS, Azure, GCP, K8s | `IaC-Security/static-analysis-checkov-tfsec.md` | `brew install terrascan` or `curl -L https://raw.githubusercontent.com/tenable/terrascan/master/scripts/install.sh \| bash` (as of June 2026, verify the install script URL is current) |
| **Cloud Custodian** | AWS, Azure, GCP | `Blue-Team-Defense/preventive-guardrails-as-code.md`, `Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md`, `IaC-Security/` | `pip install c7n` |

**Typical invocation:**

```bash
# Terraform plan JSON → IaC scanner
terraform plan -out=plan.binary
terraform show -json plan.binary > plan.json

checkov -f plan.json
trivy config --tf-plan-json plan.json .
kics scan -p . --output-path results/
terrascan scan -i terraform -d .
```

---

## 3. K8s Tooling

| Tool | Cloud(s) | Modules (lessons) | Install |
|---|---|---|---|
| **kube-bench** | Any K8s (EKS, AKS, GKE, OnPrem) | `Compute-Container-Security/`, `Compute-Container-Security/rbac-and-service-account-tokens.md` | `brew install kube-bench` or `kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml` |
| **kube-hunter** | Any K8s | `Compute-Container-Security/k8s-attack-surface-overview.md`, `Red-Team-Offense/` | `pip install kube-hunter` |
| **kubeaudit** | Any K8s | `Compute-Container-Security/pod-security-admission-and-psp-replacements.md` | `brew install kubeaudit` or `go install github.com/Shopify/kubeaudit@latest` |
| **Falco** | Any K8s, Linux hosts | `Compute-Container-Security/container-escape-classes.md`, `Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md`, `Blue-Team-Defense/` | `helm install falco falcosecurity/falco --namespace falco --create-namespace` |
| **Kyverno** | Any K8s | `Compute-Container-Security/pod-security-admission-and-psp-replacements.md`, `IaC-Security/policy-as-code-rego-sentinel.md`, `Blue-Team-Defense/preventive-guardrails-as-code.md` | `helm install kyverno kyverno/kyverno --namespace kyverno --create-namespace` |
| **OPA Gatekeeper** | Any K8s | `Compute-Container-Security/image-signing-and-admission-controllers.md`, `IaC-Security/policy-as-code-rego-sentinel.md` | `helm install gatekeeper gatekeeper/gatekeeper --namespace gatekeeper-system --create-namespace` |
| **Trivy (image scan)** | Any K8s | `Compute-Container-Security/ami-image-vuln-and-supply-chain.md`, `Compute-Container-Security/image-signing-and-admission-controllers.md` | `brew install aquasecurity/trivy/trivy` |
| **cosign** | Any K8s (container signing) | `Compute-Container-Security/image-signing-and-admission-controllers.md`, `Secrets-KMS/` | `brew install cosign` |

---

## 4. Identity Tooling

| Tool | Cloud(s) | Modules (lessons) | Install |
|---|---|---|---|
| **cloudfox** | AWS | `IAM/assume-role-chains-and-trust-graphs.md`, `Red-Team-Offense/recon-osint-and-fingerprint.md` | `brew install cloudfox` or `git clone https://github.com/BishopFox/cloudfox.git && cd cloudfox && go build` |
| **aws-vault** | AWS | `IAM/long-lived-keys-vs-workload-identity.md`, `Fundamentals/` | `brew install aws-vault` |
| **AADInternals** | Azure / Azure AD | `IAM/federation-sso-and-external-providers.md`, `Red-Team-Offense/credential-theft-and-token-physics.md` | `Install-Module -Name AADInternals -Force` (PowerShell) |
| **gcloud iam** | GCP | `IAM/identity-primitives-per-cloud.md`, `IAM/policy-as-code-checkers.md` | Built into `gcloud` CLI (`gcloud components install alpha` for preview commands) |
| **pacu** (defensive study only) | AWS | `Red-Team-Offense/credential-theft-and-token-physics.md`, `Red-Team-Offense/methodology-and-PTES-for-cloud.md` | `pip install pacu` > ⚠️ Only run in a dedicated AWS sandbox account. |

---

## 5. Secrets & Data

| Tool | Cloud(s) | Modules (lessons) | Install |
|---|---|---|---|
| **gitleaks** | n/a (source scanning) | `Secrets-KMS/git-and-cicd-leakage-paths.md`, `IaC-Security/terraform-secrets-in-state.md` | `brew install gitleaks` |
| **truffleHog** | n/a (source + S3/GCS scanning) | `Secrets-KMS/git-and-cicd-leakage-paths.md`, `Red-Team-Offense/` | `brew install trufflehog` or `pip install truffleHog` |
| **detect-secrets** | n/a (source scanning) | `Secrets-KMS/git-and-cicd-leakage-paths.md` | `pip install detect-secrets` |
| **pip-audit** | n/a (Python dependencies) | `Cloud-Native-App-Security/supply-chain-and-3p-integrations.md` | `pip install pip-audit` |
| **osv-scanner** | n/a (multi-ecosystem vulns) | `Cloud-Native-App-Security/supply-chain-and-3p-integrations.md` | `brew install osv-scanner` or `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| **cosign + Rekor** | n/a (artifact signing + transparency log) | `Compute-Container-Security/image-signing-and-admission-controllers.md`, `Secrets-KMS/` | `brew install cosign` (Rekor is accessed via cosign's `verify` command against `rekor.sigstore.dev`) |

---

## 6. Detection-as-Code

| Tool | Cloud(s) | Modules (lessons) | Install |
|---|---|---|---|
| **Sigma** (`sigmac` / `pySigma`) | n/a (rule format); backends: AWS CloudTrail, Azure Activity Log, GCP Cloud Audit Logs, Linux syslog | `Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md` | `pip install pysigma` or `git clone https://github.com/SigmaHQ/sigma.git` |
| **Cloud Custodian** | AWS, Azure, GCP | `Blue-Team-Defense/preventive-guardrails-as-code.md`, `Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md` | `pip install c7n` |
| **Falco** | Any K8s, Linux | `Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md`, `Compute-Container-Security/container-escape-classes.md` | `helm install falco falcosecurity/falco` |
| **OPA / Rego** | Any (Terraform, K8s, Envoy, custom) | `IaC-Security/policy-as-code-rego-sentinel.md`, `Blue-Team-Defense/preventive-guardrails-as-code.md` | `brew install opa` |
| **Kyverno** | Any K8s | `Compute-Container-Security/pod-security-admission-and-psp-replacements.md`, `Blue-Team-Defense/preventive-guardrails-as-code.md` | `helm install kyverno kyverno/kyverno` |

---

## 7. Forensics & Memory

| Tool | Cloud(s) | Modules (lessons) | Install |
|---|---|---|---|
| **Volatility 3** | Linux, Windows (memory images) | `IR-Forensics-Cloud/snapshot-and-memory-acquisition.md`, `IR-Forensics-Cloud/log-timeline-and-attack-reconstruction.md` | `pip install volatility3` |
| **AVML** (Acquire Volatile Memory for Linux) | Linux (AWS EC2, Azure VM, GCE, OnPrem) | `IR-Forensics-Cloud/snapshot-and-memory-acquisition.md` | `wget https://github.com/microsoft/avml/releases/latest/download/avml` |
| **LiME** (Linux Memory Extractor) | Linux (kernel module) | `IR-Forensics-Cloud/snapshot-and-memory-acquisition.md` | `git clone https://github.com/504ensicsLabs/LiME.git && cd LiME/src && make` |
| **gcore** | Linux (built-in) | `IR-Forensics-Cloud/snapshot-and-memory-acquisition.md`, `IR-Forensics-Cloud/container-k8s-forensics.md` | Built-in (`gcore <pid>`) |

---

## 8. Lab Tooling

| Tool | Purpose | Modules (lessons) | Install |
|---|---|---|---|
| **Terraform** (≥ 1.7) | IaC provisioning (plan-only safe for labs) | Multiple modules | `brew install terraform` |
| **LocalStack** | Local AWS emulation (free Community edition sufficient for labs) | `Fundamentals/`, `IaC-Security/`, `Capstone-APT-Scenario/` | `pip install localstack` or `docker run --rm -p 4566:4566 localstack/localstack` |
| **kind** | K8s-in-Docker | `Compute-Container-Security/`, `Capstone-APT-Scenario/` | `brew install kind` |
| **minikube** | Local K8s cluster | `Compute-Container-Security/` | `brew install minikube` |
| **k3d** | K3s in Docker | `Compute-Container-Security/` | `brew install k3d` |
| **k9s** | Terminal K8s dashboard | `Compute-Container-Security/` | `brew install k9s` |
| **jq** | JSON processing | Multiple modules | `brew install jq` |
| **yq** | YAML processing | Multiple modules | `brew install yq` |
| **mitmproxy** | HTTP/HTTPS interception (lab-local only) | `Cloud-Native-App-Security/`, `Network-Security/` | `brew install mitmproxy` |

---

## 9. CI Plugins

| Tool | Cloud(s) | Modules (lessons) | Install |
|---|---|---|---|
| **gitleaks-action** | GitHub Actions | `IaC-Security/static-analysis-checkov-tfsec.md`, `Secrets-KMS/git-and-cicd-leakage-paths.md` | GitHub Marketplace: `uses: gitleaks/gitleaks-action@v2` |
| **GitHub Advanced Security** (secret scanning) | GitHub-native | `Secrets-KMS/git-and-cicd-leakage-paths.md` | Enabled per-repo under Settings → Security → Code security and analysis |
| **GitLab Secret Detection** | GitLab-native | `Secrets-KMS/git-and-cicd-leakage-paths.md` | Enabled in `.gitlab-ci.yml`: `include: template: Security/Secret-Detection.gitlab-ci.yml` |
| **SonarCloud** | Multi-language SAST (free for public repos) | `IaC-Security/static-analysis-checkov-tfsec.md`, `Cloud-Native-App-Security/supply-chain-and-3p-integrations.md` (as of June 2026, SonarCloud supports IaC scanning for Terraform, CloudFormation, Bicep, and Kubernetes; verify current plugin status on SonarCloud docs) | sonarcloud.io (GitHub / GitLab / Bitbucket integration) |
| **TruffleHog Enterprise** | Self-hosted secret scanning (open-source core) | `Secrets-KMS/git-and-cicd-leakage-paths.md` | `docker run trufflesecurity/trufflehog` (community version); enterprise is paid |

---

## 10. Quick-Start: Bootstrap a Lab Workstation

```bash
# macOS (Homebrew)
brew install awscli azure-cli google-cloud-sdk terraform jq yq checkov trivy gitleaks
brew install k9s opa kyverno cosign
pip install prowler scoutsuite cloudsploit detect-secrets

# Linux (apt)
sudo apt install -y jq awscli
pip install prowler scoutsuite detect-secrets

# Verify
aws --version && az --version && gcloud --version
terraform version
trivy --version
checkov --version
```

> All commands are version-agnostic. Install the latest stable release unless a lab explicitly pins a version.

---

## Cross-Reference by Module

| Module | Primary tools |
|---|---|
| `Fundamentals/` | ScoutSuite, aws-vault, Terraform, LocalStack |
| `Network-Security/` | mitmproxy, nmap, AWS CLI, az CLI, gcloud CLI |
| `IAM/` | cloudfox, aws-vault, AADInternals, `gcloud iam`, OPA/Rego, Kyverno |
| `Compute-Container-Security/` | kube-bench, kube-hunter, kubeaudit, Falco, Trivy, cosign, Kyverno, OPA Gatekeeper, kind, minikube, k3d, k9s |
| `Storage-Data-Security/` | AWS CLI, az CLI, gcloud CLI, Cloud Custodian |
| `Secrets-KMS/` | gitleaks, truffleHog, detect-secrets, cosign+Rekor |
| `Monitoring-Detection-SIEM/` | Sigma/pySigma, Cloud Custodian, Falco, Prowler, GuardDuty, Sentinel, SCC |
| `Cloud-Native-App-Security/` | mitmproxy, pip-audit, osv-scanner, SonarCloud |
| `IaC-Security/` | Checkov, tfsec/Trivy, KICS, Terrascan, Cloud Custodian, OPA/Rego, Terraform |
| `Red-Team-Offense/` | pacu, cloudfox, ScoutSuite, AADInternals, kube-hunter, truffleHog |
| `Blue-Team-Defense/` | Prowler, ScoutSuite, CloudSploit, Cloud Custodian, OPA/Rego, Kyverno, Falco, Cosign |
| `IR-Forensics-Cloud/` | Volatility 3, AVML, LiME, gcore |
| `Compliance-Audit-Gov/` | Prowler, AWS Audit Manager, Azure Defender, GCP SCC |
| `Capstone-APT-Scenario/` | Terraform, LocalStack, kind, all above tools |

---

> See `resources/templates/` for copy-paste Sigma, Cloud Custodian, OPA, IR runbook, honeytoken provision, and post-incident-report scaffolds.
