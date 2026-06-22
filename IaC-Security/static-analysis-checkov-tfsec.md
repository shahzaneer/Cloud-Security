# 05 — Static Analysis: Checkov & tfsec

> **Level:** Intermediate
> **Prereqs:** [08-04 — Policy-as-Code Rego & Sentinel](./policy-as-code-rego-sentinel.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion, Initial Access (misconfiguration prevention)
> **Authorization scope:** Run against your own Terraform code and sandbox environments only.

## What & why

Static analyzers scan Terraform/Pulumi/CloudFormation code *before* `terraform apply` and flag known insecure patterns: public S3 buckets, `0.0.0.0/0` security groups, unencrypted volumes, plaintext secrets in attributes, and overly permissive IAM. They complement policy-as-code by catching the "known-bad" patterns that don't require custom business logic.

## The OnPrem reality

Linting tools like `cppcheck` (C/C++), `bandit` (Python), and `shellcheck` (Bash) established the pattern: scan code for known dangerous constructs before runtime. IaC scanners extend this to infrastructure syntax — they check that your Terraform doesn't create an S3 bucket with `acl = "public-read"`, just as `bandit` checks you didn't call `subprocess.call(shell=True)`.

```bash
# Pre-cloud: security lint for Python
pip install bandit
bandit -r ./myapp/  # flags: subprocess shell=True, hardcoded passwords, assert in prod
```

## Tooling landscape

| Tool | License | Coverage | PR integration | Custom policies | Output formats |
|---|---|---|---|---|---|
| **Checkov** (Bridgecrew/Palo Alto) | Apache 2.0 | AWS, Azure, GCP, K8s, Helm, Docker, GitHub Actions | GitHub/GitLab comments, SARIF | Python + YAML custom checks | JSON, JUnit XML, SARIF, CSV |
| **tfsec / Trivy** (Aqua) | MIT | AWS, Azure, GCP, K8s | PR comments, SARIF | Rego-based custom checks | JSON, SARIF, Checkstyle, JUnit |
| **KICS** (Checkmarx) | Apache 2.0 | AWS, Azure, GCP, K8s, Ansible, Docker, CloudFormation | SARIF, GitHub comments | Rego + OpenAPI | JSON, SARIF, HTML, PDF |
| **Terrascan** (Tenable) | Apache 2.0 | AWS, Azure, GCP, K8s | SARIF, GitHub | Rego-based | JSON, YAML, XML, SARIF |
| **CloudSploit** (Aqua) | MIT | AWS (primarily), Azure, GCP | N/A (runtime-focused) | Plugin-based | JSON, text |

### Coverage matrix by policy type

| Policy | Checkov | tfsec/Trivy | KICS | Terrascan |
|---|---|---|---|---|
| S3 public bucket | `CKV_AWS_18` — "Ensure S3 bucket has ignore_public_acls" | `aws-s3-enable-bucket-logging` | `b0b58de6-...` | `AC_AWS_0207` |
| Security group 0.0.0.0/0 SSH | `CKV_AWS_23` — "Every SG rule should restrict source" | `aws-ec2-no-public-ingress-sgr` | Yes | `AC_AWS_0234` |
| RDS encryption disabled | `CKV_AWS_16` — "Ensure RDS has storage_encrypted=true" | `aws-rds-enable-storage-encryption` | Yes | `AC_AWS_0039` |
| IAM policy wildcard `*` | `CKV_AWS_63` — "No IAM policy with * in actions" | `aws-iam-no-policy-wildcards` | Yes | `AC_AWS_0900` |
| Azure Storage HTTPS only | `CKV_AZURE_2` | `azure-storage-enforce-https` | Yes | `AC_AZURE_0003` |
| GCP bucket public access | `CKV_GCP_28` | `google-storage-bucket-no-public-access` | Yes | `AC_GCP_0049` |
| Lambda env vars without encryption | `CKV_AWS_173` | `aws-lambda-enable-env-encryption` | Yes | — |

> (as of June 2026, check IDs are accurate for current tool versions; always run `checkov -l` or `trivy config --list-checks` for current IDs, as they may shift across releases.)

## AWS

```bash
# Install
pip install checkov
# or: brew install checkov

# Basic scan
checkov -d .

# Scan a specific directory, output as SARIF (GitHub code scanning)
checkov -d ./terraform/aws/prod -o sarif

# Skip specific checks that are accepted risks
checkov -d . --skip-check CKV_AWS_18,CKV2_AWS_6

# Use a baseline to suppress known exceptions
checkov -d . --create-baseline baseline.yml
checkov -d . --baseline baseline.yml
```

```bash
# tfsec / Trivy
pip install tfsec
# or: brew install tfsec

# Basic scan
tfsec .

# Scan with custom exclusions
tfsec . --exclude-downloaded-modules

# Output as SARIF
tfsec . --format sarif --out results.sarif

# Trivy (successor to tfsec — broader scope)
brew install trivy
trivy config ./terraform/aws/prod
```

**PR comment example (GitHub Actions):**

```yaml
name: IaC Scan
on: [pull_request]
jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: .
          output_format: github_failed_only
          soft_fail: false
```

## Azure

```bash
# Checkov scans Azure ARM/Bicep/Terraform
checkov -d ./infra/azure --framework terraform

# tfsec Azure-specific
tfsec . --include-passed

# KICS with Azure focus
docker run -v $(pwd):/path checkmarx/kics:latest scan -p /path -o /path/results
```

```bash
# Bicep-specific: built-in linter
az bicep build --file main.bicep
# Checks: no plaintext secrets, secure parameter defaults
```

## GCP

```bash
# Checkov GCP
checkov -d ./infra/gcp --framework terraform

# Trivy for GCP config
trivy config --severity HIGH,CRITICAL ./infra/gcp

# Deployment Manager — checkov supports DM templates
checkov -d . --framework cloudformation  # also supports GCP DM via similarity
```

## OnPrem (OpenTofu / self-managed)

```bash
# Same tooling works for OpenTofu (same HCL syntax)
checkov -d ./infra/onprem

# Terrascan for non-cloud Terraform providers (vSphere, Proxmox, etc.)
terrascan scan -d ./infra/onprem -i terraform
```

## Per-cloud IaC formats supported

| Format | Checkov | tfsec/Trivy | KICS | Terrascan |
|---|---|---|---|---|
| Terraform (HCL) | Yes | Yes | Yes | Yes |
| CloudFormation (JSON/YAML) | Yes | No | Yes | Yes |
| ARM (JSON) | Yes | No | Yes | No |
| Bicep | Yes (via build) | No | No | No |
| Pulumi (Python/TS/Go) | Yes | No | No | No |
| Kubernetes (YAML) | Yes | Yes | Yes | Yes |
| Helm (charts) | Yes | Yes | Yes | Yes |
| Dockerfile | Yes | Yes | Yes | Yes |

## 🔴 Red Team view

**Narrative: Tool tuning as a backdoor vector.**

A development team adopts Checkov in CI. Initially, it flags 200+ violations — many false positives on legacy resources they can't change (e.g., an old S3 bucket created before `BlockPublicAccess` was default). The team creates a baseline file suppressing 50 checks as "accepted risk." Over 6 months, they accumulate 5 more suppressions for "noise." Two of those suppressed checks cover real vulnerabilities:

1. `CKV_AWS_79` (IMDSv2 required) — suppressed because a legacy app "needed" IMDSv1. That suppression now applies to new instances too.
2. `CKV_AWS_111` (IAM policy wildcard) — suppressed because a legacy role had broad perms. A new role inherits the same suppression.

**Contained scenario:** An attacker discovers the open IMDSv1 path on a new EC2 instance, performs SSRF to extract temporary credentials from `169.254.169.254`, and escalates.

**Artifacts:**
- `.checkov.yml` or `baseline.yml` in the repo with growing skip list
- PR history: "disabling noise" commits without security review
- CloudTrail: `ec2:RunInstances` with `MetadataOptions.HttpTokens = optional`

## 🔵 Blue Team view

**Preventive controls:**

1. **Baseline file with mandatory sign-off:**
   ```yaml
   # .checkov.yml — every suppression requires justification + owner
   skip-check:
     - CKV_AWS_79  # IMDSv2 not required
       resource: "module.legacy_app.*"
       reason: "Legacy app migration Q2 2026 — ticket CLOUD-1234"
       owner: "team-platform"
       expires: "2026-06-30"
   ```

2. **CODEOWNERS gate for baseline changes:**
   ```
   # .github/CODEOWNERS
   .checkov.yml     @example-org/security-team
   baseline.yml     @example-org/security-team
   ```

3. **Matrix export to SIEM — daily scan results as structured logs:**

   ```bash
   #!/bin/bash
   # Nightly: scan all Terraform repos, export failures as JSON → SIEM
   for repo in org/repo1 org/repo2 org/repo3; do
     git clone --depth 1 "https://github.com/$repo" /tmp/scan-$repo
     checkov -d /tmp/scan-$repo -o json > /tmp/checkov-$repo.json
     # Ship to SIEM via webhook or filebeat
     curl -X POST https://siem.internal.example.com/ingest \
       -H "Content-Type: application/json" \
       -d @/tmp/checkov-$repo.json
   done
   ```

4. **Minimal suppression sprint — reduce baseline monthly:**
   ```bash
   # Generate current baseline
   checkov -d . --create-baseline new-baseline.yml
   # Compare with old baseline
   diff old-baseline.yml new-baseline.yml | grep '^<' | wc -l  # removed suppressions
   diff old-baseline.yml new-baseline.yml | grep '^>' | wc -l  # new suppressions (require review)
   ```

5. **Fail-on-new-suppressions policy in CI:**

   ```python
   #!/usr/bin/env python3
   """CI gate: new checkov suppressions require security team approval."""
   import yaml, sys, subprocess

   # Compare current baseline vs main branch
   subprocess.run(["git", "fetch", "origin", "main"])
   diff = subprocess.run(
       ["git", "diff", "origin/main", "--", ".checkov.yml"],
       capture_output=True, text=True
   )
   added = [l for l in diff.stdout.split("\n") if l.startswith("+  - CKV_")]
   if added and "security-team" not in sys.argv[1:]:
       print("SECURITY BLOCK: New checkov suppressions require @security-team approval")
       sys.exit(1)
   ```

**Detection checklist:**
- [ ] Checkov/tfsec/Trivy run on every PR (not just main branch pushes)
- [ ] Scans run as blocking (not `soft_fail: true` without compensating controls)
- [ ] Baseline file under CODEOWNERS (security team must approve changes)
- [ ] Baseline suppressions have owner, reason, and expiration
- [ ] Nightly full scan exports results to SIEM
- [ ] Monthly baseline review reduces suppression count
- [ ] All four IaC formats (TF, CFN, ARM/Bicep, K8s) covered by at least one scanner
- [ ] CI uses `--framework all` to catch K8s/Dockerfile misconfigurations in the same repo

## Hands-on lab

1. Install and run both scanners:
   ```bash
   mkdir lab-static-scan && cd lab-static-scan
   pip install checkov tfsec

   cat > bad.tf <<'EOF'
   resource "aws_s3_bucket" "bad" {
     bucket = "bad-bucket-111111111111"
     acl    = "public-read"
   }
   resource "aws_security_group" "bad" {
     ingress {
       from_port   = 22
       to_port     = 22
       protocol    = "tcp"
       cidr_blocks = ["0.0.0.0/0"]
     }
   }
   resource "aws_db_instance" "bad" {
     allocated_storage = 20
     engine            = "postgres"
     username          = "admin"
     password          = "HardcodedPassword123"
     skip_final_snapshot = true
   }
   EOF
   ```

2. Run both scanners and compare output:
   ```bash
   checkov -d . --quiet
   # Expected: 3+ failures (public bucket, open SG, unencrypted RDS, hardcoded password)

   tfsec .
   # Expected: similar failures, possibly more granular
   ```

3. Create a baseline and fix one issue:
   ```bash
   checkov -d . --create-baseline baseline.yml
   # Fix the bucket ACL
   sed -i 's/"public-read"/"private"/' bad.tf
   checkov -d . --baseline baseline.yml
   # Expected: failures for SG + RDS remain (not in baseline), bucket passes
   ```

4. **Teardown:** `rm -rf lab-static-scan`

## References

- [Checkov Documentation](https://www.checkov.io/)
- [tfsec Documentation](https://aquasecurity.github.io/tfsec/)
- [Trivy Misconfiguration Scanning](https://aquasecurity.github.io/trivy/latest/docs/scanner/misconfiguration/)
- [KICS — Keeping Infrastructure as Code Secure](https://kics.io/)
- See ATT&CK: T1190 (Exploit Public-Facing Application), T1526 (Cloud Service Discovery)
- [05-06 — Git & CI/CD Leakage Paths](../Secrets-KMS/git-and-cicd-leakage-paths.md)
