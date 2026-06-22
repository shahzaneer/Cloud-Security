# Detection 01 — CI-Leaked Token Detection

> **Module:** 05-Secrets-KMS
> **Goal:** Detect secrets in CI pipelines and build artifacts, block builds, and trigger automatic revocation.
> **Authorization scope:** All examples use placeholder tokens and account IDs.

## Detection architecture

```
Developer push ──▶ Git provider (GitHub/GitLab) ──▶ CI Pipeline
                         │                              │
                    [Pre-receive hook]            [gitleaks step]
                         │                              │
                    Secret scan                    ┌─────┴──────┐
                    (push protection)              │             │
                                             PASS (no secrets)  FAIL (secrets found)
                                                   │             │
                                              Deploy job    ┌────┴─────┐
                                                            │          │
                                                       Block build  Alert webhook
                                                            │          │
                                                       SARIF upload  Revoke secret
                                                                     (automated pipeline)
```

---

## 1. GitHub Actions — gitleaks in CI

```yaml
# .github/workflows/secret-scan.yml
name: Secret Detection — Block on Findings

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    # Run even if previous jobs failed — secrets are critical
    if: always()

    steps:
      - name: Full checkout (all commits)
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run gitleaks
        id: gitleaks
        uses: gitleaks/gitleaks-action@v2
        with:
          config-path: .gitleaks.toml
        continue-on-error: true

      - name: Block build on findings
        if: steps.gitleaks.outcome == 'failure'
        run: |
          echo "::error::=== SECRETS DETECTED ==="
          echo "::error::The CI pipeline has blocked this build because secrets were found."
          echo "::error::Rotate any exposed credentials immediately."
          echo "::error::Remove secrets from history with: git filter-branch or BFG Repo-Cleaner"
          exit 1

      - name: Report success
        if: steps.gitleaks.outcome == 'success'
        run: echo "No secrets detected — build proceeding"
```

### GitHub Actions — with SARIF upload for CodeQL dashboard

```yaml
      - name: Upload SARIF to GitHub Security tab
        if: steps.gitleaks.outcome == 'failure'
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Notify Slack on secret detection
        if: steps.gitleaks.outcome == 'failure'
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "channel": "#security-alerts",
              "text": "SECRETS DETECTED in ${{ github.repository }} by ${{ github.actor }} in commit ${{ github.sha }}\nSee: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_SECURITY }}
```

---

## 2. GitLab CI — Secret Detection include

```yaml
# .gitlab-ci.yml
include:
  - template: Security/Secret-Detection.gitlab-ci.yml

stages:
  - test
  - secret-detection
  - build
  - deploy

secret_detection:
  stage: secret-detection
  extends: .secret-analyzer
  variables:
    SECRET_DETECTION_HISTORIC_SCAN: "true"
  rules:
    - if: $CI_COMMIT_BRANCH
      exists:
        - '**/*'
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.json
    expire_in: 30 days

block-on-secrets:
  stage: build
  needs: [secret_detection]
  script:
    - |
      if [ -f gl-secret-detection-report.json ]; then
        FINDINGS=$(jq '.vulnerabilities | length' gl-secret-detection-report.json)
        if [ "$FINDINGS" -gt 0 ]; then
          echo "SECRETS DETECTED: $FINDINGS findings"
          jq '.vulnerabilities[] | {message: .message, file: .location.file}' gl-secret-detection-report.json
          exit 1
        fi
      fi
    - echo "No secrets — build allowed"
  rules:
    - if: $CI_COMMIT_BRANCH == "main"

build:
  stage: build
  needs: [block-on-secrets]
  script:
    - echo "Building..."
```

**GitLab CI — auto-revoke on detection:**

```yaml
revoke-leaked-secret:
  stage: deploy
  needs: [secret_detection]
  when: on_failure
  script:
    - |
      # Parse the secret detection report
      LEAKED_TYPES=$(jq -r '.vulnerabilities[].identifiers[0].name' gl-secret-detection-report.json)

      for type in $LEAKED_TYPES; do
        case "$type" in
          *AWS*)
            # Deactivate the access key (IAM must have been set up to pass key ID)
            aws iam update-access-key \
              --user-name ci-service-user \
              --access-key-id "AKIAIOSFODNN7EXAMPLE" \
              --status Inactive
            ;;
          *GitHub*)
            # Revoke GitHub token via API
            gh api --method DELETE "/applications/${GITHUB_APP_ID}/token"
            ;;
        esac
      done

      echo "Automatic revocation triggered for detected secret types: $LEAKED_TYPES"
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

---

## 3. Sigma-style rule — GitHub secret scanning alert webhook

```yaml
title: GitHub Secret Scanning Alert — New Credential Leak Detected
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
level: critical
author: Cloud Security Curriculum
date: 2026-06-22

description: |
  Detects when GitHub Advanced Security finds a leaked secret in a repository push.
  The secret_scanning_alert webhook fires in near-real-time after a push.

logsource:
  category: webhook
  service: github
  definition: GitHub secret_scanning_alert event

detection:
  selection:
    action: created                          # New alert (not resolved/reopened)
    alert.secret_type_display_name:          # Secret type matched

  # Filter out known test repos
  filter_test_repos:
    alert.repository.full_name|endswith:
      - "/security-lab"
      - "/secret-test"

  condition: selection and not filter_test_repos

fields:
  - alert.secret_type
  - alert.secret_type_display_name
  - alert.repository.full_name
  - alert.push_protection_bypassed
  - sender.login

falsepositives:
  - Test repositories with known placeholder secrets
  - Custom regex rules that match non-secret patterns in config files

severity: critical
tags:
  - attack.credential_access
  - attack.t1552.004
```

---

## 4. Build-Breaker Policy (OPA / Cloud Custodian)

```rego
# OPA policy: deny deployment if secrets found in build log
package secrets.build_blocker

# In-cluster OPA/Kyverno policy checking build artifacts
deny[msg] {
    input.kind == "Build"
    log := input.build_log
    regex.match(`AKIA[A-Z0-9]{16}`, log)
    msg := sprintf("BUILD BLOCKED: AWS access key detected in build log of %s", [input.build_name])
}

deny[msg] {
    input.kind == "Build"
    log := input.build_log
    regex.match(`(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}`, log)
    msg := sprintf("BUILD BLOCKED: GitHub token detected in build log of %s", [input.build_name])
}

deny[msg] {
    input.kind == "Build"
    log := input.build_log
    regex.match(`glpat-[A-Za-z0-9\-_]{26}`, log)
    msg := sprintf("BUILD BLOCKED: GitLab token detected in build log of %s", [input.build_name])
}

deny[msg] {
    input.kind == "Build"
    log := input.build_log
    regex.match(`AIza[0-9A-Za-z\-_]{35}`, log)
    msg := sprintf("BUILD BLOCKED: GCP API key detected in build log of %s", [input.build_name])
}
```

```yaml
# Cloud Custodian policy: block CodeBuild projects without secret scanning
policies:
  - name: codebuild-secret-scanning-required
    resource: aws.codebuild
    filters:
      - type: value
        key: source.type
        value: GITHUB
      - or:
        - type: value
          key: source.buildspec
          op: regex
          value: ".*gitleaks.*"
          invert: true
    actions:
      - type: notify
        template: secret-scan-missing
        to: [security-alerts@example.com]
        transport:
          type: sns
          topic: arn:aws:sns:us-east-1:111111111111:security-alerts
```

---

## 5. Custom detection patterns (extending gitleaks)

```toml
# .gitleaks.toml — custom rules for internal patterns
title = "Corporate Secret Detection Rules"

[[rules]]
id = "corp-internal-api-key"
description = "Internal API key pattern (example.com)"
regex = '''example\.com_[a-z0-9]{32}'''
tags = ["internal", "api-key"]

[[rules]]
id = "terraform-output-secrets"
description = "Terraform output containing secrets"
regex = '''output\s+"\w*secret\w*"'''
path = '''\.tf$'''
tags = ["terraform", "iac"]

[[rules]]
id = "kubernetes-secrets-plaintext"
description = "Kubernetes secret manifest with plaintext data"
regex = '''(?s)kind:\s*Secret.*stringData:'''
path = '''\.ya?ml$'''
tags = ["kubernetes", "manifest"]

[[rules]]
id = "env-file-with-secrets"
description = ".env file with credential patterns"
regex = '''(?i)(password|secret|token|key)\s*=\s*[^\s]{8,}'''
path = '''\.env'''
tags = ["env", "config"]
```

---

## 6. Response playbook — when CI detects a secret

```
┌──────────────────────────────────────────────────────────────┐
│ 1. ALERT: CI pipeline found secrets                          │
│    → Build automatically BLOCKED                             │
│    → Security team paged via Slack/PagerDuty                 │
├──────────────────────────────────────────────────────────────┤
│ 2. IDENTIFY: What secret type? Where in repo?                │
│    → CI job log / SARIF report shows file, commit, type      │
├──────────────────────────────────────────────────────────────┤
│ 3. CONTAIN (immediate):                                      │
│    a) Revoke the leaked credential (IAM key disable,         │
│       GitHub token revoke, DB password rotate)               │
│    b) If AWS IAM key: aws iam update-access-key --status Inactive │
│    c) If GitHub token: Delete from Settings → Developer settings │
├──────────────────────────────────────────────────────────────┤
│ 4. INVESTIGATE:                                              │
│    a) Who committed? Was it accidental or malicious?         │
│    b) When was the credential first pushed?                  │
│    c) Has it been accessed from unknown IPs? (CloudTrail)    │
│    d) What resources could the credential access?            │
├──────────────────────────────────────────────────────────────┤
│ 5. ERADICATE:                                                │
│    a) Remove secret from git history (filter-branch/BFG)     │
│    b) Force-push cleaned history (if safe to do so)          │
│    c) If credential already used externally → assume         │
│       compromise and initiate full IR                        │
├──────────────────────────────────────────────────────────────┤
│ 6. RECOVER:                                                  │
│    a) Generate new credential, store in Secrets Manager      │
│    b) Update all consumers with new credential               │
│    c) Verify application health after rotation               │
├──────────────────────────────────────────────────────────────┤
│ 7. POST-MORTEM:                                              │
│    a) Why wasn't pre-commit blocking effective?              │
│    b) Enable push protection (GitHub / GitLab)               │
│    c) Review CI env var scope — reduce blast radius          │
└──────────────────────────────────────────────────────────────┘
```

---

## 7. Audit CLI one-liners

```bash
# Check all GitHub repos in org for missing secret scanning
gh repo list example-org --limit 200 --json nameWithOwner \
  --jq '.[].nameWithOwner' | while read repo; do
  gh api "repos/$repo" --jq \
    'select(.secret_scanning.status != "enabled" or .secret_scanning_push_protection.status != "enabled") | "\(.full_name): scanning=\(.secret_scanning.status) push_protection=\(.secret_scanning_push_protection.status)"'
done

# GitLab: check all projects for secret detection
curl --header "PRIVATE-TOKEN: glpat-placeholder-token-notreal" \
  "https://gitlab.example.com/api/v4/projects?per_page=100" | \
  jq '.[] | select(.security_and_analysis.secret_detection.enabled != true) | .path_with_namespace'

# AWS: find CodeBuild projects without gitleaks in buildspec
aws codebuild batch-get-projects --names $(aws codebuild list-projects --query "projects" --output text) \
  --query "projects[?!(contains(source.buildspec, 'gitleaks') || contains(source.buildspec, 'trufflehog'))].name"

# Scan ALL AWS CodeBuild recent build logs for secrets
aws logs filter-log-events \
  --log-group-name /aws/codebuild/project-name \
  --filter-pattern "AKIA" \
  --start-time $(date -v-7d +%s)000
```

---

## Integration test — verify detection pipeline end-to-end

```bash
#!/bin/bash
# test-secret-detection-pipeline.sh
# Run in a sandbox repo to verify the full detection chain works

TEST_REPO="/tmp/secret-detection-test"
rm -rf "$TEST_REPO"
mkdir "$TEST_REPO" && cd "$TEST_REPO"
git init

# 1. Commit a benign file
echo "No secrets here" > README.md
git add README.md && git commit -m "Initial commit"

# 2. Commit a secret (simulate leak)
echo 'AWS_SECRET_ACCESS_KEY=PLACEHOLDER_TEST_KEY_NOT_A_REAL_KEY' > leaked.env
git add leaked.env && git commit -m "Oops — add env file" 2>/dev/null

# 3. Run gitleaks — should DETECT
echo "=== TEST 1: gitleaks detect ==="
gitleaks detect --source . --no-git --verbose 2>&1
if [ $? -ne 0 ]; then
    echo "PASS: gitleaks detected the secret"
else
    echo "FAIL: gitleaks missed the secret"
fi

# 4. Simulate pre-commit blocking
cat > .pre-commit-config.yaml << 'YEOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.1
    hooks:
      - id: gitleaks
YEOF
pre-commit install 2>/dev/null

echo 'GITHUB_TOKEN=ghp_fakeTokenForTesting1234567890abcdefgh' > token.txt
git add token.txt
git commit -m "Should be blocked" 2>&1
if [ $? -ne 0 ]; then
    echo "PASS: pre-commit blocked the secret"
else
    echo "FAIL: pre-commit did not block"
fi

echo "=== Detection pipeline test complete ==="
```

---

## References

- [gitleaks GitHub Action](https://github.com/gitleaks/gitleaks-action)
- [GitLab Secret Detection](https://docs.gitlab.com/ee/user/application_security/secret_detection/)
- [GitHub Secret Scanning API](https://docs.github.com/en/rest/secret-scanning)
- [OWASP — Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- Cross-link: [05-06 — Git & CI/CD Leakage Paths](../git-and-cicd-leakage-paths.md)
