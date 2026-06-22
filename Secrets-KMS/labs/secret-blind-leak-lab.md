# Lab 01 — Secret Blind-Leak Lab

> **Module:** 05-Secrets-KMS
> **Duration:** 20–30 min
> **Cost:** Free (local machine only)
> **Tooling:** `git`, `gitleaks` (pre-installed or `brew install gitleaks`), `pre-commit`
> **Authorization scope:** Local-only; use the provided placeholder secret. Never use real credentials.

## Objective

Accidentally commit a secret (placeholder format), detect it with `gitleaks`, install a pre-commit hook to block future leaks, and simulate a CI pipeline failing the build on detection.

## Prerequisites

```bash
# Install gitleaks (macOS)
brew install gitleaks

# Install pre-commit
brew install pre-commit

# Verify
gitleaks version
pre-commit --version
```

## Step 1 — Create a test repository with a benign committed secret

```bash
# Create a fresh temp directory
mkdir -p /tmp/secret-leak-lab
cd /tmp/secret-leak-lab
git init
git config user.email "lab@example.com"
git config user.name "Lab Student"

# Create a harmless config file containing a FORMAT-VALID placeholder secret
# (This is the AWS-recommended documentation example key — NOT a real key)
cat > config.yaml << 'EOF'
# Application configuration
database:
  host: example-db.internal.example.com
  port: 5432
  username: app_user

# SECURITY WARNING: The line below is an AWS-DOCUMENTED PLACEHOLDER key
# used for learning purposes. It has NEVER been a live credential.
aws:
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region: us-east-1

# Benign config continues
logging:
  level: info
  output: stdout
EOF

# Commit the secret intentionally (simulating an accidental push)
git add config.yaml
git commit -m "Add application configuration"

echo "=== Secret committed to local repo ==="
git log --oneline
```

**Expected output:** A single commit on the `main` branch containing `config.yaml` with the placeholder secret.

## Step 2 — Run gitleaks on the repository history

```bash
# Scan the entire git history (all commits)
gitleaks detect --source . --verbose

# Scan the repo without git (filesystem only vs history)
gitleaks detect --source . --no-git --verbose
```

**Expected output (git history scan):**

```
Finding:
    RuleID: aws-access-key
    Description: AWS Access Key
    Secret: AKIAIOSFODNN7EXAMPLE
    File: config.yaml
    Line: 10
    Commit: <commit-hash>
    Author: Lab Student
    Email: lab@example.com
    Date: ...
```

**Expected output (--no-git scan):** Same finding.

> The `--no-git` flag scans only the current working tree, not the full history. Use both: `--no-git` for current state, full scan for git history.

### Additional scan modes

```bash
# Save findings as JSON for CI pipeline consumption
gitleaks detect --source . --report-format json --report-path gitleaks-report.json
cat gitleaks-report.json | jq '.[0] | {RuleID, File, Secret}'

# Save as SARIF (for GitHub code scanning integration)
gitleaks detect --source . --report-format sarif --report-path gitleaks-report.sarif
```

## Step 3 — Install pre-commit and block re-commits of secrets

```bash
# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.1
    hooks:
      - id: gitleaks
        args: ['--verbose']
        stages: [commit]
EOF

# Install the pre-commit hook
pre-commit install

# Verify the hook is installed
cat .git/hooks/pre-commit | head -20
```

### Test: try to commit another secret (should be BLOCKED)

```bash
# Create a new file with a fake secret
cat > api-keys.txt << 'EOF'
# This is a format-valid placeholder — LAB ONLY
GITHUB_TOKEN=ghp_FakeTokenForLabTestingPurposes1234
EOF

git add api-keys.txt

# Attempt to commit — pre-commit hook should block it
git commit -m "Add API keys (should fail)" 2>&1 || echo "=== COMMIT BLOCKED (expected) ==="
```

**Expected output:**

```
gitleaks................................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:
    RuleID: github-pat
    Secret: ghp_FakeTokenForLabTestingPurposes1234
    File: api-keys.txt

=== COMMIT BLOCKED (expected) ===
```

The file remains **staged but uncommitted**. The secret never entered the repository history.

### Verify bypass is impossible without explicit override

```bash
# Try with --no-verify (bypasses hooks — but this is detectable in CI)
git commit -m "Bypass hooks" --no-verify 2>&1
# This WILL succeed — pre-commit only runs locally
# CI should catch this in Step 4

# Undo the bypass commit to keep the lab clean
git reset --soft HEAD~1
```

## Step 4 — CI pipeline simulation

```bash
mkdir -p .github/workflows

cat > .github/workflows/secret-scan.yml << 'EOF'
name: Secret Detection

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout full history
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run gitleaks
        uses: gitleaks/gitleaks-action@v2
        with:
          config-path: .gitleaks.toml
          report-format: sarif
          report-path: gitleaks-report.sarif

      - name: Upload findings
        if: failure()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks-report.sarif

      - name: Block build on secrets
        if: failure()
        run: |
          echo "::error::SECRETS DETECTED IN REPOSITORY — BUILD BLOCKED"
          exit 1

      - name: Pass
        if: success()
        run: echo "No secrets detected — proceeding to deploy"
EOF
```

### Simulate CI locally (run the workflow check manually)

```bash
# Create a gitleaks configuration for CI (stricter than pre-commit)
cat > .gitleaks.toml << 'EOF'
# Title for the gitleaks configuration
title = "CI Secret Detection Configuration"

[allowlist]
  description = "Global allowlist"

# The CI check runs on FULL HISTORY — stricter than pre-commit
EOF

# Run the equivalent CI check locally
gitleaks detect --source . --config-path .gitleaks.toml --verbose
# If exit code = 0: no secrets found — CI passes
# If exit code = 1: secrets found — CI blocks the build
```

### Test: the CI should fail on the SECRET-IN-HISTORY

```bash
# Since Step 1 already committed the placeholder secret...
gitleaks detect --source . --config-path .gitleaks.toml 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "=== CI BUILD FAILED: Secrets detected in repository history ==="
  echo "=== This is the CORRECT behavior — the pipeline caught the leak ==="
else
  echo "UNEXPECTED: CI passed but history contains secrets"
fi
```

**Expected output:** `CI BUILD FAILED: Secrets detected in repository history`

## Step 5 — Remediation (removing the secret from history)

```bash
# Option A: Remove the file AND its history (rewrite git history)
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch config.yaml" \
  --prune-empty --tag-name-filter cat -- --all

# Verify the secret is gone from history
gitleaks detect --source . 2>&1
# Expected: No findings

# Option B: Use BFG Repo-Cleaner for larger repos
# java -jar bfg.jar --delete-files config.yaml /tmp/secret-leak-lab

# In a real scenario, after rewriting history:
# git push --force-with-lease  (NEVER force-push shared branches without coordination)
# AND rotate the actual credential immediately
```

## Step 6 — Verify the final state

```bash
# 1. gitleaks finds nothing
gitleaks detect --source . && echo "PASS: No secrets detected"

# 2. git status is clean (except staged api-keys.txt from earlier block test)
git status

# 3. pre-commit is installed and active
pre-commit run --all-files
echo "PASS: Pre-commit hook active"
```

**Final expected output:**
```
PASS: No secrets detected
PASS: Pre-commit hook active
```

## What you learned

1. `gitleaks detect` scans git history AND working tree for secret patterns
2. Pre-commit hooks **block secrets at commit time** (before they enter history)
3. CI pipelines provide a **second line of defense** — they catch what pre-commit misses (e.g., `--no-verify` bypass, or secrets committed before hooks were installed)
4. Secrets in git history persist **forever** — removing them requires history rewrite AND credential rotation
5. The remediation workflow: detect → rewrite history → rotate credentials → force-push

## Teardown

```bash
# Clean up the lab directory completely
cd /tmp
rm -rf /tmp/secret-leak-lab

# Uninstall pre-commit hooks from any remaining repos (they're per-repo)
# No global cleanup needed — pre-commit hooks are repo-local

echo "Lab teardown complete."
```

## Troubleshooting

| Problem | Solution |
|---|---|
| `gitleaks: command not found` | `brew install gitleaks` (macOS) or download from [github.com/gitleaks/gitleaks/releases](https://github.com/gitleaks/gitleaks/releases) |
| Pre-commit: `.pre-commit-config.yaml` not found | Ensure you're in the repo root directory |
| `git filter-branch` warning about replacing refs | Normal — filter-branch rewrites history; run `git update-ref -d refs/original/refs/heads/main` to clean up backup refs |
| gitleaks still finds secrets after filter-branch | Check for backup refs: `git for-each-ref --format='%(refname)' refs/original/` and delete them |
