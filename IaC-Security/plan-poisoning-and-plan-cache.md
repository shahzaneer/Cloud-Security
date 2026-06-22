# 03 — Plan Poisoning & Plan Cache Attacks

> **Level:** Advanced
> **Prereqs:** [08-01 — IaC State & Backend Security](./iac-state-and-backend-security.md), [08-06 — CI/CD Runner as Cloud Principal](./cicd-runner-as-cloud-principal.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Persistence, Defense Evasion, Execution
> **Authorization scope:** Run only against your own CI/CD pipelines and sandbox accounts; all role names and repos are placeholders.

## What & why

A CI pipeline that runs `terraform plan` on pull requests and `terraform apply` on merge shares a critical artifact — the plan file (`tfplan`). If an attacker can tamper with the plan between generation and application — by modifying a PR comment, poisoning a cached artifact, or subverting the runner — they can deploy infrastructure the reviewer never approved. Plan poisoning is a supply-chain attack on the IaC pipeline itself.

## The OnPrem reality

Before cloud CI, build artifacts lived in shared directories on Jenkins workers or in Artifactory generic repos. A `make` target would write a tarball, and a downstream job would unpack it. No cryptographic verification existed between build stages — the shared filesystem or Artifactory path was the sole trust boundary. Anyone with access to the Jenkins workspace could modify the build artifact between stages.

```bash
# Pre-cloud: shared NFS build directory — any user can tamper
make package      # writes ./build/release.tar.gz on shared NFS
# Attacker (or buggy concurrent job) overwrites it
cp /tmp/backdoor.tar.gz ./build/release.tar.gz
make deploy       # uses tampered artifact
```

## Core concepts

| Concept | Description | Attack surface |
|---|---|---|
| Plan file (`-out=tfplan`) | Binary snapshot of planned changes | Tampered between PR plan and merge apply |
| Plan cache / artifact | Stored plan passed between CI stages | Shared cache accessible across PR workflows |
| Plan signing | Cryptographic hash/signature of plan file | Missing signature = no integrity guarantee |
| Workflow identity | CI runner's cloud principal | Runner compromise = attacker gets deploy rights |
| OIDC federation | Ephemeral cloud credentials | Token lifetime and subject claim restrict blast radius |

## Cross-cloud CI runner federation

| Cloud | CI/CD Platform | Federation mechanism | Token attribute for subject claim |
|---|---|---|---|
| AWS | GitHub Actions | OIDC → IAM Role (`sts:AssumeRoleWithWebIdentity`) | `token.actions.githubusercontent.com:sub` = `repo:org/repo:ref:refs/heads/main` |
| AWS | GitLab CI | OIDC → IAM Role | `sub` = `project_path:org/repo:ref_type:branch:ref:main` |
| Azure | GitHub Actions | OIDC → Entra ID federated credential on Service Principal | `subject` = `repo:org/repo:environment:prod` |
| Azure | Azure Pipelines | Service Connection (ARM) | Native — no OIDC; connection has fixed SP |
| GCP | GitHub Actions | Workload Identity Federation → Service Account | `attribute.repository` = `org/repo` |
| GCP | GitLab CI | WIF → Service Account | `attribute.project_path` = `org/repo` |
| OnPrem | Jenkins on EC2 + Vault | EC2 instance profile + Vault token | Instance identity from metadata |

## AWS

```yaml
# GitHub Actions workflow — AWS OIDC + signed plan
name: Terraform Pipeline
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111111111111:role/github-actions-plan-readonly
          aws-region: us-east-1
          role-session-name: terraform-plan-${{ github.run_id }}
      - uses: hashicorp/setup-terraform@v3
      - run: terraform init
      - run: terraform plan -out=tfplan
      - uses: actions/upload-artifact@v4
        with:
          name: tfplan-${{ github.run_id }}
          path: tfplan

  apply:
    needs: plan
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111111111111:role/github-actions-apply
          aws-region: us-east-1
      - uses: actions/download-artifact@v4
        with:
          name: tfplan-${{ github.run_id }}
      - run: terraform init
      - run: terraform show -json tfplan | opa eval --stdin-input data.terraform.plan -f pretty
      - run: terraform apply tfplan
```

**Trust policy for plan role (read-only):**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:example-org/*:pull_request"
      }
    }
  }]
}
```

**Trust policy for apply role (write):**

```json
{
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:example-org/*:ref:refs/heads/main"
    }
  }
}
```

**Plan signing (pre-apply verification):**

```bash
# At plan time:
terraform plan -out=tfplan
sha256sum tfplan > tfplan.sha256

# Upload both tfplan and tfplan.sha256 as artifacts

# At apply time (separate job):
sha256sum -c tfplan.sha256 || { echo "PLAN TAMPERED"; exit 1; }
terraform apply tfplan
```

## Azure

```yaml
# Azure Pipelines — plan + signed artifact
trigger:
  branches:
    include: [main]

pool: ubuntu-latest

stages:
- stage: Plan
  jobs:
  - job: plan
    steps:
    - checkout: self
    - task: AzureCLI@2
      inputs:
        azureSubscription: 'sandbox-service-connection'
        scriptType: bash
        scriptLocation: inlineScript
        inlineScript: |
          terraform init
          terraform plan -out=tfplan
          sha256sum tfplan > tfplan.sha256
    - publish: tfplan
      artifact: tfplan

- stage: Apply
  dependsOn: Plan
  condition: succeeded()
  jobs:
  - deployment: apply
    environment: production
    strategy:
      runOnce:
        deploy:
          steps:
          - download: current
            artifact: tfplan
          - task: AzureCLI@2
            inputs:
              azureSubscription: 'sandbox-service-connection'
              scriptType: bash
              scriptLocation: inlineScript
              inlineScript: |
                sha256sum -c tfplan.sha256 || { echo "TAMPERED"; exit 1; }
                terraform init
                terraform apply tfplan
```

**Azure OIDC federated credential — branch scoped:**

```bash
# Create federated credential for PRs only (plan)
az ad app federated-credential create \
  --id "00000000-0000-0000-0000-000000000000" \
  --federated-credential id-plan-readonly \
  --subject "repo:example-org/repo:pull_request" \
  --audience "api://AzureADTokenExchange" \
  --issuer "https://token.actions.githubusercontent.com"
```

## GCP

```yaml
# GitLab CI — GCP WIF + plan signing
plan:
  stage: plan
  id_tokens:
    GCP_ID_TOKEN:
      aud: https://iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/gitlab-pool/providers/gitlab-provider
  script:
    - gcloud auth login --cred-file=${GCP_ID_TOKEN}
    - terraform init
    - terraform plan -out=tfplan
    - sha256sum tfplan > tfplan.sha256
  artifacts:
    paths:
      - tfplan
      - tfplan.sha256

apply:
  stage: deploy
  needs: [plan]
  only:
    - main
  id_tokens:
    GCP_ID_TOKEN:
      aud: https://iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/gitlab-deploy-pool/providers/gitlab-deploy-provider
  script:
    - sha256sum -c tfplan.sha256
    - terraform init
    - terraform apply tfplan
```

## OnPrem (Jenkins)

```groovy
// Jenkins pipeline — stage artifact signing
pipeline {
    agent { label 'terraform' }
    stages {
        stage('Plan') {
            steps {
                sh 'terraform plan -out=tfplan'
                sh 'sha256sum tfplan > tfplan.sha256'
                archiveArtifacts artifacts: 'tfplan, tfplan.sha256'
            }
        }
        stage('Apply') {
            steps {
                copyArtifacts filter: 'tfplan, tfplan.sha256', projectName: '${JOB_NAME}', selector: lastSuccessful()
                sh 'sha256sum -c tfplan.sha256 || exit 1'
                sh 'terraform apply tfplan'
            }
        }
    }
}
```

## 🔴 Red Team view

**Attack narrative: Plan poisoning between plan and apply.**

An attacker with access to the CI artifact store (or the ability to open a malicious PR that modifies a shared cache directory) intercepts the plan artifact between `terraform plan` and `terraform apply`.

**Scenario — shared plan cache poisoning:**

1. Developer opens PR #42 with a legitimate Terraform change (adds an S3 bucket).
2. CI runs `terraform plan -out=tfplan` — creates a plan that adds `aws_s3_bucket.logs`.
3. CI uploads `tfplan` to shared artifact storage keyed by `tfplan-{run_id}`.
4. Attacker opens PR #43 with a workflow that reads PR #42's `run_id` (predictable or enumerated), downloads `tfplan`, modifies it via `terraform plan -out=tfplan-new` with an added `aws_iam_user.admin` resource, and uploads the tampered plan back with PR #42's key.
5. PR #42 merges → apply job downloads the tampered plan → creates the attacker's IAM user.

**Defense: hash verification:**
```bash
# Plan step produces:
terraform plan -out=tfplan
terraform show -json tfplan > plan-summary.json
sha256sum tfplan > tfplan.sha256

# Apply step verifies before applying:
sha256sum -c tfplan.sha256 || { echo "INTEGRITY FAILURE"; exit 1; }
terraform apply tfplan
```

**Artifacts left:**
- CloudTrail: `iam:CreateUser` from the deployer role (which appears authorized — the attacker used the pipeline's own identity)
- CI audit log: two different PRs accessing the same `run_id` artifact
- GitHub Actions audit: `workflow_run` event showing unusual artifact access pattern

## 🔵 Blue Team view

**Preventive controls:**

1. **Hash + sign every plan artifact:**
   ```bash
   # Plan step — sign with cosign or a simple HMAC
   terraform plan -out=tfplan
   sha256sum tfplan | aws kms sign \
     --key-id alias/ci-artifact-signing \
     --message-type RAW \
     --signing-algorithm RSASSA_PKCS1_V1_5_SHA_256 \
     --message fileb://<(sha256sum tfplan | cut -d' ' -f1 | xxd -r -p) \
     --query Signature --output text | base64 -d > tfplan.sig

   # Apply step — verify
   sha256sum tfplan | cut -d' ' -f1 | xxd -r -p > /tmp/plan-hash.bin
   aws kms verify \
     --key-id alias/ci-artifact-signing \
     --message-type RAW \
     --signing-algorithm RSASSA_PKCS1_V1_5_SHA_256 \
     --message fileb:///tmp/plan-hash.bin \
     --signature fileb://tfplan.sig
   ```

2. **OIDC subject scoped to environment + branch:**
   ```json
   // AWS IAM trust — tightest subject claim
   "Condition": {
     "StringEquals": {
       "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
       "token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:environment:production"
     }
   }
   ```

3. **Plan-time policy evaluation (OPA/Conftest):**
   ```bash
   # In plan job, before upload:
   terraform show -json tfplan | conftest test --policy policies/ -
   # Fails the plan if policy violation detected
   ```

4. **Separate roles for plan (read-only) and apply (write):**
   - Plan role: `ReadOnlyAccess` + `s3:GetObject` on state bucket
   - Apply role: resource-specific write policies, no `iam:*`
   - Ensures even if a plan artifact is tampered, the plan job itself cannot deploy

5. **CI/CD artifact isolation — unique per workflow run, not shared across PRs:**
   ```yaml
   # Bad: shared artifact name
   - uses: actions/upload-artifact@v4
     with:
       name: tfplan  # ← same name across all runs → cache poisoning

   # Good: run-unique name
   - uses: actions/upload-artifact@v4
     with:
       name: tfplan-${{ github.run_id }}-${{ github.run_attempt }}
   ```

**Detection signals:**

| Signal | AWS | Azure | GCP |
|---|---|---|---|
| Two different PRs access same artifact | GitHub Actions audit log: `download_artifact` from mismatched `workflow_run.head_branch` | Azure Pipelines audit: artifact download from different pipeline run | GitLab audit event: `artifact_download` from different pipeline ID |
| Apply without prior plan in same run | `terraform apply` without corresponding `terraform plan` in same CI execution | Same — check pipeline stage dependencies | Same — check job `needs` graph |
| IAM/CreateUser from apply role (unexpected) | CloudTrail `iam:CreateUser` with `userAgent` = deployer pipeline | Activity Log `Microsoft.Authorization/roleAssignments/write` | Cloud Audit Log `iam.serviceAccounts.create` |

## Hands-on lab

1. Simulate a plan poisoning:
   ```bash
   mkdir lab-plan-poison && cd lab-plan-poison
   cat > main.tf <<'EOF'
   resource "local_file" "safe" {
     content  = "legitimate"
     filename = "./safe.txt"
   }
   EOF
   terraform init
   terraform plan -out=tfplan

   # Generate hash
   sha256sum tfplan > tfplan.sha256

   # "Tamper" — create a new plan with different content
   cat > main.tf <<'EOF'
   resource "local_file" "tainted" {
     content  = "malicious"
     filename = "./tainted.txt"
   }
   EOF
   terraform plan -out=tfplan-tampered

   # Copy tampered plan over the original (simulating artifact swap)
   cp tfplan-tampered tfplan
   ```

2. Detect the tamper:
   ```bash
   sha256sum -c tfplan.sha256 || echo "DETECTED: Plan file integrity failure"
   # Expected output: DETECTED: Plan file integrity failure
   ```

3. Verify plan difference:
   ```bash
   terraform show -json tfplan | jq '.resource_changes[].change.actions'
   terraform show -json tfplan-tampered | jq '.resource_changes[].change.actions'
   ```

4. **Teardown:** `rm -rf lab-plan-poison`

## References

- [GitHub Actions OIDC for AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [Azure Workload Identity Federation](https://learn.microsoft.com/en-us/azure/active-directory/develop/workload-identity-federation)
- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- See ATT&CK: T1554 (Compromise Client Software Binary), T1578 (Modify Cloud Compute Infrastructure)
- [02-04 — Long-Lived Keys vs Workload Identity](../IAM/long-lived-keys-vs-workload-identity.md)
- [02-08 — Policy-as-Code Checkers](../IAM/policy-as-code-checkers.md)
