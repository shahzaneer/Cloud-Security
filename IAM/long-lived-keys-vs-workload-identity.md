# 04 — Long-Lived Keys vs Workload Identity

> **Level:** Intermediate
> **Prereqs:** [Identity Primitives per Cloud](identity-primitives-per-cloud.md) (Identity Primitives Per Cloud)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Initial Access
> **Authorization scope:** Identity attacks only in your own sandbox accounts / sanctioned targets.

## What & why

Static, long-lived credentials (access keys, client secrets, SA keys) are the root cause of most cloud credential breaches. Ephemeral workload identity — where the platform mints short-lived tokens bound to a specific workload — eliminates the secret-injection pipeline entirely. This is the end-of-history of cloud authentication.

## The OnPrem reality

On-prem service accounts relied on vaulted secrets: a password stored in HashiCorp Vault, CyberArk, or a plaintext config file. A cron agent or CI/CD plugin fetched the secret, injected it as an env var, and ran. The problem: secrets leaked through `ps aux`, `/proc/<pid>/environ`, CI job logs, and developer laptops. Kerberos gMSA (Group Managed Service Account) was the partial on-prem answer — auto-rotated password managed by AD, no human knows it — but limited to Windows services on domain-joined hosts.

## Cross-cloud comparison

| Provider | Long-lived credential | Location if leaked | Workload identity equivalent | Token lifetime |
|---|---|---|---|---|
| AWS | IAM User `AKIA*` access key | `~/.aws/credentials`, CI env vars | IRSA (EKS), EC2 instance role, Lambda execution role | STS: 15min–12h |
| Azure | App Registration client secret | CI variables, `appsettings.json` | Managed Identity (MI), Workload Identity Federation | OAuth2: 1h |
| GCP | Service Account key (JSON) | CI secrets, GCS bucket | GKE Workload Identity, WIF (GitHub provider) | OAuth2: 1h |
| OnPrem | gMSA password / vaulted secret | Vault audit log, CI runner memory | gMSA (auto-rotated), SPNEGO | Kerberos TGT: 10h |

## AWS

**Static key (the wrong way):**

```bash
# Create IAM User with long-lived key
aws iam create-user --user-name cicd-runner
aws iam create-access-key --user-name cicd-runner

# Credential stored as CI variable or file
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws s3 ls s3://my-bucket/
```

**Workload identity — IRSA (IAM Roles for Service Accounts, EKS):**

```bash
# Create an OIDC provider for the EKS cluster
eksctl utils associate-iam-oidc-provider \
  --cluster my-cluster \
  --approve

# Create an IAM role with trust for the Kubernetes service account
eksctl create iamserviceaccount \
  --name my-app-sa \
  --namespace default \
  --cluster my-cluster \
  --role-name MyAppIRSA \
  --attach-policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess \
  --approve

# Pod spec — no static key needed
# Kubernetes ServiceAccount annotation links to IAM role
```

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: default
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111111111111:role/MyAppIRSA
```

The pod gets temporary credentials via the `sts.amazonaws.com` OIDC provider — the SDK auto-refreshes them. No static key exists anywhere.

**EC2 instance role (the original workload identity):**

```bash
# On the EC2 instance:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyInstanceRole
# Returns AccessKeyId, SecretAccessKey, Token, Expiration — all temporary
```

## Azure

**Static client secret (the wrong way):**

```bash
# Create an App Registration with client secret
az ad app create --display-name cicd-app
az ad app credential reset --id <app-id> --years 2
# Output contains: password (secret)

# Store in CI variable
export ARM_CLIENT_ID=00000000-0000-0000-0000-000000000000
export ARM_CLIENT_SECRET=PLACEHOLDER_SECRET_VALUE
export ARM_TENANT_ID=00000000-0000-0000-0000-000000000000
az login --service-principal -u $ARM_CLIENT_ID -p $ARM_CLIENT_SECRET --tenant $ARM_TENANT_ID
```

**Workload identity — Kubernetes (AKS Workload Identity):**

```bash
# Create a Managed Identity
az identity create --name mi-myapp --resource-group rg-cluster

# Create federated credential (ties the MI to a specific K8s SA)
az identity federated-credential create \
  --name fc-myapp \
  --identity-name mi-myapp \
  --resource-group rg-cluster \
  --issuer "$(az aks show -g rg-cluster -n my-cluster --query oidcIssuerProfile.issuerUrl -o tsv)" \
  --subject "system:serviceaccount:default:my-app-sa" \
  --audience "api://AzureADTokenExchange"
```

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: default
  annotations:
    azure.workload.identity/client-id: "00000000-0000-0000-0000-000000000000"
```

The AKS mutating webhook injects the OIDC token file and `AZURE_CLIENT_ID` env var. The Azure SDK uses the file to exchange the K8s token for an Entra token — no secret stored.

**On VMs — Managed Identity:**

```bash
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com&api-version=2018-02-01"
```

## GCP

**Static service account key (the wrong way):**

```bash
# Create SA key — downloads a JSON file
gcloud iam service-accounts keys create ~/sa-key.json \
  --iam-account sa-cicd@project-id-111111.iam.gserviceaccount.com

# Store key in CI
export GOOGLE_APPLICATION_CREDENTIALS=~/sa-key.json
gsutil ls gs://my-bucket/
```

**Workload identity — GKE Workload Identity:**

```bash
# Enable Workload Identity on the GKE cluster
gcloud container clusters update my-cluster \
  --workload-pool=project-id-111111.svc.id.goog

# Create GCP SA and bind to Kubernetes SA
gcloud iam service-accounts create gke-myapp

gcloud iam service-accounts add-iam-policy-binding \
  gke-myapp@project-id-111111.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:project-id-111111.svc.id.goog[default/my-app-sa]"
```

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: default
  annotations:
    iam.gke.io/gcp-service-account: gke-myapp@project-id-111111.iam.gserviceaccount.com
```

**GitHub Actions OIDC (WIF — Workload Identity Federation):**

```bash
# Create workload identity pool
gcloud iam workload-identity-pools create github-pool \
  --location global

# Add GitHub provider
gcloud iam workload-identity-pools providers create-oidc github-provider \
  --workload-identity-pool github-pool \
  --location global \
  --attribute-mapping "google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository" \
  --issuer-uri "https://token.actions.githubusercontent.com"

# Allow federation from a specific repo
gcloud iam service-accounts add-iam-policy-binding \
  sa-cicd@project-id-111111.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/github-pool/attribute.repository/example-org/example-repo"
```

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    permissions:
      id-token: write
    steps:
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/111111111111/locations/global/workloadIdentityPools/github-pool/providers/github-provider
          service_account: sa-cicd@project-id-111111.iam.gserviceaccount.com
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Static credential | Vaulted password / gMSA | IAM User access key | App Registration client secret | SA key JSON |
| Leak vector | CI log, env var, config file | Git commit, CI log export | Pipeline variable leak | Downloaded key file |
| Workload identity | Kerberos gMSA (Windows only) | IRSA (EKS), EC2 instance role | AKS Workload Identity, MI | GKE Workload Identity, WIF |
| Token refresh | KDC auto-renews TGT | AWS SDK auto-refreshes STS | Azure SDK via IMDS/OIDC | GCP SDK via metadata/WIF |
| Rotation burden | AD auto-rotates gMSA (30d) | None (ephemeral) | None (ephemeral) | SA key: manual; WIF: none |
| OIDC audience | N/A | `sts.amazonaws.com` | `api://AzureADTokenExchange` | `https://iam.googleapis.com/projects/...` |

## 🔴 Red Team view

**GitHub Actions OIDC mis-scoping.** The most common workload identity attack today: a GitHub Actions workflow with `id-token: write` permission and an overly permissive OIDC trust policy.

**The vulnerable trust policy (AWS):**

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    }
  }
}
```

This trust policy allows *any* GitHub repository to assume the role — no `sub` (subject) claim restriction, no `repo` filter. An attacker forks a public repo, creates a workflow in their fork, and gets AWS credentials.

**Contained example — what a leaked credential looks like on a CI runner:**

```bash
# Attacker with access to a CI runner enumerates environment
env | grep -i -E 'AWS|AZURE|GOOGLE|SECRET|TOKEN'

# Finds:
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
# AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
# AWS_SESSION_TOKEN=FwoGZXIvYXdzE...  (if optional STS)

# For OIDC-based workflow: attacker reads the OIDC token file
cat $ACTIONS_ID_TOKEN_REQUEST_TOKEN  # --> raw JWT
# Or accesses the OIDC endpoint:
curl -H "Authorization: bearer $(cat $ACTIONS_ID_TOKEN_REQUEST_TOKEN)" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com"
# Response contains the JWT — exchange for cloud credentials via AssumeRoleWithWebIdentity
```

**Artifacts:** The `AssumeRoleWithWebIdentity` or `AssumeRole` API call appears in CloudTrail with `sourceIdentity` from the GitHub Actions token's `sub` claim. The `userAgent` will include the CI provider's string (e.g., `aws-sdk-ruby/3.x.x` from a custom runner or `GitHub-Hookshot/`). The repository name is in the token's `repository` claim — you can determine exactly which repo minted the credential.

## 🔵 Blue Team view

**Hardened trust policy with OIDC subject restriction:**

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:ref:refs/heads/main"
    }
  }
}
```

This restricts role assumption to workflows triggered from the `main` branch of `example-org/example-repo` only.

**GCP WIF attribute condition — same hardening:**

```bash
gcloud iam workload-identity-pools providers update-oidc github-provider \
  --workload-identity-pool github-pool \
  --location global \
  --attribute-condition "attribute.repository == 'example-org/example-repo' && attribute.ref == 'refs/heads/main'"
```

**Detect tokens minted for unexpected repos:**

```
-- AWS CloudTrail Lake: detect AssumeRoleWithWebIdentity from unknown repo
SELECT eventTime, userIdentity.arn, sourceIdentity, userAgent
FROM cloudtrail_111111111111
WHERE eventName = 'AssumeRoleWithWebIdentity'
  AND sourceIdentity NOT LIKE '%repo:example-org/example-repo%'
```

```
-- Azure: detect federated credential usage from unexpected subject
AzureActivity
| where OperationNameValue contains "MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/CREDENTIALS"
| where Properties contains "subject:system:serviceaccount:default:not-my-app"
```

**Inventory — find all static keys still in use:**

```bash
# AWS: credential report
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d | \
  awk -F',' 'NR>1 && $4 == "true" && $5 == "true" {print $1 " has active key"}'

# Azure: list app registrations with client secrets
az ad app list --all --query "[?passwordCredentials != null].{App:displayName,SecretCount:length(passwordCredentials)}" -o table

# GCP: list SA user-managed keys
gcloud iam service-accounts list --format json | jq -r '.[].email' | \
  while read sa; do
    keys=$(gcloud iam service-accounts keys list --iam-account "$sa" --managed-by user 2>/dev/null)
    [ -n "$keys" ] && echo "$sa has user-managed keys"
  done
```

**Migration checklist:**
- [ ] No IAM Users with access keys for workloads (migrate to IRSA/instance roles).
- [ ] All GitHub Actions OIDC trust policies include `sub` condition (repo+ref).
- [ ] Azure App Registrations use Workload Identity Federation instead of client secrets.
- [ ] GCP Service Accounts have zero user-managed keys (enforce via Org Policy).

## Hands-on lab

**Part A: Create static key, commit it, detect it.**

```bash
# Create IAM User with key
aws iam create-user --user-name lab-key-leak
aws iam create-access-key --user-name lab-key-leak | tee /tmp/key.json

# "Accidentally" commit it
mkdir /tmp/fake-repo && cd /tmp/fake-repo
echo "AWS_KEY=$(jq -r .AccessKey.AccessKeyId /tmp/key.json)" >> config.env
git init && git add config.env && git commit -m "config"

# Search for it (simulating an attacker finding it)
git grep AKIA $(git rev-list --all)
```

**Part B: Migrate to workload identity (same workload, no static key).**

```bash
# Create IAM Role with OIDC trust (IRSA simulation)
OIDC_PROVIDER_ARN=$(aws iam list-open-id-connect-providers \
  --query "OpenIDConnectProviderList[0].Arn" --output text)

aws iam create-role --role-name LabWorkloadRole --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "'"$OIDC_PROVIDER_ARN"'"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "'"$(echo $OIDC_PROVIDER_ARN | cut -d'/' -f2 | cut -d'/' -f1)"':aud": "sts.amazonaws.com",
        "'"$(echo $OIDC_PROVIDER_ARN | cut -d'/' -f2 | cut -d'/' -f1)"':sub": "system:serviceaccount:default:lab-app"
      }
    }
  }]
}')

# No static key exists — only the trust policy
aws iam get-role --role-name LabWorkloadRole \
  --query "Role.AssumeRolePolicyDocument" --output json
```

**Expected output:** Part A's `git grep` finds the committed key. Part B shows a role with no static credentials — only a trust policy bound to a Kubernetes SA subject. The workload running as `lab-app` SA automatically gets credentials via the OIDC provider.

**Teardown:**
```bash
aws iam delete-access-key --user-name lab-key-leak --access-key-id $(jq -r .AccessKey.AccessKeyId /tmp/key.json)
aws iam delete-user --user-name lab-key-leak
aws iam delete-role --role-name LabWorkloadRole
rm -rf /tmp/fake-repo /tmp/key.json
```

## Detection rules & checklists

**GCP Org Policy — disable SA key creation:**
```bash
gcloud org-policies set-policy policy.yaml
# policy.yaml:
# constraint: constraints/iam.disableServiceAccountKeyCreation
# booleanPolicy:
#   enforced: true
```

**AWS SCP — deny IAM User creation (enforce role-only):**
```json
{
  "Effect": "Deny",
  "Action": ["iam:CreateUser", "iam:CreateAccessKey"],
  "Resource": "*"
}
```

**Checklist — secret inventory audit:**
```bash
# Count active keys across organization
for account in $(aws organizations list-accounts --query Accounts[].Id --output text); do
  echo "=== Account $account ==="
  aws iam generate-credential-report
  aws iam get-credential-report --query Content --output text | base64 -d | \
    awk -F',' '$4 == "true" && $1 != "<root_account>"'
done
```

## References
- [AWS IRSA (EKS IAM Roles for Service Accounts)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [Azure Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [GitHub Actions OIDC + cloud providers](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [MITRE ATT&CK — Unsecured Credentials: Cloud Instance Metadata API (T1552.005)](https://attack.mitre.org/techniques/T1552/005/)
