#!/usr/bin/env bash
# honey-token-provision.template.sh
# Creates one canary token per cloud and writes honeytokens.json manifest.
# ⚠️ Run ONLY in your own sandbox account/tenant/project.
# Replace every <PLACEHOLDER> before execution.

set -euo pipefail

MANIFEST="honeytokens.json"
WEBHOOK_URL="${WEBHOOK_URL:-http://localhost:9999/webhook}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ──────────────────────────────────────────────────────────────────
# AWS — Canary IAM user + access key
# ──────────────────────────────────────────────────────────────────
AWS_CANARY_USER="honeytoken-audit"
AWS_ACCOUNT="111111111111"

aws iam create-user --user-name "${AWS_CANARY_USER}" 2>/dev/null || true
AWS_KEY_JSON="$(aws iam create-access-key --user-name "${AWS_CANARY_USER}")"
AWS_ACCESS_KEY="$(echo "$AWS_KEY_JSON" | jq -r '.AccessKey.AccessKeyId')"
AWS_SECRET_KEY="$(echo "$AWS_KEY_JSON" | jq -r '.AccessKey.SecretAccessKey')"

aws iam tag-user \
  --user-name "${AWS_CANARY_USER}" \
  --tags "Key=honeytoken,Value=true" "Key=provisioned_at,Value=${TIMESTAMP}"

# No policies attached — any usage is a signal.

# ──────────────────────────────────────────────────────────────────
# Azure — Canary service principal
# ──────────────────────────────────────────────────────────────────
AZ_APP_NAME="honeytoken-sp"
AZ_TENANT="example-tenant.onmicrosoft.com"

az ad app create --display-name "${AZ_APP_NAME}" > /dev/null 2>&1 || true
AZ_APP_ID="$(az ad app list --display-name "${AZ_APP_NAME}" --query '[0].appId' -o tsv)"
az ad sp create --id "${AZ_APP_ID}" > /dev/null 2>&1 || true

az ad sp credential reset \
  --id "${AZ_APP_ID}" \
  --append \
  --display-name "honeytoken-key" \
  --years 1 > /dev/null 2>&1

# No RBAC role assignments — any usage is a signal.

# ──────────────────────────────────────────────────────────────────
# GCP — Canary service account + key
# ──────────────────────────────────────────────────────────────────
GCP_PROJECT="example-project"
GCP_SA_NAME="honeytoken-sa"
GCP_SA_EMAIL="${GCP_SA_NAME}@${GCP_PROJECT}.iam.gserviceaccount.com"

gcloud iam service-accounts create "${GCP_SA_NAME}" \
  --display-name "Honeytoken Service Account" \
  --project "${GCP_PROJECT}" 2>/dev/null || true

GCP_KEY_JSON="$(gcloud iam service-accounts keys create /dev/stdin \
  --iam-account "${GCP_SA_EMAIL}" \
  --project "${GCP_PROJECT}" 2>/dev/null || echo '{}')"

# No IAM bindings — any usage is a signal.

# ═════════════════════════════════════════════════════════════════
# Build manifest
# ═════════════════════════════════════════════════════════════════

jq -n \
  --arg provisioned_at "$TIMESTAMP" \
  --arg webhook "$WEBHOOK_URL" \
  --arg aws_account "$AWS_ACCOUNT" \
  --arg aws_user "$AWS_CANARY_USER" \
  --arg aws_access_key "$AWS_ACCESS_KEY" \
  --arg az_app_id "$AZ_APP_ID" \
  --arg az_tenant "$AZ_TENANT" \
  --arg gcp_project "$GCP_PROJECT" \
  --arg gcp_sa_email "$GCP_SA_EMAIL" \
  '{
    provisioned_at: $provisioned_at,
    webhook_url: $webhook,
    tokens: {
      aws: {
        account_id: $aws_account,
        type: "iam_access_key",
        user: $aws_user,
        access_key_id: $aws_access_key,
        note: "Key has no permissions. Any API call is a trigger."
      },
      azure: {
        tenant: $az_tenant,
        type: "service_principal_credential",
        app_id: $az_app_id,
        note: "SP has no RBAC assignments. Any sign-in or token request is a trigger."
      },
      gcp: {
        project: $gcp_project,
        type: "service_account_key",
        email: $gcp_sa_email,
        note: "SA has no IAM bindings. Any API call is a trigger."
      }
    }
  }' > "$MANIFEST"

echo "Honeytoken manifest written to $MANIFEST"
echo "Configure alerting to POST token usage events to $WEBHOOK_URL"
