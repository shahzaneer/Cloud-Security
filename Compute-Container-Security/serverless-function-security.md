# 03 — Serverless Function Security

> **Level:** Intermediate
> **Prereqs:** [IAM](../IAM), [Cloud App Threat Model](../Cloud-Native-App-Security/cloud-app-threat-model.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Execution, Privilege Escalation, Credential Access
**Authorization scope:** Run all functions in your own sandbox account. Function code and IAM roles must target non-production test resources only.

## What & why

Serverless functions eliminate OS patching but introduce a massive over-permission surface: each function has an execution role, environment variables, triggers, and resource policies that can be exploited. A single function with `s3:*` or `secretsmanager:*` can become a pivot point for data exfiltration.

## The OnPrem reality

Before serverless, scheduled tasks ran as cron jobs or daemon processes on VMs. A webhook endpoint was a microservice behind a reverse proxy. Security meant the process UID, filesystem permissions, and a network ACL — no per-invocation IAM session, no event-source filtering.

## Core concepts

| Concept | Meaning | Why it matters |
|---|---|---|
| Execution role | IAM role the function assumes at invoke | Defines what the function can touch inside the cloud |
| Resource policy | Who can invoke the function | Prevents cross-account trigger abuse |
| Event source mapping | What triggers the function (SQS, EventBridge, etc.) | Each trigger is a potential injection vector |
| Environment variables | Key-value pairs injected at runtime | Common place for hardcoded secrets |
| Layers | Reusable code packages | Supply chain risk if layer comes from untrusted source |
| VPC-attached function | Function inside your VPC via ENI | Can reach private resources — lateral movement surface |

## AWS

**Primary services:** Lambda, IAM, KMS, Secrets Manager, VPC

**Minimal hardened Lambda (Terraform):**
```hcl
# AWS
resource "aws_lambda_function" "hello" {
  filename      = "lambda.zip"
  function_name = "hello-hardened"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 3
  memory_size   = 128

  environment {
    variables = {
      DB_SECRET_ARN = aws_secretsmanager_secret.db.arn
    }
  }

  # VPC-attached only if strictly needed
  # vpc_config { ... }
}

resource "aws_iam_role" "lambda_exec" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "lambda_least" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [aws_secretsmanager_secret.db.arn]
      }
    ]
  })
}
```

**Function code with runtime secret fetch:**
```python
# AWS
import os
import boto3
import json

secrets = boto3.client('secretsmanager')
db_secret_arn = os.environ['DB_SECRET_ARN']

def handler(event, context):
    secret = json.loads(secrets.get_secret_value(SecretId=db_secret_arn)['SecretString'])
    return {"status": "ok", "db_host": secret['host']}
```

**Resource policy — restrict invocation:**
```json
{
  "Version": "2012-10-17",
  "Id": "default",
  "Statement": [
    {
      "Sid": "AllowOnlyMyAccount",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111111111111:root" },
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:us-east-1:111111111111:function:hello-hardened"
    }
  ]
}
```

**KMS encryption for environment variables:**
```bash
# AWS
aws lambda update-function-configuration \
  --function-name hello-hardened \
  --kms-key-arn arn:aws:kms:us-east-1:111111111111:key/aaaa-1111-bbbb-2222
```

## Azure

**Primary services:** Azure Functions, Managed Identity, Key Vault, Event Grid

**Minimal hardened Function (Terraform):**
```hcl
# Azure
resource "azurerm_linux_function_app" "hello" {
  name                = "func-hello-hardened"
  resource_group_name = azurerm_resource_group.rg.name
  service_plan_id     = azurerm_service_plan.plan.id
  site_config {
    application_stack {
      python_version = "3.11"
    }
  }
  identity {
    type = "SystemAssigned"
  }
  app_settings = {
    "AzureWebJobsSecretStorageType" = "keyvault"
    "KEY_VAULT_URI"                 = azurerm_key_vault.kv.vault_uri
    "SECRET_NAME"                   = "db-password"
  }
}

resource "azurerm_key_vault_access_policy" "func" {
  key_vault_id = azurerm_key_vault.kv.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_linux_function_app.hello.identity[0].principal_id
  secret_permissions = ["Get"]
}
```

**Function code (Python):**
```python
# Azure
import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    kv_uri = os.environ["KEY_VAULT_URI"]
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=kv_uri, credential=credential)
    password = client.get_secret("db-password")
    return func.HttpResponse(f"connected", status_code=200)
```

**Resource policy — function-level auth:**
```json
// Azure
{
  "bindings": [{
    "authLevel": "function",
    "type": "httpTrigger",
    "direction": "in",
    "name": "req"
  }]
}
```

## GCP

**Primary services:** Cloud Functions (2nd gen), Cloud Run, Secret Manager, Pub/Sub

**Minimal hardened Cloud Function (Terraform):**
```hcl
# GCP
resource "google_cloudfunctions2_function" "hello" {
  name     = "hello-hardened"
  location = "us-central1"
  build_config {
    runtime     = "python312"
    entry_point = "hello_handler"
  }
  service_config {
    max_instance_count = 3
    service_account_email = google_service_account.func_sa.email
    secret_environment_variables {
      key     = "DB_PASSWORD"
      secret  = google_secret_manager_secret.db_pass.id
      version = "latest"
    }
  }
}

resource "google_service_account" "func_sa" {
  account_id = "func-hello-sa"
}

resource "google_secret_manager_secret_iam_member" "func_access" {
  secret_id = google_secret_manager_secret.db_pass.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.func_sa.email}"
}
```

**Function code:**
```python
# GCP
import os
import functions_framework

@functions_framework.http
def hello_handler(request):
    db_pass = os.environ.get('DB_PASSWORD', 'not-set')
    return f"ok", 200
```

**Restrict invoker permission:**
```bash
# GCP
gcloud functions remove-invoker-policy hello-hardened \
  --member="allUsers" --region=us-central1
gcloud functions add-invoker-policy hello-hardened \
  --member="serviceAccount:func-caller@my-sandbox-project.iam.gserviceaccount.com" --region=us-central1
```

## OnPrem

OnPrem "serverless" equivalent is a webhook endpoint served by a systemd unit or container:

```yaml
# OnPrem — Ansible-deployed microservice with least privilege
- name: Deploy hardened webhook
  hosts: webhook
  become: yes
  tasks:
    - name: Create dedicated user
      user:
        name: webhook-svc
        shell: /sbin/nologin
        create_home: no
    - name: Deploy systemd unit
      copy:
        dest: /etc/systemd/system/webhook.service
        content: |
          [Unit]
          Description=Webhook endpoint
          [Service]
          User=webhook-svc
          NoNewPrivileges=yes
          ProtectSystem=strict
          ReadWritePaths=/var/lib/webhook
          ExecStart=/usr/local/bin/webhook-server
          [Install]
          WantedBy=multi-user.target
    - name: Start service
      systemd:
        name: webhook
        state: started
        enabled: yes
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Execution identity | Local user / systemd `User=` | Lambda execution role (IAM) | Managed Identity | Service account |
| Secret retrieval | Env vars or vault agent | Secrets Manager / KMS env | Key Vault reference | Secret Manager env |
| Trigger source filter | iptables / reverse proxy | Resource policy `lambda:InvokeFunction` | Function auth level / IP restrict | Invoker IAM policy |
| Network isolation | VLAN / firewall | Lambda in VPC (ENI) | VNet integration | Ingress settings / VPC connector |
| Code supply chain | Internal repo + binary hash | Lambda layers / ECR | Deployment from registry | Artifact Registry |
| Runtime logging | syslog → SIEM | CloudWatch Logs | Application Insights | Cloud Logging |

## 🔴 Red Team view

**Attack: Over-privileged Lambda role pivot**

A Lambda with the following IAM policy attached:
```json
{
  "Effect": "Allow",
  "Action": ["s3:*", "dynamodb:*", "lambda:InvokeFunction"],
  "Resource": "*"
}
```

An attacker who finds the function's ARN (via source code leak or CloudTrail enumeration) crafts an invocation payload that triggers a scan of the internal VPC:

```python
# Attacker-controlled input to the Lambda event
{
  "command": "list_buckets"
}
```

Inside the Lambda, if input is not sanitized:
```python
def handler(event, context):
    import boto3
    if event.get('command') == 'list_buckets':
        s3 = boto3.client('s3')
        buckets = s3.list_buckets()
        return buckets  # Exfiltrated via Lambda response
```

The attacker now discovers all S3 buckets, then chains to `s3:GetObject` to read sensitive data — all from a single over-privileged function ARN.

**Contained detection:** The Lambda's CloudWatch Logs show `s3:ListBuckets` calls sourced from the function's execution role. CloudTrail records `eventName=ListBuckets` with `userIdentity.invokedBy=lambda.amazonaws.com` and `sessionContext.sessionIssuer.arn=arn:aws:iam::111111111111:role/overprivileged-lambda-role`. The caller IP is an AWS internal IP (Lambda service), making it harder to attribute to the actual attacker.

**Attack: Hardcoded secret extraction**

If the function has environment variables containing a plaintext DB password:
```bash
aws lambda get-function-configuration --function-name hello-hardened \
  --query 'Environment.Variables' --output text
```

Anyone with `lambda:GetFunctionConfiguration` (often granted by `lambda:ReadOnly`) can enumerate secrets in plaintext.

**Artifacts:** CloudTrail `GetFunctionConfiguration`, `ListBuckets`, `GetObject` events; Lambda invocation log showing unexpected event shape; environment variable access via IAM policy simulation.

## 🔵 Blue Team view

**Detection signals:**

| Signal | Log Source | Query |
|---|---|---|
| Lambda making unexpected API calls | CloudTrail | `userIdentity.arn` matches Lambda role AND `eventName` not in expected list |
| `List*` or `Describe*` from Lambda | CloudTrail | `eventName =~ "List*" OR "Describe*"` with `userIdentity.invokedBy` containing `lambda` |
| Environment variable read by non-builder | CloudTrail | `eventName=GetFunctionConfiguration` from unexpected principal |
| Function invoked with unusual payload shape | CloudWatch Logs | Compare event structure to baseline using log pattern analysis |
| Secrets Manager access spike from Lambda | CloudTrail | `eventName=GetSecretValue` count > baseline with `sourceIPAddress=lambda` |

**Preventive controls:**

- **AWS:** Per-function IAM roles with `iamb`-generated least-privilege policy; resource policies restricting invocation to specific principals; KMS encryption on env vars; Lambda code signing with AWS Signer; `lambda:UpdateFunctionConfiguration` locked to pipeline role.
- **Azure:** Managed Identity with RBAC scoped to single Key Vault secret; `WEBSITE_RUN_FROM_PACKAGE` for immutable deployments; IP restrictions on function app; `authLevel=function` and key rotation.
- **GCP:** Cloud Functions 2nd gen with per-function service account; Secret Manager access limited to specific secret only; `run.invoker` IAM restricted to known callers; `--ingress-settings=internal-only` for VPC-only functions.
- **OnPrem:** Dedicated service user per webhook; systemd sandboxing (`NoNewPrivileges`, `ProtectSystem`); secrets via vault agent sidecar; iptables restrict outbound.

**Response steps:**
1. Detach or scope down the over-privileged IAM role immediately.
2. Rotate all secrets the function had access to.
3. Review CloudTrail for all API calls made by the role in the preceding 24 hours.
4. Check if the function code was modified (`UpdateFunctionCode` event).
5. If VPC-attached, inspect VPC Flow Logs for unusual outbound connections.

## Hands-on lab

**Goal:** Deploy a Lambda with least-privilege IAM and verify that over-permission is blocked.

**Steps:**
1. Create a Lambda function using the Terraform snippet above (logs + single secret only).
2. Add a temporary overly-broad policy (`s3:*`) to the role.
3. Invoke the function with an event that triggers `s3.list_buckets()` — succeeds.
4. Remove the broad policy, invoke again — `AccessDenied` in CloudWatch.
5. Run `aws lambda get-function-configuration` and verify env vars are KMS-encrypted (base64 blob, not plaintext).
6. Teardown: `terraform destroy`.

**Expected output:** Function logs show `AccessDenied` after policy scope-down; env var config shows `CiphertextBlob` not plaintext `Value`.

## Detection rules & checklists

**Cloud Custodian — detect overly permissive Lambda roles:**
```yaml
policies:
  - name: lambda-role-star-resource
    resource: aws.lambda
    filters:
      - type: check-permissions
        match: allowed
        actions:
          - "s3:*"
          - "dynamodb:*"
          - "rds:*"
    actions:
      - type: notify
```

**CLI audit one-liners:**
```bash
# AWS: list Lambda functions with wildcard IAM policies
aws lambda list-functions --query 'Functions[].FunctionArn' --output text | while read arn; do
  role=$(aws lambda get-function-configuration --function-name "$arn" --query 'Role' --output text)
  aws iam list-attached-role-policies --role-name "$(basename $role)" \
    --query 'AttachedPolicies[].PolicyArn' --output text
done

# Azure: list Functions with Key Vault references (good sign)
az functionapp config appsettings list --name func-hello \
  --resource-group rg-sec \
  --query "[?contains(value, '@Microsoft.KeyVault')]"

# GCP: list Cloud Functions with allUsers invoker
gcloud functions list --filter="ingressSettings=ALLOW_ALL" --format="table(name,httpsTrigger.securityLevel)"

# OnPrem: check systemd unit sandboxing
systemd-analyze security webhook.service
```

## References
- AWS Lambda permissions model: https://docs.aws.amazon.com/lambda/latest/dg/lambda-permissions.html
- Azure Functions security: https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts
- GCP Cloud Functions IAM: https://cloud.google.com/functions/docs/concepts/iam
- ATT&CK: see Cloud matrix for "Execution" and "Privilege Escalation"
- Cross-links: [`../IAM/assume-role-chains.md`](../IAM/assume-role-chains.md), [`03-04-lambda-event-source-mapping-abuse.md`](lambda-event-source-mapping-abuse.md)
