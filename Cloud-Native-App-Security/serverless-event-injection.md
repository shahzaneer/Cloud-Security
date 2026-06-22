# 04 — Serverless Event Injection

> **Level:** Intermediate
> **Prereqs:** `../Compute-Container-Security/serverless-function-security.md`, `cloud-app-threat-model.md`
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Execution, Persistence, Defense Evasion
> **Authorization scope:** Test event injection only against your own sandbox functions deployed from your own account. Do not target any function you do not own.

## What & why

Serverless functions consume events from many sources — HTTP, queues, object storage, scheduled timers. Each event source is a different *untrusted input boundary* with its own schema, encoding, and metadata. Misunderstanding how the platform wraps each event type lets an attacker bypass application-level auth checks or inject payloads through unexpected fields.

## The OnPrem reality

A Django REST view received an `HttpRequest` object. Parsing was explicit: `request.POST`, `request.GET`, `request.body`. In cloud serverless, the event envelope is different per trigger source, and the function handler receives the entire envelope as one object. A field like `headers['X-Forwarded-For']` may be attacker-controlled when coming from an HTTP source but trusted when undocumented.

## Core concepts

### Common event sources and their trust levels

| Source | Trust Level | Attack surface |
|---|---|---|
| API Gateway HTTP | Untrusted (public internet) | Full HTTP request smuggling, header injection, body tampering |
| S3 event notification | Semi-trusted (within account) | Object key injection, metadata tampering from PUT caller |
| SQS / Pub/Sub | Semi-trusted (queue policy scoped) | Message body injection, attribute spoofing if SNS fan-out |
| EventBridge scheduled | Trusted (account-internal) | Parameter injection if rule input transformer is misconfigured |
| CloudWatch scheduled | Trusted (account-internal) | N/A (no event body) unless the trigger passes parameters |
| SNS | Semi-trusted (topic policy scoped) | Message attribute injection, raw message delivery mode bypass |

### The event envelope problem

Each cloud wraps the raw event differently. The function handler must decode the correct field:

```python
# AWS Lambda — event mapping per source

# API Gateway proxy (REST)
event['httpMethod']       # GET/POST
event['headers']           # dict — ATTACKER-CONTROLLED
event['queryStringParameters']  # dict — ATTACKER-CONTROLLED
event['body']              # string — ATTACKER-CONTROLLED (may be base64)

# API Gateway HTTP (v2)
event['requestContext']['http']['method']
event['headers']            # dict
event['rawQueryString']     # string
event['body']               # string (base64 if isBase64Encoded)

# S3 put event
event['Records'][0]['s3']['bucket']['name']
event['Records'][0]['s3']['object']['key']   # URL-encoded; ATTACKER-CONTROLLED
event['Records'][0]['s3']['object']['size']

# SQS event
event['Records'][0]['body']  # string — ATTACKER-CONTROLLED
event['Records'][0]['messageAttributes']

# EventBridge
event['detail-type']
event['detail']              # dict — may be TRUSTED (internal) or UNTRUSTED (cross-account)
```

## AWS

### Attack: IP-based auth bypass via header injection

A Lambda behind API Gateway trusts `X-Forwarded-For` for IP allowlisting. API Gateway sets this header to the true client IP, but an attacker sends a pre-existing value:

```python
# VULNERABLE Lambda handler
def lambda_handler(event, context):
    client_ip = event['headers'].get('X-Forwarded-For', 'unknown')
    if client_ip in ALLOWED_IPS:
        return process_sensitive(event)  # bypassed if attacker sends X-Forwarded-For: <allowed-ip>
    return {'statusCode': 403}
```

**Why this fails:** API Gateway appends the true client IP to `X-Forwarded-For` but does not overwrite fake values. An attacker sends `X-Forwarded-For: 10.0.0.1` (expected internal IP), and the header becomes `10.0.0.1, <attacker-ip>`. The handler reads the first (fake) value.

**Fix:**

```python
# CORRECT: Use the guaranteed-unspoofable field
# API Gateway REST: event['requestContext']['identity']['sourceIp']
# API Gateway HTTP v2: event['requestContext']['http']['sourceIp']
def lambda_handler(event, context):
    client_ip = event['requestContext']['http']['sourceIp']
    # This value is set by API Gateway itself, not user-controllable
```

### Event body base64 confusion

API Gateway with binary media types set base64-encodes the body. If the handler forgets to decode, auth tokens in the body may not be parsed, causing an auth bypass:

```python
import base64
import json

def lambda_handler(event, context):
    body = event['body']
    if event.get('isBase64Encoded', False):
        body = base64.b64decode(body).decode('utf-8')
    data = json.loads(body)

    # Now validate data['auth_token'] — would have been skipped if still base64
```

## Azure

### Functions event envelope

```python
# Azure Function — HTTP trigger (Python v2)
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    # Trust these:
    client_ip = req.headers.get('X-Forwarded-For')  # Same risk as AWS — use x-ms-client-principal
    # Safer:
    # req.headers['X-MS-CLIENT-PRINCIPAL-ID'] — set by EasyAuth, not spoofable by client

    body = req.get_json() if req.get_body() else {}

    # Event Grid trigger
    # def main(event: func.EventGridEvent):
    #     event.topic   # trusted if same subscription
    #     event.subject # partially attacker-controlled (blob path)
    #     event.get_json()  # attacker-controlled
```

### Event Grid injection

An attacker with write access to a blob container can trigger Event Grid events to a function. The function must validate `event.subject` (the blob path) before acting on it — path traversal or unexpected extensions are common:

```python
def main(event: func.EventGridEvent):
    blob_path = event.subject  # e.g., "/blobServices/default/containers/uploads/blobs/../../../etc/passwd"
    # VULNERABLE: using blob_path directly without sanitization
```

## GCP

### Cloud Functions event envelope

```python
# GCP Cloud Functions — HTTP trigger
def process_request(request):
    # request is a Flask Request object
    client_ip = request.headers.get('X-Forwarded-For')  # Same header injection risk
    # Use request.remote_addr only if behind a trusted proxy with proper config

    body = request.get_json(silent=True) or {}

# Pub/Sub trigger
def process_pubsub(event, context):
    import base64
    import json
    data = base64.b64decode(event['data']).decode('utf-8')
    payload = json.loads(data)
    # event['attributes'] — attacker-controlled if cross-project publish is allowed
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS Lambda | Azure Functions | GCP Cloud Functions |
|---|---|---|---|---|
| HTTP request object | WSGI `environ` / `HttpRequest` | `event` dict — API Gateway proxy | `func.HttpRequest` | Flask `request` |
| True client IP | `REMOTE_ADDR` from webserver | `event['requestContext']['identity']['sourceIp']` | `X-MS-CLIENT-PRINCIPAL-ID` (if EasyAuth) | `request.remote_addr` (App Engine proxy) |
| Event source auth | Webserver itself validates | Resource policy on trigger source | Function access key / EasyAuth | IAM on trigger (Pub/Sub subscription) |
| Payload size limit | `client_max_body_size` | 6 MB (API Gateway) / 256 KB (SQS) | 100 MB (HTTP), 64 KB (Event Grid) | 32 MB (HTTP), 10 MB (Pub/Sub) |
| Cross-source validation | N/A (usually one source) | Check `event` keys to determine source | Check trigger type annotation | Check function signature |

## 🔴 Red Team view

### Attack 1: X-Forwarded-For poisoning for IP-based auth bypass

**Scenario:** A Cloud Function uses `X-Forwarded-For` for an IP-based admin panel. The attacker knows an internal IP range (e.g., `10.0.0.0/8`) from error messages or documentation.

```
# Attacker's request — spoof internal IP
curl https://us-central1-example-project.cloudfunctions.net/admin \
  -H "X-Forwarded-For: 10.0.0.5" \
  -H "Authorization: Bearer <any-valid-token>" \
  -d '{"action": "dump-database"}'
```

**Artifacts:**
- Cloud Logging / CloudWatch entry showing `X-Forwarded-For` with two values: `10.0.0.5, <attacker-real-ip>`.
- The real IP is always appended by the cloud proxy.

### Attack 2: SQS/SNS event injection — event-source mapping abuse

**Scenario:** A Lambda subscribes to an SQS queue that accepts messages from SNS. The SNS topic allows any AWS account to publish. An attacker publishes a crafted message:

```bash
aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:111111111111:order-events \
  --message '{"orderId": "123", "action": "refund", "amount": 99999}' \
  --profile attacker-account
```

The Lambda trusts the message and processes it without validating the SNS topic ARN or account origin. Cross ref: `../Compute-Container-Security/lambda-event-source-mapping-abuse.md`.

### Attack 3: S3 object key injection

An attacker uploads `../../etc/cron.d/backdoor` to a bucket that triggers a Lambda. The Lambda reads the S3 key and uses it in a local filesystem operation:

```python
# VULNERABLE Lambda
def lambda_handler(event, context):
    key = event['Records'][0]['s3']['object']['key']
    key = urllib.parse.unquote_plus(key)
    # DANGER: key = "../../etc/cron.d/backdoor" → path traversal
    with open(f'/tmp/{key}', 'r') as f:
        process(f.read())
```

**Containment:** Sanitize the S3 key — reject paths with `..`, `/` outside expected prefix, or unexpected extensions.

## 🔵 Blue Team view

### Prevention

| Control | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Use platform source IP | `event['requestContext']['http']['sourceIp']` | `X-MS-CLIENT-PRINCIPAL-ID` (EasyAuth) | `request.remote_addr` behind App Engine | `REMOTE_ADDR` from trusted proxy |
| Input schema validation | API Gateway request models / Lambda code | APIM `validate-content` + function code | API Gateway OpenAPI schema / function code | JSON Schema in view |
| Resource policy on trigger | SQS queue policy — `aws:SourceAccount` | Event Grid subscription filter | Pub/Sub subscription IAM | N/A |
| Payload size limits | API Gateway stage settings, SQS 256 KB | APIM body limit, Event Grid 1 MB | API Gateway 32 MB, Pub/Sub 10 MB | `client_max_body_size` |
| Function-level source check | Check `event['Records'][0]['eventSource']` | Check trigger binding metadata | Check function signature / context | N/A |
| CORS configuration | API Gateway CORS (do not use `*` with credentials) | APIM CORS policy | Cloud Functions CORS via `Access-Control-Allow-Origin` | Webserver CORS |

### Input validation per source (AWS Lambda template)

```python
import json
import base64
import urllib.parse

def lambda_handler(event, context):
    source = event.get('Records', [{}])[0].get('eventSource', 'aws:apigateway')

    if source == 'aws:apigateway':
        body = event.get('body', '{}')
        if event.get('isBase64Encoded'):
            body = base64.b64decode(body).decode('utf-8')
        data = json.loads(body)
        validate_http_event(data)

    elif source == 'aws:s3':
        for record in event['Records']:
            key = urllib.parse.unquote_plus(record['s3']['object']['key'])
            if '..' in key or key.startswith('/'):
                raise ValueError(f'Path traversal in key: {key}')
            if not key.startswith('uploads/'):
                raise ValueError(f'Unexpected key prefix: {key}')

    elif source == 'aws:sqs':
        for record in event['Records']:
            event_source_arn = record.get('eventSourceARN', '')
            # Validate the ARN matches expected SQS queue
            if 'expected-queue' not in event_source_arn:
                raise ValueError(f'Unexpected SQS source: {event_source_arn}')
            data = json.loads(record['body'])
            validate_sqs_payload(data)
    else:
        raise ValueError(f'Unknown event source: {source}')
```

### Detection

| Signal | Source | Query |
|---|---|---|
| Header injection attempt | Application logs / API Gateway | `X-Forwarded-For` contains comma (multiple IPs) and first IP is internal |
| Cross-account SQS publish | CloudTrail | `eventName = "SendMessage" AND eventSource = "sqs.amazonaws.com" AND userIdentity.accountId != <your-account>` |
| S3 key with path traversal | S3 access logs / Lambda logs | Object key contains `..` or `%2e%2e` |
| Oversized event payload | Lambda / Functions logs | `event size exceeds limit` or `RequestEntityTooLarge` |

## Hands-on lab

1. Deploy a Lambda behind API Gateway (HTTP API) in your sandbox.
2. Write a handler that reads `X-Forwarded-For` for an IP allowlist check.
3. Send a request with `X-Forwarded-For: 127.0.0.1` — observe the bypass.
4. Replace with `event['requestContext']['http']['sourceIp']` — confirm the fix blocks spoofed IPs.
5. Repeat with an S3-triggered function that uses the object key unsafely.

## References

- AWS Lambda event source mapping: https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html
- Azure Functions triggers: https://learn.microsoft.com/en-us/azure/azure-functions/functions-triggers-bindings
- GCP Cloud Functions events: https://cloud.google.com/functions/docs/writing
- Cross-ref: `../Compute-Container-Security/lambda-event-source-mapping-abuse.md` for persistence via event sources.
- Cross-ref: `api-gateway-and-edge-patterns.md` for gateway-level protection.
- Cross-ref: `cloud-app-threat-model.md` for trust boundary modeling.
