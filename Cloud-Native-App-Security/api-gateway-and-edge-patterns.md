# 02 — API Gateway and Edge Patterns

> **Level:** Intermediate–Advanced
> **Prereqs:** `cloud-app-threat-model.md`, `../Network-Security/load-balancers-and-waf.md`
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Credential Access, Impact
> **Authorization scope:** Configure API gateway rules only in your own sandbox account/tenant. Never test bypass payloads against production gateways.

## What & why

The API gateway is the single entrypoint — a choke point where authN, rate limiting, schema validation, OWASP rule enforcement, and request/response transformation converge. Getting gateway configuration wrong bypasses *all* downstream application security.

## The OnPrem reality

NGINX + ModSecurity Core Rule Set (CRS) + `auth_request` subrequest to an internal auth service. The gateway process had to trust the upstream `X-Auth-User` header — and spoofing that header was a common attack if the gateway was miswired.

## Core concepts

### Why the gateway matters

Every request path hits the gateway. If the gateway:
- Accepts a JWT with wrong audience → attacker uses another tenant's token
- Skips payload size limit → memory exhaustion of downstream FIFO handler
- Returns verbose errors → information disclosure (stack traces, internal IPs)
- Doesn't enforce schema → injection reaches the app

### Gateway responsibilities

| Layer | Function | If misconfigured |
|---|---|---|
| AuthN | Validate JWT / API key / mTLS | Unauthenticated access |
| AuthZ | Coarse-grained scope/audience check | Cross-tenant access |
| Rate limit | Per-IP, per-user, per-endpoint throttling | DoS, brute force |
| Schema validation | JSON/XML body schema; query param types | Injection, abuse |
| Payload size | Max body size | Memory exhaustion |
| OWASP rules | SQLi, XSS, path traversal | Classic web vulns |
| Transform | Strip internal headers, add correlation ID | Header smuggling, info leak |
| Logging | Every request, decision (allow/deny) | Blind spot for IR |

## AWS

### Services

| Capability | Service |
|---|---|
| REST APIs | API Gateway (REST) |
| HTTP APIs (cheaper, simpler) | API Gateway (HTTP) |
| WAF integration | AWS WAF attached to API Gateway stage or CloudFront |
| JWT authorizer | Cognito User Pool authorizer / Lambda authorizer |
| Rate limiting | Usage plans + API keys / WAF rate-based rule |
| Schema validation | API Gateway request validation (models) |

### JWT authorizer snippet (OpenAPI extension)

```yaml
# AWS API Gateway REST API with Cognito authorizer
openapi: 3.0.1
paths:
  /users/{userId}:
    get:
      security:
        - cognitoAuth: []
      x-amazon-apigateway-integration:
        uri: arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:111111111111:function:GetUser/invocations
        type: aws_proxy
components:
  securitySchemes:
    cognitoAuth:
      type: apiKey
      name: Authorization
      in: header
      x-amazon-apigateway-authtype: cognito_user_pools
      x-amazon-apigateway-authorizer:
        type: cognito_user_pools
        providerARNs:
          - arn:aws:cognito-idp:us-east-1:111111111111:userpool/us-east-1_AbCdEf123
```

### Rate-limit + payload cap

```json
// API Gateway stage settings
{
  "throttlingRateLimit": 5,
  "throttlingBurstLimit": 10,
  "minimumCompressionSize": 0
}
```

```json
// WAF rule: rate-based blocking — 100 req/5min per IP
{
  "Name": "RateLimit100Per5Min",
  "Priority": 1,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 100,
      "AggregateKeyType": "IP"
    }
  },
  "Action": { "Block": {} }
}
```

## Azure

### Services

| Capability | Service |
|---|---|
| API gateway | API Management (APIM) |
| WAF | Front Door WAF / Application Gateway WAF |
| JWT validation | APIM `validate-jwt` inbound policy |
| Rate limiting | APIM `rate-limit` / `rate-limit-by-key` policies |
| Schema validation | APIM `validate-content` policy |

### JWT validation snippet (APIM policy)

```xml
<!-- Inbound policy in APIM -->
<policies>
  <inbound>
    <validate-jwt header-name="Authorization"
                  failed-validation-httpcode="401"
                  failed-validation-error-message="Unauthorized"
                  require-expiration-time="true"
                  require-scheme="Bearer"
                  require-signed-tokens="true">
      <openid-config url="https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0/.well-known/openid-configuration" />
      <audiences>
        <audience>api://11111111-1111-1111-1111-111111111111</audience>
      </audiences>
      <issuers>
        <issuer>https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0</issuer>
      </issuers>
    </validate-jwt>
    <rate-limit calls="5" renewal-period="60" />
    <set-body>
      <limit size="1048576" /> <!-- 1 MB max -->
    </set-body>
  </inbound>
</policies>
```

## GCP

### Services

| Capability | Service |
|---|---|
| API gateway | API Gateway / Cloud Endpoints (ESPv2) |
| WAF | Cloud Armor (attached to load balancer) |
| JWT validation | OpenAPI `securityDefinitions` + ESPv2 |
| Rate limiting | Cloud Armor rate-based rules / Apigee quotas |
| Schema validation | OpenAPI schema in API Gateway config |

### JWT validation snippet (OpenAPI for GCP API Gateway)

```yaml
# GCP API Gateway config
swagger: '2.0'
securityDefinitions:
  firebase:
    authorizationUrl: ""
    flow: "implicit"
    type: "oauth2"
    x-google-issuer: "https://securetoken.google.com/example-project"
    x-google-jwks_uri: "https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com"
    x-google-audiences: "example-project"
paths:
  /users/{userId}:
    get:
      security:
        - firebase: []
      x-google-backend:
        address: https://us-central1-example-project.cloudfunctions.net/getUser
```

### Cloud Armor rate limiting

```bash
gcloud compute security-policies rules create 1000 \
    --security-policy my-policy \
    --expression "true" \
    --action "throttle" \
    --rate-limit-threshold-count 100 \
    --rate-limit-threshold-interval-sec 60 \
    --conform-action "allow" \
    --exceed-action "deny-429"
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| JWT validation | NGINX + lua-resty-jwt / auth_request | Cognito/Lambda authorizer | APIM `validate-jwt` | ESPv2 JWT in OpenAPI |
| Rate limiting | `limit_req_zone` + `limit_req` | WAF rate-based rule / usage plans | `rate-limit-by-key` | Cloud Armor throttle |
| Payload size | `client_max_body_size` | API Gateway `minimumCompressionSize` | `set-body` `limit` | Cloud Armor / API config |
| WAF rules | ModSecurity CRS | AWS WAF managed rules | Front Door managed rules | Cloud Armor preconfigured rules |
| IP allow/deny | `allow`/`deny` directives | WAF IP set | APIM `ip-filter` | Cloud Armor IP rules |
| Correlation ID | `$request_id` or app-generated | API Gateway `$context.requestId` | APIM `context.RequestId` | Cloud Endpoints `X-Cloud-Trace-Context` |

## 🔴 Red Team view

### Attack 1: Audience mis-scope

**Scenario:** A multi-tenant SaaS exposes API Gateway with Cognito authorizer. The authorizer validates "any token signed by my user pool" but does not pin `aud`. An attacker signs up for a free account in the *same* user pool, gets a valid JWT, and uses it to call another tenant's endpoints.

```
# Attacker gets token for their own tenant:
curl -X POST https://cognito-idp.us-east-1.amazonaws.com/ \
  -d '{"AuthParameters":{"USERNAME":"attacker@example.com","PASSWORD":"..."},
       "AuthFlow":"USER_PASSWORD_AUTH",
       "ClientId":"3qrstuv..."}'

# Token is valid per Cognito. Gateway only checks signature, not audience.
# Attacker calls GET /tenants/victim-tenant/admin — succeeds.
```

**Containment:** The gateway must validate `aud` claim == the specific app client ID. For APIM, pin `<audience>`. For Cognito authorizer, the authorizer handles this when the correct client ID ARN is wired.

### Attack 2: Payload size bypass

**Scenario:** API Gateway HTTP API does not enforce `minimumCompressionSize` or body limit. An attacker sends a 5 GB multipart upload. The Lambda/Function reads `event.body` into memory → memory exhaustion → cold-start latency for all users.

```
# No size validation at gateway → reaches Lambda
curl -X POST https://api-gateway-id.execute-api.us-east-1.amazonaws.com/upload \
  -H "Content-Type: application/octet-stream" \
  --data-binary @/dev/zero \
  -H "Transfer-Encoding: chunked"
```

**Containment:** Set payload size cap at gateway level (API Gateway: 10 MB default for REST, configurable; HTTP API: configure via stage variable). Downstream app should never trust gateway enforcement alone.

### Artifacts left:
- Gateway access logs showing `401` vs `200` for unknown audience.
- CloudTrail / Activity log entry for gateway configuration change (if misconfiguration was introduced).
- High-latency metrics for downstream function after payload-size abuse.

## 🔵 Blue Team view

### Prevention

| Control | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Pin audience in authorizer | Cognito client ID in authorizer config | `<audience>` in `validate-jwt` | `x-google-audiences` in OpenAPI | `lua-resty-jwt` audience claim check |
| Rate limit per IP + user | WAF rate-based + usage plan | `rate-limit-by-key` on `@(context.Request.IpAddress)` | Cloud Armor throttle | `limit_req` zone per `$binary_remote_addr` |
| Max payload size | Stage settings / WAF body inspection | `set-body limit` / Front Door body size | API config `max_request_size_bytes` | `client_max_body_size 1m` |
| Header stripping | Mapping template → drop `X-Forwarded-*` | `set-header` to overwrite incoming | ESPv2 drops unknown headers by default | `proxy_set_header` explicit whitelist |
| Circuit breaker | API Gateway → retry/Lambda reserved concurrency | APIM `forward-request` timeout + retry | Cloud Run max-instance / concurrency | NGINX `max_fails` + `fail_timeout` |

### Detection

**Signal: 4xx/5xx spike > baseline**

| Cloud | Log source | Query |
|---|---|---|
| AWS | CloudWatch Logs (API Gateway access logs) | `filter responseLatency > 2000 \| stats count() by httpMethod, resourcePath, statusCode` |
| Azure | Application Insights / APIM logs | `ApiManagementGatewayLogs \| where ResponseCode >= 400 \| summarize count() by bin(TimeGenerated, 5m), ResponseCode` |
| GCP | Cloud Logging (API Gateway logs) | `resource.type="api" AND httpResponse.status >= 400` |
| OnPrem | NGINX access log | `awk '$9>=400 {print $7,$9,$11}' access.log \| sort \| uniq -c \| sort -rn` |

**Signal: Unknown audience token presented**

| Cloud | Query |
|---|---|
| AWS | WAF logs `terminatingRule = "cognito_mismatch"` or API Gateway `authorizer.error = "Invalid token"` |
| Azure | `ApiManagementGatewayLogs \| where ClientResponseBody contains "aud" and ResponseCode == 401` |
| GCP | Cloud Endpoints logs `"JWT validation failed: audience not allowed"` |

### Response steps

1. **Block at WAF/gateway** — add IP to deny list, or if pattern-based, add WAF custom rule.
2. **Rotate any leaked tokens** — if audience bypass succeeded, tokens may be exfiltrated.
3. **Review authorizer configuration** — check audience, issuer, and scope settings across all APIs.
4. **Increase logging verbosity** — enable full request/response logging on gateway temporarily.

## Hands-on lab

Deploy a minimal API Gateway + Lambda with a misconfigured authorizer (no audience check) in your sandbox. Send a valid JWT from a different app client — observe it passes. Then pin the audience and confirm rejection.

## References

- AWS API Gateway Developer Guide (authorizers): https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html
- Azure APIM policies: https://learn.microsoft.com/en-us/azure/api-management/api-management-policies
- GCP API Gateway JWT: https://cloud.google.com/api-gateway/docs/authenticating-users
- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- Cross-ref: `../Network-Security/load-balancers-and-waf.md` for WAF rules.
- Cross-ref: `oauth-oidc-and-jwt-in-cloud.md` for token validation details.
