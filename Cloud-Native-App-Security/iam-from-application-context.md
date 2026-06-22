# 06 — IAM from Application Context

> **Level:** Advanced
> **Prereqs:** `../IAM/permission-boundaries-and-quarantine.md`, `../Compute-Container-Security/serverless-function-security.md`, `ssrf-and-cloud-metadata-from-app.md`
> **Clouds:** AWS · Azure · GCP
> **MITRE ATT&CK (tactics):** Privilege Escalation, Credential Access, Lateral Movement
> **Authorization scope:** Test IAM forwarding and confused-deputy patterns only in your own sandbox account. Do not forward credentials across account boundaries without explicit cross-account trust setup.

## What & why

Application endpoints carry user identity (JWT claims), but cloud service-to-service calls carry IAM/Managed-Identity tokens. When an app bridges these two — forwarding a cloud-signed request on behalf of a user — it creates a "confused deputy" risk: the app's powerful IAM role acts on behalf of a less-privileged user, or the user's claims get injected into a cloud API call.

## The OnPrem reality

N/A: Traditional apps didn't have an equivalent of the app itself having a cloud IAM role that it could forward. The closest analog was a service account with broad database access, used by the app regardless of which end-user triggered the request.

## Core concepts

### The forwarding problem

```
┌────────┐   JWT (user=alice)    ┌──────────┐   SigV4 (role=app-role)   ┌──────────┐
│ Client │ ──────────────────────▶│ App (API)│ ─────────────────────────▶│ S3 bucket │
└────────┘                       └──────────┘                            └──────────┘
                                      │
                                      │ The app uses its OWN role to call S3.
                                      │ Alice's identity is LOST at this boundary.
                                      │ Alice may read files Alice shouldn't.
```

### Signature mechanisms per cloud

| Concern | AWS | Azure | GCP |
|---|---|---|---|
| Signing mechanism | SigV4 (HMAC-SHA256 with access key + secret + session token) | Azure AD bearer token (JWT) | GCP OAuth2 bearer token (JWT) |
| What is signed | HTTP method, host, path, query params, headers, payload hash | N/A (bearer token authenticates the caller) | N/A (bearer token authenticates the caller) |
| Where replay risk exists | Signed request valid for 5 min window — replay within window | Token valid until expiry (~1 hr) — bearer theft | Token valid until expiry (~1 hr) — bearer theft |
| Application identity | IAM role on compute (Lambda/ECS/EC2) | Managed identity (System-assigned or User-assigned) | Service account attached to Cloud Run/Function |

### Two anti-patterns

1. **App-to-cloud without user context** — the app calls S3/RDS/DynamoDB using its own IAM role. The application must implement per-user ACL in code. If it forgets, every user gets the app-role's privileges.
2. **SigV4 forwarding through the app** — the app sends SigV4-signed headers to a backend, or includes them in an HTTP body. An attacker who can read the body or intercept the request gets a signed cloud API call they can replay.

## AWS

### Anti-pattern: Signed request smuggling

A Lambda that re-signs an S3 request and sends the full SigV4 headers back to the client (pre-signed URL anti-pattern):

```python
# VULNERABLE: returning SigV4 headers to client
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import requests

def lambda_handler(event, context):
    user_id = event['requestContext']['authorizer']['claims']['sub']
    bucket = event['pathParameters']['bucket']
    key = event['pathParameters']['key']

    # App signs the request with its OWN role
    s3_client = boto3.client('s3')
    url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket, 'Key': key},
        ExpiresIn=3600
    )

    # SAFE: pre-signed URL is scoped to one object and expires
    return {'statusCode': 302, 'headers': {'Location': url}}
```

```python
# VULNERABLE: App forwards SigV4 credentials in HTTP body to backend
# This creates a confused deputy — the backend gets the app's full role
session = boto3.Session()
credentials = session.get_credentials().get_frozen_credentials()

payload = {
    'user_file': key,
    'aws_access_key': credentials.access_key,
    'aws_secret_key': credentials.secret_key,
    'aws_session_token': credentials.token
}
requests.post('http://backend.internal:8080/process', json=payload)
# Backend now has the app's full IAM role — LATERAL MOVEMENT
```

### Correct pattern: Pre-signed URL + per-user conditions

```python
import boto3
from botocore.config import Config

s3 = boto3.client('s3', config=Config(signature_version='s3v4'))

def generate_user_presigned_url(user_id, bucket, key):
    # Per-user ACL enforced by the app BEFORE generating URL
    if not user_owns_object(user_id, bucket, key):
        raise PermissionError('Access denied')

    url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket, 'Key': key},
        ExpiresIn=300  # 5 minutes only
    )
    return url
```

## Azure

### Confused deputy via managed identity token forwarding

```python
# VULNERABLE: forwarding managed identity token to backend
import requests
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    # Get managed identity token
    token_resp = requests.get(
        'http://169.254.169.254/metadata/identity/oauth2/token'
        '?api-version=2021-02-01&resource=https://storage.azure.com/',
        headers={'Metadata': 'true'}
    )
    mi_token = token_resp.json()['access_token']

    # Forward to backend — backend now has app's managed identity
    user_blob = req.params.get('blob')
    backend_resp = requests.post(
        'http://backend.internal:8080/download',
        json={
            'blob': user_blob,
            'admin_token': mi_token  # VULNERABLE: app's full identity leaked
        },
        timeout=10
    )
    return func.HttpResponse(backend_resp.text)
```

### Correct pattern: User-delegation SAS

```python
from azure.storage.blob import generate_blob_sas, BlobSasPermissions
from datetime import datetime, timedelta, timezone

def generate_user_sas(storage_account, container, blob, user_id):
    if not user_has_access(user_id, container, blob):
        raise PermissionError('Access denied')

    sas_token = generate_blob_sas(
        account_name=storage_account,
        container_name=container,
        blob_name=blob,
        account_key=get_stored_account_key(),  # or use user-delegation key with managed identity
        permission=BlobSasPermissions(read=True),
        expiry=datetime.now(timezone.utc) + timedelta(minutes=5)
    )
    return sas_token
```

## GCP

### Confused deputy via OAuth2 token forwarding

```python
# VULNERABLE: forwarding service account token in app payload
import google.auth.transport.requests
import google.oauth2.id_token

def process_request(request):
    user_id = request.args.get('user')
    file_path = request.args.get('file')

    # Get the Cloud Run service account's identity token
    auth_req = google.auth.transport.requests.Request()
    token = google.oauth2.id_token.fetch_id_token(
        auth_req,
        'https://storage.googleapis.com'
    )

    # Forward to internal service — VULNERABLE
    resp = requests.post(
        'http://internal-backend:8080/export',
        json={
            'user': user_id,
            'file': file_path,
            'sa_token': token  # VULNERABLE
        }
    )
```

### Correct pattern: Signed URL

```python
from google.cloud import storage
import datetime

def generate_user_signed_url(user_id, bucket_name, blob_name):
    if not user_owns_blob(user_id, bucket_name, blob_name):
        raise PermissionError('Access denied')

    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    url = blob.generate_signed_url(
        version='v4',
        expiration=datetime.timedelta(minutes=5),
        method='GET'
    )
    return url
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| App identity | Service account (file) | IAM role on compute | Managed Identity | Service Account |
| User-to-cloud bridging | N/A | Pre-signed URL / condition keys | SAS / user-delegation key | Signed URL |
| Token replay window | Kerberos ticket lifetime | 5 min (SigV4) | 1 hr (JWT) | 1 hr (JWT) |
| Confused deputy prevention | App-level ACL only | `sts:AssumeRole` with `Policy` parameter / `aws:userid` condition | On-behalf-of flow (OBO) | IAM conditions |
| Session policy (STS) | N/A | `Policy` parameter in `AssumeRole` → restrict session | N/A (as of June 2026, Azure AD Conditional Access can restrict session scope via authentication context but does not have an inline session policy equivalent) | N/A (as of June 2026, GCP IAM Conditions on service accounts can restrict session scope at binding time, not as an inline session policy) |

## 🔴 Red Team view

### Attack: Confused deputy via STS token forwarding

**Scenario:** A SaaS app runs on EC2 with role `arn:aws:iam::111111111111:role/SaaS-App-Role` that has `s3:*` on all customer buckets. When user Alice requests a report, the app:
1. Receives Alice's JWT (sub=alice).
2. Uses the EC2 instance role to generate a signed S3 URL for *any* bucket.
3. Forwards that URL to Alice.

The app *intends* to check Alice's permissions, but a code path has no check. Alice can set `bucket=victim-corp-prod` and get a valid pre-signed URL.

```python
# VULNERABLE endpoint — missing per-user ACL check
@app.route('/api/generate-download-link')
def generate_link():
    user_sub = get_jwt_claims()['sub']  # Alice
    bucket = request.args.get('bucket')  # victim-corp-prod (another tenant!)
    key = request.args.get('key')        # secrets/database.yml

    # BUG: No check that user_sub owns bucket
    url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket, 'Key': key},
        ExpiresIn=3600
    )
    return {'download_url': url}
# Alice gets a valid signed URL for another tenant's secrets file
```

**Artifacts:**
- CloudTrail: `s3:GetObject` via pre-signed URL from Alice's IP, but with the app's assumed role.
- S3 access logs: `GET /victim-corp-prod/secrets/database.yml` from 198.51.100.10.
- Application logs: `/api/generate-download-link?bucket=victim-corp-prod&key=secrets/database.yml`.

### Attack: SigV4 replay via intercepted header

**Scenario:** The app includes SigV4 authorization header in the response body (debug mode or misconfig):

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "processing",
  "s3_request_id": "abc123",
  "sigv4_headers": {
    "Authorization": "AWS4-HMAC-SHA256 Credential=ASIA.../20260622/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=..."
  }
}
```

The attacker replays this within the 5-minute SigV4 window by sending the exact same headers to S3.

**Containment:** Never log or return SigV4 headers. Use short expiration on pre-signed operations.

## 🔵 Blue Team view

### Prevention

| Control | AWS | Azure | GCP |
|---|---|---|---|
| Per-request session policy | `sts:AssumeRole` with inline `Policy` restricting to user's S3 prefix | On-behalf-of flow: app gets user-scoped token | IAM conditions on service account |
| `aws:userid` condition | IAM policy condition: `"Condition": {"StringEquals": {"aws:userid": "${aws:username}"}}` | N/A (use OBO) | N/A |
| Pre-signed URLs (not bearer forwarding) | S3 pre-signed URL scoped to object | SAS token scoped to blob | Signed URL scoped to object |
| Short token lifetime | 5 min (SigV4 window) / 5 min (pre-signed) | 5 min (SAS expiry) | 5 min (signed URL expiry) |
| No credentials in logs/response | Strip Authorization from debug output | Strip `Bearer` from logs | Strip `Authorization` from logs |
| SCP to prevent role assumption | `Deny sts:AssumeRole unless aws:PrincipalTag/team = "${aws:RequestTag/team}"` | Azure Policy: deny role assignment unless condition | Org policy: constrain service account impersonation |

### Per-endpoint session policy (AWS STS)

```python
# App assumes a role WITH a session policy that limits to the user's prefix
import boto3

sts = boto3.client('sts')

def get_user_scoped_credentials(user_sub):
    response = sts.assume_role(
        RoleArn='arn:aws:iam::111111111111:role/Scoped-App-Role',
        RoleSessionName=f'user-{user_sub}',
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::app-data/users/{user_sub}/*"]
            }]
        }),
        DurationSeconds=900  # 15 minutes max
    )
    # Use these scoped credentials for ALL subsequent S3 calls for this user
    return response['Credentials']
```

### Detection

| Signal | Source | Query |
|---|---|---|
| STS AssumeRole followed by S3 access from new IP | CloudTrail (cross-event correlation) | `eventName = "AssumeRole" AND sourceIPAddress = <app-ip>` → then within 5 min `eventName = "s3:GetObject" AND sourceIPAddress != <app-ip>` |
| SigV4 headers in response body | Application logs / WAF response inspection | Response body contains `AWS4-HMAC-SHA256` or `Credential=ASIA` |
| Unusual pre-signed URL generation | CloudTrail | Spike in `s3:PutObject` with `x-amz-security-token` for app role, correlated with high volume of `/api/generate-download-link` |
| Cross-tenant S3 access | S3 access logs | `bucket` not in the authenticated user's tenant set |

**AWS CloudTrail query for confused deputy:**

```sql
SELECT eventTime, eventName, requestParameters.bucketName, sourceIPAddress, userIdentity.sessionContext.sessionIssuer.userName
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND userIdentity.type = 'AssumedRole'
  AND userIdentity.sessionContext.sessionIssuer.arn LIKE '%:role/SaaS-App-Role'
  AND sourceIPAddress IN (
    SELECT DISTINCT sourceIPAddress
    FROM cloudtrail_logs
    WHERE eventName = 'AssumeRole'
      AND sourceIPAddress != '<app-vpc-nat-ip>'
  )
ORDER BY eventTime DESC
```

### Response steps

1. Revoke all active sessions for the app role (`RevokeSession` on IAM role).
2. Rotate the instance credentials (stop and re-launch or force credential refresh).
3. Add the missing per-user ACL check in the application code.
4. Deploy session-policy scoping per STS `AssumeRole` call.

## Hands-on lab

1. Deploy a Lambda with `s3:ListBucket` on all buckets in the account.
2. Write a minimal API endpoint that lists objects for a given bucket without user validation.
3. Call it with `?bucket=another-customer-data` — observe the listing.
4. Add a per-user prefix check and re-test — confirm rejection.

## References

- AWS confused deputy prevention: https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
- AWS pre-signed URLs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html
- Azure managed identities: https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/
- GCP service account impersonation: https://cloud.google.com/iam/docs/service-account-impersonation
- OWASP API Security Top 10 — API1:2019 (Broken Object Level Authorization): https://owasp.org/www-project-api-security/
- Cross-ref: `../IAM/assume-role-chains-and-trust-graphs.md` for role chaining risks.
- Cross-ref: `ssrf-and-cloud-metadata-from-app.md` for how app roles leak via SSRF.
- Cross-ref: `broken-object-level-authz-and-idors.md` for per-object ACL enforcement.
