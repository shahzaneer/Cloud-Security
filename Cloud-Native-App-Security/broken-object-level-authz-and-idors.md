# 07 — Broken Object-Level Authz and IDORs

> **Level:** Intermediate
> **Prereqs:** `cloud-app-threat-model.md`, `api-gateway-and-edge-patterns.md`
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Discovery, Collection, Exfiltration
> **Authorization scope:** Test IDOR enumeration only against your own sandbox applications and buckets. Do not iterate object IDs against production APIs or storage accounts you do not own.

## What & why

Insecure Direct Object Reference (IDOR) occurs when an API endpoint uses a user-supplied identifier to access a resource without verifying the requester owns or is authorized for that resource. In cloud, this amplifies when the object is a cloud storage key (`s3://bucket/user-1001/file.pdf`) and the identifier maps directly to a bucket path.

## The OnPrem reality

Classic path traversal: `download.php?file=../../etc/passwd`. The application used the `file` parameter directly in a filesystem call without validation. Cloud IDOR is the same class of vulnerability, but the resource is a cloud object, database row, or pre-signed URL instead of a local file.

## Core concepts

### Where IDOR lives in cloud apps

| Resource type | IDOR pattern | Risk |
|---|---|---|
| Object storage | `GET /files/{user_id}/{file_name}` → no check that `{user_id}` matches the JWT sub | User 1001 reads user 1002's files |
| Database rows | `GET /api/orders/{order_id}` → no ownership check | Enumerate all orders in system |
| Pre-signed URLs | App generates pre-signed URL for any key without verifying user ownership | Access to any object in bucket |
| Compute resources | `DELETE /api/instances/{id}` → no check | Terminate other users' EC2 instances |
| API keys | `GET /api/apikeys/{key_id}` → no check | Read other users' API keys |

### The bucket-key-as-userid antipattern

```
s3://customer-files/user-1001/report.pdf
s3://customer-files/user-1002/report.pdf
s3://customer-files/user-1003/report.pdf
```

If the API does `GET /files?user=1001&file=report.pdf` and serves the file directly, an attacker enumerates `user=1001..5000` and downloads every customer file. Even if the bucket is "private," the app's IAM role has read access — so the app happily serves all objects.

## AWS

### IDOR-vulnerable endpoint (API Gateway + Lambda)

```python
# VULNERABLE: no ownership check
import boto3
import json

s3 = boto3.client('s3')
BUCKET = 'customer-files'

def lambda_handler(event, context):
    user_id = event['pathParameters']['user_id']  # from URL, attacker-controlled
    file_name = event['pathParameters']['file_name']

    # VULNERABLE: fetches any object, regardless of who requested it
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=f'{user_id}/{file_name}')
        return {
            'statusCode': 200,
            'body': obj['Body'].read().decode('utf-8'),
            'headers': {'Content-Type': obj['ContentType']}
        }
    except s3.exceptions.NoSuchKey:
        return {'statusCode': 404, 'body': 'Not found'}
```

**Attacker's enumeration:**

```bash
# Iterate user IDs
for uid in $(seq 1000 5000); do
  curl "https://api.example.com/files/${uid}/passport.pdf" -o "dumps/${uid}.pdf"
done
```

### Fixed endpoint with per-user IAM check

```python
import boto3
import json

s3 = boto3.client('s3')
BUCKET = 'customer-files'

def lambda_handler(event, context):
    # Get the authenticated user's sub from the JWT (validated by authorizer)
    claims = event['requestContext']['authorizer']['claims']
    auth_user_sub = claims['sub']  # e.g., "user-1001"

    # Path parameter — attacker-controlled
    requested_user_id = event['pathParameters']['user_id']
    file_name = event['pathParameters']['file_name']

    # CRITICAL CHECK: requested path must match authenticated user
    if requested_user_id != auth_user_sub:
        return {
            'statusCode': 403,
            'body': json.dumps({'error': 'Access denied: you can only access your own files'})
        }

    # Additional: sanitize file_name — no path traversal
    if '..' in file_name or '/' in file_name:
        return {'statusCode': 400, 'body': 'Invalid file name'}

    key = f'{auth_user_sub}/{file_name}'
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=key)
        return {
            'statusCode': 200,
            'body': obj['Body'].read().decode('utf-8'),
            'headers': {'Content-Type': obj['ContentType']}
        }
    except s3.exceptions.NoSuchKey:
        return {'statusCode': 404, 'body': 'Not found'}
```

### Fixed with pre-signed URL per principal

```python
def lambda_handler(event, context):
    claims = event['requestContext']['authorizer']['claims']
    auth_user_sub = claims['sub']
    file_name = event['pathParameters']['file_name']

    if '..' in file_name or '/' in file_name:
        return {'statusCode': 400}

    # Generate pre-signed URL for this specific user's object only
    key = f'{auth_user_sub}/{file_name}'
    url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': BUCKET, 'Key': key},
        ExpiresIn=300
    )

    return {
        'statusCode': 302,
        'headers': {'Location': url}
    }
```

## Azure

### IDOR-vulnerable endpoint (Functions + Blob Storage)

```python
# VULNERABLE: no ownership check
import azure.functions as func
from azure.storage.blob import BlobServiceClient
import os

blob_service = BlobServiceClient.from_connection_string(os.environ['STORAGE_CONNECTION_STRING'])

def main(req: func.HttpRequest) -> func.HttpResponse:
    user_id = req.route_params.get('user_id')
    file_name = req.route_params.get('file_name')

    # VULNERABLE
    container_client = blob_service.get_container_client('customer-files')
    blob_client = container_client.get_blob_client(f'{user_id}/{file_name}')
    data = blob_client.download_blob().readall()

    return func.HttpResponse(data)
```

### Fixed with user-delegation SAS

```python
from azure.storage.blob import generate_blob_sas, BlobSasPermissions
from datetime import datetime, timedelta, timezone

def main(req: func.HttpRequest) -> func.HttpResponse:
    auth_user = get_authenticated_user(req)  # from validated JWT
    requested_user_id = req.route_params.get('user_id')
    file_name = req.route_params.get('file_name')

    if auth_user['sub'] != requested_user_id:
        return func.HttpResponse('Access denied', status_code=403)

    sas_token = generate_blob_sas(
        account_name='appstorageaccount',
        container_name='customer-files',
        blob_name=f'{auth_user["sub"]}/{file_name}',
        account_key=os.environ['STORAGE_ACCOUNT_KEY'],
        permission=BlobSasPermissions(read=True),
        expiry=datetime.now(timezone.utc) + timedelta(minutes=5)
    )

    return func.HttpResponse(
        status_code=302,
        headers={'Location': f'https://appstorageaccount.blob.core.windows.net/customer-files/{auth_user["sub"]}/{file_name}?{sas_token}'}
    )
```

## GCP

### IDOR-vulnerable endpoint (Cloud Run + Cloud Storage)

```python
# VULNERABLE
from flask import Flask, request
from google.cloud import storage

app = Flask(__name__)
client = storage.Client()

@app.route('/files/<user_id>/<file_name>')
def get_file(user_id, file_name):
    bucket = client.bucket('customer-files')
    blob = bucket.blob(f'{user_id}/{file_name}')

    # VULNERABLE: no check that user_id matches authenticated user
    data = blob.download_as_text()
    return data
```

### Fixed with signed URL + user check

```python
@app.route('/files/<user_id>/<file_name>')
def get_file(user_id, file_name):
    auth_sub = get_auth_user_sub(request)  # from validated Firebase/Identity Platform token

    if auth_sub != user_id:
        return {'error': 'Access denied'}, 403

    bucket = client.bucket('customer-files')
    blob = bucket.blob(f'{auth_sub}/{file_name}')

    if not blob.exists():
        return {'error': 'Not found'}, 404

    url = blob.generate_signed_url(version='v4', expiration=300, method='GET')
    return {'url': url}
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Resource identifier | File path (LFI/RFI) | S3 object key + bucket | Blob path + container | Object path + bucket |
| Authorization check | App-level ACL in code | JWT `sub` == object prefix + IAM condition | JWT `oid` == object prefix + SAS | JWT `sub` == object prefix + IAM |
| Safe resource access | Serve file only after ACL check | Pre-signed URL (5 min) | User-delegation SAS (5 min) | Signed URL (5 min) |
| Enumeration prevention | Rate limit + generic 404 | Rate limit + consistent 403/404 | Rate limit + consistent 403/404 | Rate limit + consistent 403/404 |
| Bucket-level discovery | N/A | S3 prefix listing (if ListBucket enabled) | Blob prefix listing | Object listing |

## 🔴 Red Team view

### Attack: Sequential ID enumeration

**Scenario:** The API endpoint `GET /api/orders/{order_id}` uses auto-incrementing integer IDs. No ownership check. Attacker iterates:

```bash
# Enumerate all orders
for order_id in $(seq 1000 5000); do
  resp=$(curl -s -w '%{http_code}' "https://api.example.com/orders/${order_id}")
  if [ "$resp" != "404" ]; then
    echo "Order $order_id: $resp"
  fi
done
```

**Cloud amplification:** If the response includes a cloud resource identifier:

```json
{
  "order_id": 1423,
  "customer": "victim@example.com",
  "receipt_url": "https://s3.amazonaws.com/invoices/user-9832/order-1423.pdf?AWSAccessKeyId=..."
}
```

The attacker now has pre-signed URLs to all invoices. Even if the S3 bucket is "private," the pre-signed URL bypasses the bucket policy for the expiry window.

### Attack: Bucket-level discovery via IDOR

Most cloud object stores support prefix listing. If the app has `ListBucket` permission and reflects object listings, an attacker can discover valid user prefixes:

```bash
# If GET /files returns a listing for the authenticated user:
# Attacker with user_id "test-user" discovers the pattern.
# Sends GET /files?prefix=user-1001 → gets listing of user-1001's objects
```

### Artifacts:
- API access logs showing rapid sequential requests: `GET /orders/1001`, `GET /orders/1002`, `GET /orders/1003` from one IP.
- CloudTrail / Activity Log showing `s3:GetObject` / `Get Blob` for disparate user prefixes from the same app role.
- Response codes: 200s interspersed with 403s/404s — enumeration pattern.

## 🔵 Blue Team view

### Prevention

| Control | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| JWT `sub` ownership check | Server compares `event['requestContext']['authorizer']['claims']['sub']` to resource owner | Same — compare `oid`/`sub` from validated token | Same — compare Firebase Auth `uid` | Server-side session check |
| Object-key-to-user mapping | User prefix enforced in Lambda code | User prefix enforced in Function code | User prefix enforced in Cloud Run code | File-path ACL |
| Pre-signed / SAS URLs | 5-minute expiry, object-specific | 5-minute expiry, blob-specific | 5-minute expiry, object-specific | N/A (app mediates access) |
| Rate limiting on GET by ID | WAF rate-based rule 50 req/min per IP | APIM `rate-limit-by-key` | Cloud Armor throttle | `limit_req` |
| Consistent error messages | Always return 404 (even for 403) to avoid user-enumeration | Same | Same | Same |
| UUIDs not sequential ints | Route keys as UUIDs, not integers | Same | Same | Use UUIDs or hash-based IDs |

### Detection

**Signal: One source IP requesting many distinct resource IDs**

| Cloud | Source | Query |
|---|---|---|
| AWS | ALB access logs + CloudWatch | Count distinct `resourcePath` per `client_ip` in 5-min window; alert if > 50 unique paths |
| Azure | APIM logs / App Insights | `ApiManagementGatewayLogs \| where ResponseCode in (200, 403) \| summarize DistinctPaths=dcount(Url) by ClientIp, bin(TimeGenerated, 5m) \| where DistinctPaths > 50` |
| GCP | Cloud Logging (HTTP Load Balancer) | Count distinct `httpRequest.requestUrl` per `httpRequest.remoteIp` |
| OnPrem | NGINX access log | `awk '{print $1,$7}' access.log \| sort -u \| awk '{print $1}' \| uniq -c \| sort -rn` |

**Signal: Cross-user S3 access pattern**

```sql
-- AWS CloudTrail — app role accessing objects across many user prefixes
SELECT userIdentity.arn, COUNT(DISTINCT regexp_extract(requestParameters.key, '([^/]+)/', 1)) AS user_prefix_count
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND requestParameters.bucketName = 'customer-files'
  AND eventTime >= date_add('hour', -1, current_timestamp)
GROUP BY userIdentity.arn
HAVING COUNT(DISTINCT regexp_extract(requestParameters.key, '([^/]+)/', 1)) > 10
```

### SCP to prevent bucket listing

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::customer-files",
      "Condition": {
        "StringNotLike": {
          "s3:prefix": "${aws:username}/*"
        }
      }
    }
  ]
}
```

### Response steps

1. Block the enumerating IP at WAF/gateway.
2. Audit the vulnerable endpoint — add per-user ACL check.
3. Rotate any pre-signed URLs that may have been generated during the enumeration window.
4. Review access logs for data exfiltrated during the attack window.

## Hands-on lab

1. Create an S3 bucket with folders `user-1001/`, `user-1002/`, each with a test file.
2. Deploy a Lambda behind API Gateway with a GET `/files/{userId}` endpoint.
3. First deploy the vulnerable version (no sub check) — confirm user-1001 can read user-1002's file.
4. Deploy the fixed version with JWT `sub` check — confirm access denied.
5. Add rate limiting via WAF and observe enforcement.

## References

- OWASP API1:2019 — Broken Object Level Authorization: https://owasp.org/www-project-api-security/
- OWASP IDOR: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- CWE-639: Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- Cross-ref: `../Storage-Data-Security/object-storage-primitives.md` for object storage basics.
- Cross-ref: `../Storage-Data-Security/pre-signed-urls-and-tokenized-access.md` for pre-signed URL security.
- Cross-ref: `iam-from-application-context.md` for IAM forwarding and session policy.
- Cross-ref: `api-gateway-and-edge-patterns.md` for gateway-level rate limiting.
