# 09 — SSRF and IMDS Pivots

> **Level:** Advanced
> **Prereqs:** [Compute Container Security](../Compute-Container-Security) (container/EC2 sections), [Vpc Segmentation Design](vpc-segmentation-design.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** see ATT&CK Cloud matrix for Credential Access, Privilege Escalation
**Authorization scope:** Run only in your own sandbox account / lab VPC. SSRF PoC must target localhost only.

## What & why
Server-Side Request Forgery (SSRF) against the Instance Metadata Service (IMDS) at `169.254.169.254` is the canonical cloud compromise pivot. An attacker who coerces an application into making an HTTP request to the metadata endpoint can steal temporary IAM/role credentials, gaining the permissions of the instance's attached role — often full admin to the account's resources. This single bug class has caused more cloud breaches than any other network vulnerability.

## The OnPrem reality
Metadata services do not exist on-prem. SSRF against on-prem applications typically targets internal APIs (admin panels, configuration endpoints, health checks) accessible from the compromised server but not from the internet. The OnPrem equivalent of an IMDS pivot is hitting an internal URL like `http://config-server.internal/vault-secrets` — lower blast radius, but the same vulnerability class.

### OnPrem SSRF → internal API

```
Attacker-crafted URL → App server (SSRF) → http://admin-panel.internal/api/keys
```

No automated credential refresh, no temporary IAM tokens — the attacker gets whatever the config endpoint returns. Cloud metadata services make this far more dangerous because the credentials auto-rotate and grant broad cloud API access.

## Core concepts

### IMDS endpoints across clouds

| Provider | Endpoint | Version | Required header | Token TTL |
|----------|----------|---------|----------------|-----------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | v1 | None | N/A |
| AWS IMDSv2 | `http://169.254.169.254/latest/meta-data/` | v2 | `X-aws-ec2-metadata-token` | 1 sec – 6 hrs |
| Azure IMDS | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | N/A (single version; no v1/v2 split) | `Metadata: true` | Managed identity token lifetime varies |
| GCP Metadata | `http://169.254.169.254/computeMetadata/v1/` | v1 | `Metadata-Flavor: Google` | 1 hr (access token) |
| GCP Metadata | `http://169.254.169.254/computeMetadata/v1/` | v1.1 (identity) | `Metadata-Flavor: Google` + audience param | 1 hr |

> (as of June 2026, Azure IMDS requires the `Metadata: true` header on all requests and specifies API version via the `?api-version=` query parameter; there is no IMDSv1/v2 split analogous to AWS — Azure IMDS has always been header-gated by default.)

### SSRF → IMDS attack flow

```
┌──────────┐    ┌───────────┐    ┌──────────────────────┐
│ Attacker │───▶│ Web App   │───▶│  169.254.169.254     │
│  (craft  │    │ (SSRF)    │    │  /latest/meta-data/  │
│   URL)   │    │           │◀───│  iam/security-creds  │
└──────────┘    └─────┬─────┘    └──────────────────────┘
                      │
                      │ returns IAM creds / managed identity token
                      ▼
              ┌───────────────┐
              │ Attacker uses │
              │ creds via API │
              └───────────────┘
```

## AWS

### Querying metadata (IMDSv2 — token-based)

```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole
```

### Forcing IMDSv2

```hcl
resource "aws_instance" "app" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"    # IMDSv2 only; v1 requests rejected
  }
}

resource "aws_launch_template" "imdsv2_required" {
  name = "imdsv2-only"

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
}
```

### SCP to enforce IMDSv2 organization-wide

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    }
  ]
}
```

CLI audit for IMDSv1 usage:

```
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[?MetadataOptions.HttpTokens==`optional`].[InstanceId,State.Name]' \
  --output table
```

## Azure

### Querying Azure IMDS

```bash
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

The `Metadata: true` header is mandatory — Azure IMDS rejects requests without it (this is an SSRF mitigation, but easily bypassed if the application allows custom headers).

### Restricting managed identity use

Azure does not have an "IMDSv2" equivalent toggle. Mitigations:
- **Disable managed identity** on the VM/VMSS if not needed
- **Use Azure Policy** to deny `Microsoft.Compute/virtualMachines` identity assignment in non-production subscriptions
- **Network restriction:** NSG rules blocking outbound `169.254.169.254` from the VM's subnet

```hcl
resource "azurerm_network_security_rule" "block_imds" {
  name                        = "BlockIMDS"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "80"
  source_address_prefix       = "*"
  destination_address_prefixes = ["169.254.169.254/32", "169.254.169.253/32"]
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.app.name
}
```

## GCP

### Querying GCP metadata

```bash
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example.com"
```

The `Metadata-Flavor: Google` header must be present; however, some legacy endpoints respond without it. GCP also supports `X-Google-Metadata-Request: True` as an alternative header.

### Restricting metadata access

- **Disable service account on instance:** Configure instance to run without a service account
- **Scopes:** Limit OAuth2 scopes on the instance (e.g., `cloud-platform` → `storage-ro`)
- **Shielded VM:** vTPM-based attestation as an alternative to metadata
- **Firewall rule:** VPC firewall denying egress to `169.254.169.254/32` on TCP 80

```hcl
resource "google_compute_instance" "no_sa" {
  name         = "app-no-sa"
  machine_type = "e2-micro"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = google_compute_network.main.name
  }

  service_account {
    email  = ""
    scopes = []     # empty = no scopes, no metadata creds
  }
}
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---------|--------|-----|-------|-----|
| Metadata endpoint | N/A (internal APIs only) | `169.254.169.254` | `169.254.169.254` | `169.254.169.254` |
| Required header | N/A | `X-aws-ec2-metadata-token` (v2) | `Metadata: true` | `Metadata-Flavor: Google` |
| Credential type | Static API keys (vault) | Temporary IAM creds (1-6 hr) | Managed identity token | OAuth2 access token |
| Hardening toggle | Firewall to internal API | `HttpTokens = required` | No toggle — block via NSG | Block via firewall / remove SA |
| Enforcement policy | — | SCP `ec2:MetadataHttpTokens` | Azure Policy deny identity | Org Policy `compute.disableDefaultServiceAccount` |

## 🔴 Red Team view

A contained SSRF PoC against a local metadata service simulator — this runs entirely on `localhost`, no remote services.

### Step 1: Simulated metadata server on localhost

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

CREDS = {
    "Code": "Success",
    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "SecretAccessKey": "wJalrXUtfFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "FwoGZXIvYXdzEJr...EXAMPLE",
    "Expiration": "2026-06-22T12:00:00Z"
}

class MetadataSimulator(BaseHTTPRequestHandler):
    def do_GET(self):
        if "api/token" in self.path:
            self.send_response(200)
            self.send_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            self.end_headers()
            self.wfile.write(b"SIMULATED-TOKEN==")
            return

        if "security-credentials" in self.path:
            token = self.headers.get("X-aws-ec2-metadata-token", "")
            if token == "":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(CREDS).encode())
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(CREDS).encode())
            return

        self.send_response(404)
        self.end_headers()

if __name__ == "__main__":
    HTTPServer(("127.0.0.2", 80), MetadataSimulator).serve_forever()
```

Start the simulator in one terminal, then redirect `169.254.169.254` to `127.0.0.2`:

```bash
sudo ifconfig lo0 alias 169.254.169.254/32 up   # macOS
```

### Step 2: SSRF simulation (IMDSv1 — no token required)

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/SimRole
```

Returns the simulated credentials. This is exactly what an SSRF vulnerability in a web application would do — the app server, coerced by the attacker, makes this request internally and returns the response.

### Step 3: Using stolen credentials (simulated)

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtfFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_SESSION_TOKEN=FwoGZXIvYXdzEJr...EXAMPLE

aws sts get-caller-identity --region us-east-1
```

In a real attack, this would return the IAM role identity, and the attacker would enumerate what the role can do with `aws iam list-roles`, `aws s3 ls`, etc.

### Step 4: Teardown the IP alias

```bash
sudo ifconfig lo0 169.254.169.254/32 delete
```

### What artifacts does this leave?

- **CloudTrail (AWS):** `GetCallerIdentity` followed by enumeration API calls (`ListBuckets`, `DescribeInstances`, etc.) from an IP that belongs to the compromised EC2 instance. The user agent will show `aws-cli` with the access key of the instance role — but it's indistinguishable from legitimate application use without behavioral analysis.
- **Azure:** `Microsoft.Compute/virtualMachines/retrievePassword` or management API calls from the VM's managed identity.
- **GCP:** Cloud Audit Logs showing API calls from the VM's service account.

**Detection pairing:** IMDSv1 usage is logged differently than IMDSv2 in some providers. AWS CloudTrail records do **not** directly log IMDS access, but you can infer IMDSv1 use by checking if the instance `MetadataOptions.HttpTokens` was `optional` at the time of a suspicious API call. The SCP forcing IMDSv2 blocks the attack entirely — the SSRF request to IMDS gets a 401 rather than credentials.

## 🔵 Blue Team view

### Forcing IMDSv2 / equivalent

| Provider | Enforcement mechanism |
|----------|----------------------|
| AWS | Launch template: `http_tokens = required` + SCP `ec2:MetadataHttpTokens != required` deny |
| Azure | NSG outbound block to `169.254.169.254` + Azure Policy deny managed identity on non-compliant VMs |
| GCP | Remove service account from instance + org policy `compute.disableDefaultServiceAccount` |
| OnPrem | Network ACL on internal API endpoints — require mTLS or short-lived tokens |

### CloudTrail detection for IMDSv1 use

```
fields @timestamp, userIdentity.arn, sourceIPAddress, userAgent, eventName
| filter userAgent like /aws-cli/ or userAgent like /boto3/
| filter eventName in ["GetCallerIdentity", "ListBuckets", "DescribeInstances"]
| sort @timestamp desc
```

This query surfaces API calls made with instance role credentials. Cross-reference with EC2 metadata status: if the instance has `HttpTokens = optional`, an attacker could have used IMDSv1 to obtain the credential.

### IMDS access denial via iptables (defense in depth)

```bash
iptables -A OUTPUT -d 169.254.169.254 -p tcp --dport 80 -m owner ! --uid-owner root -j DROP
```

This prevents non-root processes (like a compromised web app running as `www-data`) from reaching IMDS. Only root-level processes can query metadata. This is a defense-in-depth measure that works across all clouds.

### AWS-specific: VPC Endpoint policy to restrict S3 access from the instance

If the SSRF victim has an IAM role with `s3:*`, the attacker can exfiltrate data from any S3 bucket the role can access. A VPC Endpoint policy can restrict S3 access to only specific buckets:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-app-bucket/*"
  }]
}
```

### Response steps after SSRF detection

1. **Revoke the compromised credential:** Detach the IAM role from the instance (forces new credential rotation)
2. **Isolate the instance:** Change its SG to deny all inbound/outbound except to your forensic tools
3. **Snapshot:** Take EBS snapshot / disk image for forensic analysis
4. **Rotate all secrets** accessible to the compromised role (RDS passwords, API keys in Parameter Store/Secrets Manager)
5. **Audit CloudTrail** for all API calls from that role in the last 7 days
6. **Enable IMDSv2** on all instances in the account before relaunching

## Hands-on lab

1. Set up the metadata simulator from the Red Team section on `localhost`
2. Verify IMDSv1 access works: `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/SimRole`
3. Verify IMDSv2 requires token — simulate the SSRF with and without `X-aws-ec2-metadata-token`
4. Verify token enforcement: modify the simulator to reject requests without a valid token
5. Retry the IMDSv1 curl — it should fail (401)
6. Test that the IMDSv2 curl with token still works
7. Optionally: deploy an EC2 instance with `http_tokens = required` and confirm `curl http://169.254.169.254/latest/meta-data/` returns a 401
8. Teardown: `sudo ifconfig lo0 169.254.169.254/32 delete`, `pkill -f metadata_simulator.py`

## Detection rules & checklists

```
# AWS Config rule — IMDSv2 enforced
- managed rule: ec2-imdsv2-check
- custom config: ensure all launch templates have MetadataOptions.HttpTokens == required

# Cloud Custodian — IMDSv1 instances
policies:
  - name: imdsv2-required
    resource: ec2
    filters:
      - type: metadata-options
        key: HttpTokens
        value: optional

# OPA — require IMDSv2 on launch
deny[msg] {
  template := input.launch_templates[_]
  template.metadata_options.http_tokens != "required"
  msg = sprintf("Launch template %s allows IMDSv1", [template.name])
}
```

```
# Checklist
- [ ] All EC2 instances / launch templates enforce IMDSv2 (HttpTokens = required)
- [ ] SCP blocks ec2:RunInstances unless MetadataHttpTokens = required
- [ ] Azure VMs not needing managed identity have it disabled
- [ ] GCP instances run without default service account where possible
- [ ] NSG/firewall/iptrules block outbound 169.254.169.254:80 as defense-in-depth
- [ ] CloudTrail alert on suspicious API calls from instance roles
- [ ] VPC Endpoint policies restrict S3/blobby access scope to specific buckets/containers
```

## References

- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Azure IMDS](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [GCP Metadata server](https://cloud.google.com/compute/docs/metadata/overview)
- [Capital One 2019 breach — SSRF + IMDS pivot](https://www.justice.gov/usao-wdwa/pr/former-seattle-tech-worker-sentenced-wire-fraud-and-computer-intrusions) — the canonical real-world example
- see ATT&CK Cloud matrix for Credential Access — Unsecured Credentials (T1552.005)
