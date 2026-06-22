# Lab 01 — Credential Dip: Detect & Respond to a Leaked Access Key

> **Level:** Intermediate
> **Prereqs:** 02-01 (Identity Primitives), 02-04 (Long-Lived Keys vs Workload Identity)
> **Clouds:** AWS (primary; Azure/GCP notes for analogous exercises)
> **Time:** ~30 minutes
> **Cost:** Free-tier eligible (CloudTrail Lake costs ~$0 in trial queries; STS/IAM are free)

## Lab overview

You will:
1. Create an IAM User with a long-lived access key in your AWS sandbox.
2. Commit the key "accidentally" to a git repository.
3. Simulate attacker usage from an unusual IP/region.
4. Detect the leaked key usage in CloudTrail Lake.
5. Rotate and quarantine the key.
6. Repeat step 5 but using workload identity (IRSA concept) — show no static secret exists.

## Prerequisites

- AWS account (sandbox only — `111111111111` placeholder used throughout)
- AWS CLI configured with admin credentials
- Git installed
- `jq` installed
- CloudTrail enabled (default on new accounts; verify with `aws cloudtrail describe-trails`)

## Part A — Create the key and leak it

### Step A1: Create IAM User with access key

```bash
aws iam create-user --user-name lab-creddip-user
aws iam attach-user-policy \
  --user-name lab-creddip-user \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

KEY_OUTPUT=$(aws iam create-access-key --user-name lab-creddip-user)
echo "$KEY_OUTPUT" | jq .

AKID=$(echo "$KEY_OUTPUT" | jq -r .AccessKey.AccessKeyId)
SAK=$(echo "$KEY_OUTPUT" | jq -r .AccessKey.SecretAccessKey)
echo "Key created: $AKID"
```

### Step A2: "Accidentally" commit the key

```bash
mkdir -p /tmp/creddip-repo && cd /tmp/creddip-repo
git init

cat > config.json << EOF
{
  "aws_access_key_id": "${AKID}",
  "aws_secret_access_key": "${SAK}",
  "region": "us-east-1"
}
EOF

git add config.json
git commit -m "Add deployment config"
echo "Key committed to git repo at /tmp/creddip-repo"
```

### Step A3: Simulate attacker usage from a different region

```bash
# The "attacker" exports the key and uses it
export AWS_ACCESS_KEY_ID="$AKID"
export AWS_SECRET_ACCESS_KEY="$SAK"

# Verify the key works
aws sts get-caller-identity --region us-west-2
# This creates a CloudTrail event from us-west-2 — which is unlikely
# to be your normal region for this test user.

# Enumerate what the key can access
aws s3 ls --region us-west-2
aws iam list-attached-user-policies --user-name lab-creddip-user --region us-west-2

echo "Attacker actions complete — check CloudTrail in the next step"
```

## Part B — Detect the leaked key with CloudTrail Lake

### Step B1: Set up CloudTrail Lake (if not already)

```bash
# Create an event data store for management events
aws cloudtrail create-event-data-store \
  --name lab-creddip-eds \
  --retention-period 7 \
  --multi-region-enabled

# Wait for the event data store to be created
sleep 10

# Get the event data store ID
EDS_ID=$(aws cloudtrail list-event-data-stores \
  --query "EventDataStores[?Name=='lab-creddip-eds'].EventDataStoreId" \
  --output text)
echo "Event data store ID: $EDS_ID"
```

> **Note:** CloudTrail Lake queries against new event data stores may take up to 24 hours to reflect fresh events. For immediate results, use `aws cloudtrail lookup-events` instead:

### Step B2: Detect the leaked key usage (immediate method)

```bash
# Look up events for the leaked access key
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$AKID" \
  --max-results 20 \
  --query "Events[].[EventTime,EventName,Username,SourceIPAddress]" \
  --output table
```

**Expected output:** You should see `GetCallerIdentity`, `ListBuckets` (s3 ls), and `ListAttachedUserPolicies` events with the `lab-creddip-user` username, from a source IP address that is your own — but the region (`us-west-2`) and event sequence match an enumeration pattern.

### Step B3: CloudTrail Lake query (for event data stores)

```sql
SELECT eventTime, eventName, awsRegion, sourceIPAddress, userAgent
FROM "<EDS_ID>"
WHERE userIdentity.accessKeyId = '<AKID>'
ORDER BY eventTime DESC
```

Run with:

```bash
aws cloudtrail start-query \
  --query-statement "SELECT eventTime, eventName, awsRegion, sourceIPAddress FROM \"$EDS_ID\" WHERE userIdentity.accessKeyId = '$AKID' ORDER BY eventTime DESC" \
  --query QueryId --output text
```

### Step B4: Analyze the pattern — what would a SOC analyst see?

| Signal | Meaning |
|---|---|
| `GetCallerIdentity` from `us-west-2` | Attacker verifying credential validity |
| Multiple API calls in rapid succession | Enumeration (not normal human pacing) |
| `ListAttachedUserPolicies` | Attacker checking what the key can do |
| No `console.amazonaws.com` User-Agent | Programmatic access, not console |

## Part C — Rotate and quarantine

### Step C1: Deactivate the compromised key

```bash
aws iam update-access-key \
  --user-name lab-creddip-user \
  --access-key-id "$AKID" \
  --status Inactive

echo "Key $AKID deactivated."
```

### Step C2: Verify the key no longer works

```bash
# As the "attacker" — key should now fail
aws sts get-caller-identity --region us-west-2 2>&1
# Expected: AccessDenied

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```

### Step C3: Attach a quarantine policy (deny-all inline)

```bash
aws iam put-user-policy \
  --user-name lab-creddip-user \
  --policy-name QuarantineDenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

echo "Quarantine policy attached to lab-creddip-user."
```

### Step C4: Create a new key if needed (rotation)

```bash
aws iam create-access-key --user-name lab-creddip-user
echo "New key created. Deploy this to the legitimate workload (not this lab)."
```

### Step C5: Clean up the compromised key

```bash
aws iam delete-access-key \
  --user-name lab-creddip-user \
  --access-key-id "$AKID"
```

## Part D — Repeat with workload identity (no static secret)

### Step D1: Create an IAM Role (IRSA-style workload identity)

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws iam create-role --role-name lab-creddip-wl --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

aws iam attach-role-policy \
  --role-name lab-creddip-wl \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

### Step D2: Show there is NO static key to leak

```bash
# Enumerate all access keys for the role's functions
# A role has NO access keys — only STS temporary credentials
aws iam list-access-keys --user-name lab-creddip-user 2>/dev/null || echo "Roles do not have access keys."

# Try to find any static credential associated with this role
aws iam get-role --role-name lab-creddip-wl \
  --query "Role.{Name:RoleName,Arn:Arn,MaxSession:MaxSessionDuration}" --output json

# Result: No AccessKeyId. No SecretAccessKey. Only a role ARN and a trust policy.
echo "No static key exists for role lab-creddip-wl."
```

### Step D3: Compare — what would an attacker find?

```bash
cd /tmp/creddip-repo
git grep -i "AKIA\|ASIA" $(git rev-list --all)
# For the role: no key in config.json — nothing to leak.
# For the user: finds the committed AKIA* key.
```

### Step D4: How an EC2 instance gets the role credentials

```bash
# On an EC2 instance with lab-creddip-wl role:
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/lab-creddip-wl
# Returns: { "AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "...", "Expiration": "..." }
# All temporary, automatically rotated by AWS — never stored in git or env vars.
```

## Expected results

| Part | Expected outcome |
|---|---|
| A2 | `git log` shows the committed access key |
| A3 | `sts get-caller-identity` succeeds from `us-west-2` |
| B2 | CloudTrail `lookup-events` returns the leaked key's activity |
| C2 | After deactivation, `sts get-caller-identity` returns `AccessDenied` |
| D3 | No `AKIA*` key found — workload identity leaves no static secret |

## Azure equivalent (notes)

```bash
# Create an App Registration with client secret (= static key)
az ad app create --display-name "creddip-app"
SECRET=$(az ad app credential reset --id <app-id> --years 1 --query password -o tsv)

# Check Azure Activity Log for credential usage
az monitor activity-log list --caller "<app-id>" --offset 1h

# Migrate to Workload Identity Federation (no secret)
az ad app federated-credential create \
  --id <app-id> \
  --name "github-fc" \
  --issuer "https://token.actions.githubusercontent.com" \
  --subject "repo:example-org/example-repo:ref:refs/heads/main" \
  --audiences "api://AzureADTokenExchange"
```

## GCP equivalent (notes)

```bash
# Create SA with key (= static key)
gcloud iam service-accounts keys create key.json \
  --iam-account sa-creddip@project-id-111111.iam.gserviceaccount.com

# Check Cloud Audit Logs for SA key usage
gcloud logging read \
  'protoPayload.authenticationInfo.serviceAccountKeyName:"sa-creddip"'

# Migrate to Workload Identity Federation (GitHub OIDC — no key)
gcloud iam workload-identity-pools create github-pool --location global
```

## Teardown

```bash
# AWS cleanup
aws iam delete-user-policy --user-name lab-creddip-user --policy-name QuarantineDenyAll
aws iam detach-user-policy --user-name lab-creddip-user \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
aws iam delete-access-key --user-name lab-creddip-user --access-key-id "$(aws iam list-access-keys --user-name lab-creddip-user --query 'AccessKeyMetadata[0].AccessKeyId' --output text)" 2>/dev/null
aws iam delete-user --user-name lab-creddip-user

aws iam detach-role-policy --role-name lab-creddip-wl \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
aws iam delete-role --role-name lab-creddip-wl

aws cloudtrail delete-event-data-store --event-data-store-id "$EDS_ID"

rm -rf /tmp/creddip-repo
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AKID SAK EDS_ID
echo "Cleanup complete."
```

## Reflection questions

1. How long between the key being committed to git and the detection query running? (Simulating MTTD — Mean Time to Detect.)
2. What if the attacker used the key from an IP in your normal corporate range? Would CloudTrail still be sufficient?
3. Compare the teardown steps for the IAM User vs. the IAM Role — which required more cleanup? Why?
4. In Part D, what would an attacker need to compromise to get the role's credentials?

## References
- [AWS CloudTrail Lake](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html)
- [AWS IAM Access Key Rotation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#rotating_access_keys)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
