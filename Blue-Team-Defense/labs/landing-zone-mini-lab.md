# Lab — Landing Zone Mini Lab

> **Module:** 10-01 Landing Zone as Defense
> **Approx. time:** 30 minutes
> **Cost:** Free tier (AWS Organizations is free; SCPs are free; no EC2/resources created)
> **Authorization scope:** Run only in your own AWS sandbox organization.

## Objective

Stand up a minimal AWS landing zone with:
1. One logging account + one workload account + one suspended account in a "Suspended" OU.
2. SCP denying `s3:CreateBucket` with public ACL.
3. SCP denying `cloudtrail:StopLogging`.
4. Verify that the workload account cannot bypass the SCPs.
5. Tear down cleanly.

## Prerequisites

- An AWS account with `organizations:*` and `iam:*` permissions.
- AWS CLI configured with credentials for the management account.
- The account must be an AWS Organizations management account (or you must create an organization).

## Step 1 — Create the organization

```bash
aws organizations create-organization --feature-set ALL

ORG_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
echo "Organization created. Root ID: $ORG_ID"
```

## Step 2 — Create OUs

```bash
aws organizations create-organizational-unit \
  --parent-id $ORG_ID \
  --name "Security"

aws organizations create-organizational-unit \
  --parent-id $ORG_ID \
  --name "Workloads"

aws organizations create-organizational-unit \
  --parent-id $ORG_ID \
  --name "Suspended"

SECURITY_OU=$(aws organizations list-organizational-units-for-parent \
  --parent-id $ORG_ID \
  --query "OrganizationalUnits[?Name=='Security'].Id" --output text)

WORKLOADS_OU=$(aws organizations list-organizational-units-for-parent \
  --parent-id $ORG_ID \
  --query "OrganizationalUnits[?Name=='Workloads'].Id" --output text)

SUSPENDED_OU=$(aws organizations list-organizational-units-for-parent \
  --parent-id $ORG_ID \
  --query "OrganizationalUnits[?Name=='Suspended'].Id" --output text)

echo "OUs created: Security=$SECURITY_OU, Workloads=$WORKLOADS_OU, Suspended=$SUSPENDED_OU"
```

## Step 3 — Create member accounts

```bash
aws organizations create-account \
  --account-name "LogArchive" \
  --email "aws-logarchive-lab@example.com" \
  --role-name OrganizationAccountAccessRole

LOG_ACCOUNT_ID=$(aws organizations list-accounts --query "Accounts[?Name=='LogArchive'].Id" --output text)

aws organizations create-account \
  --account-name "WorkloadApp" \
  --email "aws-workloadapp-lab@example.com" \
  --role-name OrganizationAccountAccessRole

WORKLOAD_ACCOUNT_ID=$(aws organizations list-accounts --query "Accounts[?Name=='WorkloadApp'].Id" --output text)

echo "Accounts created: LogArchive=$LOG_ACCOUNT_ID, WorkloadApp=$WORKLOAD_ACCOUNT_ID"
```

## Step 4 — Move accounts to correct OUs

```bash
aws organizations move-account \
  --account-id $LOG_ACCOUNT_ID \
  --source-parent-id $ORG_ID \
  --destination-parent-id $SECURITY_OU

aws organizations move-account \
  --account-id $WORKLOAD_ACCOUNT_ID \
  --source-parent-id $ORG_ID \
  --destination-parent-id $WORKLOADS_OU
```

## Step 5 — Create and attach SCPs

### SCP 1 — Deny public S3 bucket creation

```bash
aws organizations create-policy \
  --name "DenyPublicS3" \
  --type SERVICE_CONTROL_POLICY \
  --description "Deny creation of public S3 buckets" \
  --content '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyPublicS3ACL",
        "Effect": "Deny",
        "Action": "s3:PutBucketAcl",
        "Resource": "*",
        "Condition": {
          "StringEqualsIgnoreCaseIfExists": {
            "s3:x-amz-acl": [
              "public-read",
              "public-read-write",
              "authenticated-read"
            ]
          }
        }
      },
      {
        "Sid": "DenyPublicS3Policy",
        "Effect": "Deny",
        "Action": "s3:PutBucketPolicy",
        "Resource": "*",
        "Condition": {
          "StringLike": {
            "s3:policy/Statement/Principal": "*"
          }
        }
      }
    ]
  }'

DENY_PUBLIC_S3_POLICY_ID=$(aws organizations list-policies \
  --filter SERVICE_CONTROL_POLICY \
  --query "Policies[?Name=='DenyPublicS3'].Id" --output text)
```

### SCP 2 — Deny CloudTrail disable

```bash
aws organizations create-policy \
  --name "DenyCloudTrailDisable" \
  --type SERVICE_CONTROL_POLICY \
  --description "Deny stopping or deleting CloudTrail trails" \
  --content '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyStopLogging",
        "Effect": "Deny",
        "Action": [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail"
        ],
        "Resource": "*"
      }
    ]
  }'

DENY_CLOUDTRAIL_POLICY_ID=$(aws organizations list-policies \
  --filter SERVICE_CONTROL_POLICY \
  --query "Policies[?Name=='DenyCloudTrailDisable'].Id" --output text)
```

### Attach SCPs to Workloads OU

```bash
aws organizations attach-policy \
  --policy-id $DENY_PUBLIC_S3_POLICY_ID \
  --target-id $WORKLOADS_OU

aws organizations attach-policy \
  --policy-id $DENY_CLOUDTRAIL_POLICY_ID \
  --target-id $WORKLOADS_OU

echo "SCPs attached to Workloads OU"
```

## Step 6 — Create a quarantine SCP for the Suspended OU

```bash
aws organizations create-policy \
  --name "QuarantineDenyAll" \
  --type SERVICE_CONTROL_POLICY \
  --description "Deny all actions except read-only for forensics" \
  --content '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "QuarantineDeny",
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
          "StringNotEquals": {
            "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassRole"
          }
        }
      }
    ]
  }'

QUARANTINE_POLICY_ID=$(aws organizations list-policies \
  --filter SERVICE_CONTROL_POLICY \
  --query "Policies[?Name=='QuarantineDenyAll'].Id" --output text)

aws organizations attach-policy \
  --policy-id $QUARANTINE_POLICY_ID \
  --target-id $SUSPENDED_OU

echo "Quarantine SCP attached to Suspended OU"
```

## Step 7 — Test the SCPs (in the workload account)

You need to assume the `OrganizationAccountAccessRole` in the workload account to test.

```bash
aws sts assume-role \
  --role-arn "arn:aws:iam::$WORKLOAD_ACCOUNT_ID:role/OrganizationAccountAccessRole" \
  --role-session-name "scp-test-$(date +%s)" \
  --duration-seconds 900 > /tmp/workload-creds.json

export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId /tmp/workload-creds.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretAccessKey /tmp/workload-creds.json)
export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken /tmp/workload-creds.json)

aws sts get-caller-identity
```

### Test 1 — Try to create a public S3 bucket (should fail)

```bash
aws s3 mb s3://scp-test-bucket-$(date +%s)-11111 --region us-east-1 2>/dev/null && echo "Bucket created"
# Attempt to make it public-read:
aws s3api put-bucket-acl --bucket scp-test-bucket-$(date +%s)-11111 --acl public-read 2>&1
```

**Expected output:** `An error occurred (AccessDenied) when calling the PutBucketAcl operation: ... denied by SCP`

### Test 2 — Try to stop CloudTrail (should fail)

```bash
aws cloudtrail stop-logging --name nonexistent-trail 2>&1
```

**Expected output:** Either `AccessDenied` or `TrailNotFoundException` — either way, the SCP blocks the `cloudtrail:StopLogging` action before it reaches the CloudTrail service.

### Test 3 — Verify read operations still work

```bash
aws s3 ls 2>&1
aws cloudtrail describe-trails 2>&1
```

**Expected:** Both should succeed — the SCPs deny only specific write actions, not reads.

## Step 8 — Tear down

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

aws organizations detach-policy --policy-id $DENY_PUBLIC_S3_POLICY_ID --target-id $WORKLOADS_OU
aws organizations detach-policy --policy-id $DENY_CLOUDTRAIL_POLICY_ID --target-id $WORKLOADS_OU
aws organizations detach-policy --policy-id $QUARANTINE_POLICY_ID --target-id $SUSPENDED_OU

aws organizations delete-policy --policy-id $DENY_PUBLIC_S3_POLICY_ID
aws organizations delete-policy --policy-id $DENY_CLOUDTRAIL_POLICY_ID
aws organizations delete-policy --policy-id $QUARANTINE_POLICY_ID

aws organizations close-account --account-id $LOG_ACCOUNT_ID
aws organizations close-account --account-id $WORKLOAD_ACCOUNT_ID

aws organizations delete-organizational-unit --organizational-unit-id $SECURITY_OU
aws organizations delete-organizational-unit --organizational-unit-id $WORKLOADS_OU
aws organizations delete-organizational-unit --organizational-unit-id $SUSPENDED_OU

aws organizations delete-organization

rm /tmp/workload-creds.json 2>/dev/null
```

> **Note:** `close-account` initiates account closure (90-day post-close window). Monitor billing to confirm no charges accrue.

## Expected output summary

| Test | Expected result | What it proves |
|---|---|---|
| Create S3 bucket | Success (bucket created) | Non-public bucket creation is allowed |
| `PutBucketAcl public-read` | AccessDenied | SCP blocks public ACL |
| `PutBucketPolicy with Principal:*` | AccessDenied | SCP blocks public bucket policy |
| `cloudtrail:StopLogging` | AccessDenied | SCP blocks logging disable |
| `s3:ListBuckets` | Success (may be empty) | Read operations unblocked |
| `cloudtrail:DescribeTrails` | Success | Read operations unblocked |

## Cost note

- AWS Organizations: Free.
- SCPs: Free.
- No EC2, S3 storage beyond test bucket (delete during teardown), no CloudTrail trail created. Cost should be near $0.

## References
- [AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html)
- [AWS SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [10-01 Landing Zone as Defense](../landing-zone-as-defense.md)
- [10-02 Preventive Guardrails as Code](../preventive-guardrails-as-code.md)
