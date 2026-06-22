# =============================================================================
# sandbox-aws-bootstrap.tf
# Purpose: Minimal Terraform to bootstrap a learner's personal AWS sandbox
#          account. Creates remote state infrastructure (S3 + DynamoDB lock)
#          and a limited-privilege CI/CD IAM role so learners can ship IaC
#          without using root / full-admin credentials.
#
# Curriculum cross-references:
#   - IaC-Security/           (tfsec, checkov scanning labs)
#   - IAM/policy-as-code-checkers.md
#   - Blue-Team-Defense/preventive-guardrails-as-code.md
#   - Compliance-Audit-Gov/evidence-automation.md
#
# Expected usage:
#   export AWS_PROFILE=sandbox-root          # one-time bootstrap with admin creds
#   terraform init
#   terraform plan -var="aws_account_id=111111111111"
#   terraform apply -var="aws_account_id=111111111111"
#
# After bootstrap, export TF_BACKEND_STATE_BUCKET=<output.bucket_name> and
# configure your module backends to use this bucket + lock table.
#
# ⚠️  ALL ACCOUNT IDS ARE PLACEHOLDERS — replace `111111111111` with your
#    actual sandbox account ID before running.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  # --- Backend block (deferred until after initial apply) --------------------
  # After the first `terraform apply` creates the S3 bucket and DynamoDB table,
  # uncomment this block, copy the bucket name + table name, and re-run
  # `terraform init -migrate-state`.
  #
  # backend "s3" {
  #   bucket         = "sandbox-tfstate-111111111111-us-east-1"
  #   key            = "sandbox-bootstrap/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "sandbox-tfstate-lock"
  #   encrypt        = true
  # }
}

# ---- Provider (defaults to env AWS_PROFILE / default credential chain) ------
provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Curriculum = "cloud-security-ops"
      ManagedBy  = "terraform"
      Purpose    = "sandbox-bootstrap"
      Owner      = "learner@example.com"   # replace with your learner tag
    }
  }
}

# ---- Input variables --------------------------------------------------------
variable "aws_account_id" {
  description = "AWS account ID of the learner sandbox (placeholder: 111111111111)"
  type        = string
  default     = "111111111111"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be a 12-digit AWS account number."
  }
}

variable "region" {
  description = "Primary AWS region for state resources"
  type        = string
  default     = "us-east-1"
}

# ---- Data sources (account identity) ---------------------------------------
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# =============================================================================
# 1. S3 bucket for remote Terraform state
# =============================================================================

resource "aws_s3_bucket" "tfstate" {
  bucket = "sandbox-tfstate-${var.aws_account_id}-${var.region}"

  # Block all public access — state files are sensitive
  # Reference: Storage-Data-Security/ (public bucket detection)
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # SSE-S3
    }
  }
}

# Deny non-SSL requests (enforce encryption in transit)
resource "aws_s3_bucket_policy" "tfstate_ssl" {
  bucket = aws_s3_bucket.tfstate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.tfstate.arn,
          "${aws_s3_bucket.tfstate.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# =============================================================================
# 2. DynamoDB lock table for Terraform state locking
# =============================================================================

resource "aws_dynamodb_table" "tfstate_lock" {
  name         = "sandbox-tfstate-lock"
  billing_mode = "PAY_PER_REQUEST"   # free-tier friendly for sandbox workloads
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  # Point-in-time recovery for compliance / forensics
  # Reference: Compliance-Audit-Gov/audit-log-retention-and-immutability.md
  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  ttl {
    attribute_name = "ExpiresAt"
    enabled        = true
  }
}

# =============================================================================
# 3. CI/CD IAM role with limited sandbox permissions
#    Purpose: role that a GitHub Actions / GitLab CI pipeline can assume.
#    Permissions are scoped to common IaC operations — least privilege.
#    Reference: IAM/long-lived-keys-vs-workload-identity.md
# =============================================================================

data "aws_iam_policy_document" "cicd_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }
    actions = ["sts:AssumeRole"]

    # In production, restrict this condition to your OIDC provider:
    # condition {
    #   test     = "StringLike"
    #   variable = "token.actions.githubusercontent.com:sub"
    #   values   = ["repo:example-org/*"]
    # }
  }
}

resource "aws_iam_role" "cicd" {
  name               = "sandbox-cicd-role"
  assume_role_policy = data.aws_iam_policy_document.cicd_assume_role.json
  description        = "Limited-privilege CI/CD role for sandbox IaC deployments"

  max_session_duration = 3600   # 1 hour

  # Reference: Blue-Team-Defense/blast-radius-reduction-patterns.md
  permissions_boundary = aws_iam_policy.cicd_permission_boundary.arn
}

resource "aws_iam_policy" "cicd_permission_boundary" {
  name        = "sandbox-cicd-boundary"
  description = "Permission boundary scoping CI/CD role to sandbox resources only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAllSandboxTaggedResources"
        Effect = "Allow"
        Action = [
          "s3:*",
          "iam:*",
          "lambda:*",
          "logs:*",
          "ec2:*",
          "ecs:*",
          "dynamodb:*",
          "kms:*",
          "secretsmanager:*",
          "ssm:*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Curriculum" = "cloud-security-ops"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cicd_admin_boundary" {
  role       = aws_iam_role.cicd.name
  policy_arn = aws_iam_policy.cicd_permission_boundary.arn
}

# Limited CI/CD inline policy — scope this down for production labs
resource "aws_iam_role_policy" "cicd_limited" {
  name = "sandbox-cicd-limited"
  role = aws_iam_role.cicd.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowStateBackendAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.tfstate.arn,
          "${aws_s3_bucket.tfstate.arn}/*"
        ]
      },
      {
        Sid    = "AllowDynamoDBLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = aws_dynamodb_table.tfstate_lock.arn
      }
    ]
  })
}

# =============================================================================
# Outputs
# =============================================================================

output "state_bucket_name" {
  value       = aws_s3_bucket.tfstate.bucket
  description = "S3 bucket for remote Terraform state"
}

output "state_lock_table_name" {
  value       = aws_dynamodb_table.tfstate_lock.name
  description = "DynamoDB table for Terraform state lock"
}

output "cicd_role_arn" {
  value       = aws_iam_role.cicd.arn
  description = "ARN of the CI/CD IAM role (assume from pipeline)"
}

output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "Sandbox AWS account ID (verify against input)"
}

output "bootstrap_region" {
  value       = data.aws_region.current.name
  description = "Region where state infrastructure was created"
}
