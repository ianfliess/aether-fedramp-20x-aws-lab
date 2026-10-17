data "aws_caller_identity" "current" {}

resource "aws_kms_key" "fedramp_20x_cmk" {
  description             = "FedRAMP 20x MAS Master Encryption Key (FIPS 140-3 Level 3 HSM)"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootAndAdminPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailAndLogsEncryption"
        Effect    = "Allow"
        Principal = {
          Service = [
            "cloudtrail.amazonaws.com",
            "logs.${var.aws_region}.amazonaws.com"
          ]
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "fedramp_20x_cmk_alias" {
  name          = "alias/aether-fedramp-20x-mas-key"
  target_key_id = aws_kms_key.fedramp_20x_cmk.key_id
}

# Immutable Living Evidence Vault (Step 7: Reporting Integrity & Chain of Custody)
resource "aws_s3_bucket" "evidence_vault" {
  bucket              = "aether-20x-living-evidence-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = true
  force_destroy       = true
}

resource "aws_s3_bucket_public_access_block" "evidence_vault_block" {
  bucket                  = aws_s3_bucket.evidence_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault_sse" {
  bucket = aws_s3_bucket.evidence_vault.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.fedramp_20x_cmk.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_vault_worm" {
  bucket = aws_s3_bucket.evidence_vault.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }
}

# Enforce TLS 1.3 Minimum on S3 Evidence Vault (SC-08 / SC-28)
resource "aws_s3_bucket_policy" "evidence_vault_policy" {
  bucket = aws_s3_bucket.evidence_vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS13Requests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.evidence_vault.arn,
          "${aws_s3_bucket.evidence_vault.arn}/*"
        ]
        Condition = {
          NumericLessThan = {
            "s3:TlsVersion" = "1.3"
          }
        }
      }
    ]
  })
}
