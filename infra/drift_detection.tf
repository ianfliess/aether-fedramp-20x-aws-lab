# 1. S3 Bucket & Multi-Region CloudTrail Trail (Step 2 Data Sourcing for EventBridge)
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "aether-20x-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_block" {
  bucket                  = aws_s3_bucket.cloudtrail_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_sse" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.fedramp_20x_cmk.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_bucket.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "mas_management_trail" {
  name                          = "aether-20x-mas-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.fedramp_20x_cmk.arn
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_bucket_policy]
}

# 2. Package the Python 7-Step KSI Validator into a Lambda Zip Archive
data "archive_file" "ksi_validator_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/ksi_validator/handler.py"
  output_path = "${path.module}/ksi_validator.zip"
}

resource "aws_iam_role" "ksi_validator_lambda_role" {
  name = "aether-20x-ksi-validator-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    "LogAccessClearance" = "Authorized-JIT-Auditor"
  }
}

resource "aws_iam_role_policy" "ksi_validator_policy" {
  name = "aether-20x-ksi-validator-least-priv"
  role = aws_iam_role.ksi_validator_lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecs:DescribeServices", "ecs:DescribeTaskDefinition", "rds:DescribeDBInstances"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectRetention"]
        Resource = "${aws_s3_bucket.evidence_vault.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.fedramp_20x_cmk.arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "ksi_validator" {
  function_name    = "aether-20x-7step-ksi-validator"
  role             = aws_iam_role.ksi_validator_lambda_role.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.ksi_validator_zip.output_path
  source_code_hash = data.archive_file.ksi_validator_zip.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      EVIDENCE_BUCKET_NAME       = aws_s3_bucket.evidence_vault.id
      ECS_CLUSTER_NAME           = aws_ecs_cluster.mas_cluster.name
      ECS_SERVICE_NAME           = aws_ecs_service.immutable_microservice_svc.name
      RDS_DB_IDENTIFIER          = aws_db_instance.mas_database.identifier
      SECURITY_ALERT_WEBHOOK_URL = var.security_alert_webhook_url
    }
  }
}

# 3. EventBridge Rules & Targets (Real-Time Drift + Daily Persistent Schedule)
resource "aws_cloudwatch_event_rule" "ksi_cmt_lmc_drift_guard" {
  name        = "aether-20x-ksi-cmt-lmc-drift-detector"
  description = "Catches live container ExecuteCommand or manual Console/CLI modifications"

  event_pattern = jsonencode({
    source      = ["aws.ecs", "aws.ec2", "aws.rds", "aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ecs.amazonaws.com", "ec2.amazonaws.com", "rds.amazonaws.com", "ssm.amazonaws.com"]
      eventName = [
        "ExecuteCommand",
        "RegisterTaskDefinition",
        "UpdateService",
        "ModifyInstanceAttribute",
        "AuthorizeSecurityGroupIngress",
        "ModifyDBInstance",
        "StartSession"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "drift_to_lambda" {
  rule      = aws_cloudwatch_event_rule.ksi_cmt_lmc_drift_guard.name
  target_id = "InvokeKSIValidatorOnDrift"
  arn       = aws_lambda_function.ksi_validator.arn
}

resource "aws_lambda_permission" "allow_eventbridge_drift" {
  statement_id  = "AllowExecutionFromEventBridgeDrift"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ksi_validator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ksi_cmt_lmc_drift_guard.arn
}

resource "aws_cloudwatch_event_rule" "daily_ksi_validation_schedule" {
  name                = "aether-20x-daily-ksi-validator"
  description         = "Executes persistent daily validation of KSI-CMT-LMC, KSI-CNA-DFP, and KSI-SVC"
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "daily_to_lambda" {
  rule      = aws_cloudwatch_event_rule.daily_ksi_validation_schedule.name
  target_id = "InvokeKSIValidatorDaily"
  arn       = aws_lambda_function.ksi_validator.arn
}

resource "aws_lambda_permission" "allow_eventbridge_daily" {
  statement_id  = "AllowExecutionFromEventBridgeDaily"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ksi_validator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_ksi_validation_schedule.arn
}
