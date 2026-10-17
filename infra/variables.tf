variable "aws_region" {
  description = "AWS US Commercial Region supporting FIPS 140-3 endpoints"
  type        = string
  default     = "us-east-1"
}

variable "ecr_repository_url" {
  description = "Amazon ECR Repository URL for the MAS microservice"
  type        = string
}

variable "image_digest" {
  description = "Immutable SHA256 digest (e.g., sha256:abc123...) for KSI-CMT-LMC"
  type        = string
}

variable "security_alert_webhook_url" {
  description = "Optional Slack/Teams/Webhook URL for Step 6 Detection & Response alerts"
  type        = string
  default     = ""
}
