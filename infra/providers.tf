terraform {
  required_version = ">= 1.9.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.5"
    }
  }
  backend "s3" {
    bucket       = "aether-20x-tfstate-532404260491-us-east-1"
    key          = "fedramp-20x-lab/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region            = var.aws_region
  use_fips_endpoint = true # Enforces FIPS 140-3 AWS API endpoints (SC-13)

  default_tags {
    tags = {
      "FedRAMP-20x-MAS"      = "In-Scope"              # Rule MAS-CSO-IIR
      "FedRAMP-Class"        = "Class-C"               # CR26 Moderate Replacement
      "Immutable-Managed"    = "true"                  # KSI-CMT-LMC
      "Managed-By"           = "Terraform-GitHub-OIDC" # KSI-CMT-VTD
      "CMMC-Enclave-Scope"   = "CUI-Asset"             # NIST SP 800-171 3.4.1 / 3.4.2
      "Security-Decision-ID" = "SDR-AETHER-001"        # Links to Security Decision Record
    }
  }
}
