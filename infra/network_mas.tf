resource "aws_vpc" "mas_boundary" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "aether-20x-mas-vpc"
    MAS-Rule-ID = "MAS-CSO-IIR"
  }
}

# Lock down the default security group completely (KSI-CNA-DFP / SC-07)
resource "aws_default_security_group" "default_lockdown" {
  vpc_id = aws_vpc.mas_boundary.id
}

resource "aws_subnet" "private_app_az1" {
  vpc_id                  = aws_vpc.mas_boundary.id
  cidr_block              = "10.20.10.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false
}

resource "aws_subnet" "private_app_az2" {
  vpc_id                  = aws_vpc.mas_boundary.id
  cidr_block              = "10.20.11.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = false
}

resource "aws_subnet" "isolated_db_az1" {
  vpc_id                  = aws_vpc.mas_boundary.id
  cidr_block              = "10.20.20.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false
}

resource "aws_subnet" "isolated_db_az2" {
  vpc_id                  = aws_vpc.mas_boundary.id
  cidr_block              = "10.20.21.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = false
}

resource "aws_route_table" "private_app_rt" {
  vpc_id = aws_vpc.mas_boundary.id
}

resource "aws_route_table_association" "private_app_az1_assoc" {
  subnet_id      = aws_subnet.private_app_az1.id
  route_table_id = aws_route_table.private_app_rt.id
}

resource "aws_route_table_association" "private_app_az2_assoc" {
  subnet_id      = aws_subnet.private_app_az2.id
  route_table_id = aws_route_table.private_app_rt.id
}

# Security Group for PrivateLink Endpoints & Internal MAS Services
resource "aws_security_group" "vpce_tls" {
  name        = "aether-20x-vpce-fips-sg"
  description = "Allow TLS 443 and 8443 inside MAS VPC"
  vpc_id      = aws_vpc.mas_boundary.id

  ingress {
    description = "HTTPS 443 from MAS VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.mas_boundary.cidr_block]
  }

  ingress {
    description = "Microservice 8443 from MAS VPC"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.mas_boundary.cidr_block]
  }

  egress {
    description = "Allow outbound HTTPS and PostgreSQL within MAS VPC and S3 Gateway"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# S3 Gateway Endpoint (Required for ECR image layer pulls inside private subnets)
resource "aws_vpc_endpoint" "s3_gateway" {
  vpc_id            = aws_vpc.mas_boundary.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private_app_rt.id]
}

# KMS FIPS Interface Endpoint
resource "aws_vpc_endpoint" "kms_fips" {
  vpc_id              = aws_vpc.mas_boundary.id
  service_name        = "com.amazonaws.${var.aws_region}.kms-fips"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_app_az1.id, aws_subnet.private_app_az2.id]
  security_group_ids  = [aws_security_group.vpce_tls.id]
  private_dns_enabled = true
}

# Secrets Manager Interface Endpoint
resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.mas_boundary.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_app_az1.id, aws_subnet.private_app_az2.id]
  security_group_ids  = [aws_security_group.vpce_tls.id]
  private_dns_enabled = true
}

# ECR API & DKR Interface Endpoints (Required so private Fargate tasks can pull images)
resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.mas_boundary.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_app_az1.id, aws_subnet.private_app_az2.id]
  security_group_ids  = [aws_security_group.vpce_tls.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.mas_boundary.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_app_az1.id, aws_subnet.private_app_az2.id]
  security_group_ids  = [aws_security_group.vpce_tls.id]
  private_dns_enabled = true
}

# CloudWatch Logs Interface Endpoint
resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.mas_boundary.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_app_az1.id, aws_subnet.private_app_az2.id]
  security_group_ids  = [aws_security_group.vpce_tls.id]
  private_dns_enabled = true
}
