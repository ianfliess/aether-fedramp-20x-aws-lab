resource "aws_db_subnet_group" "isolated_rds" {
  name       = "aether-20x-isolated-rds-sng"
  subnet_ids = [aws_subnet.isolated_db_az1.id, aws_subnet.isolated_db_az2.id]
}

resource "aws_security_group" "rds_sg" {
  name        = "aether-20x-rds-sg"
  description = "Allow PostgreSQL 5432 strictly from MAS App Subnets"
  vpc_id      = aws_vpc.mas_boundary.id

  ingress {
    description     = "PostgreSQL TLS from ECS Fargate"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.vpce_tls.id]
  }
}

resource "aws_db_parameter_group" "postgres_fips_tls" {
  name   = "aether-20x-pg16-tls13"
  family = "postgres16"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }
  parameter {
    name         = "ssl_min_protocol_version"
    value        = "TLSv1.3"
    apply_method = "immediate"
  }
}

resource "aws_db_instance" "mas_database" {
  identifier                    = "aether-20x-mas-db"
  engine                        = "postgres"
  engine_version                = "16"
  instance_class                = "db.t4g.micro"
  allocated_storage             = 20
  storage_type                  = "gp3"
  storage_encrypted             = true # Mandatory SC-28 encryption at rest
  kms_key_id                    = aws_kms_key.fedramp_20x_cmk.arn
  db_name                       = "fedramp20xlab"
  username                      = "mas_admin"
  manage_master_user_password   = true # KSI-SVC: Secrets Manager auto-manages & rotates password
  master_user_secret_kms_key_id = aws_kms_key.fedramp_20x_cmk.key_id

  db_subnet_group_name    = aws_db_subnet_group.isolated_rds.name
  vpc_security_group_ids  = [aws_security_group.rds_sg.id]
  parameter_group_name    = aws_db_parameter_group.postgres_fips_tls.name
  multi_az                = false
  publicly_accessible     = false
  backup_retention_period = 7 # KSI-RPL-ABO: Aligning Backups with RPO
  copy_tags_to_snapshot   = true
  skip_final_snapshot     = true
}
