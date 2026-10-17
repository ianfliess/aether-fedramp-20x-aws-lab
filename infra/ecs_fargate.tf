resource "aws_ecs_cluster" "mas_cluster" {
  name = "aether-20x-immutable-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "ecs_logs" {
  name              = "/ecs/aether-20x-api"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.fedramp_20x_cmk.arn
}

resource "aws_iam_role" "ecs_execution_role" {
  name = "aether-20x-ecs-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_exec_standard" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_secrets_kms_least_priv" {
  name = "aether-20x-ecs-secrets-kms-policy"
  role = aws_iam_role.ecs_execution_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "kms:Decrypt"
        ]
        Resource = [
          aws_db_instance.mas_database.master_user_secret[0].secret_arn,
          aws_kms_key.fedramp_20x_cmk.arn
        ]
      }
    ]
  })
}

resource "aws_ecs_task_definition" "immutable_microservice" {
  family                   = "aether-20x-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn

  container_definitions = jsonencode([
    {
      name                   = "mas-api-container"
      image                  = "${replace(var.ecr_repository_url, ".ecr-fips.", ".ecr.")}@${var.image_digest}" # Pinned @sha256 over PrivateLink!
      essential              = true
      readonlyRootFilesystem = true # KSI-CMT-LMC: Prevents runtime filesystem tampering
      user                   = "10001:10001"
      environment = [
        { name = "AWS_USE_FIPS_ENDPOINT", value = "true" },
        { name = "AWS_REGION", value = var.aws_region }
      ]
      secrets = [
        {
          name      = "DB_CREDENTIALS"
          valueFrom = aws_db_instance.mas_database.master_user_secret[0].secret_arn
        }
      ]
      portMappings = [
        {
          name          = "api-tls"
          containerPort = 8443
          protocol      = "tcp"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "immutable_microservice_svc" {
  name                   = "aether-20x-api-svc"
  cluster                = aws_ecs_cluster.mas_cluster.id
  task_definition        = aws_ecs_task_definition.immutable_microservice.arn
  desired_count          = 1
  launch_type            = "FARGATE"
  platform_version       = "1.4.0"
  enable_execute_command = false # CRITICAL FOR KSI-CMT-LMC: Blocks live interactive shell access!

  network_configuration {
    subnets          = [aws_subnet.private_app_az1.id, aws_subnet.private_app_az2.id]
    security_groups  = [aws_security_group.vpce_tls.id]
    assign_public_ip = false
  }
}
