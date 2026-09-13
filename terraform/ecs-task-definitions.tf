# ============================================================
# SecNet CSPM - ECS Fargate Task Definitions
# ============================================================

locals {
  secnet_rds_secret_arn = "arn:aws:secretsmanager:ap-southeast-1:392024306192:secret:rds!db-a22ac30c-8001-4dfe-aaef-4cd5231967d7-JopBIq"

  secnet_api_image = "392024306192.dkr.ecr.ap-southeast-1.amazonaws.com/secnet-cspm-api:latest"

  secnet_worker_image = "392024306192.dkr.ecr.ap-southeast-1.amazonaws.com/secnet-cspm-worker:latest"
}

# ============================================================
# API Task Definition
# ============================================================

resource "aws_ecs_task_definition" "secnet_api" {
  family                   = "secnet-cspm-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]

  cpu    = "256"
  memory = "512"

  execution_role_arn = aws_iam_role.secnet_ecs_execution.arn
  task_role_arn      = aws_iam_role.secnet_ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = local.secnet_api_image
      essential = true

      portMappings = [
        {
          containerPort = 8000
          hostPort      = 8000
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "AWS_REGION"
          value = "ap-southeast-1"
        },
        {
          name  = "CSPM_SCOPE"
          value = "LAB"
        },
        {
          name  = "DB_SECRET_ARN"
          value = local.secnet_rds_secret_arn
        },
        {
          name  = "DB_HOST"
          value = aws_db_instance.secnet.address
        },
        {
          name  = "DB_PORT"
          value = "5432"
        },
        {
          name  = "DB_NAME"
          value = "secnet_cspm"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"

        options = {
          awslogs-group         = aws_cloudwatch_log_group.secnet_ecs.name
          awslogs-region        = "ap-southeast-1"
          awslogs-stream-prefix = "api"
        }
      }
    }
  ])

  tags = {
    Name        = "SecNet-CSPM-API"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "SecNet CSPM API"
  }
}

# ============================================================
# Worker Task Definition
# ============================================================

resource "aws_ecs_task_definition" "secnet_worker" {
  family                   = "secnet-cspm-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]

  cpu    = "256"
  memory = "512"

  execution_role_arn = aws_iam_role.secnet_ecs_execution.arn
  task_role_arn      = aws_iam_role.secnet_ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "worker"
      image     = local.secnet_worker_image
      essential = true

      command = [
        "python",
        "-m",
        "app.worker"
      ]

      environment = [
        {
          name  = "AWS_REGION"
          value = "ap-southeast-1"
        },
        {
          name  = "CSPM_SCOPE"
          value = "LAB"
        },
        {
          name  = "DB_SECRET_ARN"
          value = local.secnet_rds_secret_arn
        },
        {
          name  = "DB_HOST"
          value = aws_db_instance.secnet.address
        },
        {
          name  = "DB_PORT"
          value = "5432"
        },
        {
          name  = "DB_NAME"
          value = "secnet_cspm"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"

        options = {
          awslogs-group         = aws_cloudwatch_log_group.secnet_ecs.name
          awslogs-region        = "ap-southeast-1"
          awslogs-stream-prefix = "worker"
        }
      }
    }
  ])

  tags = {
    Name        = "SecNet-CSPM-Worker"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "SecNet CSPM Worker"
  }
}