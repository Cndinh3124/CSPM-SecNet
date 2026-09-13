# ============================================================
# SecNet CSPM - ECS Services
# ============================================================

# ============================================================
# API Service
# ============================================================

resource "aws_ecs_service" "secnet_api" {
  name            = "secnet-cspm-api"
  cluster         = aws_ecs_cluster.secnet.id
  task_definition = aws_ecs_task_definition.secnet_api.arn

  desired_count = 1

  launch_type = "FARGATE"

  network_configuration {
    subnets = [
      aws_subnet.public.id
    ]

    security_groups = [
      aws_security_group.secnet_ecs.id
    ]

    assign_public_ip = true
  }

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  enable_execute_command = true

  tags = {
    Name        = "SecNet-CSPM-API-Service"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "SecNet CSPM API"
  }
}

# ============================================================
# Worker Service
# ============================================================

resource "aws_ecs_service" "secnet_worker" {
  name            = "secnet-cspm-worker"
  cluster         = aws_ecs_cluster.secnet.id
  task_definition = aws_ecs_task_definition.secnet_worker.arn

  desired_count = 1

  launch_type = "FARGATE"

  network_configuration {
    subnets = [
      aws_subnet.public.id
    ]

    security_groups = [
      aws_security_group.secnet_ecs.id
    ]

    assign_public_ip = true
  }

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  enable_execute_command = true

  tags = {
    Name        = "SecNet-CSPM-Worker-Service"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "SecNet CSPM Worker"
  }
}