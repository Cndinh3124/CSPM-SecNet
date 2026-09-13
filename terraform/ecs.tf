# ============================================================
# SecNet CSPM - ECS Cluster
# ============================================================

resource "aws_ecs_cluster" "secnet" {
  name = "secnet-cspm"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "SecNet-CSPM-ECS"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "SecNet CSPM"
  }
}

# ============================================================
# CloudWatch Log Group
# ============================================================

resource "aws_cloudwatch_log_group" "secnet_ecs" {
  name              = "/ecs/secnet-cspm"
  retention_in_days = 3

  tags = {
    Name        = "SecNet-CSPM-ECS-Logs"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "ECS Container Logs"
  }
}