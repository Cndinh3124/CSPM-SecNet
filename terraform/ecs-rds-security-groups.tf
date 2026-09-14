# ============================================================
# SecNet CSPM - ECS / RDS Security Groups
# ============================================================


# ============================================================
# ECS Security Group
# ============================================================

resource "aws_security_group" "secnet_ecs" {
  name        = "${var.project_name}-ECS-SG"
  description = "Security group for SecNet CSPM ECS tasks"
  vpc_id      = aws_vpc.cspm.id

  # Temporary application access.
  # This will be restricted further when the public access
  # architecture is finalized.
  ingress {
    description = "HTTP for SecNet CSPM API"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-ECS-SG"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "SecNet ECS Fargate"
  }
}


# ============================================================
# RDS Security Group
# ============================================================

resource "aws_security_group" "secnet_rds" {
  name        = "${var.project_name}-RDS-SG"
  description = "Security group for SecNet CSPM PostgreSQL RDS"
  vpc_id      = aws_vpc.cspm.id

  # PostgreSQL ingress rules are managed separately
  # using aws_security_group_rule resources.
  #
  # ECS -> RDS :5432
  # Lambda -> RDS :5432

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-RDS-SG"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "SecNet PostgreSQL"
  }
}


# ============================================================
# RDS Ingress - ECS
# ============================================================

resource "aws_security_group_rule" "rds_from_ecs" {
  type                     = "ingress"
  description              = "PostgreSQL from SecNet ECS"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.secnet_rds.id
  source_security_group_id = aws_security_group.secnet_ecs.id
}