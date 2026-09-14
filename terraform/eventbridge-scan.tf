# ============================================================
# SecNet CSPM - Realtime Event-Driven Scan Trigger
# ============================================================

# ============================================================
# Security Group - Lambda Scan Trigger
# ============================================================

resource "aws_security_group" "secnet_scan_trigger" {
  name        = "${var.project_name}-Scan-Trigger-Lambda-SG"
  description = "Security group for SecNet CSPM realtime scan trigger Lambda"
  vpc_id      = aws_vpc.cspm.id

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "SecNet-CSPM-Scan-Trigger-Lambda-SG"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "Realtime CSPM scan trigger"
  }
}

# ============================================================
# Security Group - VPC Endpoint
# ============================================================

resource "aws_security_group" "secnet_vpce" {
  name        = "${var.project_name}-VPC-Endpoint-SG"
  description = "Security group for SecNet CSPM VPC Interface Endpoints"
  vpc_id      = aws_vpc.cspm.id

  ingress {
    description     = "HTTPS from Scan Trigger Lambda"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.secnet_scan_trigger.id]
  }

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "SecNet-CSPM-VPC-Endpoint-SG"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "Secrets Manager VPC Endpoint"
  }
}

# ============================================================
# RDS Access - Lambda -> PostgreSQL
# ============================================================

resource "aws_security_group_rule" "rds_from_scan_trigger" {
  type                     = "ingress"
  description              = "PostgreSQL from realtime CSPM scan trigger Lambda"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.secnet_rds.id
  source_security_group_id = aws_security_group.secnet_scan_trigger.id
}

# ============================================================
# Secrets Manager VPC Interface Endpoint
# ============================================================

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id = aws_vpc.cspm.id

  service_name      = "com.amazonaws.ap-southeast-1.secretsmanager"
  vpc_endpoint_type = "Interface"

  subnet_ids = [
    aws_subnet.private_a.id,
    aws_subnet.private_b.id
  ]

  security_group_ids = [
    aws_security_group.secnet_vpce.id
  ]

  private_dns_enabled = true

  tags = {
    Name        = "SecNet-CSPM-SecretsManager-Endpoint"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "Private Secrets Manager access for Lambda"
  }
}

# ============================================================
# IAM Role - Lambda Scan Trigger
# ============================================================

resource "aws_iam_role" "secnet_scan_trigger" {
  name = "SecNet-CSPM-Scan-Trigger-Lambda-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "lambda.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "SecNet-CSPM-Scan-Trigger-Lambda-Role"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "Realtime CSPM scan trigger"
  }
}

# ============================================================
# IAM Policy - Lambda Scan Trigger
# ============================================================

resource "aws_iam_role_policy" "secnet_scan_trigger" {
  name = "SecNet-CSPM-Scan-Trigger-Policy"
  role = aws_iam_role.secnet_scan_trigger.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "ReadRDSSecret"
        Effect = "Allow"

        Action = [
          "secretsmanager:GetSecretValue"
        ]

        Resource = local.secnet_rds_secret_arn
      },
      {
        Sid    = "LambdaVPCAccess"
        Effect = "Allow"

        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]

        Resource = "*"
      },
      {
        Sid    = "LambdaLogging"
        Effect = "Allow"

        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]

        Resource = "*"
      }
    ]
  })
}

# ============================================================
# Lambda - Realtime Scan Trigger
# ============================================================

resource "aws_lambda_function" "secnet_scan_trigger" {
  function_name = "secnet-cspm-scan-trigger"

  role = aws_iam_role.secnet_scan_trigger.arn

  handler = "scan_trigger.lambda_handler"
  runtime = "python3.13"

  filename = "${path.module}/../lambda/secnet-scan-trigger.zip"

  source_code_hash = filebase64sha256(
    "${path.module}/../lambda/secnet-scan-trigger.zip"
  )

  timeout     = 30
  memory_size = 256

  architectures = ["x86_64"]

  vpc_config {
    subnet_ids = [
      aws_subnet.private_a.id,
      aws_subnet.private_b.id
    ]

    security_group_ids = [
      aws_security_group.secnet_scan_trigger.id
    ]
  }

  environment {
    variables = {


      CSPM_SCOPE = "LAB"

      DB_SECRET_ARN = local.secnet_rds_secret_arn

      DB_HOST = aws_db_instance.secnet.address

      DB_PORT = "5432"

      DB_NAME = "secnet_cspm"
    }
  }

  tags = {
    Name        = "SecNet-CSPM-Scan-Trigger"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "Realtime CSPM scan trigger Lambda"
  }
}


resource "aws_cloudwatch_event_rule" "secnet_config_change" {
  name        = "secnet-cspm-config-change"
  description = "Trigger SecNet CSPM scan when AWS Config detects a configuration change"

  event_pattern = jsonencode({
    source = [
      "aws.config"
    ]

    detail-type = [
      "Config Configuration Item Change"
    ]

    detail = {
      configurationItem = {
        resourceType = [
          "AWS::EC2::SecurityGroup"
        ]
      }
    }
  })

  tags = {
    Project     = var.project_name
    Environment = "LAB"
    ManagedBy   = "Terraform"
    Purpose     = "Realtime CSPM"
  }
}

resource "aws_cloudwatch_event_target" "secnet_scan_trigger" {
  rule = aws_cloudwatch_event_rule.secnet_config_change.name

  arn = aws_lambda_function.secnet_scan_trigger.arn
}

resource "aws_lambda_permission" "allow_eventbridge_scan_trigger" {
  statement_id = "AllowEventBridgeInvoke"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.secnet_scan_trigger.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.secnet_config_change.arn
}