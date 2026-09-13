# ============================================================
# SecNet CSPM - ECS IAM Roles
# ============================================================

resource "aws_iam_role" "secnet_ecs_execution" {
  name = "SecNet-CSPM-ECS-Execution-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "ECS Fargate Task Execution"
  }
}

resource "aws_iam_role_policy_attachment" "secnet_ecs_execution" {
  role = aws_iam_role.secnet_ecs_execution.name

  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "secnet_ecs_task" {
  name = "SecNet-CSPM-ECS-Task-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "SecNet CSPM Application"
  }
}

resource "aws_iam_role_policy" "secnet_ecs_task" {
  name = "SecNet-CSPM-ECS-Task-Policy"
  role = aws_iam_role.secnet_ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "SecurityHubReadOnly"
        Effect = "Allow"

        Action = [
          "securityhub:GetFindings",
          "securityhub:DescribeHub",
          "securityhub:GetEnabledStandards"
        ]

        Resource = "*"
      },
      {
        Sid    = "EC2ReadOnly"
        Effect = "Allow"

        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeFlowLogs",
          "ec2:DescribeRouteTables",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeAccountAttributes"
        ]

        Resource = "*"
      },
      {
        Sid    = "S3ReadOnly"
        Effect = "Allow"

        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketVersioning",
          "s3:GetBucketLogging",
          "s3:ListAllMyBuckets",
          "s3:ListBucket"
        ]

        Resource = "*"
      },
      {
        Sid    = "ConfigReadOnly"
        Effect = "Allow"

        Action = [
          "config:DescribeConfigRules",
          "config:DescribeConfigurationRecorders",
          "config:DescribeConfigurationRecorderStatus",
          "config:DescribeDeliveryChannels",
          "config:DescribeDeliveryChannelStatus",
          "config:GetComplianceDetailsByConfigRule",
          "config:GetComplianceDetailsByResource",
          "config:ListDiscoveredResources"
        ]

        Resource = "*"
      },
      {
        Sid    = "CloudTrailReadOnly"
        Effect = "Allow"

        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:ListTags"
        ]

        Resource = "*"
      },
      {
        Sid    = "IAMReadOnly"
        Effect = "Allow"

        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:ListAccountAliases",
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:GetUser",
          "iam:GetRole"
        ]

        Resource = "*"
      },
      {
        Sid    = "RDSSecretRead"
        Effect = "Allow"

        Action = [
          "secretsmanager:GetSecretValue"
        ]

        Resource = "arn:aws:secretsmanager:ap-southeast-1:392024306192:secret:rds!db-a22ac30c-8001-4dfe-aaef-4cd5231967d7-JopBIq"
      },
      {
        Sid    = "ECSExecSSMMessages"
        Effect = "Allow"

        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]

        Resource = "*"
      }
    ]
  })
}