resource "aws_kms_key" "cspm_cloudtrail" {
  description             = "KMS key for encrypting CSPM CloudTrail logs"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"

        Principal = {
          AWS = "arn:aws:iam::392024306192:root"
        }

        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailEncryptLogs"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]

        Resource = "*"

        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = "392024306192"
          }

          StringLike = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:ap-southeast-1:392024306192:trail/cspm-cloudtrail"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "CSPM-CloudTrail-KMS"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
  }
}

resource "aws_kms_alias" "cspm_cloudtrail" {
  name          = "alias/cspm-cloudtrail"
  target_key_id = aws_kms_key.cspm_cloudtrail.key_id
}