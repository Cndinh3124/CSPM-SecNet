data "aws_iam_policy_document" "config_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "config" {
  name               = "${var.project_name}-AWSConfig-Role"
  assume_role_policy = data.aws_iam_policy_document.config_assume_role.json

  tags = {
    Name = "${var.project_name}-AWSConfig-Role"
  }
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.cspm_lab.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"

        Principal = {
          Service = "config.amazonaws.com"
        }

        Action = "s3:GetBucketAcl"

        Resource = aws_s3_bucket.cspm_lab.arn

        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"

        Principal = {
          Service = "config.amazonaws.com"
        }

        Action = "s3:PutObject"

        Resource = "${aws_s3_bucket.cspm_lab.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"

        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }

          StringLike = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

resource "aws_config_configuration_recorder" "cspm" {
  name     = "cspm-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.config
  ]
}

resource "aws_config_delivery_channel" "cspm" {
  name           = "cspm-config-delivery"
  s3_bucket_name = aws_s3_bucket.cspm_lab.id
  s3_key_prefix  = "AWSLogs"

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [
    aws_config_configuration_recorder.cspm,
    aws_s3_bucket_policy.config
  ]
}

resource "aws_config_configuration_recorder_status" "cspm" {
  name       = aws_config_configuration_recorder.cspm.name
  is_enabled = true

  depends_on = [
    aws_config_delivery_channel.cspm
  ]
}