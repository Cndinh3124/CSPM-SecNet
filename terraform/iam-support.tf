data "aws_iam_policy" "aws_support_access" {
  arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

resource "aws_iam_role" "cspm_support" {
  name        = "CSPM-AWSSupport-Role"
  description = "Role for authorized CSPM lab users to access AWS Support"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          AWS = "arn:aws:iam::392024306192:user/cspm-admin"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "CSPM-AWSSupport-Role"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
  }
}

resource "aws_iam_role_policy_attachment" "cspm_support" {
  role       = aws_iam_role.cspm_support.name
  policy_arn = data.aws_iam_policy.aws_support_access.arn
}