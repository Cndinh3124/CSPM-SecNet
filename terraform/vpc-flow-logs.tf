resource "aws_cloudwatch_log_group" "cspm_vpc_flow_logs" {
  name              = "/aws/vpc-flow-logs/cspm"
  retention_in_days = 7

  tags = {
    Name = "CSPM-VPC-Flow-Logs"
  }
}

resource "aws_iam_role" "cspm_vpc_flow_logs" {
  name = "CSPM-VPC-FlowLogs-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "CSPM-VPC-FlowLogs-Role"
  }
}

resource "aws_iam_role_policy" "cspm_vpc_flow_logs" {
  name = "CSPM-VPC-FlowLogs-Policy"
  role = aws_iam_role.cspm_vpc_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]

        Resource = "${aws_cloudwatch_log_group.cspm_vpc_flow_logs.arn}:*"
      }
    ]
  })
}

resource "aws_flow_log" "cspm_vpc" {
  vpc_id = aws_vpc.cspm.id

  traffic_type = "ALL"

  iam_role_arn = aws_iam_role.cspm_vpc_flow_logs.arn

  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.cspm_vpc_flow_logs.arn

  tags = {
    Name = "CSPM-VPC-Flow-Logs"
  }
}