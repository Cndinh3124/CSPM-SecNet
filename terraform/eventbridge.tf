resource "aws_sns_topic" "secnet_alerts" {
  name = "secnet-cspm-alerts"
}

data "archive_file" "secnet_alert_lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambda/finding_alert.py"
  output_path = "${path.module}/secnet-finding-alert.zip"
}

resource "aws_iam_role" "secnet_alert_lambda" {
  name = "SecNet-CSPM-Alert-Lambda-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "secnet_alert_lambda" {
  role = aws_iam_role.secnet_alert_lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["sns:Publish"]
        Resource = aws_sns_topic.secnet_alerts.arn
      },
      {
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

resource "aws_lambda_function" "secnet_finding_alert" {
  function_name    = "secnet-cspm-finding-alert"
  role             = aws_iam_role.secnet_alert_lambda.arn
  handler          = "finding_alert.lambda_handler"
  runtime          = "python3.13"
  filename         = data.archive_file.secnet_alert_lambda.output_path
  source_code_hash = data.archive_file.secnet_alert_lambda.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.secnet_alerts.arn
    }
  }
}

resource "aws_cloudwatch_event_rule" "secnet_securityhub" {
  name        = "secnet-securityhub-findings"
  description = "Forward Security Hub finding events to SecNet alert Lambda"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })
}

resource "aws_cloudwatch_event_target" "secnet_securityhub_lambda" {
  rule = aws_cloudwatch_event_rule.secnet_securityhub.name
  arn  = aws_lambda_function.secnet_finding_alert.arn
}

resource "aws_lambda_permission" "secnet_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.secnet_finding_alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.secnet_securityhub.arn
}
