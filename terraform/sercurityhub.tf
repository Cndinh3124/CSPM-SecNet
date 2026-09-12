resource "aws_securityhub_account" "cspm" {
  enable_default_standards = false

  depends_on = [
    aws_config_configuration_recorder_status.cspm
  ]
}

data "aws_region" "current" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.region}::standards/cis-aws-foundations-benchmark/v/5.0.0"

  depends_on = [
    aws_securityhub_account.cspm
  ]
}