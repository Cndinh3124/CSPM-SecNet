resource "aws_accessanalyzer_analyzer" "cspm_external" {
  analyzer_name = "CSPM-External-Access-Analyzer"
  type          = "ACCOUNT"

  tags = {
    Name        = "CSPM-External-Access-Analyzer"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
  }
}