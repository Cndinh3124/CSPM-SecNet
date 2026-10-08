provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      {
        Project     = var.project_name
        CSPMTest    = "true"
        ManagedBy   = "Terraform"
        Environment = var.environment
      },
      var.project_tags
    )
  }
}
