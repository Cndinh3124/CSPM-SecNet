provider "aws" {
  region = "ap-southeast-1"

  default_tags {
    tags = {
      Project     = "CSPM"
      Environment = "Lab"
      ManagedBy   = "Terraform"
    }
  }
}