provider "aws" {
 region=var.aws_region
 default_tags { tags={Project=var.project_name CSPMTest="true" ManagedBy="Terraform" Environment=var.environment} }
}
