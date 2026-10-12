variable "aws_region" {
  type        = string
  description = "AWS region for the CSPM demonstration environment."
  default     = "ap-southeast-1"
}

variable "project_name" {
  type        = string
  description = "Project identifier used in resource names and default tags."
  default     = "SecNet-CSPM"
}

variable "environment" {
  type        = string
  description = "Environment name. This Terraform stack is intended for a controlled demonstration."
  default     = "demo"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the demonstration VPC."
  default     = "10.50.0.0/16"
}

variable "allowed_ssh_cidr" {
  type        = string
  description = "Trusted CIDR used when the intentional public-SSH finding is disabled."
  default     = "10.50.0.0/16"
}

variable "enable_public_ssh_test" {
  type        = bool
  description = "Intentionally expose TCP/22 to the Internet to create a real Prowler finding."
  default     = false
}

variable "enable_public_s3_test" {
  type        = bool
  description = "Reserved for the S3 public-access scenario; not enabled in the first vertical slice."
  default     = false
}

variable "instance_type" {
  type        = string
  description = "Small instance type used only for the controlled demonstration."
  default     = "t3.micro"
}

variable "project_tags" {
  type        = map(string)
  description = "Additional tags applied to demonstration resources."
  default = {
    Owner = "CSPM-Demo"
  }
}
